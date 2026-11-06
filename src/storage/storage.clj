(ns storage.storage
  "File-backed DNS rule store (EDN on disk) plus an in-memory capped query
  log. The query log is what turns this proxy into a device-discovery
  tool: every name a LAN client asks for is recorded with the client IP."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.nio.file Files StandardCopyOption]
           [java.nio.file.attribute FileAttribute]))

(def default-state
  {:uscan-scanners []
   :rules []
   :proxy-maps []
   :proxy-listeners []
   :proxy-mounts []
   :transformers []
   :ptr-records []
   :blocklists []
   :query-log-size 1000
   :blocking-enabled true})

(defn- read-state [path]
  (let [f (io/file path)]
    (if (.exists f)
      (try
        (merge default-state (dissoc (edn/read-string (slurp f)) :stats :query-log))
        (catch Exception e
          (println "storage: cannot read" path "-" (.getMessage e))
          default-state))
      default-state)))

(defn save!
  "Atomically persist state (query log stays in memory only)."
  [path state]
  (let [f (io/file path)
        tmp (io/file (str path ".tmp"))]
    (io/make-parents f)
    (spit tmp (pr-str (dissoc state :query-log :stats)))
    (Files/move (.toPath tmp) (.toPath f)
                (into-array StandardCopyOption
                            [StandardCopyOption/REPLACE_EXISTING]))
    true))

(defn open
  "Open (or create) the store at path. Returns an atom of state
  path rides along in metadata so mutations can persist themselves."
  [path]
  (atom (with-meta (read-state path) {::path path})))




(defn- rule-type [rule]
  (keyword (or (get-in rule [:match :type]) (:match_type rule) "suffix")))

(defn- rule-value [rule]
  (str/lower-case (str (or (get-in rule [:match :value]) (:match rule) ""))))

(defn match? [rule qname]
  (let [t (rule-type rule)
        v (rule-value rule)]
    (case t
      :exact (= qname v)
      :suffix (or (= qname v)
                  (str/ends-with? qname
                                  (if (str/starts-with? v ".")
                                    v
                                    (str "." v))))
      :regex (try (boolean (re-find (re-pattern v) qname))
                  (catch Exception _ false))
      false)))

(defn find-rule
  "Best rule for qname: exact beats suffix (longest first), regex last."
  [rules qname]
  (->> rules
       (filter #(match? % qname))
       (sort-by (fn [r]
                  [(case (rule-type r) :exact 0 :suffix 1 :regex 2)
                   (- (count (rule-value r)))
                   (- (if (number? (:priority r)) (long (:priority r)) 0))]))
       first))




(defn list-rules [store]
  (vec (:rules @store)))

(defn add-rule!
  "Insert or replace (by :id) a rule, then persist."
  [store rule]
  (let [rule (update rule :id #(or % (str "r" (System/currentTimeMillis))))
        rule (update rule :action #(keyword (or % "passthrough")))]
    (swap! store
           (fn [s]
             (let [rules (vec (:rules s))
                   idx (first (keep-indexed (fn [i r] (when (= (:id r) (:id rule)) i))
                                            rules))]
               (assoc s :rules
                      (if idx (assoc rules idx rule) (conj rules rule))))))
    (let [path (::path (meta @store))]
      (when path (save! path @store)))
    rule))

(defn remove-rule! [store id]
  (swap! store update :rules (fn [rs] (vec (remove #(= (:id %) id) rs))))
  (let [path (::path (meta @store))]
    (when path (save! path @store)))
  true)

(defn seed-rules!
  "Add rules from config only when the store has none yet."
  [store rules]
  (when (and (seq rules) (empty? (:rules @store)))
    (doseq [r rules] (add-rule! store r))))

(defn- count-key [counts value limit]
  (if (or (contains? counts value) (< (count counts) limit))
    (update counts value (fnil inc 0))
    counts))

(defn log-query! [store entry]
  (let [entry (assoc entry :ts (System/currentTimeMillis))
        action (keyword (:action entry))
        blocked? (contains? #{:blackhole :blocklist} action)
        failed? (contains? #{:upstream-failed :forward-failed} action)
        domain (-> (str (:qname entry)) str/lower-case (str/replace #"\.$" ""))]
    (swap! store
           (fn [s]
             (let [size (or (:query-log-size s) 1000)
                   log (conj (vec (:query-log s)) entry)]
               (cond-> (-> s
                           (assoc :query-log (vec (take-last size log)))
                           (update-in [:stats :queries] (fnil inc 0))
                           (update-in [:stats (cond blocked? :blocked failed? :errors :else :allowed)] (fnil inc 0))
                           (update-in [:stats :actions action] (fnil inc 0))
                           (update-in [:stats :clients] count-key (str (:client entry)) 4096)
                           (update-in [:stats :domains] count-key domain 10000))
                 blocked? (update-in [:stats :blocked-domains] count-key domain 10000)))))
    (when-let [publish (::on-query (meta store))]
      (publish (assoc entry :type "dns" :blocked blocked?))))
  nil)

(defn recent-queries
  "Newest-first slice of the bounded query log."
  [store n]
  (vec (take (max 0 (or n 100)) (reverse (:query-log @store)))))

(defn stats [store]
  (dissoc (or (:stats @store) {}) :domains :blocked-domains))

(defn dashboard-stats [store]
  (let [s @store
        stats (:stats s)
        rank (fn [field label]
               (->> (get stats field {})
                    (sort-by (fn [[value count]] [(- count) value]))
                    (take 15)
                    (mapv (fn [[value count]] {label value :queries count}))))]
    {:queries (get stats :queries 0) :allowed (get stats :allowed 0)
     :blocked (get stats :blocked 0) :errors (get stats :errors 0)
     :actions (:actions stats {}) :blocking-enabled (:blocking-enabled s true)
     :top-domains (rank :domains :domain) :top-blocked (rank :blocked-domains :domain)
     :top-clients (rank :clients :client)
     :period "since restart" :domain-limit 10000 :client-limit 4096
     :tracked-domains (count (:domains stats)) :tracked-clients (count (:clients stats))}))

(defn top-clients
  "Clients ranked by query count - device discovery helper."
  [store n]
  (->> (get (stats store) :clients {})
       (sort-by (comp - val))
       (take (or n 20))
       (mapv (fn [[client count]] {:client client :queries count}))))

(defn list-proxy-maps [store] (vec (:proxy-maps @store)))
(defn list-transformers [store] (vec (:transformers @store)))

(defn- persist-current! [store]
  (when-let [path (::path (meta @store))] (save! path @store)))

(defn- put-record! [store field record prefix]
  (let [record (update record :id #(or % (str prefix (System/currentTimeMillis))))]
    (swap! store update field
           (fn [records]
             (let [records (vec records)
                   idx (first (keep-indexed (fn [i r] (when (= (:id r) (:id record)) i)) records))]
               (if (some? idx) (assoc records idx record) (conj records record)))))
    (persist-current! store)
    record))

(defn put-proxy-map! [store record] (put-record! store :proxy-maps record "map-"))
(defn put-transformer! [store record] (put-record! store :transformers record "xform-"))

(defn remove-record! [store field id]
  (swap! store update field (fn [records] (vec (remove #(= (str (:id %)) (str id)) records))))
  (persist-current! store)
  true)

(defn remove-proxy-map! [store id] (remove-record! store :proxy-maps id))
(defn remove-transformer! [store id] (remove-record! store :transformers id))
(defn list-proxy-listeners [store] (vec (:proxy-listeners @store)))
(defn put-proxy-listener! [store record] (put-record! store :proxy-listeners record "listener-"))
(defn remove-proxy-listener! [store id] (remove-record! store :proxy-listeners id))
(defn list-proxy-mounts [store] (vec (:proxy-mounts @store)))
(defn put-proxy-mount! [store record] (put-record! store :proxy-mounts record "mount-"))
(defn remove-proxy-mount! [store id] (remove-record! store :proxy-mounts id))

(defn list-ptr-records [store] (vec (:ptr-records @store)))
(defn put-ptr-record! [store record] (put-record! store :ptr-records record "ptr-"))
(defn remove-ptr-record! [store id] (remove-record! store :ptr-records id))

(defn list-blocklists [store] (vec (:blocklists @store)))
(defn put-blocklist! [store record] (put-record! store :blocklists record "list-"))
(defn remove-blocklist! [store id] (remove-record! store :blocklists id))

(defn replace-blocklist-entries! [store id entries refreshed-at]
  (swap! store update :blocklists
         (fn [records]
           (mapv (fn [record]
                   (if (= (str (:id record)) (str id))
                     (assoc record :entries (vec (sort (distinct entries))) :refreshed-at refreshed-at)
                     record)) records)))
  (persist-current! store)
  (first (filter #(= (str (:id %)) (str id)) (list-blocklists store))))

(defn- normalized-domain [name]
  (-> (str name) str/lower-case (str/replace #"\.$" "")))

(defonce ^:private blocklist-index-cache (atom nil))

(defn blocklisted? [store name]
  (let [name (normalized-domain name)
        blocklists (:blocklists @store)
        cached @blocklist-index-cache
        entries (if (and cached (identical? blocklists (:source cached)))
                  (:entries cached)
                  (let [index (into #{} (map normalized-domain)
                                    (mapcat :entries (filter #(not= false (:enabled % true)) blocklists)))]
                    (reset! blocklist-index-cache {:source blocklists :entries index})
                    index))]
    (loop [candidate name]
      (cond
        (contains? entries candidate) true
        (str/includes? candidate ".") (recur (subs candidate (inc (.indexOf ^String candidate "."))))
        :else false))))

(defn set-blocking! [store enabled]
  (swap! store assoc :blocking-enabled (boolean enabled))
  (persist-current! store)
  (:blocking-enabled @store))

(defn list-uscan-scanners [store] (vec (:uscan-scanners @store)))
(defn put-uscan-scanner! [store record] (put-record! store :uscan-scanners record "scanner-"))
(defn remove-uscan-scanner! [store id] (remove-record! store :uscan-scanners id))
