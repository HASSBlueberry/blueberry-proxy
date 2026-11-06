(ns dns.upstream.upstreamStore
  (:require [dns.upstream.over.https :as https]
            [dns.upstream.over.tcp :as tcp]
            [dns.upstream.over.udp :as udp]
            [dns.dnsPrims :as prims]))

(def default-upstreams
  [{:name "cloudflare" :protocol :udp :host "1.1.1.1" :port 53
    :timeout 3000 :weight 10}
   {:name "google" :protocol :udp :host "8.8.8.8" :port 53
    :timeout 3000 :weight 5}
   {:name "quad9" :protocol :tcp :host "9.9.9.9" :port 53
    :timeout 3000 :weight 3}
   {:name "cloudflare-doh" :protocol :https
    :host "https://cloudflare-dns.com/dns-query"
    :timeout 5000 :weight 1}])

(defn normalize [u]
  (-> u
      (update :protocol #(keyword (or % "udp")))
      (update :port #(or % (if (= :https (keyword (:protocol u))) nil 53)))
      (update :timeout #(or % 3000))
      (update :weight #(or % 1))
      (update :name str)))

(defn open
  "Create an upstream store from a seq of upstream maps (defaults when nil
  or empty)."
  ([upstreams] (open upstreams {}))
  ([upstreams {:keys [enabled max-entries max-ttl]
               :or {enabled true max-entries 10000 max-ttl 86400}}]
  (let [ups (vec (map normalize (if (seq upstreams) upstreams default-upstreams)))]
    (atom {:upstreams ups
           :health (into {} (for [u ups]
                              [(:name u) {:fails 0 :ok 0 :errors 0
                                          :last-fail nil :rtt nil
                                          :down-until 0}]))
           :stats {:queries 0 :failovers 0 :failures 0}
           :cache-config {:enabled enabled :max-entries (max 1 (long max-entries))
                          :max-ttl (max 1 (long max-ttl))}
           :cache {} :cache-stats {:hits 0 :misses 0 :evictions 0}}))))

(defn cache-stats [store]
  (merge (:cache-stats @store) {:entries (count (:cache @store))
                                :enabled (get-in @store [:cache-config :enabled])}))

(defn list-upstreams [store]
  (let [{:keys [upstreams health]} @store]
    (vec (for [u upstreams]
           (merge u {:health (get health (:name u))})))))

(defn add-upstream! [store u]
  (let [u (normalize u)]
    (swap! store
           (fn [s]
             (-> s
                 (update :upstreams
                         (fn [ups]
                           (if (some #(= (:name u) (:name %)) ups)
                             (mapv #(if (= (:name u) (:name %)) u %) ups)
                             (conj ups u))))
                 (update :health #(assoc % (:name u)
                                         {:fails 0 :ok 0 :errors 0
                                          :last-fail nil :rtt nil
                                          :down-until 0})))))))

(defn remove-upstream! [store name]
  (swap! store
         (fn [s]
           (-> s
               (update :upstreams (fn [ups] (filterv #(not= name (:name %)) ups)))
               (update :health dissoc name))))
  true)

(defn- mark-ok! [store name rtt]
  (swap! store
         (fn [s]
           (-> s
               (update-in [:health name]
                          #(merge % {:fails 0 :ok (inc (or (:ok %) 0))
                                     :rtt rtt :down-until 0}))
               (update-in [:stats :queries] (fnil inc 0))))))

(defn- mark-fail! [store name]
  (swap! store
         (fn [s]
           (let [h (get-in s [:health name] {:fails 0})
                 fails (inc (or (:fails h) 0))
                 ;; 1s, 2s, 4s ... capped at 30s
                 backoff (min 30000 (bit-shift-left 1 (min fails 5)))]
             (-> s
                 (update-in [:health name]
                            #(merge % {:fails fails
                                       :errors (inc (or (:errors %) 0))
                                       :last-fail (System/currentTimeMillis)
                                       :down-until (+ (System/currentTimeMillis)
                                                      backoff)}))
                 (update-in [:stats :failures] (fnil inc 0)))))))

(defn- dispatch [u msg-bytes]
  (case (:protocol u)
    :udp (udp/query u msg-bytes)
    :tcp (tcp/query u msg-bytes)
    :https (https/query u msg-bytes)
    (throw (ex-info "unknown upstream protocol" {:protocol (:protocol u)
                                                 :name (:name u)}))))

(declare query)

(defn query-single
  "Send msg-bytes via one named upstream. Unknown name falls back to the
  normal failover path; a failing named upstream returns nil."
  [store name msg-bytes]
  (if-let [u (first (filter #(= name (:name %)) (:upstreams @store)))]
    (let [t0 (System/currentTimeMillis)
          res (try (dispatch u msg-bytes)
                   (catch Exception _ nil))]
      (if (bytes? res)
        (let [rtt (- (System/currentTimeMillis) t0)]
          (mark-ok! store name rtt)
          {:bytes res :upstream name :rtt rtt})
        (do (mark-fail! store name) nil)))
    (query store msg-bytes)))

(defn- query-uncached
  "Send raw DNS message bytes through the best available upstream.
  Returns {:bytes .. :upstream .. :rtt ..} or nil when every candidate
  failed."
  [store msg-bytes]
  (let [{:keys [upstreams health]} @store
        now (System/currentTimeMillis)
        cooled? (fn [u] (> (long (:down-until (get health (:name u)) 0)) now))
        order (sort-by (fn [u] [(if (cooled? u) 1 0) (- (long (:weight u 1)))])
                       upstreams)]
    (swap! store update-in [:stats :queries] (fnil inc 0))
    (loop [remaining order failovers 0]
      (if-let [u (first remaining)]
        (let [t0 (System/currentTimeMillis)]
          (let [res (try (dispatch u msg-bytes)
                         (catch Exception e
                           (mark-fail! store (:name u))
                           (when (> (count remaining) 1)
                             (swap! store update-in [:stats :failovers]
                                    (fnil inc 0)))
                           e))]
            (if (bytes? res)
              (let [rtt (- (System/currentTimeMillis) t0)]
                (mark-ok! store (:name u) rtt)
                {:bytes res :upstream (:name u) :rtt rtt})
              (recur (rest remaining) (inc failovers)))))
        nil))))

(defn- cache-key [msg-bytes]
  (try
    (let [msg (prims/parse-message msg-bytes)]
      (let [opts (filterv #(= :OPT (:type %)) (:additional msg))]
        (when (and (not (:qr msg)) (= 0 (:opcode msg))
                   (= 1 (count (:questions msg)))
                   (= (count opts) (count (:additional msg)))
                   (every? #(empty? (get-in % [:data :options])) opts))
          [(select-keys msg [:questions :rd :z])
           (bit-and 0x0110 (bit-or (bit-shift-left (bit-and (aget ^bytes msg-bytes 2) 0xff) 8)
                                    (bit-and (aget ^bytes msg-bytes 3) 0xff)))
           (mapv #(select-keys % [:class :ttl]) opts)])))
    (catch Exception _ nil)))

(defn- ttl-floor [msg]
  (let [records (concat (:answers msg) (:authority msg) (:additional msg))
        ttls (keep (fn [rr] (when (and (not= :OPT (:type rr)) (:ttl rr))
                              (long (:ttl rr)))) records)
        negative-ttls (keep (fn [rr]
                              (when (and (= :SOA (:type rr))
                                         (get-in rr [:data :minimum]))
                                (min (long (:ttl rr))
                                     (long (get-in rr [:data :minimum])))))
                            (:authority msg))]
    (cond
      (and (zero? (:rcode msg)) (seq (:answers msg)) (seq ttls)) (apply min ttls)
      (and (or (= 3 (:rcode msg))
               (and (zero? (:rcode msg)) (empty? (:answers msg))))
           (seq negative-ttls)) (apply min negative-ttls)
      :else nil)))

(defn- age-records [records elapsed]
  (mapv (fn [rr]
          (if (= :OPT (:type rr)) rr
            (update rr :ttl #(max 0 (- (long (or % 0)) elapsed))))) records))

(defn- cache-response [entry id]
  (let [elapsed (quot (- (System/currentTimeMillis) (:stored entry)) 1000)
        msg (:message entry)]
    (prims/encode-message
      (-> msg
          (assoc :id id)
          (update :answers age-records elapsed)
          (update :authority age-records elapsed)
          (update :additional age-records elapsed)))))

(defn query [store msg-bytes]
  "Send a DNS query through upstreams, caching eligible positive answers by question and flags."
  (let [key (cache-key msg-bytes)
        id (try (:id (prims/parse-message msg-bytes)) (catch Exception _ 0))
        cfg (:cache-config @store)
        now (System/currentTimeMillis)
        entry (when (and key (:enabled cfg)) (get-in @store [:cache key]))]
    (if (and entry (< now (+ (:stored entry) (* 1000 (:ttl entry)))))
      (do (swap! store update-in [:cache-stats :hits] (fnil inc 0))
          {:bytes (cache-response entry id) :upstream (:upstream entry) :cached true :rtt 0})
      (do
        (when (and key (:enabled cfg))
          (swap! store update-in [:cache-stats :misses] (fnil inc 0)))
        (let [result (query-uncached store msg-bytes)]
          (when (and result key (:enabled cfg))
            (try
              (let [parsed (prims/parse-message (:bytes result))
                    ttl (some-> (ttl-floor parsed) (min (:max-ttl cfg)))]
                (when (and ttl (pos? ttl) (not (:tc parsed)))
                  (let [entry {:message parsed :ttl ttl :stored now :upstream (:upstream result)}]
                    (swap! store
                           (fn [state]
                             (let [cache (assoc (:cache state) key entry)
                                   excess (- (count cache) (:max-entries cfg))
                                   [cache evicted] (if (pos? excess)
                                                     (let [victims (->> cache (sort-by (comp :stored val))
                                                                        (take excess) (map clojure.core/key) vec)]
                                                       [(apply dissoc cache victims) (count victims)])
                                                     [cache 0])]
                               (-> state (assoc :cache cache)
                                   (update-in [:cache-stats :evictions] (fnil + 0) evicted))))))))
              (catch Exception _ nil)))
          result)))))
