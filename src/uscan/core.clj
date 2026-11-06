(ns uscan.core
  "Persistent scanner definitions, bounded background jobs, and discovery events."
  (:require [clojure.string :as str]
            [storage.storage :as storage]
            [uscan.scope :as scope]
            [uscan.protocols :as protocols]
            [uscan.scripts :as scripts])
  (:import [java.util UUID]
           [java.util.concurrent Executors ExecutorService]))

(def builtins
  [{:id "arp" :kind "arp" :enabled true :parameters {}}
   {:id "mdns" :kind "mdns" :enabled true :parameters {}}
   {:id "wsd" :kind "wsd" :enabled true :parameters {}}
   {:id "onvif" :kind "onvif" :enabled true :parameters {}}
   {:id "avahi" :kind "avahi" :enabled true :parameters {}}
   {:id "tcp" :kind "tcp" :enabled true :parameters {:ports [80 443 554 1883 8000 8080]}}])

(def kinds #{"arp" "tcp" "mdns" "wsd" "onvif" "avahi" "graaljs"})

(defn scanners [runtime] (storage/list-uscan-scanners (:store runtime)))

(defn register! [runtime record]
  (when-not (and (map? record) (string? (:id record)) (re-matches #"[A-Za-z0-9_.-]{1,80}" (:id record))
                 (contains? kinds (:kind record)) (map? (:parameters record {})))
    (throw (ex-info "Scanner needs id, supported kind, and an optional parameters object" {})))
  (when (and (contains? record :enabled) (not (instance? Boolean (:enabled record))))
    (throw (ex-info "enabled must be a boolean" {})))
  (when (= "graaljs" (:kind record))
    (when-not (and (string? (:script record)) (< (count (:script record)) 262144))
      (throw (ex-info "GraalJS scanner needs a script under 256 KiB" {}))))
  ;; Validate explicit scopes now; interface-derived default scopes are checked at job start.
  (scope/parameters (update (:parameters record {}) :cidrs #(if (seq %) % ["127.0.0.1/32"])))
  (when (and (>= (count (scanners runtime)) 128) (not-any? #(= (:id %) (:id record)) (scanners runtime)))
    (throw (ex-info "At most 128 scanner profiles may be registered" {})))
  (storage/put-uscan-scanner! (:store runtime) record))

(defn- normalized-mac [value]
  (when (string? value)
    (let [value (str/lower-case (str/replace value #"[:-]" ""))]
      (when (and (re-matches #"[0-9a-f]{12}" value) (not= value "000000000000"))
        (str/join ":" (map #(apply str %) (partition 2 value)))))))

(defn emit! [runtime job-id scanner params record]
  (when-not (and (map? record) (scope/contains-ip? (:networks params) (:ip record)))
    (throw (ex-info "Discovery record IP is outside the scanner CIDRs" {})))
  (doseq [field [:services :ports :endpoints :scopes]]
    (when (and (contains? record field) (not (sequential? (get record field))))
      (throw (ex-info "Discovery collection fields must be arrays" {}))))
  (when (or (and (:hostname record) (not (string? (:hostname record))))
            (some #(not (and (integer? %) (<= 1 % 65535))) (:ports record)))
    (throw (ex-info "Invalid discovery hostname or port" {})))
  (let [input record
        now (System/currentTimeMillis)
        record (-> (select-keys record [:ip :hostname :interface :evidence :services :ports :endpoints :scopes])
                   (assoc :scanner (:id scanner) :protocol (:kind scanner)))
        record (cond-> record (normalized-mac (:mac input)) (assoc :mac (normalized-mac (:mac input))))]
    ;; Only normalized, observed MACs are retained.
    (let [record record
          change (volatile! nil)]
      (swap! (:devices runtime)
             (fn [devices]
               (vreset! change nil)
               (let [old (get devices (:ip record))
                     previous (if (and (:mac old) (:mac record) (not= (:mac old) (:mac record))) nil old)
                     list-values (fn [key limit] (vec (take limit (distinct (concat (get previous key []) (get record key []))))))
                     merged (merge previous (select-keys record [:ip :hostname :mac :interface])
                                   {:first_seen (:first_seen previous now) :last_seen now
                                    :protocols (vec (distinct (conj (:protocols previous []) (:protocol record))))
                                    :scanners (vec (distinct (conj (:scanners previous []) (:scanner record))))
                                    :services (list-values :services 64) :ports (list-values :ports 256)
                                    :endpoints (list-values :endpoints 32) :scopes (list-values :scopes 32)
                                    :evidence (vec (take 16 (distinct (remove nil? (conj (:evidence previous []) (:evidence record))))))})]
                 (when (and (or previous (< (count devices) 65536))
                            (not= (dissoc previous :last_seen) (dissoc merged :last_seen)))
                   (vreset! change (assoc merged :new_device (nil? previous))))
                 (if (or previous (< (count devices) 65536)) (assoc devices (:ip record) merged) devices))))
      (when-let [device @change]
        ((:publish runtime) (assoc device :type "discovery" :ts now :job_id job-id :scanner (:id scanner)))
        (swap! (:jobs runtime) update-in [job-id :discoveries] (fnil inc 0))))))

(defn import-devices! [runtime body]
  (let [records (:devices body)
        source (:source body)
        params (scope/parameters {:cidrs (:cidrs body)})]
    (when-not (and (string? source) (re-matches #"[A-Za-z0-9_.-]{1,80}" source)
                   (vector? records) (<= (count records) 4096) (seq (:cidrs body)))
      (throw (ex-info "Inventory requires source, explicit CIDRs, and up to 4096 devices" {})))
    ;; Validate the entire batch before publishing any external inventory evidence.
    (doseq [record records]
      (when-not (and (map? record) (or (nil? (:hostname record)) (string? (:hostname record)))
                     (scope/contains-ip? (:networks params) (:ip record)))
        (throw (ex-info "Inventory IP is outside its advertised networks" {}))))
    (let [job-id (str "inventory-" (UUID/randomUUID))]
      (doseq [record records]
        (emit! runtime job-id {:id source :kind "inventory"} params
               (assoc (select-keys record [:ip :mac :hostname]) :evidence (str "Inventory from " source))))
      (swap! (:jobs runtime) dissoc job-id)
      {:imported (count records) :source source})))

(defn- emit-scoped! [runtime job-id scanner params record]
  (when (scope/contains-ip? (:networks params) (:ip record))
    ;; Include ARP MACs only as observed neighbor evidence, never inferred from IP.
    (let [mac (:mac record)]
      (emit! runtime job-id scanner params (cond-> record mac (assoc :mac mac))))))

(defn job [runtime id] (get @(:jobs runtime) id))

(defn snapshot
  ([runtime] (snapshot runtime 65536))
  ([runtime limit]
   {:scanners (mapv #(assoc (dissoc % :script) :has_script (boolean (:script %))) (scanners runtime))
    :interfaces (scope/interfaces) :device_count (count @(:devices runtime))
    :devices (vec (take limit (sort-by :ip (vals @(:devices runtime)))))
    :jobs (vec (take 20 (sort-by (comp - :created_at) (vals @(:jobs runtime)))))}))

(defn cancel! [runtime id]
  (if-let [cancel (get @(:cancels runtime) id)]
    (do (reset! cancel true) {:cancelled id})
    (throw (ex-info "Unknown or completed scan job" {}))))

(defn start-job! [runtime options]
  (locking (:jobs runtime)
    (when-not @(:running runtime) (throw (ex-info "UScan is stopped" {})))
    (when (>= (count @(:cancels runtime)) 8) (throw (ex-info "At most eight jobs may be queued or running" {})))
    (let [ids (:scanner_ids options)
          _ (when (and ids (not (and (sequential? ids) (every? string? ids)))) (throw (ex-info "scanner_ids must be an array" {})))
          selected (if (seq ids) (mapv (fn [id] (or (first (filter #(= (:id %) id) (scanners runtime)))
                                                 (throw (ex-info "Unknown scanner ID" {:id id})))) (distinct ids))
                       (filterv #(not= false (:enabled %)) (scanners runtime)))
          _ (when (> (count selected) 32) (throw (ex-info "Select at most 32 scanners per job" {})))
          _ (when (empty? selected) (throw (ex-info "Select at least one scanner" {})))
          plan (mapv (fn [scanner]
                       (let [params (scope/parameters (merge (:parameters scanner {}) (:parameters options {})))]
                         (when (and (= "tcp" (:kind scanner)) (> (* (count (:targets params)) (count (:ports params))) (:max_probes params)))
                           (throw (ex-info "TCP host/port combinations exceed max_probes" {})))
                         [scanner params])) selected)
          id (str (UUID/randomUUID))
          cancelled (atom false)
          record {:id id :status "queued" :created_at (System/currentTimeMillis) :discoveries 0
                  :scanners (mapv #(select-keys (first %) [:id :kind]) plan) :results []}]
      (swap! (:jobs runtime) (fn [jobs] (into {} (take 40 (sort-by (comp - :created_at val) (assoc jobs id record))))))
      (swap! (:cancels runtime) assoc id cancelled)
      ((:publish runtime) (assoc record :type "scan" :job_id id))
      (.submit ^ExecutorService (:pool runtime) ^Runnable
               (fn []
                 (swap! (:jobs runtime) update id assoc :status "running" :started_at (System/currentTimeMillis))
                 (try
                   (doseq [[scanner params] plan :while (not @cancelled)]
                     (let [deadline (+ (System/currentTimeMillis) (:deadline_ms params))
                           check! (fn [] (when (or @cancelled (Thread/interrupted) (> (System/currentTimeMillis) deadline))
                                           (throw (ex-info "Scan cancelled or scanner deadline reached" {}))))
                           emit (fn [record] (check!) (emit-scoped! runtime id scanner params record))]
                       (swap! (:jobs runtime) update id assoc :active_scanner (:id scanner))
                       ((:publish runtime) (assoc (job runtime id) :type "scan" :job_id id))
                       (try
                         (check!)
                         (let [result (if (= "graaljs" (:kind scanner))
                                        (scripts/run! (:script scanner) params emit check! (:timer runtime))
                                        (protocols/run! (:kind scanner) params emit check!))]
                           (doseq [record (protocols/arp-records)]
                             (check!) (emit-scoped! runtime id {:id "arp" :kind "arp"} params record))
                           (swap! (:jobs runtime) update-in [id :results] conj
                                  (merge {:scanner (:id scanner) :status "complete"}
                                         (when (map? result) (select-keys result [:backend :warning])))))
                         (catch Exception error
                           (swap! (:jobs runtime) update-in [id :results] conj {:scanner (:id scanner) :status "failed" :error (subs (str (.getMessage error)) 0 (min 240 (count (str (.getMessage error)))))})))))
                   (finally
                     (swap! (:jobs runtime) update id assoc :status (cond @cancelled "cancelled"
                                                                                     (every? #(= "complete" (:status %)) (:results (job runtime id))) "complete"
                                                                                     (some #(= "complete" (:status %)) (:results (job runtime id))) "partial"
                                                                                     :else "failed") :finished_at (System/currentTimeMillis))
                     ((:publish runtime) (assoc (job runtime id) :type "scan" :job_id id))
                     (swap! (:cancels runtime) dissoc id)))))
      record)))

(defn start [store publish]
  (let [runtime {:store store :publish publish :devices (atom {}) :jobs (atom {}) :cancels (atom {})
                 :running (atom true) :pool (Executors/newSingleThreadExecutor)
                 :timer (Executors/newScheduledThreadPool 1)}]
    (doseq [scanner builtins :when (not-any? #(= (:id scanner) (:id %)) (scanners runtime))]
      (register! runtime scanner))
    (assoc runtime :stop (fn []
                           (reset! (:running runtime) false)
                           (doseq [cancel (vals @(:cancels runtime))] (reset! cancel true))
                           (.shutdownNow ^ExecutorService (:pool runtime))
                           (.shutdownNow ^ExecutorService (:timer runtime))))))
