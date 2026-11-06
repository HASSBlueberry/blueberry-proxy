(ns uscan.scope
  (:require [clojure.string :as str])
  (:import [java.net Inet4Address InetAddress NetworkInterface]))

(defn ipv4-long [value]
  (when-not (and (string? value) (re-matches #"(?:[0-9]{1,3}\.){3}[0-9]{1,3}" value))
    (throw (ex-info "An IPv4 address is required" {})))
  (let [parts (mapv #(Long/parseLong %) (str/split value #"\."))]
    (when-not (every? #(<= 0 % 255) parts) (throw (ex-info "Invalid IPv4 address" {})))
    (reduce #(+ (* %1 256) %2) 0 parts)))

(defn long-ip [n]
  (str/join "." (map #(bit-and 255 (bit-shift-right (long n) %)) [24 16 8 0])))

(defn network [cidr]
  (let [[address prefix & more] (str/split (str cidr) #"/" -1)
        prefix (if prefix (try (Long/parseLong prefix) (catch Exception _ -1)) 32)]
    (when (or (seq more) (not (<= 0 prefix 32))) (throw (ex-info "Invalid IPv4 CIDR" {})))
    (let [size (bit-shift-left 1 (- 32 prefix))
          start (bit-and (ipv4-long address) (- size))]
      {:cidr (str (long-ip start) "/" prefix) :start start :end (+ start size -1) :size size
       :first (if (< prefix 31) (inc start) start) :last (if (< prefix 31) (- (+ start size) 2) (dec (+ start size)))})))

(defn contains-ip? [networks ip]
  (try (let [n (ipv4-long ip)] (boolean (some #(<= (:start %) n (:end %)) networks)))
       (catch Exception _ false)))

(defn interfaces []
  (try
    (vec (for [^NetworkInterface nic (enumeration-seq (NetworkInterface/getNetworkInterfaces))
               :when (and (.isUp nic) (not (.isLoopback nic)))
               address (.getInterfaceAddresses nic)
               :when (instance? Inet4Address (.getAddress address))
               :let [ip (.getHostAddress (.getAddress address)) prefix (.getNetworkPrefixLength address)]
               :when (not (.isLinkLocalAddress (.getAddress address)))]
           {:name (.getName nic) :ip ip :cidr (:cidr (network (str ip "/" prefix)))
            :virtual (.isVirtual nic) :multicast (.supportsMulticast nic)}))
    (catch Exception _ [])))

(defn default-cidrs []
  (vec (distinct (map :cidr (remove #(or (:virtual %) (re-find #"^(docker|veth|br-|cni|lo)" (:name %))) (interfaces))))))

(defn bounded-int [value fallback minimum maximum name]
  (let [value (if (nil? value) fallback value)]
    (when-not (and (integer? value) (<= minimum value maximum))
      (throw (ex-info (str name " must be an integer from " minimum " to " maximum) {})))
    value))

(defn ports [values]
  (when-not (sequential? values) (throw (ex-info "ports must be an array of integers or ranges" {})))
  (let [result (reduce (fn [result value]
                        (let [range (cond
                                      (integer? value) [value value]
                                      (and (string? value) (re-matches #"\d{1,5}-\d{1,5}" value))
                                      (mapv #(Long/parseLong %) (str/split value #"-"))
                                      :else (throw (ex-info "Invalid port or port range" {})))
                              [start end] range]
                          (when-not (<= 1 start end 65535) (throw (ex-info "Ports must be from 1 to 65535" {})))
                          (when (> (+ (count result) (inc (- end start))) 1024)
                            (throw (ex-info "Select at most 1024 ports per scanner" {})))
                          (into result (clojure.core/range start (inc end))))) #{} values)]
    (vec (sort result))))

(defn parameters [params]
  (when-not (map? params) (throw (ex-info "parameters must be an object" {})))
  (let [cidrs (or (seq (:cidrs params)) (seq (default-cidrs)))
        _ (when-not (and (sequential? cidrs) (every? string? cidrs)) (throw (ex-info "Select one or more IPv4 CIDRs" {})))
        networks (mapv network cidrs)
        limit (bounded-int (:max_hosts params) 4096 1 65536 "max_hosts")
        _ (when (or (empty? networks) (> (reduce + (map #(- (:last %) (:first %) -1) networks)) limit))
            (throw (ex-info "CIDR targets exceed max_hosts; narrow the CIDRs or increase the explicit host budget" {})))
        targets (vec (distinct (mapcat #(map long-ip (range (:first %) (inc (:last %)))) networks)))
        interfaces (:interfaces params [])
        _ (when-not (and (sequential? interfaces) (every? #(and (string? %) (re-matches #"[A-Za-z0-9_.:-]{1,64}" %)) interfaces))
            (throw (ex-info "interfaces must contain interface names" {})))]
    (assoc params :cidrs (mapv :cidr networks) :networks networks :targets targets
           :interfaces (vec interfaces) :ports (ports (:ports params [80 443 554 1883 8000 8080]))
           :timeout_ms (bounded-int (:timeout_ms params) 300 50 3000 "timeout_ms")
           :duration_ms (bounded-int (:duration_ms params) 4000 250 30000 "duration_ms")
           :deadline_ms (bounded-int (:deadline_ms params) 60000 1000 300000 "deadline_ms")
           :max_probes (bounded-int (:max_probes params) 32768 1 262144 "max_probes")
           :workers (bounded-int (:workers params) 32 1 64 "workers"))))

(defn selected-interfaces [params]
  (let [names (set (:interfaces params))]
    (->> (interfaces)
         (filter #(and (:multicast %) (or (empty? names) (contains? names (:name %)))
                       (contains-ip? (:networks params) (:ip %))))
         (map :name) distinct
         (map #(NetworkInterface/getByName %))
         (remove nil?))))
