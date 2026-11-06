(ns blueberryProxy
  (:require [clojure.data.json :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [admin.api :as admin]
            [dns.dnsPrims :as prims]
            [dns.blocklists :as blocklists]
            [dns.over.https :as doh]
            [dns.over.tcp :as tcp]
            [dns.over.udp :as udp]
            [dns.upstream.upstreamStore :as upstreams]
            [storage.storage :as storage]
            [xform.proxy :as proxy]
            [xform.graal :as graal]
            [xform.tls :as tls]
            [xform.websocket :as websocket]
            [uscan.core :as uscan])
  (:import [java.time Instant])
  (:gen-class))

(def default-config
  {:dns-port 53
   :bind "0.0.0.0"
   :doh-port 8053
   :admin-port 8054
   :admin-bind "127.0.0.1"
   :proxy-port 8080
   :proxy-bind "0.0.0.0"
   :proxy-tls-enabled false
   :proxy-tls-keystore "/data/blueberry-proxy.p12"
   :proxy-tls-password nil
   :proxy-tls-self-signed false
   :proxy-tls-common-name "blueberryProxy"
   :proxy-tls-sans []
   :websocket-port 8055
   :ingress-port 8056
   :blocklist-refresh-hours 24
   :blocklist-action :blackhole
   :data-dir "data"
   :log-queries true
   :log true
   :upstreams nil
   :proxy-maps nil
   :blocklists nil
   :ptr-records nil
   :transformers nil
   :rules nil})


(defn- read-edn-file [path]
  (let [f (io/file path)]
    (when (.exists f)
      (try (edn/read-string (slurp f))
           (catch Exception e
             (println "config: cannot read" path "-" (.getMessage e)))))))

(defn- read-ha-options []
  (let [f (io/file "/data/options.json")]
    (when (.exists f)
      (try
        (letfn [(normalize-keys [v]
                  (cond
                    (map? v) (into {} (map (fn [[k value]]
                                             [(keyword (str/replace (name k) "_" "-"))
                                              (normalize-keys value)])) v)
                    (vector? v) (mapv normalize-keys v)
                    :else v))]
          (normalize-keys (json/read-str (slurp f) :key-fn keyword)))
        (catch Exception e
          (println "config: cannot read options.json -" (.getMessage e)))))))

(def ^:private env-keys
  {:dns-port "BLUEBERRY_DNS_PORT"
   :bind "BLUEBERRY_BIND"
   :doh-port "BLUEBERRY_DOH_PORT"
   :admin-port "BLUEBERRY_ADMIN_PORT"
   :proxy-port "BLUEBERRY_PROXY_PORT"
   :websocket-port "BLUEBERRY_WEBSOCKET_PORT"
   :blocklist-refresh-hours "BLUEBERRY_BLOCKLIST_REFRESH_HOURS"
   :admin-bind "BLUEBERRY_ADMIN_BIND"
   :data-dir "BLUEBERRY_DATA_DIR"
   :log-queries "BLUEBERRY_LOG_QUERIES"})

(defn- env-config []
  (into {}
        (keep (fn [[k env]]
                (when-let [v (System/getenv env)]
                  [k (case k
                       :dns-port (Long/parseLong v)
                       :doh-port (Long/parseLong v)
                       :admin-port (Long/parseLong v)
                       :proxy-port (Long/parseLong v)
                       :websocket-port (Long/parseLong v)
                       :blocklist-refresh-hours (Long/parseLong v)
                       :log-queries (Boolean/parseBoolean v)
                       v)]))
              env-keys)))

(defn load-config []
  (-> default-config
      (merge (or (read-edn-file "config.edn") {}))
      (merge (env-config))
      (merge (or (read-ha-options) {}))))

(defn- normalize-rule [r]

  (let [match (or (:match r)
                  {:type (keyword (or (:match_type r) "suffix"))
                   :value (or (:value r) (:match_value r) (:match r))})]
    (-> r
        (assoc :match {:type (keyword (or (:type match) (:match_type r) "suffix"))
                       :value (str (or (:value match) (:match_value r) (:match r) ""))})
        (dissoc :match_type :match_value)
        (update :action #(keyword (or % "passthrough"))))))




(defn- client-ip [addr]
  (when addr
    (try
      (if (instance? java.net.InetSocketAddress addr)
        (.getHostAddress (.getAddress ^java.net.InetSocketAddress addr))
        (str addr))
      (catch Exception _ (str addr)))))

(defn- ipv4? [s] (boolean (re-matches #"\d{1,3}(\.\d{1,3}){3}" (str s))))
(defn- ipv6? [s] (boolean (re-matches #"[0-9a-fA-F:]{2,45}" (str s))))

(defn- values [v]
  (->> (str/split (str v) #",")
       (map str/trim)
       (remove str/blank?)))

(defn- static-answers [qname qtype v ttl]
  (let [vs (values v)]
    (case qtype
      :A (mapv #(prims/a-rr qname % ttl) (filter ipv4? vs))
      :AAAA (mapv #(prims/aaaa-rr qname % ttl) (filter ipv6? vs))
      :TXT (mapv #(prims/txt-rr qname % ttl) vs)
      :PTR (if-let [t (first vs)] [(prims/ptr-rr qname t ttl)] [])
      :CNAME (if-let [t (first vs)] [(prims/cname-rr qname t ttl)] [])
      :ANY (vec (concat (mapv #(prims/a-rr qname % ttl) (filter ipv4? vs))
                        (mapv #(prims/aaaa-rr qname % ttl) (filter ipv6? vs))))

      [])))

(defn- blackhole-answers [qname qtype ttl]
  (case qtype
    :A [(prims/a-rr qname "0.0.0.0" ttl)]
    :AAAA [(prims/aaaa-rr qname "::" ttl)]
    :ANY [(prims/a-rr qname "0.0.0.0" ttl)]
    []))

(defn- redirect-answers [qname qtype v ttl]
  (case qtype
    (:CNAME :ANY) [(prims/cname-rr qname v ttl)]

    (:A :AAAA) [(prims/cname-rr qname v ttl)]
    []))

(defn- proxy-maps [store]
  (let [transformers (into {} (map (juxt :id identity) (storage/list-transformers store)))
        base-maps (storage/list-proxy-maps store)
        by-id (into {} (map (juxt (comp str :id) identity) base-maps))
        mounts (keep (fn [mount]
                       (when-let [base (get by-id (str (:proxy-map-id mount)))]
                         (merge base mount {:id (:id mount) :proxymount? true})))
                     (storage/list-proxy-mounts store))]
    (mapv (fn [m]
            (reduce (fn [m [field transform-field]]
                      (if-let [id (get m field)]
                        (if-let [x (get transformers id)]
                          (assoc m transform-field (dissoc x :id :type))
                          m)
                        m))
                    m [[:request-header-transformer :request-headers]
                       [:response-header-transformer :response-headers]
                       [:request-body-transformer :request-body]
                       [:response-body-transformer :response-body]
                       [:request-script-transformer :request-script]
                       [:response-script-transformer :response-script]]))
          (concat base-maps mounts))))

(defn- reverse-name->ip [name]
  (let [labels (str/split (str/lower-case name) #"\.")]
    (cond
      (and (= "arpa" (last labels)) (= "in-addr" (nth labels (- (count labels) 2) nil)))
      (let [octets (reverse (take 4 labels))]
        (when (and (= 4 (count octets))
                   (every? #(and (re-matches #"\d{1,3}" %) (<= (Long/parseLong %) 255)) octets))
          (str/join "." octets)))

      (and (= "arpa" (last labels)) (= "ip6" (nth labels (- (count labels) 2) nil))
           (= 32 (- (count labels) 2))
           (every? #(re-matches #"[0-9a-f]" %) (take 32 labels)))
      (try
        (let [nibbles (reverse (take 32 labels))
              bytes (byte-array (map (fn [[hi lo]]
                                       (unchecked-byte (Integer/parseInt (str hi lo) 16)))
                                     (partition 2 nibbles)))]
          (.getHostAddress (java.net.InetAddress/getByAddress bytes)))
        (catch Exception _ nil))
      :else nil)))

(defn- reverse-ip->name [ip]
  (try
    (let [bytes (.getAddress (java.net.InetAddress/getByName (str ip)))]
      (if (= 4 (alength bytes))
        (str (str/join "." (reverse (map #(bit-and % 0xff) bytes))) ".in-addr.arpa")
        (str (str/join "." (mapcat (fn [b]
                                      (let [v (bit-and b 0xff)]
                                        [(format "%x" (bit-and v 15))
                                         (format "%x" (bit-shift-right v 4))]))
                                    (reverse bytes))) ".ip6.arpa")))
    (catch Exception _ nil)))

(defn- forward
  "Re-encode the request (adding EDNS when absent) and send it upstream."
  [up-store msg]
  (let [req (cond-> msg
              (not (prims/request-opt msg))
              (update :additional (fnil conj []) (prims/opt-rr 4096)))
        bytes (prims/encode-message req)]
    (upstreams/query up-store bytes)))

(defn- respond-rcode [msg rcode]
  (prims/make-response msg [] {:rcode rcode}))

(defn make-handler
  "Build the (fn [msg remote] response-msg) shared by UDP/TCP/DoH."
  [{:keys [store up-store config log]}]
  (fn [msg remote]
    (let [qname (prims/qname msg)
          qtype (prims/qtype msg)
          client (client-ip remote)
          req-opt (prims/request-opt msg)
          resp-addl (if req-opt [(prims/opt-rr (:class req-opt))] [])
          base (fn [answers extra]
                 (prims/make-response msg answers
                                      (merge {:ra true :additional resp-addl}
                                             extra)))
          action (fn [act rule upstream]
                   (when (:log-queries config)
                     (storage/log-query! store
                                         {:client client
                                          :qname qname
                                          :qtype (if (keyword? qtype)
                                                   (clojure.core/name qtype)
                                                   (str qtype))
                                          :action (keyword act)
                                          :rule (:id rule)
                                          :upstream upstream})))]

      (cond

        (not= 0 (:opcode msg))
        (respond-rcode msg 4)

        (empty? (:questions msg))
        (respond-rcode msg 1)

        :else
        (let [rule (storage/find-rule
                     (if (:blocking-enabled @store true)
                       (storage/list-rules store)
                       (remove #(= :blackhole (keyword (:action %))) (storage/list-rules store)))
                     qname)
              reverse-ip (when (= qtype :PTR) (reverse-name->ip qname))
              ptr-record (when reverse-ip
                           (first (filter #(= (str/lower-case (str (:ip %)))
                                              (str/lower-case reverse-ip))
                                          (storage/list-ptr-records store))))
              blocked? (and (:blocking-enabled @store true) (not= :passthrough (some-> rule :action keyword)) (contains? #{:A :AAAA :ANY} qtype)
                            (storage/blocklisted? store qname))
              action-key (cond blocked? :blocklisted ptr-record :ptr
                               :else (some-> rule :action keyword))]
          (case action-key
            :blocklisted
            (do (action :blocklist nil nil)
                (if (= :nxdomain (some-> (:blocklist-action config) keyword))
                  (base [] {:rcode 3})
                  (base (blackhole-answers qname qtype 60) {})))

            :ptr
            (do (action :ptr ptr-record nil)
                (base [(prims/ptr-rr qname (:hostname ptr-record) (or (:ttl ptr-record) 300))] {}))

            :static
            (do (action :static rule nil)
                (base (static-answers qname qtype
                                      (or (:value rule)
                                          (get-in rule [:match :value]))
                                      (or (:ttl rule) 300))
                      {}))


            :blackhole
            (do (action :blackhole rule nil)
                (base (blackhole-answers qname qtype (or (:ttl rule) 60)) {}))

            :redirect
            (do (action :redirect rule nil)
                (base (redirect-answers qname qtype
                                        (or (:value rule)
                                            (get-in rule [:match :value]))
                                        (or (:ttl rule) 300))
                      {}))

            :upstream
            (let [target (:value rule)
                  res (upstreams/query-single up-store target
                                              (prims/encode-message msg))]
              (if res
                (do (action :upstream rule target)
                    (let [parsed (prims/parse-message (:bytes res))]
                      (assoc parsed
                             :id (:id msg)
                             :rd (:rd msg)
                             :ra true
                             :additional (if req-opt
                                           [(prims/opt-rr (:class req-opt))]
                                           (filterv #(not= :OPT (:type %))
                                                    (:additional parsed))))))
                (do (action :upstream-failed rule target)
                    (respond-rcode msg 2))))

            (let [res (forward up-store msg)]
              (if res
                (do (action :passthrough rule (:upstream res))
                    (let [parsed (prims/parse-message (:bytes res))]
                      (assoc parsed
                             :id (:id msg)
                             :rd (:rd msg)
                             :ra true
                             :additional (if req-opt
                                           [(prims/opt-rr (:class req-opt))]
                                           (filterv #(not= :OPT (:type %))
                                                    (:additional parsed))))))
                (do (action :upstream-failed rule nil)
                    (respond-rcode msg 2))))))))))




(defn -main [& _args]
  (let [config (load-config)
        data-dir (:data-dir config)
        log (fn [m] (when (:log config)
                      (println (str (Instant/now) " " (pr-str m)))))
        store (storage/open (str data-dir "/rules.edn"))
        _ (storage/seed-rules! store (map normalize-rule (:rules config)))
        up-store (upstreams/open (:upstreams config)
                                 {:enabled (not= false (:dns-cache-enabled config))
                                  :max-entries (or (:dns-cache-max-entries config) 10000)
                                  :max-ttl (or (:dns-cache-max-ttl config) 86400)})
        _ (when (empty? (storage/list-proxy-maps store))
            (doseq [m (:proxy-maps config)] (storage/put-proxy-map! store m)))
        _ (when (empty? (storage/list-blocklists store))
            (doseq [record (:blocklists config)] (storage/put-blocklist! store record)))
        _ (when (empty? (storage/list-ptr-records store))
            (doseq [record (:ptr-records config)] (storage/put-ptr-record! store record)))
        _ (when (empty? (storage/list-transformers store))
            (doseq [record (:transformers config)] (storage/put-transformer! store record)))
        _ (when (empty? (storage/list-proxy-listeners store))
            (doseq [record (:proxy-listeners config)] (storage/put-proxy-listener! store record)))
        _ (when (empty? (storage/list-proxy-mounts store))
            (doseq [record (:proxy-mounts config)] (storage/put-proxy-mount! store record)))
        tls-context (when (or (:proxy-tls-enabled config)
                              (some :tls (storage/list-proxy-listeners store)))
                      (tls/ssl-context {:keystore (:proxy-tls-keystore config)
                                        :password (:proxy-tls-password config)
                                        :self-signed? (:proxy-tls-self-signed config)
                                        :common-name (:proxy-tls-common-name config)
                                        :sans (:proxy-tls-sans config)}))
        blocklist-scheduler (blocklists/start-scheduler store (:blocklist-refresh-hours config) log)
        ws-listener (websocket/start {:port (:websocket-port config)
                                      :bind (:proxy-bind config)
                                      :http-host (if (contains? #{"0.0.0.0" "::"} (:admin-bind config)) "127.0.0.1" (:admin-bind config))
                                      :http-port (:admin-port config)})
        ingress-listener (websocket/start {:port (:ingress-port config 8056)
                                            :bind "0.0.0.0" :allowed-clients #{"172.30.32.2"}
                                            :http-host (if (contains? #{"0.0.0.0" "::"} (:admin-bind config)) "127.0.0.1" (:admin-bind config))
                                            :http-port (:admin-port config)})
        publish (fn [event] ((:publish ws-listener) event) ((:publish ingress-listener) event))
        _ (alter-meta! store assoc :storage.storage/on-query publish)
        uscan-runtime (uscan/start store publish)
        handler (make-handler {:store store :up-store up-store
                               :config config :log log})
        proxy-listener (proxy/start {:port (:proxy-port config)
                                     :bind (:proxy-bind config)
                                     :tls-context (when (:proxy-tls-enabled config) tls-context)
                                     :listeners (storage/list-proxy-listeners store)
                                     :maps #(proxy-maps store)
                                     :on-event publish
                                     :log log})
        listeners
        [(udp/start {:port (:dns-port config)
                     :bind (:bind config)
                     :handler handler
                     :log log})
         (tcp/start {:port (:dns-port config)
                     :bind (:bind config)
                     :handler handler
                     :log log})
         (doh/start {:port (:doh-port config)
                     :bind (:bind config)
                     :handler handler
                     :log log})
         (admin/start {:port (:admin-port config)
                       :bind (:admin-bind config)
                       :store store
                       :upstore up-store
                       :uscan uscan-runtime
                       :log log})
         proxy-listener
         ws-listener
         ingress-listener
         uscan-runtime
         blocklist-scheduler]]
    (log {:event :start
          :dns (str (:bind config) ":" (:dns-port config))
          :doh (str (:bind config) ":" (:doh-port config) "/dns-query")
          :admin (str (:admin-bind config) ":" (:admin-port config))
          :proxy (str (:proxy-bind config) ":" (:proxy-port config))
          :websocket (str (:proxy-bind config) ":" (:websocket-port config))
          :rules (count (storage/list-rules store))
          :upstreams (map :name (upstreams/list-upstreams up-store))})
    (.addShutdownHook
     (Runtime/getRuntime)
     (Thread. ^Runnable
      (fn []
        (log {:event :shutdown})
        (doseq [l listeners]
          (try (:stop l) (catch Exception _ nil))))))

    @(promise)))
