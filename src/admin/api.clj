(ns admin.api
  (:require [clojure.data.json :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [dns.upstream.upstreamStore :as upstreams]
            [dns.blocklists :as blocklists]
            [storage.storage :as storage]
            [uscan.core :as uscan]
            [uscan.scope :as scope])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.net InetAddress InetSocketAddress NetworkInterface]
           [java.nio.charset StandardCharsets]
           [java.util Collections]
           [java.util.concurrent Executors]))

(def ^:private ^java.nio.charset.Charset utf8 StandardCharsets/UTF_8)
(def ^:private started-at (System/currentTimeMillis))

(defn- send-bytes [^HttpExchange ex status ^bytes body ^String ctype]
  (let [h (.getResponseHeaders ex)]
    (.set h "Content-Type" ctype)
    (.set h "Cache-Control" "no-store")
    (.set h "Access-Control-Allow-Origin" "*"))
  (.sendResponseHeaders ex status (long (alength body)))
  (with-open [os (.getResponseBody ex)]
    (.write os body)))

(defn- send-json [^HttpExchange ex status obj]
  (send-bytes ex status
              (.getBytes ^String (json/write-str obj) utf8)
              "application/json; charset=utf-8"))

(defn- send-edn [^HttpExchange ex status obj]
  (send-bytes ex status
              (.getBytes ^String (pr-str obj) utf8)
              "application/edn; charset=utf-8"))

(defn- read-body [^HttpExchange ex]
  (let [bos (java.io.ByteArrayOutputStream.)
        buf (byte-array 8192)]
    (loop []
      (let [n (.read (.getRequestBody ex) buf)]
        (if (neg? n)
          (String. ^bytes (.toByteArray bos) utf8)
          (do (.write bos buf 0 n) (recur)))))))

(defn- parse-body
  "Accept JSON (preferred) or EDN request bodies."
  [^String body]
  (when-not (str/blank? body)
    (let [t (str/triml body)]
      (if (str/starts-with? t "{")
        (json/read-str t :key-fn keyword)
        (edn/read-string t)))))




(defn- client-ip [addr]
  (when addr
    (try
      (if (instance? InetSocketAddress addr)
        (.getHostAddress (.getAddress ^InetSocketAddress addr))
        (str addr))
      (catch Exception _ (str addr)))))

(defn- interfaces-info []
  (try
    (vec
     (for [nif (enumeration-seq (NetworkInterface/getNetworkInterfaces))
           :when (.isUp ^NetworkInterface nif)]
       {:name (.getName ^NetworkInterface nif)
        :mac (let [m (.getHardwareAddress ^NetworkInterface nif)]
               (when m
                 (->> (map #(format "%02x" (bit-and % 0xff)) m)
                      (str/join ":"))))
        :addresses (vec (for [addr (enumeration-seq (.getInetAddresses ^NetworkInterface nif))
                              :when (not (.isLoopbackAddress ^InetAddress addr))]
                          (.getHostAddress ^InetAddress addr)))}))
    (catch Exception _ [])))

(defn arp-table []
  (try
    (with-open [r (io/reader "/proc/net/arp")]
      (->> (line-seq r)
           (drop 1)
           (map #(str/split (str/trim %) #"\s+"))
           (filter #(>= (count %) 6))
           (mapv (fn [[ip _hw flags mac _mask dev]]
                   {:ip ip :mac mac :flags flags :device dev}))))
    (catch Exception _ [])))

(defn- ip->long ^long [^String ip]
  (reduce (fn [acc part] (+ (* acc 256) (Long/parseLong part)))
          0
          (str/split ip #"\.")))

(defn- long->ip ^String [^long n]
  (->> [(bit-shift-right n 24) (bit-shift-right n 16) (bit-shift-right n 8) n]
       (map #(bit-and (long %) 0xff))
       (str/join ".")))

(defn cidr-hosts
  "Expand a CIDR (e.g. 192.168.1.0/24) into host addresses, capped at
  limit entries. Network and broadcast addresses are skipped for /30..8."
  ([cidr] (cidr-hosts cidr 256))
  ([^String cidr limit]
   (let [[base bits] (str/split cidr #"/")
         bits (Long/parseLong (or bits "32"))
         host-bits (max 0 (- 32 bits))
         size (bit-shift-left 1 host-bits)
         base (bit-and (ip->long base) (bit-shift-left -1 host-bits))
         skip (if (<= host-bits 30) 1 0)
         last (- (+ base size) skip)]
     (->> (range (+ base skip) (inc last))
          (take limit)
          (mapv long->ip)))))

(defn- probe [^String ip timeout-ms]
  (try
    (let [addr (InetAddress/getByName ip)]
      (.isReachable ^InetAddress addr (int timeout-ms)))
    (catch Exception _ false)))

(defn- ping-sweep [cidr timeout-ms workers]
  (let [hosts (cidr-hosts cidr (if (<= timeout-ms 200) 1024 256))
        pool (Executors/newFixedThreadPool (int workers))
        futs (mapv #(let [ip %] (.submit pool ^Callable (fn [] [ip (probe ip timeout-ms)])))
                   hosts)]
    (try
      (->> futs
           (keep (fn [^java.util.concurrent.Future f]
                   (try
                     (let [[ip ok] (.get f)]
                       (when ok ip))
                     (catch Exception _ nil))))
           (set))
      (finally (.shutdownNow pool)))))

(defn scan
  "Merge the kernel ARP table with a ping sweep of cidr (optional).
  Returns {:arp [...] :live [...] :cidr ...}."
  [{:keys [cidr timeout workers] :or {timeout 300 workers 32}}]
  (let [arp (arp-table)
        live (when cidr (ping-sweep cidr timeout workers))]
    {:arp arp
     :live (vec (sort (or live [])))
     :cidr cidr
     :interfaces (interfaces-info)}))

(defn- handle-rules [store ex method path query]
  (case method
    "GET" (send-json ex 200 {:rules (storage/list-rules store)})
    "POST" (let [body (parse-body (read-body ex))]
             (if (:match body)
               (send-json ex 200 {:rule (storage/add-rule! store body)})
               (send-json ex 400 {:error "rule requires :match and :action"})))
    "DELETE" (let [id (or (:id query) (get query "id"))]
               (if id
                 (do (storage/remove-rule! store id)
                     (send-json ex 200 {:removed id}))
                 (send-json ex 400 {:error "missing id"})))
    (send-json ex 405 {:error "method not allowed"})))

(defn- handle-upstreams [up-store ex method]
  (case method
    "GET" (send-json ex 200 {:upstreams (upstreams/list-upstreams up-store)})
    "POST" (let [body (parse-body (read-body ex))]
             (if (:name body)
               (do (upstreams/add-upstream! up-store body)
                   (send-json ex 200 {:upstreams (upstreams/list-upstreams up-store)}))
               (send-json ex 400 {:error "upstream requires :name"})))
    "DELETE" (let [body (parse-body (read-body ex))]
               (if (:name body)
                 (do (upstreams/remove-upstream! up-store (:name body))
                     (send-json ex 200 {:removed (:name body)}))
                 (send-json ex 400 {:error "missing name"})))
    (send-json ex 405 {:error "method not allowed"})))

(defn- handle-queries [store ex query]
  (let [n (try (Long/parseLong (str (or (:n query) (get query "n") "100")))
               (catch Exception _ 100))]
    (send-json ex 200 {:queries (storage/recent-queries store n)
                       :top-clients (storage/top-clients store 20)
                       :stats (storage/stats store)})))

(defn- handle-scan [ex query runtime]
  (let [cidr (or (:cidr query) (get query "cidr"))
        timeout (try (Long/parseLong (str (or (:timeout query)
                                              (get query "timeout") "250")))
                     (catch Exception _ 250))
        result (scan {:cidr cidr :timeout timeout :workers 32})
        devices (when runtime (:devices (uscan/snapshot runtime)))]
    (send-json ex 200 (assoc result :discoveries (vec devices)
                            :arp (vec (distinct (concat (filter :mac devices) (:arp result))))))))

(defn- handle-uscan [runtime store ex method path query]
  (if-not runtime
    (send-json ex 503 {:error "UScan is unavailable"})
    (try
      (case path
        "/uscan" (if (= method "GET") (send-json ex 200 (uscan/snapshot runtime (if (:limit query) (scope/bounded-int (Long/parseLong (:limit query)) 65536 1 65536 "limit") 65536))) (send-json ex 405 {:error "method not allowed"}))
        "/uscan/devices" (case method
          "GET" (send-json ex 200 {:devices (:devices (uscan/snapshot runtime))})
          "POST" (send-json ex 200 (uscan/import-devices! runtime (parse-body (read-body ex))))
          (send-json ex 405 {:error "method not allowed"}))
        "/uscan/scanners"
        (case method
          "GET" (send-json ex 200 {:scanners (uscan/scanners runtime) :kinds (sort uscan/kinds) :interfaces (scope/interfaces)})
          "POST" (send-json ex 200 {:scanner (uscan/register! runtime (parse-body (read-body ex)))})
          "DELETE" (let [id (:id query)]
                     (when-not id (throw (ex-info "id is required" {})))
                     (when (some #(= (:id %) id) uscan/builtins) (throw (ex-info "Disable built-in scanners instead of deleting them" {})))
                     (storage/remove-uscan-scanner! store id)
                     (send-json ex 200 {:removed id}))
          (send-json ex 405 {:error "method not allowed"}))
        "/uscan/jobs"
        (case method
          "GET" (if-let [id (:id query)]
                  (if-let [job (uscan/job runtime id)] (send-json ex 200 job) (send-json ex 404 {:error "job not found"}))
                  (send-json ex 200 {:jobs (:jobs (uscan/snapshot runtime))}))
          "POST" (send-json ex 202 (uscan/start-job! runtime (or (parse-body (read-body ex)) {})))
          "DELETE" (send-json ex 200 (uscan/cancel! runtime (:id query)))
          (send-json ex 405 {:error "method not allowed"})))
      (catch Exception error
        (send-json ex 400 {:error (str (.getMessage error))})))))

(defn- handle-ptr [store ex method query]
  (case method
    "GET" (send-json ex 200 {:records (storage/list-ptr-records store)})
    "POST" (let [body (parse-body (read-body ex))]
             (if (and (:ip body) (:hostname body))
               (send-json ex 200 {:record (storage/put-ptr-record! store body)})
               (send-json ex 400 {:error "PTR record requires :ip and :hostname"})))
    "DELETE" (let [id (or (:id query) (get query "id"))]
               (if id (do (storage/remove-ptr-record! store id)
                          (send-json ex 200 {:removed id}))
                   (send-json ex 400 {:error "missing id"})))
    (send-json ex 405 {:error "method not allowed"})))

(defn- handle-blocklists [store ex method query]
  (case method
    "GET" (send-json ex 200 {:blocklists (storage/list-blocklists store)})
    "POST" (let [body (parse-body (read-body ex))]
             (if (:url body)
               (send-json ex 200 {:blocklist (storage/put-blocklist! store body)})
               (send-json ex 400 {:error "blocklist requires :url"})))
    "DELETE" (let [id (or (:id query) (get query "id"))]
               (if id (do (storage/remove-blocklist! store id)
                          (send-json ex 200 {:removed id}))
                   (send-json ex 400 {:error "missing id"})))
    (send-json ex 405 {:error "method not allowed"})))

(defn- handle-blocklist-refresh [store ex]
  (send-json ex 200 {:results (blocklists/refresh! store)}))

(defn- handle-status [store up-store ex]
  (send-json ex 200
             {:name "blueberryProxy"
              :version "0.3.0"
              :uptime-ms (- (System/currentTimeMillis) started-at)
              :stats (storage/stats store)
              :rules (count (storage/list-rules store))
              :proxy-maps (count (storage/list-proxy-maps store))
              :proxy-listeners (storage/list-proxy-listeners store)
              :proxy-mounts (storage/list-proxy-mounts store)
              :transformers (count (storage/list-transformers store))
              :ptr-records (count (storage/list-ptr-records store))
              :blocklists (mapv #(select-keys % [:id :url :enabled :refreshed-at])
                                (storage/list-blocklists store))
              :upstreams (upstreams/list-upstreams up-store)
              :dns-cache (upstreams/cache-stats up-store)
              :interfaces (interfaces-info)}))

(defn start
  "Start the admin HTTP API.
  opts: {:port :bind :store :upstore :log}
  Returns {:stop fn}."
  [{:keys [port bind store upstore log uscan]
    :or {port 8054 bind "127.0.0.1"}}]
  (let [server (HttpServer/create (InetSocketAddress. ^String bind (int port)) 0)
        pool (Executors/newFixedThreadPool 4)
        handler
        (reify HttpHandler
          (handle [_ ex]
            (try
              (let [method (.getRequestMethod ex)
                    uri (.getRequestURI ex)
                    path (.getPath uri)
                    query (into {}
                                (for [pair (str/split (or (.getQuery uri) "") #"&")
                                      :when (str/includes? pair "=")
                                      :let [[k v] (str/split pair #"=" 2)]]
                                  [(keyword k) v]))]
                (cond
                  (= method "OPTIONS")
                  (let [h (.getResponseHeaders ex)]
                    (.set h "Access-Control-Allow-Origin" "*")
                    (.set h "Access-Control-Allow-Methods" "GET, POST, DELETE, OPTIONS")
                    (.set h "Access-Control-Allow-Headers" "Content-Type")
                    (.sendResponseHeaders ex 204 -1))

                  (and (= method "GET") (contains? #{"/" "/dashboard.js" "/dashboard.css"} path))
                  (let [[resource ctype] (get {"/" ["public/index.html" "text/html; charset=utf-8"]
                                               "/dashboard.js" ["public/dashboard.js" "text/javascript; charset=utf-8"]
                                               "/dashboard.css" ["public/dashboard.css" "text/css; charset=utf-8"]} path)]
                    (if-let [url (io/resource resource)]
                      (with-open [in (io/input-stream url)]
                        (let [bytes (.readAllBytes in)
                              ingress (.getFirst (.getRequestHeaders ex) "X-Ingress-Path")
                              bytes (if (and (= path "/") ingress
                                             (re-matches #"/api/hassio_ingress/[A-Za-z0-9_-]+/?" ingress))
                                      (.getBytes (str/replace (String. bytes utf8) "<head>"
                                                             (str "<head><base href=\"" (str/replace ingress #"/$" "") "/\">")) utf8)
                                      bytes)]
                          (send-bytes ex 200 bytes ctype)))
                      (send-json ex 404 {:error "dashboard resource missing"})))

                  (and (= method "GET") (= path "/stats"))
                  (send-json ex 200 (assoc (storage/dashboard-stats store)
                                          :uptime-ms (- (System/currentTimeMillis) started-at)
                                          :cache (upstreams/cache-stats upstore)))

                  (contains? #{"/uscan" "/uscan/devices" "/uscan/scanners" "/uscan/jobs"} path)
                  (handle-uscan uscan store ex method path query)

                  (= path "/settings")
                  (case method
                    "GET" (send-json ex 200 {:blocking-enabled (:blocking-enabled @store true)})
                    "POST" (let [body (parse-body (read-body ex))]
                             (if (instance? Boolean (:blocking-enabled body))
                               (send-json ex 200 {:blocking-enabled (storage/set-blocking! store (:blocking-enabled body))})
                               (send-json ex 400 {:error "blocking-enabled must be a boolean"})))
                    (send-json ex 405 {:error "method not allowed"}))

                  (and (= method "POST") (= path "/cache/clear"))
                  (do (swap! upstore assoc :cache {})
                      (send-json ex 200 {:cache (upstreams/cache-stats upstore)}))

                  (and (= method "GET") (= path "/status"))
                  (handle-status store upstore ex)

                  (= path "/rules")
                  (handle-rules store ex method path query)

                  (= path "/upstreams")
                  (handle-upstreams upstore ex method)

                  (= path "/proxy/maps")
                  (case method
                    "GET" (send-json ex 200 {:maps (storage/list-proxy-maps store)})
                    "POST" (let [body (parse-body (read-body ex))]
                             (if (:target body)
                               (send-json ex 200 {:map (storage/put-proxy-map! store body)})
                               (send-json ex 400 {:error "map requires :target"})))
                    "DELETE" (let [id (or (:id query) (get query "id"))]
                               (if id (do (storage/remove-proxy-map! store id)
                                          (send-json ex 200 {:removed id}))
                                   (send-json ex 400 {:error "missing id"})))
                    (send-json ex 405 {:error "method not allowed"}))

                  (= path "/proxy/transformers")
                  (case method
                    "GET" (send-json ex 200 {:transformers (storage/list-transformers store)})
                    "POST" (let [body (parse-body (read-body ex))]
                             (if (or (:type body) (:script body))
                               (send-json ex 200 {:transformer (storage/put-transformer! store body)})
                               (send-json ex 400 {:error "transformer requires :type or :script"})))
                    "DELETE" (let [id (or (:id query) (get query "id"))]
                               (if id (do (storage/remove-transformer! store id)
                                          (send-json ex 200 {:removed id}))
                                   (send-json ex 400 {:error "missing id"})))
                    (send-json ex 405 {:error "method not allowed"}))

                  (contains? #{"/proxy/listeners" "/proxy/mounts" "/proxymount"} path)
                  (let [mount? (contains? #{"/proxy/mounts" "/proxymount"} path)
                        list-fn (if mount? storage/list-proxy-mounts storage/list-proxy-listeners)
                        put-fn (if mount? storage/put-proxy-mount! storage/put-proxy-listener!)
                        remove-fn (if mount? storage/remove-proxy-mount! storage/remove-proxy-listener!)
                        key (if mount? :mount :listener)
                        collection (if mount? :mounts :listeners)]
                    (case method
                      "GET" (send-json ex 200 {collection (list-fn store)})
                      "POST" (let [body (parse-body (read-body ex))]
                               (if (or (and mount? (:target body) (:proxy-map-id body) (:path body))
                                       (and (not mount?) (:port body) (:map-id body)))
                                 (send-json ex 200 {key (put-fn store body)})
                                 (send-json ex 400 {:error (if mount?
                                                             "mount requires :target"
                                                             "listener requires :port and :map-id")})))
                      "DELETE" (let [id (or (:id query) (get query "id"))]
                                 (if id (do (remove-fn store id)
                                            (send-json ex 200 {:removed id}))
                                     (send-json ex 400 {:error "missing id"})))
                      (send-json ex 405 {:error "method not allowed"})))

                  (= path "/ptr")
                  (handle-ptr store ex method query)

                  (= path "/blocklists/refresh")
                  (if (= method "POST") (handle-blocklist-refresh store ex)
                      (send-json ex 405 {:error "method not allowed"}))

                  (= path "/blocklists")
                  (handle-blocklists store ex method query)

                  (and (= method "GET") (= path "/queries"))
                  (handle-queries store ex query)

                  (and (= method "GET") (= path "/scan"))
                  (handle-scan ex query uscan)

                  (and (= method "GET") (= path "/health"))
                  (send-json ex 200 {:ok true})

                  :else
                  (send-json ex 404 {:error "not found" :path path})))
              (catch Exception e
                (when log (log {:event :admin-error :error (str e)}))
                (try (send-json ex 500 {:error (str e)})
                     (catch Exception _ nil)))
              (finally
                (try (.close ex) (catch Exception _ nil))))))]
    (.createContext server "/" handler)
    (.setExecutor server pool)
    (.start server)
    (when log (log {:event :admin-start :port (.getPort (.getAddress server))}))
    {:server server
     :port (.getPort (.getAddress server))
     :stop (fn [] (.stop server 0) (.shutdownNow pool))}))
