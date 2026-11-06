(ns xform.proxy
  (:require [clojure.string :as str]
            [xform.graal :as graal])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer HttpsServer HttpsConfigurator]
           [java.net InetSocketAddress URI]
           [java.nio.charset StandardCharsets]
           [java.util.concurrent Executors]
           [java.net.http HttpClient HttpClient$Redirect HttpRequest HttpRequest$BodyPublishers
            HttpResponse$BodyHandlers]))

(def ^:private utf8 StandardCharsets/UTF_8)

(defn transform-headers
  "Apply header operations {:set {name value}, :remove [name ...]} to a map."
  [headers {:keys [set remove]}]
  (let [removed (clojure.core/set (map str/lower-case remove))
        kept (into {} (clojure.core/remove (fn [[k _]] (contains? removed (str/lower-case (name k)))) headers))]
    (merge kept set)))

(defn transform-data
  "Apply a declarative body transform. Supported operations are replace and
  prefix, and are only applied when the body is valid UTF-8 text."
  [data xform]
  (if-not xform data
    (let [{:keys [operation from to value]} xform
          s (String. ^bytes data utf8)]
      (.getBytes ^String
                 (case (keyword operation)
                   :replace (str/replace s (str from) (str to))
                   :prefix (str value s)
                   :suffix (str s value)
                   s) utf8))))

(defn- apply-script [value script]
  (if script (merge value (graal/transform script value)) value))

(defn- header-map [^HttpExchange ex]
  (into {} (for [[k vs] (.entrySet (.getRequestHeaders ex))]
             [k (str/join ", " vs)])))

(defn- matching-map [maps ^HttpExchange ex map-id]
  (let [host (some-> (.getFirst (.getRequestHeaders ex) "Host") str/lower-case)
        path (.getPath (.getRequestURI ex))]
    (first (filter (fn [m]
                     (and (:enabled m true)
                          (or (nil? map-id)
                              (= (str map-id) (str (:id m)))
                              (= (str map-id) (str (:proxy-map-id m))))
                          (or (nil? (:host m))
                              (= host (str/lower-case (:host m)))
                              (str/starts-with? (or host "")
                                                (str (str/lower-case (:host m)) ":")))
                          (let [prefix (or (:path m) "/")]
                            (or (= prefix "/") (= path prefix)
                                (str/starts-with? path (str (str/replace prefix #"/$" "") "/")))))) maps))))

(defn- make-handler [client maps map-id on-event log]
  (reify HttpHandler
    (handle [_ ex]
      (try
        (let [m (matching-map (maps) ex map-id)]
          (if-not (and m (:target m))
            (let [b (.getBytes "No proxy map matched this listener and request" utf8)]
              (.sendResponseHeaders ex 404 (alength b))
              (with-open [o (.getResponseBody ex)] (.write o b)))
            (let [request-path (.getRawPath (.getRequestURI ex))
                  routed-path (if (:proxymount? m)
                                (let [prefix (or (:path m) "/")
                                      suffix (subs request-path (min (count request-path) (count prefix)))]
                                  (str (str/replace (or (:target-path m) "/") #"/$" "")
                                       (if (str/blank? suffix) "/" suffix)))
                                request-path)
                  initial-uri (URI/create (str (str/replace (:target m) #"/$" "")
                                                routed-path
                                                (when-let [q (.getRawQuery (.getRequestURI ex))] (str "?" q))))
                  initial-body (with-open [in (.getRequestBody ex)] (.readAllBytes in))
                  initial-body (transform-data initial-body (:request-body m))
                  initial-headers (transform-headers (header-map ex) (:request-headers m))
                  request-data (apply-script {:method (.getRequestMethod ex)
                                              :uri (str initial-uri)
                                              :headers initial-headers
                                              :body (String. initial-body utf8)}
                                             (:request-script m))
                  uri (URI/create (str (:uri request-data)))
                  req-body (.getBytes (str (:body request-data "")) utf8)
                  req-headers (:headers request-data)
                  method (str (:method request-data "GET"))
                  builder (HttpRequest/newBuilder uri)
                  _ (doseq [[k v] req-headers
                            :when (not (contains? #{"host" "content-length" "connection"} (str/lower-case k)))]
                      (.header builder (str k) (str v)))
                  _ (.method builder method
                             (if (contains? #{"GET" "HEAD"} method)
                               (HttpRequest$BodyPublishers/noBody)
                               (HttpRequest$BodyPublishers/ofByteArray req-body)))
                  _ (on-event {:type "request" :map (:id m)
                               :listener (:websocket-listener m)
                               :method method :uri (str uri)
                               :headers req-headers :body (String. req-body utf8)})
                  response (.send client (.build builder) HttpResponse$BodyHandlers/ofByteArray)
                  initial-status (.statusCode response)
                  initial-response-body (transform-data (.body response) (:response-body m))
                  initial-response-headers
                  (transform-headers (into {} (for [[k v] (.map (.headers response))]
                                                [k (str/join ", " v)]))
                                     (:response-headers m))
                  response-data (apply-script {:status initial-status
                                               :headers initial-response-headers
                                               :body (String. initial-response-body utf8)}
                                              (:response-script m))
                  status (int (:status response-data initial-status))
                  body (.getBytes (str (:body response-data "")) utf8)
                  headers (:headers response-data)]
              (doseq [[k v] headers
                      :when (not (contains? #{"content-length" "transfer-encoding"} (str/lower-case (str k))))]
                (.set (.getResponseHeaders ex) (str k) (str v)))
              (on-event {:type "response" :map (:id m)
                         :listener (:websocket-listener m)
                         :status status :headers headers :body (String. body utf8)})
              (.sendResponseHeaders ex status (long (alength body)))
              (with-open [o (.getResponseBody ex)] (.write o body)))))
        (catch Exception e
          (when log (log {:event :proxy-error :listener map-id :error (str e)}))
          (try (.sendResponseHeaders ex 502 -1) (catch Exception _ nil)))
        (finally (try (.close ex) (catch Exception _ nil)))))))

(defn- create-listener [{:keys [port bind map-id tls-context maps on-event log]
                         :or {bind "0.0.0.0" maps (constantly []) on-event (fn [_] nil)}} client]
  (let [address (InetSocketAddress. ^String bind (int port))
        server (if tls-context
                 (let [s (HttpsServer/create address 0)]
                   (.setHttpsConfigurator s (HttpsConfigurator. tls-context))
                   s)
                 (HttpServer/create address 0))
        handler (make-handler client maps map-id on-event log)]
    (.createContext server "/" handler)
    (.setExecutor server (Executors/newCachedThreadPool))
    (.start server)
    {:server server :port (.getPort (.getAddress server)) :bind bind :map-id map-id
     :tls (boolean tls-context) :stop (fn [] (.stop server 0))}))

(defn start
  "Start the shared HTTP proxy and any isolated per-map listeners. Listener
  records accept :map-id, :bind, :port, and optional :tls-context."
  [{:keys [port bind maps on-event log listeners tls-context]
    :or {port 8080 bind "0.0.0.0" maps (constantly []) on-event (fn [_] nil)}}]
  (let [client (-> (HttpClient/newBuilder) (.followRedirects HttpClient$Redirect/NEVER) .build)
        base {:port port :bind bind :maps maps :on-event on-event :log log :tls-context tls-context}
        shared (create-listener base client)
        isolated (mapv #(create-listener (merge base % {:tls-context (when (:tls %) tls-context)}) client)
                       (filter #(not= false (:enabled % true)) (or listeners [])))
        all (into [shared] isolated)]
    {:listeners all
     :port (:port shared)
     :stop (fn [] (doseq [listener all] ((:stop listener))))}))
