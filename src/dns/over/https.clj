(ns dns.over.https
  "DNS-over-HTTPS server endpoint (RFC 8484) on the JDK built-in HTTP
  server. Serves GET ?dns=<base64url> and POST application/dns-message
  on a single configurable path."
  (:require [clojure.string :as str]
            [dns.dnsPrims :as prims])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.io ByteArrayOutputStream]
           [java.net InetSocketAddress]
           [java.nio.charset StandardCharsets]
           [java.util Base64]
           [java.util.concurrent Executors]))

(def ^:private ^java.nio.charset.Charset utf8 StandardCharsets/UTF_8)

(defn- respond [^HttpExchange ex status ^bytes body ^String ctype]
  (let [h (.getResponseHeaders ex)]
    (.set h "Content-Type" ctype)
    (.set h "Cache-Control" "no-store")
    (.set h "Access-Control-Allow-Origin" "*")
    (.set h "X-Content-Type-Options" "nosniff"))
  (.sendResponseHeaders ex status (long (alength body)))
  (with-open [os (.getResponseBody ex)]
    (.write os body)))

(defn- query-param [^String query ^String key]
  (when query
    (when-let [param (->> (str/split query #"&")
                          (filter #(str/starts-with? % (str key "=")))
                          first)]
      (java.net.URLDecoder/decode ^String (second (str/split param #"=" 2))
                                  "UTF-8"))))

(defn- read-body [^HttpExchange ex ^long limit]
  (let [bos (ByteArrayOutputStream.)
        buf (byte-array 4096)]
    (loop []
      (let [n (.read (.getRequestBody ex) buf)]
        (cond
          (neg? n) (.toByteArray bos)
          (> (+ (.size bos) n) limit) (throw (ex-info "body too large" {}))
          :else (do (.write bos buf 0 n) (recur)))))))

(defn start
  "Start a DoH endpoint.
  opts: {:port :bind :path :handler :log :max-body}
  handler is (fn [msg remote-sockaddr] response-msg).
  Returns {:stop fn :server srv}."
  [{:keys [port bind path handler log max-body]
    :or {port 8053 bind "0.0.0.0" path "/dns-query" max-body 65535}}]
  (let [server (HttpServer/create (InetSocketAddress. ^String bind (int port)) 0)
        http-handler
        (reify HttpHandler
          (handle [_ ex]
            (try
              (let [method (.getRequestMethod ex)]
                (cond
                  (= method "OPTIONS")
                  (let [h (.getResponseHeaders ex)]
                    (.set h "Access-Control-Allow-Origin" "*")
                    (.set h "Access-Control-Allow-Methods" "GET, POST, OPTIONS")
                    (.set h "Access-Control-Allow-Headers" "Content-Type")
                    (.sendResponseHeaders ex 204 -1))

                  (= method "GET")
                  (let [raw (query-param (.getQuery (.getRequestURI ex)) "dns")]
                    (if (str/blank? raw)
                      (respond ex 400 (.getBytes "missing dns parameter" utf8)
                               "text/plain; charset=utf-8")
                      (let [in (prims/b64url-decode raw)
                            msg (prims/parse-message in)
                            resp (handler msg (.getRemoteAddress ex))
                            out (prims/encode-response resp 65535)]
                        (when log
                          (log {:event :query :proto :doh
                                :client (str (.getRemoteAddress ex))
                                :qname (prims/qname msg)
                                :qtype (prims/qtype msg)
                                :rcode (:rcode resp)}))
                        (respond ex 200 out "application/dns-message"))))

                  (= method "POST")
                  (try
                    (let [in (read-body ex max-body)
                          msg (prims/parse-message in)
                          resp (handler msg (.getRemoteAddress ex))
                          out (prims/encode-response resp 65535)]
                      (when log
                        (log {:event :query :proto :doh
                              :client (str (.getRemoteAddress ex))
                              :qname (prims/qname msg)
                              :qtype (prims/qtype msg)
                              :rcode (:rcode resp)}))
                      (respond ex 200 out "application/dns-message"))
                    (catch Exception e
                      (when log (log {:event :parse-error :error (str e)}))
                      (respond ex 400 (.getBytes "bad dns message" utf8)
                               "text/plain; charset=utf-8")))

                  :else
                  (respond ex 405 (.getBytes "method not allowed" utf8)
                           "text/plain; charset=utf-8")))
              (catch Exception e
                (when log (log {:event :doh-error :error (str e)}))
                (try
                  (respond ex 500 (.getBytes "server error" utf8)
                           "text/plain; charset=utf-8")
                  (catch Exception _ nil)))
              (finally
                (try (.close ex) (catch Exception _ nil))))))]
    (.createContext server path http-handler)
    (.setExecutor server (Executors/newFixedThreadPool 4))
    (.start server)
    {:server server
     :port (.getPort (.getAddress server))
     :stop (fn [] (.stop server 0))}))
