(ns dashboard-test
  (:require [clojure.test :refer :all]
            [clojure.data.json :as json]
            [storage.storage :as storage]
            [dns.upstream.upstreamStore :as upstreams]
            [admin.api :as admin]
            [xform.websocket :as websocket]
            [blueberryProxy :as proxy]
            [dns.dnsPrims :as prims])
  (:import [java.net URI Socket]
           [java.io ByteArrayInputStream ByteArrayOutputStream]
           [java.util.concurrent ArrayBlockingQueue]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers WebSocket$Listener]
           [java.nio.file Files]
           [java.util.concurrent CompletableFuture TimeUnit]))

(defn test-store []
  (storage/open (str (Files/createTempDirectory "blueberry-dashboard-" (make-array java.nio.file.attribute.FileAttribute 0)) "/state.edn")))

(deftest counts-retention-and-restart
  (let [store (test-store)]
    (swap! store assoc :query-log-size 2)
    (doseq [entry [{:qname "allowed.example." :client "one" :action :passthrough}
                   {:qname "blocked.example" :client "two" :action :blocklist}
                   {:qname "blocked.example" :client "two" :action :blackhole}
                   {:qname "failed.example" :client "one" :action :upstream-failed}]]
      (storage/log-query! store entry))
    (let [stats (storage/dashboard-stats store)]
      (is (= [4 1 2 1] (mapv stats [:queries :allowed :blocked :errors])))
      (is (= {:domain "blocked.example" :queries 2} (first (:top-blocked stats)))))
    (is (= ["failed.example" "blocked.example"] (mapv :qname (storage/recent-queries store 2))))
    (storage/set-blocking! store false)
    (let [reopened (storage/open (:storage.storage/path (meta @store)))]
      (is (false? (:blocking-enabled @reopened)))
      (is (= 0 (:queries (storage/dashboard-stats reopened)))))))

(deftest safe-event-summary
  (let [summary (websocket/event-summary {:type "request" :uri "https://user:secret@example.com/a?token=private" :headers {"Authorization" "private"} :body "private"})]
    (is (= "https://example.com/a" (:uri summary)))
    (is (not (contains? summary :headers)))
    (is (not (contains? summary :body)))))

(deftest ^:integration http-facade-and-live-events
  (let [store (test-store)
        api (admin/start {:port 0 :bind "127.0.0.1" :store store :upstore (upstreams/open nil)})
        gateway (websocket/start {:port 0 :bind "127.0.0.1" :http-port (:port api)})
        client (HttpClient/newHttpClient)
        base (str "http://127.0.0.1:" (:port gateway))
        response (fn [path body]
                   (let [builder (HttpRequest/newBuilder (URI/create (str base path)))
                         request (if body (.POST builder (HttpRequest$BodyPublishers/ofString body)) (.GET builder))]
                     (.send client (.build request) (HttpResponse$BodyHandlers/ofString))))]
    (try
      (is (= 200 (.statusCode (response "/" nil))))
      (is (.contains (.body (response "/" nil)) "Live flow"))
      (is (= 200 (.statusCode (response "/dashboard.js" nil))))
      (is (= 200 (.statusCode (response "/settings" "{\"blocking-enabled\":false}"))))
      (is (false? (:blocking-enabled @store)))
      (is (= 400 (.statusCode (response "/settings" "{\"blocking-enabled\":\"false\"}"))))
      (storage/log-query! store {:qname "live.example" :client "127.0.0.1" :action :blocklist})
      (let [stats (json/read-str (.body (response "/stats" nil)) :key-fn keyword)]
        (is (= 1 (:queries stats)))
        (is (= 1 (:blocked stats))))
      (let [ready (promise) event (promise) text (StringBuilder.)
            listener (reify WebSocket$Listener
                       (onOpen [_ ws] (.request ws 1) (deliver ready true))
                       (onText [_ ws data last]
                         (.append text data)
                         (when last (deliver event (json/read-str (str text) :key-fn keyword)))
                         (.request ws 1)
                         (CompletableFuture/completedFuture nil)))
            ws (.get (.buildAsync (.newWebSocketBuilder client) (URI/create (str "ws://127.0.0.1:" (:port gateway) "/events")) listener) 3 TimeUnit/SECONDS)]
        (try
          (is (deref ready 1000 false))
          ((:publish gateway) {:type "request" :uri "http://example.com/path?secret=hidden" :body "sensitive"})
          (let [received (deref event 3000 nil)]
            (is (= "request" (:type received)))
            (is (= "http://example.com/path" (:uri received)))
            (is (not (contains? received :body))))
          (finally (.abort ws))))
      (finally ((:stop gateway)) ((:stop api))))))

(deftest websocket-framing-and-unbuffered-http-body
  (let [input (ByteArrayInputStream. (.getBytes "POST /settings HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbody" "UTF-8"))
        headers (#'websocket/read-headers input)]
    (is (= "POST /settings HTTP/1.1" (first headers)))
    (is (= "body" (String. (.readAllBytes input) "UTF-8"))))
  (doseq [n [12 256 70000]]
    (let [out (ByteArrayOutputStream.) data (byte-array n)]
      (#'websocket/write-frame! out 1 data)
      (let [bytes (.toByteArray out)]
        (is (= 129 (bit-and 255 (aget bytes 0))))
        (is (= (cond (< n 126) n (< n 65536) 126 :else 127) (bit-and 255 (aget bytes 1)))))))
  (let [input (ByteArrayInputStream. (byte-array (map unchecked-byte [137 129 1 2 3 4 121])))
        queue (ArrayBlockingQueue. 2)
        socket (proxy [Socket] [] (getInputStream [] input))]
    (is (#'websocket/read-control! socket queue))
    (let [[opcode payload] (.poll queue)]
      (is (= 10 opcode))
      (is (= "x" (String. payload "UTF-8"))))))

(deftest protection-switch-and-domain-overrides
  (let [store (test-store)
        request {:id 1 :qr false :opcode 0 :questions [{:name "device.example" :type :A :class 1}]}
        handler (proxy/make-handler {:store store :up-store (upstreams/open nil) :config {:log-queries true} :log (fn [_])})
        response (prims/encode-message (prims/make-response request []))]
    (storage/put-blocklist! store {:id "list" :entries ["device.example"]})
    (with-redefs [upstreams/query (fn [_ _] {:bytes response :upstream "test"})]
      (handler request nil)
      (is (= :blocklist (:action (first (storage/recent-queries store 1)))))
      (storage/add-rule! store {:id "existing" :match_type "exact" :match "device.example" :action "blackhole"})
      (storage/add-rule! store {:id "allow" :match_type "exact" :match "device.example" :action "passthrough" :priority 100})
      (handler request nil)
      (is (= :passthrough (:action (first (storage/recent-queries store 1)))))
      (storage/add-rule! store {:id "allow" :match_type "exact" :match "device.example" :action "blackhole"})
      (storage/set-blocking! store false)
      (handler request nil)
      (is (= :passthrough (:action (first (storage/recent-queries store 1))))))))
