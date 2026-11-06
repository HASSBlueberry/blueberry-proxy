(ns xform.websocket
  "Bounded local event feed with an HTTP facade for same-origin Ingress access."
  (:require [clojure.data.json :as json]
            [clojure.string :as str])
  (:import [java.net ServerSocket Socket InetAddress InetSocketAddress URI]
           [java.io InputStream OutputStream ByteArrayOutputStream EOFException]
           [java.nio.charset StandardCharsets]
           [java.security MessageDigest]
           [java.util Base64]
           [java.util.concurrent Executors Semaphore ArrayBlockingQueue TimeUnit]))

(defn- accept-key [key]
  (.encodeToString (Base64/getEncoder)
                  (.digest (MessageDigest/getInstance "SHA-1")
                           (.getBytes (str key "258EAFA5-E914-47DA-95CA-C5AB0DC85B11") StandardCharsets/ISO_8859_1))))

(defn- write-frame! [^OutputStream out opcode ^bytes data]
  (locking out
    (.write out (bit-or 0x80 opcode))
    (let [n (alength data)]
      (cond (< n 126) (.write out n)
            (< n 65536) (do (.write out 126) (.write out (bit-shift-right n 8)) (.write out (bit-and n 255)))
            :else (do (.write out 127)
                      (doseq [shift (range 56 -1 -8)]
                        (.write out (bit-and (bit-shift-right (long n) shift) 255)))))
    (.write out data)
    (.flush out))))

(defn- byte! [^InputStream in]
  (let [b (.read in)] (if (neg? b) (throw (EOFException.)) b)))

(defn- read-headers [^InputStream in]
  (let [buffer (ByteArrayOutputStream.)]
    (loop [tail 0]
      (when (>= (.size buffer) 32768) (throw (ex-info "HTTP headers too large" {})))
      (let [b (byte! in) next-tail (bit-and 0xffffffff (bit-or (bit-shift-left tail 8) b))]
        (.write buffer b)
        (if (= next-tail 0x0d0a0d0a)
          (str/split (String. (.toByteArray buffer) StandardCharsets/ISO_8859_1) #"\r\n")
          (recur next-tail))))))

(defn- copy-body! [^InputStream in ^OutputStream out n]
  (let [buffer (byte-array 8192)]
    (loop [left (long n)]
      (when (pos? left)
        (let [n (.read in buffer 0 (int (min left 8192)))]
          (when (neg? n) (throw (EOFException.)))
          (.write out buffer 0 n)
          (recur (- left n)))))))

(defn- forward-http! [^Socket socket lines headers host port]
  (when (get headers "transfer-encoding") (throw (ex-info "Chunked upload is not supported by the dashboard" {})))
  (let [length (Long/parseLong (get headers "content-length" "0"))]
    (when (or (neg? length) (> length 1048576)) (throw (ex-info "Dashboard body exceeds 1 MiB" {})))
    (with-open [upstream (Socket.)]
      (.connect upstream (InetSocketAddress. ^String host (int port)) 3000)
      (.setSoTimeout upstream 60000)
      (let [out (.getOutputStream upstream)
            request (str (str/join "\r\n" (remove #(re-find #"(?i)^(connection|upgrade|keep-alive|proxy-connection):" %) lines))
                         "\r\nConnection: close\r\n\r\n")]
        (.write out (.getBytes request StandardCharsets/ISO_8859_1))
        (copy-body! (.getInputStream socket) out length)
        (.flush out)
        (.transferTo (.getInputStream upstream) (.getOutputStream socket))))))

(defn- read-control! [^Socket socket queue]
  (let [in (.getInputStream socket)
        first-byte (byte! in) second-byte (byte! in)
        opcode (bit-and first-byte 15)
        length (bit-and second-byte 127)]
    (when (or (not (bit-test second-byte 7)) (> length 125) (not (bit-test first-byte 7)))
      (throw (ex-info "Only masked control frames are accepted" {})))
    (let [mask (.readNBytes in 4) payload (.readNBytes in length)]
      (when (or (not= 4 (alength mask)) (not= length (alength payload))) (throw (EOFException.)))
      (dotimes [i length]
        (aset-byte payload i (unchecked-byte (bit-xor (aget payload i) (aget mask (mod i 4))))))
      (case opcode
        8 (do (write-frame! (.getOutputStream socket) 8 payload) false)
        9 (do (when-not (.offer ^ArrayBlockingQueue queue [10 payload]) (.close socket)) true)
        10 true
        (throw (ex-info "Event socket accepts ping, pong, and close only" {}))))))

(defn- serve-client! [^Socket socket running clients http-host http-port]
  (try
    (.setSoTimeout socket 45000)
    (let [lines (read-headers (.getInputStream socket))
          headers (into {} (keep (fn [line]
                                  (let [idx (.indexOf ^String line ":")]
                                    (when (pos? idx) [(str/lower-case (subs line 0 idx)) (str/trim (subs line (inc idx)))]))) (rest lines)))]
      (if (= "websocket" (some-> (get headers "upgrade") str/lower-case))
        (let [key (get headers "sec-websocket-key")
              _ (when-not (and key (= "13" (get headers "sec-websocket-version"))
                               (= 16 (alength (.decode (Base64/getDecoder) ^String key))))
                  (throw (ex-info "Invalid WebSocket handshake" {})))
              path (second (str/split (first lines) #"\s+"))
              route (some-> path (str/split #"\?") first (str/replace #"^/|/$" ""))
              route (when-not (contains? #{nil ""} route) route)
              out (.getOutputStream socket)
              queue (ArrayBlockingQueue. 128)
              writer (Thread. (fn []
                                (try
                                  (while (and @running (not (.isClosed socket)))
                                    (let [item (.poll queue 15 TimeUnit/SECONDS)
                                          [opcode data] (or item [9 (byte-array 0)])]
                                      (write-frame! out opcode data)))
                                  (catch Exception _ (try (.close socket) (catch Exception _ nil))))))]
          (swap! clients assoc socket {:route route :queue queue})
          (.write out (.getBytes (str "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                     "Sec-WebSocket-Accept: " (accept-key key) "\r\n\r\n") StandardCharsets/ISO_8859_1))
          (.flush out)
          (.setDaemon writer true)
          (.start writer)
          (try (loop [] (when (and @running (read-control! socket queue)) (recur)))
               (finally (.interrupt writer))))
        (if http-port
          (forward-http! socket lines headers http-host http-port)
          (throw (ex-info "HTTP facade is not configured" {})))))
    (catch Exception _ nil)
    (finally (swap! clients dissoc socket) (try (.close socket) (catch Exception _ nil)))))

(defn event-summary [event]
  (cond-> (assoc (select-keys event [:type :client :qname :qtype :action :blocked :rule :upstream :method :status :map :listener :ip :mac :hostname :protocols :services :ports :scanner :job_id :new_device :discoveries :active_scanner :results]) :ts (or (:ts event) (System/currentTimeMillis)))
    (:uri event) (assoc :uri (try (let [uri (URI/create (str (:uri event)))]
                                      (str (.getScheme uri) "://" (.getHost uri) (.getRawPath uri)))
                                 (catch Exception _ "[invalid URI]")))))

(defn start [{:keys [port bind http-host http-port allowed-clients] :or {port 8055 bind "0.0.0.0" http-host "127.0.0.1"}}]
  (let [server (ServerSocket. (int port) 50 (InetAddress/getByName bind))
        clients (atom {}) running (atom true) sockets (atom #{})
        slots (Semaphore. 64) pool (Executors/newCachedThreadPool)
        acceptor (Thread. (fn []
                            (while @running
                              (try
                                (let [socket (.accept server)]
                                  (if (and (or (nil? allowed-clients) (contains? allowed-clients (.getHostAddress (.getInetAddress socket)))) (.tryAcquire slots))
                                    (do (swap! sockets conj socket)
                                        (.submit pool ^Runnable (fn []
                                                                 (try (serve-client! socket running clients http-host http-port)
                                                                      (finally (swap! sockets disj socket) (.release slots))))))
                                    (.close socket)))
                                (catch Exception _ nil)))))]
    (.setDaemon acceptor true)
    (.start acceptor)
    {:port (.getLocalPort server)
     :publish (fn [event]
                (let [data (.getBytes (json/write-str event) StandardCharsets/UTF_8)
                      summary (event-summary event)
                      safe-data (.getBytes (json/write-str summary) StandardCharsets/UTF_8)]
                  (doseq [[^Socket socket {:keys [route queue]}] @clients
                          :when (or (nil? route) (= "events" route) (= route (str (:listener event))))]
                    (when-not (.offer ^ArrayBlockingQueue queue [1 (if (= "events" route) safe-data data)])
                      (swap! clients dissoc socket)
                      (try (.close socket) (catch Exception _ nil))))))
     :stop (fn []
             (reset! running false)
             (.close server)
             (doseq [^Socket socket @sockets] (try (.close socket) (catch Exception _ nil)))
             (.shutdownNow pool))}))
