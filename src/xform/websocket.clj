(ns xform.websocket
  "RFC 6455 text event feed for local proxy inspection clients."
  (:require [clojure.data.json :as json]
            [clojure.string :as str])
  (:import [java.net ServerSocket Socket InetAddress]
           [java.io BufferedReader InputStreamReader OutputStream]
           [java.nio.charset StandardCharsets]
           [java.security MessageDigest]
           [java.util Base64]
           [java.util.concurrent Executors]))

(defn- accept-key [key]
  (let [raw (.digest (MessageDigest/getInstance "SHA-1")
                     (.getBytes (str key "258EAFA5-E914-47DA-95CA-C5AB0DC85B11") StandardCharsets/ISO_8859_1))]
    (.encodeToString (Base64/getEncoder) raw)))

(defn- write-frame! [^OutputStream out ^bytes data]
  (locking out
    (.write out 0x81)
    (let [n (alength data)]
      (cond (< n 126) (.write out n)
            (< n 65536) (do (.write out 126) (.write out (bit-shift-right n 8)) (.write out (bit-and n 255)))
            :else (do (.write out 127)
                      (doseq [shift (range 56 -1 -8)]
                        (.write out (bit-and (bit-shift-right (long n) shift) 255)))))
      (.write out data)
      (.flush out))))

(defn- serve-client! [^Socket socket running clients]
  (try
    (let [reader (BufferedReader. (InputStreamReader. (.getInputStream socket) StandardCharsets/ISO_8859_1))
          lines (loop [acc []]
                  (let [line (.readLine reader)]
                    (if (or (nil? line) (= line "")) acc (recur (conj acc line)))))
          headers (into {} (keep (fn [line]
                                   (let [idx (.indexOf ^String line ":")]
                                     (when (pos? idx)
                                       [(str/lower-case (subs line 0 idx))
                                        (str/trim (subs line (inc idx)))]))) lines))]
      (when-let [key (get headers "sec-websocket-key")]
        (let [out (.getOutputStream socket)]
          (.write out (.getBytes (str "HTTP/1.1 101 Switching Protocols\r\n"
                                      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                      "Sec-WebSocket-Accept: " (accept-key key) "\r\n\r\n")
                                StandardCharsets/ISO_8859_1))
          (.flush out)
          (let [request-line (first lines)
                path (second (str/split (or request-line "") #"\s+"))
                route (some-> path (str/split #"\?") first (str/replace #"^/|/$" ""))
                route (when-not (str/blank? route) route)]
          (swap! clients assoc socket route)
          (let [in (.getInputStream socket) buf (byte-array 512)]
            (loop []
              (when (and @running (not (.isClosed socket)) (not (neg? (.read in buf))))
                (recur))))))))
    (catch Exception _ nil)
    (finally
      (swap! clients dissoc socket)
      (try (.close socket) (catch Exception _ nil)))))

(defn start [{:keys [port bind] :or {port 8055 bind "0.0.0.0"}}]
  (let [server (ServerSocket. (int port) 50 (InetAddress/getByName bind))
        clients (atom {})
        running (atom true)
        pool (Executors/newCachedThreadPool)
        acceptor (Thread.
                   (fn []
                     (while @running
                       (try
                         (let [socket (.accept server)]
                           (.submit pool ^Runnable (fn [] (serve-client! socket running clients))))
                         (catch Exception _ (when @running (Thread/sleep 25)))))))]
    (.setDaemon acceptor true)
    (.start acceptor)
    {:port (.getLocalPort server)
     :publish (fn [event]
                (let [data (.getBytes (json/write-str event) StandardCharsets/UTF_8)]
                  (doseq [[^Socket socket route] @clients
                          :when (or (nil? route) (= route (str (:listener event))))]
                    (try (write-frame! (.getOutputStream socket) data)
                         (catch Exception _ (swap! clients dissoc socket))))))
     :stop (fn []
             (reset! running false)
             (try (.close server) (catch Exception _ nil))
             (doseq [^Socket socket (keys @clients)] (try (.close socket) (catch Exception _ nil)))
             (.shutdownNow pool))}))
