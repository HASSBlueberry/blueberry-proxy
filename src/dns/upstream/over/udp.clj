(ns dns.upstream.over.udp
  "Plain DNS over UDP upstream client."
  (:import [java.net InetSocketAddress]
           [java.nio ByteBuffer]
           [java.nio.channels DatagramChannel]))

(defn- request-id ^long [^bytes bs]
  (if (>= (alength bs) 2)
    (bit-or (bit-shift-left (bit-and (aget bs 0) 0xff) 8)
            (bit-and (aget bs 1) 0xff))
    -1))

(defn query
  "Send raw DNS message bytes upstream, return response bytes.
  Retries reads until the response id matches or the timeout expires."
  [{:keys [host port timeout] :or {port 53 timeout 3000}} ^bytes msg]
  (with-open [ch (DatagramChannel/open)]
    (let [sock (.socket ch)
          deadline (+ (System/currentTimeMillis) (long timeout))
          want (request-id msg)]
      (.connect ch (InetSocketAddress. ^String host (int port)))
      (.write ch (ByteBuffer/wrap msg))
      (loop []
        (let [remaining (- deadline (System/currentTimeMillis))]
          (when (<= remaining 0)
            (throw (ex-info "upstream udp timeout" {:host host :port port})))
          (.setSoTimeout sock (int remaining))
          (let [buf (ByteBuffer/allocate 65535)
                n (.read ch buf)]
            (when (neg? n)
              (throw (ex-info "upstream udp closed" {:host host})))
            (.flip buf)
            (let [out (byte-array (.remaining buf))]
              (.get buf out)
              (if (= want (request-id out))
                out
                (recur)))))))))
