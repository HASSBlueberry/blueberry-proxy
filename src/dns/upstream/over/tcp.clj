(ns dns.upstream.over.tcp
  "Plain DNS over TCP upstream client (RFC 1035 length-prefix framing)."
  (:import [java.net InetSocketAddress Socket]))

(defn- read-fully [^java.io.InputStream in ^bytes buf]
  (loop [off 0]
    (if (>= off (alength buf))
      true
      (let [n (.read in buf off (- (alength buf) off))]
        (if (neg? n) false (recur (+ off n)))))))

(defn query
  "Send raw DNS message bytes upstream over TCP, return response bytes."
  [{:keys [host port timeout] :or {port 53 timeout 3000}} ^bytes msg]
  (with-open [sock (Socket.)]
    (.connect sock (InetSocketAddress. ^String host (int port)) (int timeout))
    (.setSoTimeout sock (int timeout))
    (let [out (.getOutputStream sock)
          in (.getInputStream sock)
          n (alength msg)
          lenbuf (byte-array [(unchecked-byte (bit-shift-right n 8))
                              (unchecked-byte n)])]
      (.write out lenbuf)
      (.write out msg)
      (.flush out)
      (let [hdr (byte-array 2)]
        (when-not (read-fully in hdr)
          (throw (ex-info "upstream tcp closed before header" {:host host})))
        (let [rn (bit-or (bit-shift-left (bit-and (aget hdr 0) 0xff) 8)
                         (bit-and (aget hdr 1) 0xff))]
          (when-not (and (pos? rn) (<= rn 65535))
            (throw (ex-info "upstream tcp bad length" {:host host :len rn})))
          (let [body (byte-array rn)]
            (when-not (read-fully in body)
              (throw (ex-info "upstream tcp closed mid-body" {:host host})))
            body))))))
