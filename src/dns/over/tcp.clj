(ns dns.over.tcp
  "TCP DNS listener (RFC 1035 4.2.2): 2-byte length prefix framing,
  one handler thread per connection."
  (:require [dns.dnsPrims :as prims])
  (:import [java.net InetSocketAddress StandardSocketOptions]
           [java.nio ByteBuffer]
           [java.nio.channels SocketChannel]
           [java.util.concurrent Executors]))

(defn- read-fully
  "Read exactly buf's remaining bytes. Returns false on EOF."
  [^SocketChannel ch ^bytes buf]
  (loop [off 0]
    (if (>= off (alength buf))
      true
      (let [n (.read ch (ByteBuffer/wrap buf off (- (alength buf) off)))]
        (if (neg? n)
          false
          (recur (+ off n)))))))

(defn- write-fully [^SocketChannel ch ^bytes bs]
  (let [bb (ByteBuffer/wrap bs)]
    (while (.hasRemaining bb)
      (when (neg? (.write ch bb))
        (throw (ex-info "tcp write failed" {}))))))

(defn- serve-connection [^SocketChannel ch handler max-size log]
  (try
    (loop []
      (let [lenbuf (byte-array 2)]
        (when (read-fully ch lenbuf)
          (let [n (bit-or (bit-shift-left (bit-and (aget lenbuf 0) 0xff) 8)
                          (bit-and (aget lenbuf 1) 0xff))]
            (when (and (pos? n) (<= n max-size))
              (let [in (byte-array n)]
                (when (read-fully ch in)
                  (try
                    (let [msg (prims/parse-message in)]
                      (try
                        (let [resp (handler msg (.getRemoteAddress ch))
                              out (prims/encode-response resp max-size)
                              framed (byte-array (+ 2 (alength out)))]
                          (aset-byte framed 0 (unchecked-byte
                                               (bit-shift-right (alength out) 8)))
                          (aset-byte framed 1 (unchecked-byte (alength out)))
                          (System/arraycopy out 0 framed 2 (alength out))
                          (write-fully ch framed)
                          (when log
                            (log {:event :query :proto :tcp
                                  :client (str (.getRemoteAddress ch))
                                  :qname (prims/qname msg)
                                  :qtype (prims/qtype msg)
                                  :rcode (:rcode resp)})))
                        (catch Exception e
                          (when log (log {:event :handler-error :error (str e)}))
                          (let [resp (prims/make-response msg [] {:rcode 2})
                                out (prims/encode-response resp max-size)
                                framed (byte-array (+ 2 (alength out)))]
                            (aset-byte framed 0 (unchecked-byte
                                                 (bit-shift-right (alength out) 8)))
                            (aset-byte framed 1 (unchecked-byte (alength out)))
                            (System/arraycopy out 0 framed 2 (alength out))
                            (write-fully ch framed)))))
                    (catch Exception e
                      (when log (log {:event :parse-error :error (str e)})))))
                (recur)))))))
    (catch Exception e
      (when log (log {:event :tcp-error :error (str e)})))
    (finally
      (try (.close ch) (catch Exception _ nil)))))

(defn start
  "Start a TCP DNS server.
  opts: {:port :bind :handler :max-size :log}
  Returns {:stop fn}."
  [{:keys [port bind handler max-size log]
    :or {port 53 bind "0.0.0.0" max-size 65535}}]
  (let [ss (doto (java.nio.channels.ServerSocketChannel/open)
             (.setOption StandardSocketOptions/SO_REUSEADDR true)
             (.bind (InetSocketAddress. ^String bind (int port))))
        pool (Executors/newCachedThreadPool)
        running (atom true)
        worker
        (Thread.
         (fn []
           (while @running
             (try
               (let [ch (.accept ss)]
                 (.submit pool ^Runnable #(serve-connection ch handler max-size log)))
               (catch Exception e
                 (when @running
                   (when log (log {:event :tcp-accept-error :error (str e)}))
                   (try (Thread/sleep 50) (catch InterruptedException _ nil))))))))]
    (doto worker (.setDaemon true) (.start))
    {:channel ss
     :port (.getPort (.getLocalAddress ss))
     :stop (fn []
             (reset! running false)
             (try (.close ss) (catch Exception _ nil))
             (.shutdownNow pool))}))
