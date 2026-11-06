(ns dns.over.udp
  "UDP DNS listener. Reads datagrams on one thread, hands each parsed
  message to the handler on a pool, sends the response back to the source."
  (:require [dns.dnsPrims :as prims])
  (:import [java.net InetSocketAddress StandardSocketOptions]
           [java.nio ByteBuffer]
           [java.nio.channels DatagramChannel]
           [java.util.concurrent Executors]))

(defn- serve-one [^DatagramChannel ch handler udp-size log ^bytes in src]
  (try
    (let [msg (prims/parse-message in)]
      (try
        (let [resp (handler msg src)
              out (prims/encode-response resp udp-size)]
          (when log (log {:event :query
                          :client (str src)
                          :qname (prims/qname msg)
                          :qtype (prims/qtype msg)
                          :rcode (:rcode resp)
                          :answers (count (:answers resp))}))
          (.send ch (ByteBuffer/wrap out) src))
        (catch Exception e
          ;; handler blew up after a good parse: answer SERVFAIL
          (when log (log {:event :handler-error :error (str e)}))
          (try
            (let [resp (prims/make-response msg [] {:rcode 2})
                  out (prims/encode-response resp udp-size)]
              (.send ch (ByteBuffer/wrap out) src))
            (catch Exception _ nil)))))
    (catch Exception e
      ;; malformed packet: drop it
      (when log (log {:event :parse-error :error (str e)})))))

(defn start
  "Start a UDP DNS server.
  opts: {:port :bind :handler :udp-size :threads :log}
  handler is (fn [msg src-sockaddr] response-msg).
  Returns {:stop fn :channel ch}."
  [{:keys [port bind handler udp-size threads log]
    :or {port 53 bind "0.0.0.0" udp-size 4096 threads 4}}]
  (let [ch (doto (DatagramChannel/open)
             (.setOption StandardSocketOptions/SO_REUSEADDR true)
             (.bind (InetSocketAddress. ^String bind (int port))))
        pool (Executors/newFixedThreadPool (int threads))
        running (atom true)
        worker
        (Thread.
         (fn []
           (while @running
             (try
               (let [buf (ByteBuffer/allocate 65535)
                     src (.receive ch buf)]
                 (.flip buf)
                 (let [in (byte-array (.remaining buf))]
                   (.get buf in)
                   (.submit pool
                            ^Runnable
                            #(serve-one ch handler udp-size log in src))))
               (catch Exception e
                 (when @running
                   (when log (log {:event :udp-error :error (str e)}))
                   (try (Thread/sleep 50) (catch InterruptedException _ nil))))))))
        _ (doto worker (.setDaemon true) (.start))]
    {:channel ch
     :port (.getPort (.getLocalAddress ch))
     :stop (fn []
             (reset! running false)
             (try (.close ch) (catch Exception _ nil))
             (.shutdownNow pool))}))
