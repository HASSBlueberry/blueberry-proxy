(ns uscan.scripts
  "GraalJS scanners with explicit scoped networking capabilities."
  (:refer-clojure :exclude [run!])
  (:require [clojure.data.json :as json]
            [uscan.protocols :as protocols]
            [uscan.scope :as scope])
  (:import [org.graalvm.polyglot Context HostAccess]
           [org.graalvm.polyglot.proxy ProxyExecutable]
           [java.util.concurrent TimeUnit ScheduledExecutorService]))

(defn run! [script params emit! check! ^ScheduledExecutorService timer]
  (when-not (and (string? script) (< (count script) 262144))
    (throw (ex-info "Scanner script must be text under 256 KiB" {})))
  (let [probes (atom 0)
        guard! (fn [ip port]
                 (check!)
                 (when-not (and (scope/contains-ip? (:networks params) ip) (some #{port} (:ports params)))
                   (throw (ex-info "Script probe is outside its registered CIDRs or ports" {})))
                 (when (> (swap! probes inc) (:max_probes params)) (throw (ex-info "Scanner probe budget exhausted" {}))))
        builder (-> (Context/newBuilder (into-array String ["js"]))
                    (.allowHostAccess HostAccess/NONE)
                    (.allowHostClassLookup (reify java.util.function.Predicate (test [_ _] false)))
                    (.allowIO false) (.allowNativeAccess false) (.allowCreateThread false))]
    (with-open [ctx (.build builder)]
      (let [timeout (.scheduleAtFixedRate timer ^Runnable (fn [] (try (check!) (catch Exception _ (try (.close ctx true) (catch Exception _ nil)))))
                                          100 100 TimeUnit/MILLISECONDS)
            bindings (.getBindings ctx "js")]
        (try
          (.putMember bindings "inputJson" (json/write-str (dissoc params :networks)))
          (.putMember bindings "__tcp" (reify ProxyExecutable
                                         (execute [_ args]
                                           (let [ip (.asString (aget args 0)) port (.asInt (aget args 1))]
                                             (guard! ip port)
                                             (protocols/tcp-probe ip port (:timeout_ms params))))))
          (.putMember bindings "__udp" (reify ProxyExecutable
                                         (execute [_ args]
                                           (let [ip (.asString (aget args 0)) port (.asInt (aget args 1)) hex (.asString (aget args 2))]
                                             (guard! ip port)
                                             (when (> (count hex) 8192) (throw (ex-info "UDP payload exceeds 4096 bytes" {})))
                                             (json/write-str (protocols/udp-probe ip port (.parseHex (java.util.HexFormat/of) hex) (:timeout_ms params)))))))
          (.putMember bindings "__emit" (reify ProxyExecutable
                                          (execute [_ args]
                                            (check!)
                                            (let [text (.asString (aget args 0))]
                                              (when (> (count text) 32768) (throw (ex-info "Discovery record exceeds 32 KiB" {})))
                                              (let [record (json/read-str text :key-fn keyword)]
                                                (when-not (scope/contains-ip? (:networks params) (:ip record)) (throw (ex-info "Script emitted an IP outside its CIDRs" {})))
                                                (emit! record)))
                                            nil)))
          (.eval ctx "js" "const p = JSON.parse(inputJson); const ctx = Object.freeze({targets: Object.freeze(p.targets), parameters: Object.freeze(p), tcp: (ip,port) => __tcp(String(ip),port), udp: (ip,port,hex) => JSON.parse(__udp(String(ip),port,String(hex))), emit: record => __emit(JSON.stringify(record))});")
          (.eval ctx "js" script)
          (.eval ctx "js" "if (typeof scan !== 'function') throw new Error('Declare scan(ctx)'); scan(ctx);")
          (finally (.cancel timeout false)))))))
