(ns xform.graal
  "Run locally authored transformer functions in a restricted GraalJS context."
  (:require [clojure.data.json :as json])
  (:import [org.graalvm.polyglot Context HostAccess]))

(defn transform
  "Evaluate a script that declares transform(input) and returns JSON data.
  The script sees one JSON object and receives no Java host access."
  [script input]
  (when (or (not (string? script)) (> (count script) 262144))
    (throw (ex-info "transformer script must be text under 256 KiB" {})))
  (with-open [ctx (-> (Context/newBuilder (into-array String ["js"]))
                      (.allowHostAccess HostAccess/NONE)
                      (.allowHostClassLookup (reify java.util.function.Predicate
                                               (test [_ _] false)))
                      (.allowIO false)
                      (.allowNativeAccess false)
                      (.allowCreateThread false)
                      .build)]
    (let [bindings (.getBindings ctx "js")]
      (.putMember bindings "inputJson" (json/write-str input))
      (.eval ctx "js" script)
      (let [result (.eval ctx "js"
                          "JSON.stringify(transform(JSON.parse(inputJson)))")]
        (when (.isNull result)
          (throw (ex-info "transformer returned an undefined or unserializable result" {})))
        (json/read-str (.asString result) :key-fn keyword)))))
