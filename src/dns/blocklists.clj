(ns dns.blocklists
  "Fetch and normalize configurable DNS blocklists."
  (:require [clojure.string :as str]
            [storage.storage :as storage])
  (:import [java.net URI]
           [java.net.http HttpClient HttpClient$Redirect HttpRequest HttpResponse$BodyHandlers]
           [java.time Duration]
           [java.util.concurrent Executors TimeUnit]))

(def ^:private max-source-bytes (* 8 1024 1024))
(def ^:private domain-pattern #"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$")

(defn- domain? [s]
  (boolean (and (string? s) (re-matches domain-pattern s))))

(defn- normalize-line [line]
  (let [line (-> line str/trim (str/replace #"\s+#.*$" ""))]
    (when-not (or (str/blank? line) (str/starts-with? line "#") (str/starts-with? line "!")
                  (str/starts-with? line "["))
      (let [line (str/replace line #"^\|\|" "")
            line (str/replace line #"\^.*$" "")
            fields (str/split line #"\s+")
            candidate (if (and (> (count fields) 1)
                               (or (= "0.0.0.0" (first fields)) (= "127.0.0.1" (first fields))
                                   (= "::" (first fields)) (= "::1" (first fields))))
                        (second fields)
                        (first fields))
            candidate (-> candidate str/lower-case (str/replace #"\.$" ""))]
        (when (domain? candidate) candidate)))))

(defn- read-source [^java.io.InputStream in]
  (let [out (java.io.ByteArrayOutputStream.)
        buffer (byte-array 8192)]
    (loop [total 0]
      (let [n (.read in buffer)]
        (if (neg? n)
          (.toByteArray out)
          (let [next-total (+ total n)]
            (when (> next-total max-source-bytes)
              (throw (ex-info "blocklist source exceeds the 8 MiB limit" {})))
            (.write out buffer 0 n)
            (recur next-total)))))))

(defn parse-list [body]
  (->> (str/split-lines body) (keep normalize-line) distinct vec))

(defn refresh-one! [store client list-record]
  (let [uri (URI/create (str (:url list-record)))]
    (when-not (contains? #{"http" "https"} (some-> (.getScheme uri) str/lower-case))
      (throw (ex-info "blocklist URL must use HTTP or HTTPS" {:id (:id list-record)})))
    (let [request (-> (HttpRequest/newBuilder uri)
                      (.timeout (Duration/ofSeconds 20))
                      (.header "User-Agent" "blueberryProxy/0.2 blocklist updater")
                      (.GET) .build)
          response (.send client request (HttpResponse$BodyHandlers/ofInputStream))]
      (when-not (<= 200 (.statusCode response) 299)
        (try (.close (.body response)) (catch Exception _ nil))
        (throw (ex-info "blocklist fetch returned a non-success status"
                        {:id (:id list-record) :status (.statusCode response)})))
      (let [bytes (with-open [in ^java.io.InputStream (.body response)] (read-source in))
            entries (parse-list (String. ^bytes bytes java.nio.charset.StandardCharsets/UTF_8))]
        (storage/replace-blocklist-entries! store (:id list-record) entries (System/currentTimeMillis))
        {:id (:id list-record) :entries (count entries) :refreshed true}))))

(defn refresh! [store]
  (let [client (-> (HttpClient/newBuilder)
                   (.connectTimeout (Duration/ofSeconds 8))
                   (.followRedirects HttpClient$Redirect/NORMAL)
                   .build)]
    (mapv (fn [record]
            (try (refresh-one! store client record)
                 (catch Exception e {:id (:id record) :refreshed false :error (.getMessage e)})))
          (filter #(and (:url %) (not= false (:enabled % true))) (storage/list-blocklists store)))))

(defn start-scheduler [store interval-hours log]
  (let [executor (Executors/newSingleThreadScheduledExecutor)
        interval (max 1 (long interval-hours))]
    (.scheduleAtFixedRate executor
                          ^Runnable (fn []
                                      (doseq [result (refresh! store)]
                                        (when log (log (assoc result :event :blocklist-refresh)))))
                          0 interval TimeUnit/HOURS)
    {:stop #(.shutdownNow executor)}))
