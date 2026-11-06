(ns uscan.protocols
  (:refer-clojure :exclude [run!])
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [dns.dnsPrims :as dns]
            [uscan.scope :as scope])
  (:import [java.net InetAddress InetSocketAddress Socket MulticastSocket DatagramPacket SocketTimeoutException]
           [java.io ByteArrayInputStream]
           [java.nio.charset StandardCharsets]
           [java.util UUID]
           [java.util.concurrent Executors TimeUnit Callable]
           [javax.xml.parsers DocumentBuilderFactory]))

(defn arp-records []
  (try (with-open [reader (io/reader "/proc/net/arp")]
         (vec (for [line (drop 1 (line-seq reader))
                    :let [[ip _ flags mac _ interface] (str/split (str/trim line) #"\s+")]
                    :when (and ip mac (not= flags "0x0") (not= mac "00:00:00:00:00:00"))]
                {:ip ip :mac (str/lower-case mac) :interface interface :evidence "arp"})))
       (catch Exception _ [])))

(defn tcp-probe [ip port timeout]
  (try (with-open [socket (Socket.)]
         (.connect socket (InetSocketAddress. ^String ip (int port)) (int timeout)) true)
       (catch Exception _ false)))

(defn udp-probe [ip port payload timeout]
  (with-open [socket (java.net.DatagramSocket.)]
    (.setSoTimeout socket (int timeout))
    (.connect socket (InetAddress/getByName ip) (int port))
    (.send socket (DatagramPacket. ^bytes payload (alength ^bytes payload)))
    (try
      (let [packet (DatagramPacket. (byte-array 65507) 65507)]
        (.receive socket packet)
        {:ip (.getHostAddress (.getAddress packet)) :port (.getPort packet)
         :hex (.formatHex (java.util.HexFormat/of) (.getData packet) 0 (.getLength packet))})
      (catch SocketTimeoutException _ nil)
      (catch java.net.PortUnreachableException _ nil))))

(defn tcp-scan! [params emit! check!]
  (let [pool (Executors/newFixedThreadPool (int (:workers params)))
        completion (java.util.concurrent.ExecutorCompletionService. pool)
        tasks (for [ip (:targets params) port (:ports params)] [ip port])]
    (try
      ;; Limit outstanding work instead of queuing every host/port combination.
      (loop [remaining (seq tasks) pending 0]
        (check!)
        (cond
          (and remaining (< pending (:workers params)))
          (let [[ip port] (first remaining)]
            (.submit completion ^Callable (fn [] (when (tcp-probe ip port (:timeout_ms params)) {:ip ip :ports [port] :evidence "tcp-open"})))
            (recur (next remaining) (inc pending)))
          (pos? pending)
          (if-let [future (.poll completion 200 TimeUnit/MILLISECONDS)]
            (do (when-let [record (.get future)] (emit! record)) (recur remaining (dec pending)))
            (recur remaining pending))
          :else nil))
      (finally (.shutdownNow pool)))))

(defn parse-wsd [^bytes data ip]
  (when (> (alength data) 65507) (throw (ex-info "Discovery packet too large" {})))
  (let [factory (DocumentBuilderFactory/newInstance)]
    (.setNamespaceAware factory true)
    (.setFeature factory "http://apache.org/xml/features/disallow-doctype-decl" true)
    (.setFeature factory "http://xml.org/sax/features/external-general-entities" false)
    (.setFeature factory "http://xml.org/sax/features/external-parameter-entities" false)
    (.setXIncludeAware factory false)
    (.setExpandEntityReferences factory false)
    (let [builder (.newDocumentBuilder factory)
          _ (.setErrorHandler builder (org.xml.sax.helpers.DefaultHandler.))
          doc (.parse builder (ByteArrayInputStream. data))
          values (fn [name]
                   (let [nodes (.getElementsByTagNameNS doc "*" name)]
                     (mapv #(str/trim (.getTextContent (.item nodes %))) (range (min 64 (.getLength nodes))))))]
      (when (seq (values "ProbeMatch"))
        {:ip ip :evidence "ws-discovery-response"
         :services (vec (take 32 (mapcat #(str/split % #"\s+") (values "Types"))))
         :endpoints (vec (take 16 (mapcat #(str/split % #"\s+") (values "XAddrs"))))
         :scopes (vec (take 32 (mapcat #(str/split % #"\s+") (values "Scopes"))))}))))

(defn wsd-probe [onvif?]
  (str "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"><s:Header>"
       "<a:MessageID>urn:uuid:" (UUID/randomUUID) "</a:MessageID><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
       "<a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action></s:Header><s:Body><d:Probe>"
       (when onvif? "<d:Types>tds:Device</d:Types>") "</d:Probe></s:Body></s:Envelope>"))

(defn- multicast! [params group port payload receive! check!]
  (let [nics (vec (scope/selected-interfaces params))]
    (when (empty? nics) (throw (ex-info "No selected interface supports multicast in the configured CIDRs" {})))
    (doseq [nic nics]
      (check!)
      (with-open [socket (MulticastSocket. (int 0))]
        (.setTimeToLive socket 1)
        (.setNetworkInterface socket nic)
        (.setSoTimeout socket 200)
        (.send socket (DatagramPacket. ^bytes payload (alength ^bytes payload) (InetAddress/getByName group) (int port)))
        (let [deadline (+ (System/currentTimeMillis) (:duration_ms params))]
          (loop []
            (check!)
            (when (< (System/currentTimeMillis) deadline)
              (let [packet (DatagramPacket. (byte-array 65507) 65507)]
                (try (.receive socket packet)
                     (receive! socket packet)
                     (catch SocketTimeoutException _ nil))
                (recur)))))))))

(defn wsd-scan! [params onvif? emit! check!]
  (let [probe (wsd-probe onvif?)
        probe (if (:wsd_2009 params)
                (-> probe
                    (str/replace "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous" "http://www.w3.org/2005/08/addressing/anonymous")
                    (str/replace "http://schemas.xmlsoap.org/ws/2004/08/addressing" "http://www.w3.org/2005/08/addressing")
                    (str/replace "http://schemas.xmlsoap.org/ws/2005/04/discovery" "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01")
                    (str/replace "urn:schemas-xmlsoap-org:ws:2005:04:discovery" "urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01")) probe)
        payload (.getBytes probe StandardCharsets/UTF_8)]
    (multicast! params "239.255.255.250" 3702 payload
                (fn [_ packet]
                  (try (when-let [record (parse-wsd (java.util.Arrays/copyOf (.getData ^DatagramPacket packet) (.getLength ^DatagramPacket packet))
                                                    (.getHostAddress (.getAddress ^DatagramPacket packet)))] (emit! record))
                       (catch Exception _ nil))) check!)))

(defn mdns-records [message sender]
  (let [records (concat (:answers message) (:additional message))
        addresses (filter #(= :A (:type %)) records)
        services (filter #(= :SRV (:type %)) records)
        known (for [address addresses]
                {:ip (:data address) :hostname (:name address) :evidence "mdns-address"
                 :services (vec (for [service services :when (= (:name address) (get-in service [:data :target]))] (:name service)))
                 :ports (vec (for [service services :when (= (:name address) (get-in service [:data :target]))] (get-in service [:data :port])))})]
    (vec (cons {:ip sender :evidence "mdns-response" :services []} known))))

(defn mdns-query [names]
  (dns/encode-message {:id 0 :questions (mapv #(hash-map :name % :type :PTR :class 1) names)}))

(defn mdns-scan! [params emit! check!]
  (let [names (or (seq (:services params)) ["_services._dns-sd._udp.local" "_http._tcp.local" "_hap._tcp.local" "_netcom._tcp.local" "_onvif._tcp.local"])
        _ (when-not (and (<= (count names) 64) (every? #(and (string? %) (< (count %) 254) (str/ends-with? % ".local")) names))
            (throw (ex-info "services must be DNS-SD names ending in .local" {})))
        queried (atom (set names))]
    (multicast! params "224.0.0.251" 5353 (mdns-query names)
                (fn [socket ^DatagramPacket packet]
                  (try
                    (let [message (dns/parse-message (java.util.Arrays/copyOf (.getData packet) (.getLength packet)))
                          records (concat (:answers message) (:additional message))]
                      (doseq [record (mdns-records message (.getHostAddress (.getAddress packet)))] (emit! record))
                      (doseq [question (keep (fn [record]
                                              (case (:type record)
                                                :PTR (when (string? (:data record)) {:name (:data record) :type :ANY :class 1})
                                                :SRV (when (get-in record [:data :target]) {:name (get-in record [:data :target]) :type :A :class 1})
                                                nil)) records)
                              :let [key [(.getName (.getNetworkInterface ^MulticastSocket socket)) (:name question) (:type question)]]
                              :when (and (< (count @queried) 256) (not (contains? @queried key)))]
                        (check!)
                        (swap! queried conj key)
                        (let [payload (dns/encode-message {:id 0 :questions [question]})]
                          (.send ^MulticastSocket socket (DatagramPacket. payload (alength payload) (InetAddress/getByName "224.0.0.251") 5353)))))
                    (catch Exception _ nil))) check!)))

(defn parse-avahi [body]
  (vec (keep (fn [line]
               (let [[flag interface family name service _ hostname ip port] (str/split line #";" 10)]
                 (when (and (= flag "=") (= family "IPv4") ip port)
                   (try {:ip ip :interface interface :hostname hostname :services [(str name "." service ".local")]
                         :ports [(Long/parseLong port)] :evidence "avahi"}
                        (catch Exception _ nil))))) (str/split-lines body))))

(defn avahi-scan! [params emit! check!]
  (let [file (java.io.File/createTempFile "blueberry-avahi-" ".txt")
        process (atom nil)
        deadline (+ (System/currentTimeMillis) (:duration_ms params))]
    (try
      (reset! process (.start (doto (ProcessBuilder. ^java.util.List ["avahi-browse" "--all" "--resolve" "--parsable" "--terminate" "--no-db-lookup"])
                               (.redirectErrorStream true) (.redirectOutput file))))
      (loop []
        (check!)
        (when (> (System/currentTimeMillis) deadline) (throw (ex-info "Avahi browse timed out" {})))
        (when (> (.length file) 1048576) (throw (ex-info "Avahi output exceeds 1 MiB" {})))
        (if (.waitFor ^Process @process 200 TimeUnit/MILLISECONDS)
          (do (when-not (zero? (.exitValue ^Process @process)) (throw (ex-info "Avahi daemon is unavailable; use the native mdns scanner or provide Avahi/D-Bus" {})))
              (when (> (.length file) 1048576) (throw (ex-info "Avahi output exceeds 1 MiB" {})))
              (doseq [record (parse-avahi (slurp file))] (emit! record)))
          (recur)))
      (finally (when @process (.destroyForcibly ^Process @process)) (.delete file)))))

(defn run! [kind params emit! check!]
  (case kind
    "arp" (doseq [record (arp-records)] (check!) (emit! record))
    "tcp" (tcp-scan! params emit! check!)
    "mdns" (mdns-scan! params emit! check!)
    "wsd" (do (wsd-scan! params false emit! check!)
              (wsd-scan! (assoc params :wsd_2009 true) false emit! check!))
    "onvif" (wsd-scan! params true emit! check!)
    "avahi" (try (avahi-scan! params emit! check!) {:backend "avahi-daemon"}
                 (catch Exception error
                   (check!)
                   (if (:require_daemon params) (throw error)
                     (do (mdns-scan! params emit! check!)
                         {:backend "native-dns-sd" :warning "Avahi daemon unavailable; native DNS-SD discovery used"}))))
    (throw (ex-info "Unknown built-in scanner" {}))))
