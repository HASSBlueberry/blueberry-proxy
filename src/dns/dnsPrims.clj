(ns dns.dnsPrims
  (:require [clojure.string :as str])
  (:import [java.net InetAddress]
           [java.nio ByteBuffer ByteOrder]
           [java.nio.charset StandardCharsets]
           [java.util Arrays Base64]))




(def type->code
  {:A 1 :NS 2 :CNAME 5 :SOA 6 :PTR 12 :MX 15 :TXT 16 :AAAA 28
   :SRV 33 :OPT 41 :SVCB 64 :HTTPS 65 :ANY 255})

(def code->type (into {} (map (fn [[k v]] [v k])) type->code))

(def class->code {:IN 1 :CS 2 :CH 3 :HS 4 :ANY 255})

(def rcode->name {0 :NOERROR 1 :FORMERR 2 :SERVFAIL 3 :NXDOMAIN
                  4 :NOTIMP 5 :REFUSED})
(def name->rcode (into {} (map (fn [[k v]] [v k])) rcode->name))

(def ^:private ^java.nio.charset.Charset ascii StandardCharsets/US_ASCII)




(defn- u8 ^long [^bytes ba ^long p]
  (bit-and (aget ba p) 0xff))

(defn- u16 ^long [^bytes ba ^long p]
  (bit-or (bit-shift-left (u8 ba p) 8) (u8 ba (inc p))))

(defn- u32 ^long [^bytes ba ^long p]
  (bit-or (bit-shift-left (u16 ba p) 16) (u16 ba (+ p 2))))




(defn- read-name
  "Read a possibly-compressed domain name at pos. Returns [name next-pos]
  where next-pos is the offset just past the name in the linear stream
  (past the first pointer, when compression is used)."
  [^bytes ba ^long pos]
  (loop [p pos labels [] jumped false end nil depth 0]
    (when (> depth 128)
      (throw (ex-info "compression pointer loop" {:pos pos})))
    (let [len (u8 ba p)]
      (cond
        (zero? len)
        [(str/join "." labels) (if jumped end (inc p))]

        (>= len 0xc0)
        (let [ptr (bit-or (bit-shift-left (bit-and len 0x3f) 8) (u8 ba (inc p)))]
          (if jumped
            (recur ptr labels true end (inc depth))
            (recur ptr labels true (+ p 2) (inc depth))))

        :else
        (do
          (when (> (+ p 1 len) (alength ba))
            (throw (ex-info "name overruns message" {:pos pos})))
          (recur (+ p 1 len)
                 (conj labels (String. ba (inc p) (int len) ascii))
                 jumped end (inc depth)))))))

(defn- write-name [^ByteBuffer bb ^String nm]
  (let [nm (if (or (nil? nm) (= nm ".")) "" (str/replace nm #"\.$" ""))]
    (if (str/blank? nm)
      (.put bb (byte 0))
      (do
        (doseq [label (str/split nm #"\.")]
          (let [bs (.getBytes ^String label ascii)]
            (when (or (zero? (alength bs)) (> (alength bs) 63))
              (throw (ex-info "invalid label" {:label label})))
            (.put bb (byte (alength bs)))
            (.put bb bs)))
        (.put bb (byte 0))))))




(defn- ipv4-str [^bytes ba ^long p]
  (str (u8 ba p) "." (u8 ba (inc p)) "." (u8 ba (+ p 2)) "." (u8 ba (+ p 3))))

(defn- ipv6-str [^bytes ba ^long p]
  (.getHostAddress (InetAddress/getByAddress (Arrays/copyOfRange ba p (+ p 16)))))

(defn- read-char-strings [^bytes ba ^long p ^long end]
  (loop [p p out []]
    (if (>= p end)
      out
      (let [n (u8 ba p)]
        (when (> (+ p 1 n) end)
          (throw (ex-info "character-string overruns rdata" {:pos p})))
        (recur (+ p 1 n)
               (conj out (String. ba (inc p) (int n) ascii)))))))

(defn- parse-rdata [^bytes ba ^long t ^long rdstart ^long rdlen]
  (let [end (+ rdstart rdlen)]
    (case t
      1  (ipv4-str ba rdstart)
      28 (ipv6-str ba rdstart)
      
      (2 5 12) (str/lower-case (first (read-name ba rdstart)))
      16 (read-char-strings ba rdstart end)
      15 (let [pref (u16 ba rdstart)
               [ex _] (read-name ba (+ rdstart 2))]
           {:preference pref :exchange (str/lower-case ex)})
      6  (let [[mnp p1] (read-name ba rdstart)
               [rnp p2] (read-name ba p1)]
           {:mname (str/lower-case mnp)
            :rname (str/lower-case rnp)
            :serial (u32 ba p2)
            :refresh (u32 ba (+ p2 4))
            :retry (u32 ba (+ p2 8))
            :expire (u32 ba (+ p2 12))
            :minimum (u32 ba (+ p2 16))})
      33 (let [prio (u16 ba rdstart)
               weight (u16 ba (+ rdstart 2))
               port (u16 ba (+ rdstart 4))
               [tgt _] (read-name ba (+ rdstart 6))]
           {:priority prio :weight weight :port port
            :target (str/lower-case tgt)})
      
      
      41 (let [opts (loop [p rdstart out []]
                      (if (>= p end)
                        out
                        (let [code (u16 ba p)
                              ln (u16 ba (+ p 2))]
                          (when (> (+ p 4 ln) end)
                            (throw (ex-info "EDNS option overruns rdata" {:pos p})))
                          (recur (+ p 4 ln)
                                 (conj out {:code code
                                            :data (Arrays/copyOfRange ba (+ p 4) (+ p 4 ln))})))))]
           {:options opts})
      {:raw (Arrays/copyOfRange ba rdstart end)})))

(defn- put-ipv4 [^ByteBuffer bb ^String ip]
  (let [bs (.getAddress (InetAddress/getByName ip))]
    (when (not= 4 (alength bs))
      (throw (ex-info "value is not an IPv4 address" {:value ip})))
    (.put bb bs)))

(defn- put-ipv6 [^ByteBuffer bb ^String ip]
  (let [bs (.getAddress (InetAddress/getByName ip))]
    (when (not= 16 (alength bs))
      (throw (ex-info "value is not an IPv6 address" {:value ip})))
    (.put bb bs)))

(defn- encode-rdata [^ByteBuffer bb ^long t data]
  (case t
    1  (put-ipv4 bb data)
    28 (put-ipv6 bb data)
    (2 5 12) (write-name bb data)
    16 (doseq [s data]
         (let [bs (.getBytes (str s) ascii)]
           (when (> (alength bs) 255)
             (throw (ex-info "TXT chunk longer than 255 bytes" {:chunk s})))
           (.put bb (byte (alength bs)))
           (.put bb bs)))
    15 (do
         (.putShort bb (unchecked-short (:preference data)))
         (write-name bb (:exchange data)))
    6  (do
         (write-name bb (:mname data))
         (write-name bb (:rname data))
         (.putInt bb (unchecked-int (:serial data)))
         (.putInt bb (unchecked-int (:refresh data)))
         (.putInt bb (unchecked-int (:retry data)))
         (.putInt bb (unchecked-int (:expire data)))
         (.putInt bb (unchecked-int (:minimum data))))
    33 (do
         (.putShort bb (unchecked-short (:priority data)))
         (.putShort bb (unchecked-short (:weight data)))
         (.putShort bb (unchecked-short (:port data)))
         (write-name bb (:target data)))
    41 (doseq [o (:options data)]
         (let [d ^bytes (:data o)]
           (.putShort bb (unchecked-short (:code o)))
           (.putShort bb (unchecked-short (alength d)))
           (.put bb d)))
    
    (.put bb ^bytes (:raw data))))




(defn- parse-question [^bytes ba ^long pos]
  (let [[nm np] (read-name ba pos)
        t (u16 ba np)
        c (u16 ba (+ np 2))]
    (when (> (+ np 4) (alength ba))
      (throw (ex-info "question overruns message" {:pos pos})))
    [{:name (str/lower-case nm)
      :type (code->type t t)
      :class c}
     (+ np 4)]))

(defn- parse-questions [^bytes ba ^long n ^long pos]
  (loop [i 0 pos pos out []]
    (if (>= i n)
      [out pos]
      (let [[q np] (parse-question ba pos)]
        (recur (inc i) (long np) (conj out q))))))

(defn- parse-section [^bytes ba ^long n ^long pos]
  (loop [i 0 pos pos out []]
    (if (>= i n)
      [out pos]
      (let [[rr np] (let [[nm p0] (read-name ba pos)
                          t (u16 ba p0)
                          c (u16 ba (+ p0 2))
                          ttl (u32 ba (+ p0 4))
                          rdlen (u16 ba (+ p0 8))
                          rdstart (+ p0 10)]
                      (when (> (+ rdstart rdlen) (alength ba))
                        (throw (ex-info "rdata overruns message" {:pos pos})))
                      [{:name (str/lower-case nm)
                        :type (code->type t t)
                        :class c
                        :ttl ttl
                        :data (parse-rdata ba t rdstart rdlen)}
                       (+ rdstart rdlen)])]
        (recur (inc i) (long np) (conj out rr))))))

(defn parse-message
  "Parse raw DNS message bytes into a map. Throws on malformed input."
  [^bytes ba]
  (when (< (alength ba) 12)
    (throw (ex-info "message shorter than header" {:len (alength ba)})))
  (let [flags (u16 ba 2)
        [qs p1] (parse-questions ba (u16 ba 4) 12)
        [ans p2] (parse-section ba (u16 ba 6) p1)
        [auth p3] (parse-section ba (u16 ba 8) p2)
        [addl _] (parse-section ba (u16 ba 10) p3)]
    {:id (u16 ba 0)
     :qr (boolean (bit-test flags 15))
     :opcode (bit-and (bit-shift-right flags 11) 0xf)
     :aa (boolean (bit-test flags 10))
     :tc (boolean (bit-test flags 9))
     :rd (boolean (bit-test flags 8))
     :ra (boolean (bit-test flags 7))
     :z (boolean (bit-test flags 6))
     :rcode (bit-and flags 0xf)
     :questions qs
     :answers ans
     :authority auth
     :additional addl}))

(defn- flags-int [{:keys [qr opcode aa tc rd ra z rcode]}]
  (cond-> 0
    qr (bit-or 0x8000)
    true (bit-or (bit-shift-left (bit-and (or opcode 0) 0xf) 11))
    aa (bit-or 0x0400)
    tc (bit-or 0x0200)
    rd (bit-or 0x0100)
    ra (bit-or 0x0080)
    z (bit-or 0x0040)
    true (bit-or (bit-and (or rcode 0) 0xf))))

(defn- put-rr [^ByteBuffer bb {:keys [name type class ttl data]}]
  (let [code (type->code type type)]
    (write-name bb name)
    (.putShort bb (unchecked-short code))
    (.putShort bb (unchecked-short (or class 1)))
    (.putInt bb (unchecked-int (or ttl 300)))
    (let [len-pos (.position bb)]
      (.putShort bb (unchecked-short 0))
      (let [start (.position bb)]
        (encode-rdata bb code data)
        ;; absolute putShort: (index, value)
        (.putShort bb (int len-pos)
                   (unchecked-short (- (.position bb) start)))))))

(defn encode-message
  "Serialize a message map back to wire-format bytes."
  ^bytes
  [{:keys [questions answers authority additional] :as msg}]
  (let [bb (doto (ByteBuffer/allocate 65535)
             (.order ByteOrder/BIG_ENDIAN))]
    (.putShort bb (unchecked-short (or (:id msg) 0)))
    (.putShort bb (unchecked-short (flags-int msg)))
    (.putShort bb (unchecked-short (count questions)))
    (.putShort bb (unchecked-short (count answers)))
    (.putShort bb (unchecked-short (count authority)))
    (.putShort bb (unchecked-short (count additional)))
    (doseq [q questions]
      (write-name bb (:name q))
      (.putShort bb (unchecked-short (type->code (:type q) (:type q))))
      (.putShort bb (unchecked-short (or (:class q) 1))))
    (doseq [rr answers] (put-rr bb rr))
    (doseq [rr authority] (put-rr bb rr))
    (doseq [rr additional] (put-rr bb rr))
    (let [n (.position bb)]
      (Arrays/copyOfRange (.array bb) 0 n))))

(defn encode-response
  [msg max-bytes]
  (let [limit (or max-bytes 512)
        full (encode-message msg)]
    (if (<= (alength full) limit)
      full
      (encode-message (assoc msg
                             :tc true
                             :answers []
                             :authority []
                             :additional (filterv #(= :OPT (:type %))
                                                  (:additional msg)))))))

(defn rr
  ([name type data] (rr name type 300 data))
  ([name type ttl data]
   {:name (str/lower-case (or name ""))
    :type type
    :class (if (= type :OPT) 41 1)
    :ttl ttl
    :data data}))

(defn a-rr [name ip & [ttl]] (rr name :A (or ttl 300) ip))
(defn aaaa-rr [name ip & [ttl]] (rr name :AAAA (or ttl 300) ip))
(defn cname-rr [name target & [ttl]] (rr name :CNAME (or ttl 300) target))
(defn ptr-rr [name target & [ttl]] (rr name :PTR (or ttl 300) target))
(defn txt-rr [name chunks & [ttl]]
  (rr name :TXT (or ttl 300) (if (string? chunks) [chunks] (vec chunks))))

(defn opt-rr
  "OPT pseudo-record. `udp-size` goes into the class field, flags (DO bit
  etc.) into the low 16 bits of ttl."
  ([] (opt-rr 4096))
  ([udp-size] (opt-rr udp-size 0x8000))
  ([udp-size flags]
   {:name "" :type :OPT :class (int (or udp-size 4096))
    :ttl (int (bit-and flags 0xffff))
    :data {:options []}}))

(defn make-response
  "Build a response for request `req` carrying `answers`."
  ([req answers] (make-response req answers {}))
  ([req answers {:keys [rcode ra aa authority additional tc]
                 :or {rcode 0 ra true}}]
   (-> req
       (assoc :qr true
              :rcode (or rcode 0)
              :ra (boolean ra)
              :aa (boolean aa)
              :tc (boolean tc)
              :answers (vec answers)
              :authority (vec authority)
              :additional (vec additional)))))

(defn first-question [msg] (first (:questions msg)))

(defn qname [msg] (some-> (first-question msg) :name str/lower-case))
(defn qtype [msg] (some-> (first-question msg) :type))

(defn edns-udp-size
  "Requester's advertised EDNS payload size, defaulting to 512."
  [msg]
  (->> (:additional msg)
       (filter #(= :OPT (:type %)))
       first
       :class
       (#(or % 512))
       (min 4096)))

(defn request-opt [msg]
  (->> (:additional msg) (filter #(= :OPT (:type %))) first))

(defn b64url-encode ^String [^bytes bs]
  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bs))

(defn b64url-decode ^bytes [^String s]
  (.decode (Base64/getUrlDecoder) s))
