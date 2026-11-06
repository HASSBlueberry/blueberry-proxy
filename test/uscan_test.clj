(ns uscan-test
  (:require [clojure.test :refer :all]
            [storage.storage :as storage]
            [dns.dnsPrims :as dns]
            [uscan.scope :as scope]
            [uscan.protocols :as protocols]
            [uscan.scripts :as scripts]
            [uscan.core :as uscan])
  (:import [java.nio.file Files]
           [java.util.concurrent Executors]))

(defn store []
  (storage/open (str (Files/createTempDirectory "blueberry-uscan-" (make-array java.nio.file.attribute.FileAttribute 0)) "/state.edn")))

(deftest explicit-scope-and-port-budgets
  (let [params (scope/parameters {:cidrs ["192.168.1.0/30"] :ports [80 "8000-8002"]})]
    (is (= ["192.168.1.1" "192.168.1.2"] (:targets params)))
    (is (= [80 8000 8001 8002] (:ports params)))
    (is (scope/contains-ip? (:networks params) "192.168.1.2"))
    (is (not (scope/contains-ip? (:networks params) "192.168.2.2"))))
  (is (= ["10.0.0.0" "10.0.0.1"] (:targets (scope/parameters {:cidrs ["10.0.0.0/31"]}))))
  (is (= ["10.0.0.4"] (:targets (scope/parameters {:cidrs ["10.0.0.4/32"]}))))
  (doseq [params [{:cidrs ["10.0.0.0/16"]} {:cidrs ["not-a-network"]} {:cidrs ["10.0.0.0/33"]}
                  {:cidrs ["10.0.0.1/32"] :ports ["1-65535"]} {:cidrs ["10.0.0.1/32"] :workers 1000}]]
    (is (thrown? Exception (scope/parameters params)))))

(deftest discovery-merges-real-mac-and-emits-changes
  (let [events (atom [])
        runtime {:devices (atom {}) :jobs (atom {"job" {:discoveries 0}}) :publish #(swap! events conj %)}
        params (scope/parameters {:cidrs ["192.168.1.0/24"]})
        scanner {:id "arp" :kind "arp"}
        record {:ip "192.168.1.4" :mac "AA-BB-CC-DD-EE-FF" :evidence "arp"}]
    (uscan/emit! runtime "job" scanner params record)
    (uscan/emit! runtime "job" scanner params record)
    (is (= 1 (count @events)))
    (is (= "aa:bb:cc:dd:ee:ff" (:mac (first @events))))
    (is (:new_device (first @events)))
    (uscan/emit! runtime "job" {:id "web" :kind "tcp"} params {:ip "192.168.1.4" :ports [80] :evidence "tcp-open"})
    (is (= 2 (count @events)))
    (is (= [80] (get-in @(:devices runtime) ["192.168.1.4" :ports])))
    (is (thrown? Exception (uscan/emit! runtime "job" scanner params {:ip "192.168.2.5"})))
    (is (= 1 (count @(:devices runtime))))))

(deftest discovery-protocol-parsers
  (let [message {:id 0 :qr true :answers [(dns/a-rr "camera.local" "192.168.1.4")
                                         (dns/rr "cam._http._tcp.local" :SRV {:priority 0 :weight 0 :port 8080 :target "camera.local"})]}
        parsed (dns/parse-message (dns/encode-message message))
        records (protocols/mdns-records parsed "192.168.1.4")]
    (is (some #(= [8080] (:ports %)) records))
    (is (some #(= "camera.local" (:hostname %)) records)))
  (let [xml "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:d='http://schemas.xmlsoap.org/ws/2005/04/discovery'><s:Body><d:ProbeMatches><d:ProbeMatch><d:Types>tds:Device</d:Types><d:XAddrs>http://192.168.1.5/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"
        record (protocols/parse-wsd (.getBytes xml "UTF-8") "192.168.1.5")]
    (is (= ["tds:Device"] (:services record)))
    (is (= ["http://192.168.1.5/onvif/device_service"] (:endpoints record))))
  (is (thrown? Exception (protocols/parse-wsd (.getBytes "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>" "UTF-8") "192.168.1.5")))
  (is (= [{:ip "192.168.1.4" :interface "eth0" :hostname "cam.local" :services ["Cam._http._tcp.local"] :ports [80] :evidence "avahi"}]
         (protocols/parse-avahi "=;eth0;IPv4;Cam;_http._tcp;local;cam.local;192.168.1.4;80;txt"))))

(deftest graal-scanners-use-only-scoped-capabilities
  (let [params (scope/parameters {:cidrs ["192.168.1.4/32"] :ports [80]})
        timer (Executors/newScheduledThreadPool 1)
        records (atom []) calls (atom [])]
    (try
      (with-redefs [protocols/tcp-probe (fn [ip port timeout] (swap! calls conj [ip port timeout]) true)]
        (scripts/run! "function scan(ctx) { if (typeof Java !== 'undefined') { let denied = false; try { Java.type('java.lang.Runtime'); } catch(e) { denied = true; } if (!denied) throw new Error('Java host access was enabled'); } for (const ip of ctx.targets) if (ctx.tcp(ip,80)) ctx.emit({ip,ports:[80]}); }"
                      params #(swap! records conj %) (fn []) timer)
        (is (= [["192.168.1.4" 80 300]] @calls))
        (is (= [{:ip "192.168.1.4" :ports [80]}] @records))
        (is (thrown? Exception (scripts/run! "function scan(ctx) { ctx.tcp('192.168.2.4', 80); }" params (fn [_]) (fn []) timer)))
        (is (= 1 (count @calls))))
      (finally (.shutdownNow timer)))))

(deftest graal-scanner-deadline-cancels-infinite-loop
  (let [timer (Executors/newScheduledThreadPool 1)
        deadline (+ (System/currentTimeMillis) 1000)
        check! (fn [] (when (> (System/currentTimeMillis) deadline) (throw (ex-info "deadline" {}))))]
    (try
      (is (thrown? Exception (scripts/run! "function scan(ctx) { while(true) {} }" (scope/parameters {:cidrs ["192.168.1.4/32"]}) (fn [_]) check! timer)))
      (is (< (System/currentTimeMillis) (+ deadline 5000)))
      (finally (.shutdownNow timer)))))

(deftest registered-jobs-are-asynchronous-and-persisted
  (let [s (store) events (atom []) runtime (uscan/start s #(swap! events conj %))]
    (try
      (uscan/register! runtime {:id "custom" :kind "tcp" :parameters {:cidrs ["192.168.1.4/32"] :ports [80]}})
      (is (some #(= "custom" (:id %)) (storage/list-uscan-scanners (storage/open (:storage.storage/path (meta @s))))))
      (with-redefs [protocols/run! (fn [_ _ emit _] (emit {:ip "192.168.1.4" :ports [80]}))
                    protocols/arp-records (fn [] [{:ip "192.168.1.4" :mac "aa:bb:cc:dd:ee:ff" :evidence "arp"}])]
        (let [job (uscan/start-job! runtime {:scanner_ids ["custom"]})
              deadline (+ (System/currentTimeMillis) 3000)]
          (loop [] (when (and (contains? #{"queued" "running"} (:status (uscan/job runtime (:id job)))) (< (System/currentTimeMillis) deadline)) (Thread/sleep 10) (recur)))
          (is (= "complete" (:status (uscan/job runtime (:id job)))))
          (is (= "aa:bb:cc:dd:ee:ff" (get-in @(:devices runtime) ["192.168.1.4" :mac])))
          (is (some #(= "discovery" (:type %)) @events))))
      (finally ((:stop runtime))))))

(deftest script-port-emission-and-probe-budgets-are-enforced
  (let [params (scope/parameters {:cidrs ["192.168.1.4/32"] :ports [80] :max_probes 2})
        timer (Executors/newScheduledThreadPool 1)
        calls (atom 0)]
    (try
      (with-redefs [protocols/tcp-probe (fn [& _] (swap! calls inc) false)]
        (is (thrown? Exception (scripts/run! "function scan(ctx){ctx.tcp('192.168.1.4',81);}" params (fn [_]) (fn []) timer)))
        (is (zero? @calls))
        (is (thrown? Exception (scripts/run! "function scan(ctx){ctx.emit({ip:'192.168.2.4'});}" params (fn [_]) (fn []) timer)))
        (is (thrown? Exception (scripts/run! "function scan(ctx){for(let i=0;i<3;i++)ctx.tcp('192.168.1.4',80);}" params (fn [_]) (fn []) timer)))
        (is (= 2 @calls)))
      (finally (.shutdownNow timer)))))

(deftest generic-inventory-import-is-scoped-and-publishes-evidence
  (let [events (atom [])
        runtime {:devices (atom {}) :jobs (atom {}) :publish #(swap! events conj %)}]
    (is (thrown? Exception (uscan/import-devices! runtime {:source "gateway" :cidrs ["192.168.1.0/24"] :devices [{:ip "192.168.2.3"}]})))
    (is (empty? @events))
    (is (= 1 (:imported (uscan/import-devices! runtime {:source "gateway" :cidrs ["192.168.1.0/24"] :devices [{:ip "192.168.1.3" :mac "AA-BB-CC-DD-EE-FF" :hostname "light"}]}))))
    (is (= ["inventory"] (:protocols (first @events))))
    (is (= "aa:bb:cc:dd:ee:ff" (:mac (first @events))))
    (is (empty? @(:jobs runtime)))))
