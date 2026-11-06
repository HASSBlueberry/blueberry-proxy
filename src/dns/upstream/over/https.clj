(ns dns.upstream.over.https
  "DNS-over-HTTPS upstream client (RFC 8484 POST) on java.net.http."
  (:import [java.net URI]
           [java.net.http HttpClient HttpClient$Redirect HttpRequest
            HttpRequest$BodyPublishers HttpResponse HttpResponse$BodyHandlers]
           [java.time Duration]))

(def ^:private client
  (delay
    (-> (HttpClient/newBuilder)
        (.connectTimeout (Duration/ofSeconds 5))
        (.followRedirects HttpClient$Redirect/NORMAL)
        (.build))))

(defn query
  "POST raw DNS message bytes to a DoH URL (host must be a full https URL),
  return response bytes."
  [{:keys [host timeout] :or {timeout 5000}} ^bytes msg]
  (let [req (-> (HttpRequest/newBuilder (URI/create host))
                (.timeout (Duration/ofMillis (long timeout)))
                (.header "content-type" "application/dns-message")
                (.header "accept" "application/dns-message")
                (.header "user-agent" "blueberryProxy/0.1")
                (.POST (HttpRequest$BodyPublishers/ofByteArray msg))
                (.build))
        ^HttpResponse resp (.send ^HttpClient @client req
                                  (HttpResponse$BodyHandlers/ofByteArray))]
    (when-not (= 200 (.statusCode resp))
      (throw (ex-info "doh upstream status" {:status (.statusCode resp)
                                             :host host})))
    (.body resp)))
