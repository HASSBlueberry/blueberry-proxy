(ns xform.tls
  "TLS context loading and optional local self-signed PKCS12 generation."
  (:require [clojure.string :as str])
  (:import [java.io FileInputStream]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files Path Paths StandardOpenOption]
           [java.security KeyStore SecureRandom]
           [javax.net.ssl SSLContext KeyManagerFactory]))

(defn- random-password []
  (let [bytes (byte-array 24)]
    (.nextBytes (SecureRandom.) bytes)
    (-> (java.util.Base64/getUrlEncoder) (.withoutPadding) (.encodeToString bytes))))

(defn- load-or-create-password [^Path path configured]
  (if (seq configured)
    configured
    (let [password-path (.toAbsolutePath (Paths/get (str path ".password") (make-array String 0)))]
      (if (Files/exists password-path (make-array java.nio.file.LinkOption 0))
        (str/trim (slurp (.toFile password-path)))
        (let [password (random-password)]
          (Files/createDirectories (.getParent password-path) (make-array java.nio.file.attribute.FileAttribute 0))
          (Files/write password-path (.getBytes password StandardCharsets/UTF_8)
                       (into-array StandardOpenOption [StandardOpenOption/CREATE_NEW StandardOpenOption/WRITE]))
          (try
            (Files/setPosixFilePermissions password-path
              (java.nio.file.attribute.PosixFilePermissions/fromString "rw-------"))
            (catch UnsupportedOperationException _ nil))
          password)))))

(defn- generate-keystore! [^Path path password {:keys [common-name sans]
                                                :or {common-name "blueberryProxy" sans []}}]
  (when-let [parent (.getParent path)]
    (Files/createDirectories parent (make-array java.nio.file.attribute.FileAttribute 0)))
  (let [java-home (System/getProperty "java.home")
        keytool (str java-home java.io.File/separator "bin" java.io.File/separator "keytool")
        san-values (distinct (concat ["DNS:localhost" "IP:127.0.0.1"]
                                    (map (fn [entry]
                                           (let [value (str entry)]
                                             (if (str/includes? value ":")
                                               (str "IP:" value)
                                               (str "DNS:" value)))) sans)))
        args (into-array String
               [keytool "-genkeypair" "-alias" "blueberryProxy"
                "-keyalg" "RSA" "-keysize" "2048" "-validity" "3650"
                "-dname" (str "CN=" common-name)
                "-ext" (str "SAN=" (str/join "," san-values))
                "-storetype" "PKCS12" "-keystore" (str path)
                "-storepass" password "-keypass" password "-noprompt"])
        process (.start (ProcessBuilder. args))
        finished (.waitFor process 30 java.util.concurrent.TimeUnit/SECONDS)]
    (when-not finished
      (.destroyForcibly process)
      (throw (ex-info "keytool timed out while creating a TLS certificate" {:keystore (str path)})))
    (when-not (zero? (.exitValue process))
      (let [error (slurp (.getErrorStream process))]
        (throw (ex-info "keytool could not create a TLS certificate"
                        {:keystore (str path) :error error}))))
    (try
      (Files/setPosixFilePermissions path
        (java.nio.file.attribute.PosixFilePermissions/fromString "rw-------"))
      (catch UnsupportedOperationException _ nil))
    path))

(defn ssl-context
  "Load a PKCS12 keystore or generate one when `self-signed?` is true.
  Returns an initialized javax.net.ssl.SSLContext."
  [{:keys [keystore password self-signed? common-name sans]}]
  (when-not keystore
    (throw (ex-info "TLS listener requires a PKCS12 keystore" {})))
  (let [path (.toAbsolutePath (Paths/get (str keystore) (make-array String 0)))
        password (load-or-create-password path password)]
    (when (and self-signed? (not (Files/exists path (make-array java.nio.file.LinkOption 0))))
      (generate-keystore! path password {:common-name common-name :sans sans}))
    (when-not (Files/exists path (make-array java.nio.file.LinkOption 0))
      (throw (ex-info "TLS keystore does not exist" {:keystore (str path)})))
    (let [store (KeyStore/getInstance "PKCS12")]
      (with-open [in (FileInputStream. (.toFile path))]
        (.load store in (.toCharArray ^String password)))
      (let [factory (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))]
        (.init factory store (.toCharArray ^String password))
        (doto (SSLContext/getInstance "TLS")
          (.init (.getKeyManagers factory) nil (SecureRandom.)))))))
