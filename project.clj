(defproject blueberryProxy "0.3.0-SNAPSHOT"
  :description "Home network DNS and HTTP proxy with reverse DNS, refreshable
                blocklists, GraalJS transforms, LAN discovery and Home
                Assistant add-on packaging."
  :url "https://git.crit.rip/BlueberryFaygo/blueberryProxy"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.12.2"]
                 [org.clojure/data.json "2.5.1"]
                 [org.graalvm.polyglot/polyglot "25.3.4.1"]
                 [org.graalvm.polyglot/js "25.3.4.1" :extension "pom"]]
  :test-selectors {:default (complement :integration)
                   :integration :integration
                   :all (constantly true)}
  :main ^:skip-aot blueberryProxy
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all
                       :jvm-opts ["-Dclojure.compiler.direct-linking=true"]}})
