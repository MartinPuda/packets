(defproject packets "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.12.0-alpha3"]
                 [org.pcap4j/pcap4j-core "2.0.0-alpha.6"]
                 [cljfx "1.7.23"]
                 [io.github.cljfx/dev "1.0.36"]]
  :main ^:skip-aot packets.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all
                       :jvm-opts ["-Dclojure.compiler.direct-linking=true"]}})
