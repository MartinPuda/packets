(ns packets.core
  (:require
    [cljfx.api :as fx]
    [cljfx.dev :as d]
    [clojure.string :as str])
  (:import
    (org.pcap4j.core Pcaps PcapNetworkInterface$PromiscuousMode PacketListener PcapPacket)
    (org.pcap4j.packet Packet)
    (java.time.format DateTimeFormatter)
    (java.time ZoneId)
    (javafx.scene Cursor))
  (:gen-class))
;(d/help-ui)

(defn timestamp [packet]
  (.format (-> (DateTimeFormatter/ofPattern "HH:mm:ss dd.MM.yyyy")
               (.withZone (ZoneId/systemDefault)))
           (.getTimestamp packet)))

(defn ints->port [int-seq]
  (-> (map #(Integer/toHexString %) int-seq)
      str/join
      (Integer/parseInt 16)))

(defn format-ip [int-seq]
  (str/join "." int-seq))

(defn source [raw-ints]
  (->> (subvec raw-ints 26 30)
       format-ip))

(defn source-port [raw-ints]
  (->> (subvec raw-ints 34 36)
       ints->port))

(defn destination [raw-ints]
  (->> (subvec raw-ints 30 34)
       format-ip))

(defn destination-port [raw-ints]
  (->> (subvec raw-ints 36 38)
       ints->port))

(defn protocol [raw-ints]
  (raw-ints 23))

(defn length [packet]
  (.length packet))

(defn info [raw-ints]
  "")

(defn packet->map [^PcapPacket packet]
  (let [raw-ints (->> (.getRawData packet)
                      (mapv #(bit-and % 0xff)))]
    (merge (zipmap [:source :source-port :destination :destination-port :protocol :info]
                   ((juxt source source-port destination destination-port protocol info)
                    raw-ints))
           (zipmap [:timestamp :length]
                   ((juxt timestamp length)
                    packet)))))

(def *state
  (atom {:device     nil
         :timeout    0
         :packet-log []}))

(defn capture-packets [event]
  (let [{:keys [device timeout]} @*state
        scene-root (-> event
                       .getSource
                       .getScene
                       .getRoot)]
    (when device
      (.setCursor scene-root
                  Cursor/WAIT)
      (swap! *state assoc :packet-log [])
      (let [snapshot-length 65536
            handle (.openLive device
                              snapshot-length
                              PcapNetworkInterface$PromiscuousMode/PROMISCUOUS
                              timeout)
            ^PacketListener listener (proxy [PacketListener] []
                                       (gotPacket [^Packet packet]
                                         (swap! *state update :packet-log conj (packet->map packet))))]
        (try (let [max-packets 50]
               (.loop handle max-packets listener))
             (catch InterruptedException e (.printStackTrace e)))
        (.close handle)
        (.setCursor scene-root
                    Cursor/DEFAULT)))))

(defn devices [state]
  {:fx/type                  :list-view
   :max-height               200
   :on-selected-item-changed (fn [event]
                               (swap! *state assoc :device event))
   :cell-factory             {:fx/cell-type :list-cell
                              :describe     (fn [item] {:text (.getDescription item)})}
   :items                    (Pcaps/findAllDevs)})

(defn timeout-input [{:keys [timeout]}]
  {:fx/type          :spinner
   :editable         true
   :max-width        75
   :on-value-changed #(swap! *state assoc :timeout %)
   :value-factory    {:fx/type           :integer-spinner-value-factory
                      :amount-to-step-by 1
                      :min               0
                      :max               100
                      :value             50}})

(defn root [{:keys [timeout packet-log]}]
  {:fx/type :stage
   :showing true
   :title   "Packet Capture"
   :scene   {:fx/type :scene
             :root    {:fx/type  :h-box
                       :children [{:fx/type   :v-box
                                   :min-width 350
                                   :padding   10
                                   :spacing   10
                                   :children  [{:fx/type :label
                                                :text    "Device"}
                                               {:fx/type devices}
                                               {:fx/type  :h-box
                                                :spacing  10
                                                :children [{:fx/type :label
                                                            :text    "Read Timeout"}
                                                           {:fx/type timeout-input}]}
                                               {:fx/type   :button
                                                :on-action (fn [event] (capture-packets event))
                                                :text      "Capture Packets"}]}
                                  {:fx/type   :v-box
                                   :min-width 750
                                   :children  [{:fx/type      :scroll-pane
                                                :fit-to-width true
                                                :content      {:fx/type  :table-view
                                                               :editable false
                                                               :columns  [{:cell-value-factory :timestamp, :text "Timestamp", :fx/type :table-column}
                                                                          {:cell-value-factory :source, :text "Source", :fx/type :table-column}
                                                                          {:cell-value-factory :source-port, :text "Port", :fx/type :table-column}
                                                                          {:cell-value-factory :destination, :text "Destination", :fx/type :table-column}
                                                                          {:cell-value-factory :destination-port, :text "Port", :fx/type :table-column}
                                                                          {:cell-value-factory :protocol, :text "Protocol", :fx/type :table-column}
                                                                          {:cell-value-factory :length, :text "Length", :fx/type :table-column}
                                                                          {:cell-value-factory :info, :text "Info", :fx/type :table-column}]
                                                               :items    packet-log}}]}]}}})

(defn -main [& args]
  (swap! *state assoc :packet-log [])
  (let [renderer (fx/create-renderer
                   :middleware (fx/wrap-map-desc assoc :fx/type root))]
    (fx/mount-renderer *state renderer)))