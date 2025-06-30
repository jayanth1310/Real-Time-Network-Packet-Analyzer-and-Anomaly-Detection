import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import load_model
from scapy.all import sniff, IP
import threading
import tkinter as tk
from tkinter import scrolledtext
from queue import Queue, Empty

# Packet Analyzer Class
class PacketAnalyzerApp:
    def __init__(self, root, model, scaler, feature_columns):
        self.root = root
        self.root.title("Packet Analyzer and Anomaly Detection")
        self.sniffing = False
        self.sniff_thread = None
        self.queue = Queue()
        self.model = model
        self.scaler = scaler
        self.feature_columns = feature_columns

        self.start_button = tk.Button(root, text="Start Capturing", command=self.start_analyzing)
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Stop Capturing", command=self.stop_analyzing, state=tk.DISABLED)
        self.stop_button.pack()

        self.packet_list = scrolledtext.ScrolledText(root, width=100, height=20)
        self.packet_list.pack()

        # Start the periodic update check
        self.update_gui()

    def start_analyzing(self):
        if not self.sniffing:
            self.sniffing = True
            self.sniff_thread = threading.Thread(target=self.sniff_packets)
            self.sniff_thread.start()
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

    def stop_analyzing(self):
        if self.sniffing:
            self.sniffing = False
            self.sniff_thread.join()
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, stop_filter=lambda x: not self.sniffing, store=0)

    def packet_callback(self, packet):
        PROTOCOL_MAP = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            47: "GRE",
        }
        if packet.haslayer(IP):
            protocol_num = packet[IP].proto
            protocol_name = PROTOCOL_MAP.get(protocol_num, str(protocol_num))  # Get protocol name or use number
            packet_info = {
                'Time': packet.time,
                'Source': packet[IP].src,
                'Destination': packet[IP].dst,
                'Protocol': protocol_name,
                'Length': len(packet)
            }

            packet_df = pd.DataFrame([packet_info])
            packet_df = pd.get_dummies(packet_df)
            packet_df = packet_df.reindex(columns=self.feature_columns, fill_value=0)

            # Normalize the packet data using the loaded scaler
            packet_df_scaled = self.scaler.transform(packet_df)

            # Predict if the packet is an anomaly
            prediction = self.model.predict(packet_df_scaled)
            is_anomaly = prediction[0][0] > 0.5
            anomaly_status = 'Yes' if is_anomaly else 'No'
            self.queue.put(f"Packet: {packet_info} - Anomaly: {anomaly_status}\n")

    def update_gui(self):
        try:
            while True:
                message = self.queue.get_nowait()
                self.packet_list.insert(tk.END, message)
                self.packet_list.yview(tk.END)
        except Empty:
            pass
        self.root.after(100, self.update_gui)

# Load the model and scaler
def load_model_and_scaler():
    model = load_model('anomaly_detection_model.h5')

    # Load the scaler
    scaler = StandardScaler()
    scaler_data = np.load('scaler_data.npy', allow_pickle=True)
    scaler.fit(scaler_data)  # Fit the scaler with the same data used during training

    # Load the feature columns
    feature_columns = np.load('feature_columns.npy', allow_pickle=True)

    return model, scaler, feature_columns

# Main Code
if __name__ == "__main__":
    model, scaler, feature_columns = load_model_and_scaler()  # Load model, scaler, and feature columns

    root = tk.Tk()
    app = PacketAnalyzerApp(root, model, scaler, feature_columns)
    root.mainloop()
