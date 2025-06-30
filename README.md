# 🛡️ Real-Time Network Packet Analyzer with Anomaly Detection (GUI-based)
real-time network packet analyzer to capture, inspect, and classify network traffic using deep packet inspection techniques.


## 📌 Overview

This project is a real-time network packet analyzer and anomaly detection system built with **Python**, **Tkinter**, and **Scapy**, and powered by a **pre-trained machine learning model** (e.g., deep learning using Keras). It provides a GUI for live packet capture, protocol analysis, and anomaly detection using a trained neural network model. A **feature scaler** and **feature vector template** ensure consistency between real-time data and the model's training data.

---

## 🚀 Features

- 📡 Real-time packet sniffing using **Scapy**
- 🔍 Protocol analysis (TCP, UDP, ICMP, GRE, etc.)
- 🧠 Anomaly detection using a pre-trained **Keras model**
- 🧮 Feature normalization with `StandardScaler`
- 📋 Live logging of packets and anomaly results in a **Tkinter-based GUI**
- 📊 One-click start/stop for packet analysis

---

## 🛠️ Tech Stack

- **Frontend:** Tkinter (Python GUI)
- **Packet Capture:** Scapy
- **Machine Learning:** TensorFlow / Keras
- **Data Preprocessing:** Pandas, NumPy, Scikit-learn
- **Other:** Threading, Queue for safe GUI updates

---

## 📦 Setup & Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/packet-analyzer-ai.git
cd packet-analyzer-ai
