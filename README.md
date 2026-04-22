# 🛡️ Intelligent Security System for DDoS Attack Detection and Mitigation using SDN

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flutter-02569B?style=for-the-badge&logo=flutter&logoColor=white"/>
  <img src="https://img.shields.io/badge/Firebase-FFCA28?style=for-the-badge&logo=firebase&logoColor=black"/>
  <img src="https://img.shields.io/badge/TensorFlow-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white"/>
  <img src="https://img.shields.io/badge/Blockchain-121D33?style=for-the-badge&logo=bitcoin&logoColor=white"/>
</p>

> 🎓 Graduation Project — B.Sc. in Information Technology  
> Faculty of Computer and Information, **Kafrelsheikh University** — 2024/2025

---

## 📖 Abstract

Smart home environments face growing cybersecurity threats, particularly **Distributed Denial of Service (DDoS)** attacks targeting resource-constrained IoT devices. This project proposes a comprehensive, multi-layered security framework that leverages **Software-Defined Networking (SDN)** for centralized control, real-time monitoring, and dynamic policy enforcement.

The system integrates:
- **Threat Intelligence** for proactive attack detection
- **Deep Learning** (RNN & LSTM) for behavioral anomaly analysis
- **Blockchain** for decentralized authentication, data integrity, and tamper-proof event logging
- **Mobile Application** (Flutter) for real-time alerts and remote control

Results confirm that this hybrid architecture enhances protection against modern attack vectors while preserving privacy and availability.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔍 **DDoS Detection** | Real-time identification of DDoS and SYN Flood attacks using deep learning |
| ⚙️ **SDN Control** | Centralized network management via Ryu Controller + Mininet emulation |
| 🧠 **Deep Learning** | RNN & LSTM models for behavioral anomaly detection |
| 🔗 **Blockchain Security** | Decentralized authentication, smart contracts, and audit logging |
| 📱 **Mobile App** | Flutter app with Firebase backend for real-time alerts and remote control |
| 🔒 **Encryption** | Secure IoT device communication using MQTT with encryption |
| 🛡️ **Rate Limiting** | Automated countermeasures including rate limiting and flow isolation |

---

## 🏗️ System Architecture

The system is built on three integrated layers:

```
┌─────────────────────────────────────────┐
│          Mobile Application (Flutter)    │  ← User Interface & Real-time Alerts
├─────────────────────────────────────────┤
│    SDN Control Layer (Ryu Controller)    │  ← Policy Enforcement & Monitoring
│    + Deep Learning (RNN / LSTM)          │
│    + Blockchain Authentication           │
├─────────────────────────────────────────┤
│   Infrastructure Layer (Mininet / IoT)   │  ← Smart Home Devices & Network
└─────────────────────────────────────────┘
```

**Communication:** Devices communicate via **MQTT** with encryption. The SDN controller dynamically enforces security policies, while all events are logged immutably to the Blockchain. Real-time alerts are pushed to the Flutter mobile app via **Firebase**.

---

## 🛠️ Technologies Used

### Networking & Security
- **SDN (Software-Defined Networking)** — Separates control and data planes for dynamic management
- **Ryu SDN Controller** — Python-based controller for flow management and attack mitigation
- **Mininet** — Network emulation for testing and simulation
- **MQTT** — Lightweight IoT messaging protocol with encryption

### Machine Learning & AI
- **Deep Learning (RNN / LSTM)** — Sequence-based anomaly detection for network traffic
- **Threat Intelligence** — Proactive attack pattern identification
- **Feature Extraction** — Traffic-based feature engineering for anomaly detection

### Security & Blockchain
- **Blockchain** — Tamper-proof event logging, decentralized authentication, smart contracts
- **SYN Proxy** — Defense mechanism against SYN Flood attacks
- **Encryption Algorithms** — Securing IoT device communication

### Mobile & Backend
- **Flutter** — Cross-platform mobile application
- **Firebase (Firestore)** — Real-time database and cloud backend
- **Firebase Authentication** — Secure user access

---

## 📁 Project Structure

```
├── sdn/
│   ├── ryu_controller/        # Ryu SDN controller scripts
│   ├── mininet_topology/      # Mininet network topology definitions
│   └── rate_limiting/         # DDoS mitigation and rate limiting rules
├── ml_models/
│   ├── rnn_model/             # Recurrent Neural Network model
│   ├── lstm_model/            # LSTM anomaly detection model
│   └── feature_extraction/    # Traffic feature engineering
├── blockchain/
│   ├── smart_contracts/       # Smart contracts for authentication
│   └── event_logging/         # Tamper-proof audit logging
├── mobile_app/
│   ├── lib/                   # Flutter application source code
│   ├── android/               # Android build files
│   └── ios/                   # iOS build files
├── mqtt/
│   └── broker_config/         # MQTT broker and encryption config
└── docs/
    └── Final_Project_2025.pdf # Full project report
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Mininet
- Ryu SDN Framework
- Flutter SDK
- Firebase project

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/intelligent-ddos-sdn.git
cd intelligent-ddos-sdn

# Install Python dependencies
pip install -r requirements.txt

# Install Ryu
pip install ryu

# Set up Mininet (Linux only)
sudo apt-get install mininet
```

### Running the SDN Controller

```bash
# Start Ryu controller with DDoS mitigation app
ryu-manager sdn/ryu_controller/ddos_mitigation.py

# In a new terminal, start the Mininet topology
sudo python3 sdn/mininet_topology/smart_home_topo.py
```

### Running the ML Detection Model

```bash
# Train the LSTM model
python3 ml_models/lstm_model/train.py

# Run inference / real-time detection
python3 ml_models/lstm_model/detect.py
```

### Running the Mobile App

```bash
cd mobile_app
flutter pub get
flutter run
```

---

## 📊 Results & Evaluation

| Metric | Result |
|---|---|
| Attack Detection Accuracy | Evaluated across multiple ML models |
| Rate Limiting Effectiveness | Tested against DDoS traffic simulations |
| SYN Proxy Defense | Validated against SYN Flood attacks |
| Blockchain Integrity | Verified tamper-proof logging |
| Mobile App Performance | Optimized with Flutter profiling tools |

> Full experimental results, screenshots, and comparison charts are available in [Chapter 6 of the project report](docs/Final_Project_2025.pdf).

---

## 👥 Team

| Name |
|---|
| Ahmed Abdelmohsen Abouzeid |
| Ahmed Ibrahim Elkasass |
| Bassma Mohamed Abdelaziz |
| Sabah Salah Elharoon |
| Shahd Mohamed Elshazly |
| Mariam Hosny Abdelfatah |
| Menna-Allah Essam Aboelhasan |

---

## 🎓 Supervision

- **Assoc. Prof. Dr. Mai Ramadan** — Project Supervisor, Head of IT Department
- **Eng. Hadeel Farag** — Project Coordinator

---

## 🏫 Institution

**Faculty of Computer and Information Sciences**  
Kafrelsheikh University — Department of Information Technology  
Academic Year: 2024–2025

---

## 📄 License

This project was developed as an academic graduation project at Kafrelsheikh University. All rights reserved © 2025.

---

## 🙏 Acknowledgements

We would like to express our heartfelt gratitude to **Prof. Dr. Mai Ramadan** for her patience, unwavering guidance, and continuous support throughout the semester. Special thanks to **Eng. Hadeel Farag** for her consistent follow-up and constructive feedback. We also thank everyone who supported and encouraged us throughout this journey.
