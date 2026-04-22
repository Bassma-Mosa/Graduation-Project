# 🛡️ Intelligent SDN-Based DDoS Detection & Mitigation System

🎓 Graduation Project — B.Sc. in Information Technology
Faculty of Computer and Information, Kafrelsheikh University — 2024/2025

---

## 🚀 Overview

A real-time cybersecurity system designed to detect and mitigate DDoS attacks in smart home and IoT environments using Software-Defined Networking (SDN), Deep Learning, and Blockchain.

The system combines centralized network control with intelligent traffic analysis to automatically identify malicious behavior and respond instantly.

---

## ⚠️ Problem Statement

Smart home and IoT environments are highly vulnerable to DDoS attacks due to:

* Limited device resources
* Lack of centralized security control
* Increasing exposure to internet-based threats

---

## 💡 Solution

This project introduces a multi-layered defense system that:

* Monitors network traffic in real-time using SDN
* Detects anomalies using Deep Learning (RNN / LSTM)
* Automatically mitigates attacks via flow control and rate limiting
* Sends real-time alerts to users and administrators
* Logs security events securely using Blockchain

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────┐
│       Mobile Application (Flutter)       │
│    Real-time Alerts & User Interface     │
├─────────────────────────────────────────┤
│ SDN Controller (Ryu) + Detection Engine  │
│  - Deep Learning (RNN / LSTM)            │
│  - Threat Intelligence                  │
│  - Blockchain Integration               │
├─────────────────────────────────────────┤
│  Infrastructure Layer (Mininet / IoT)   │
│   Smart Devices & Network Simulation     │
└─────────────────────────────────────────┘
```

---

## 🔄 System Workflow

Traffic → SDN Controller → Feature Extraction → ML Model → Detection → Mitigation → Alerts → Blockchain Logging

---

## ✨ Key Features

* 🔍 Real-time DDoS & SYN Flood detection
* ⚙️ SDN-based centralized traffic control (Ryu + Mininet)
* 🧠 Deep Learning models (RNN / LSTM) for anomaly detection
* 🛡️ Automated mitigation (Rate Limiting & Flow Rules)
* 📱 Mobile App (Flutter + Firebase) for live alerts
* 💬 Discord alerts for security administrators
* 🔗 Blockchain for tamper-proof logging and authentication
* 🔒 Secure communication via MQTT with encryption

---

## 🛠️ Tech Stack

### 🔐 Networking & Security

* SDN (Software-Defined Networking)
* Ryu Controller
* Mininet
* MQTT (Encrypted Communication)

### 🧠 AI & Detection

* Deep Learning (RNN / LSTM)
* Feature Engineering & Traffic Analysis
* Threat Intelligence Integration

### 🔗 Blockchain

* Smart Contracts
* Event Logging (Tamper-proof)
* Web3 Integration

### 📱 Application Layer

* Flutter Mobile App
* Firebase (Firestore + Authentication)
* Discord Webhooks

---

## 📁 Project Structure

```
├── sdn/
├── ml_models/
├── blockchain/
├── mobile_app/
├── mqtt/
└── docs/
```

---

## 🎥 Demo

👉 Watch the system in action:

* Attack simulation
* Real-time detection
* Automated mitigation
* Mobile + Discord alerts

[Add Video Link Here]

---

## ⚙️ How to Run

```bash
# Clone repository
git clone https://github.com/Bassma-Mosa/Graduation-Project.git
cd Graduation-Project

# Install dependencies
pip install -r requirements.txt

# Run SDN controller
ryu-manager sdn/ryu_controller/ddos_mitigation.py

# Start Mininet topology
sudo python3 sdn/mininet_topology/smart_home_topo.py
```

---

## 📊 Results

* High detection accuracy using deep learning models
* Real-time mitigation using SDN flow control
* Effective defense against SYN Flood and DDoS attacks
* Secure and immutable logging using Blockchain

---

## 🎯 Project Impact

This project demonstrates practical experience in:

* Cybersecurity (DDoS Detection & Mitigation)
* SDN Network Control
* AI in Security Systems
* Real-time System Design
* Secure System Architecture


