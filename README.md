# Intelligent Security System for DDoS Attack Detection and Mitigation using SDN
- Designed Android app and SDN-based controller with Ryu.
- Integrated AI model for DDoS detection.
- Integrated DL model for predict new DDoS attacks.
- Used Threat Intelligence to check IP is known attacker or not.
- Used Blockchain to record attacks in system.
- Used Rate Limit to reduce number of requests.
- Used SYN Role to reduce number of Packets and secure server from drop.
- Integrated with Discord server for send alerts.

## Overview
This project is a real-time cybersecurity defense system designed to detect and mitigate DDoS attacks in Software Defined Networking (SDN) environments.
It integrates Machine Learning, Deep Learning, Blockchain logging, and multi-channel alerting.

## Problem Statement
Modern IoT and smart home networks are highly vulnerable to DDoS attacks due to centralized control and limited resource protection mechanisms.


## Objectives
- Detect DDoS attacks in real-time SDN traffic
- Classify normal vs malicious traffic using ML/DL models
- Apply mitigation techniques (rate limiting, flow control)
- Log security policies using blockchain for integrity
- Send alerts to the mobile app and Discord server

## How It Works
1. SDN Controller captures network flows
2. Traffic is analyzed in real-time
3. ML/DL model classifies traffic (Normal / DDoS)
4. If attack detected:
   - Rate limiting is applied
   - Flow rules are updated in switch
5. Alerts are sent to:
   - Mobile application (Flutter)
   - Discord server for administrators
6. Security logs are stored on blockchain for integrity

## Technologies Used
- Python (Ryu SDN Controller)
- Machine Learning / Deep Learning
- Flutter (Mobile App)
- Web3.py (Blockchain Integration)
- Solidity (Smart Contracts)
- Mininet (Network Simulation)
- Discord Webhooks (Alert System)


## Features
- Real-time DDoS detection
- Automated mitigation (Rate Limiting)
- AI-based traffic classification
- Mobile notifications (Flutter app)
- Discord security alerts
- Blockchain-based audit logging

## Results
- Achieved high detection accuracy (~XX%)
- Reduced attack impact latency by XX%
- Real-time response within milliseconds
- Successfully mitigated simulated DDoS attacks in SDN environment

## Demo
Watch the full system demonstration:
[Click here to view demo](https://your-video-link.com)
  
 

