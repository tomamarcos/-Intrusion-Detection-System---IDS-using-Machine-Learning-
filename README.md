Network Intrusion Detection System (NIDS) using Machine Learning
Project Overview
A real-time network intrusion detection system that captures network traffic, extracts flow-based features, and employs multiple machine learning models to detect malicious activities. The system combines anomaly detection and attack-specific models to provide comprehensive threat detection with a live monitoring dashboard.

Key Features
1. Real-Time Packet Capture
Continuous network traffic monitoring using Scapy
Configurable capture interface and duration
Automatic packet filtering to remove unwanted traffic (ARP, mDNS, IPv6 router solicitations)
PCAP file storage for historical analysis


2. Dual-Model Detection System
Anomaly Detection Models
Isolation Forest: Identifies outliers in traffic patterns

Local Outlier Factor (LOF): Detects local anomalies based on density

Attack Detection Models
Multiple ensemble models for specific attack classification

Majority voting mechanism for final decision



3. Live Web Dashboard
Real-time visualization using Flask:

Alert Table: Displays recent detections with timestamps, IP addresses, and verdicts

Pie Chart: Visual breakdown of NORMAL vs ATTACK vs POSSIBLE_ATTACK

Timeline Chart: Attack frequency over last 10 minutes

Clear Alerts Button: Reset dashboard data

Technical Architecture
text
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Packet Capture │     │ Feature          │    │ ML Model        │
│  (Scapy)        │───▶│ Extraction       │───▶│ Prediction      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Flask Dashboard│    │ Alert Generation │    │ Decision Logic  │
│  (Real-time)    │◀───│ & Storage        │◀───│ & Voting        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
Configuration Parameters
python
SAVE_PATH = r"D:\NetRadar\container"        # Output directory
INTERFACE = "Ethernet"                       # Network interface
CAPTURE_DURATION = 7                          # Capture window (seconds)
PROCESS_DELAY = 0.5                            # Processing delay
ANOMALY_MODEL_PATH = "normal_behavior_models.pkl"
ATTACK_MODEL_PATH = "ATTACK_SUBSYSTEM_BINARY.pkl"
Flow Features Extracted (84 features)
The system extracts comprehensive network flow features including:

C
Installation
Prerequisites
Python 3.7+
Npcap/WinPcap (Windows) or libpcap (Linux)
Administrator/root privileges for packet capture


Install dependencies

Place trained ML models in specified paths

Run with appropriate privileges

Usage
bash
python netradar.py
Access the dashboard at: http://127.0.0.1:5000

Model Training
The system expects pre-trained models:

Anomaly models: Pickle file containing Isolation Forest and LOF models

Attack models: Pickle file containing multiple attack classifiers

Training data should include the 84 features listed above with labeled normal/attack traffic.

Detection Logic
Packet Capture: Continuous 7-second capture windows

Flow Assembly: Group packets into bi-directional flows

Feature Extraction: Calculate 84 statistical features per flow

Port Check: Apply whitelist/blacklist rules

ML Prediction: Run features through both model subsystems

Decision Fusion: Combine predictions with voting mechanism

Alert Generation: Store and display results on dashboard

Output
PCAP Files: Raw packet captures (1.pcap, 2.pcap, ...)

CSV Files: Extracted features (1.csv, 2.csv, ...)

Live Dashboard: Real-time visualization at http://localhost:5000

Dashboard Interface
Real-time alerts table with timestamp, source/destination IP, and verdict

Pie chart showing traffic classification distribution

Timeline chart tracking attack frequency over time

Clear button to reset current session data

Use Cases
Network security monitoring

Research on ML-based intrusion detection

Educational demonstration of NIDS systems

Real-time threat detection in small networks

Implement real-time streaming processing

Add model retraining capabilities

Support for custom rule sets

Export alerts to SIEM systems

Multi-interface capture support


Acknowledgments
Uses Scapy for packet manipulation

Flask for web interface

Scikit-learn for ML models

Inspired by CICFlowMeter features
