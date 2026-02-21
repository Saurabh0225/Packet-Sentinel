# 🛡️ Packet Sentinel – Network Traffic Analyzer

A Flask-based Network Traffic Analysis Dashboard that processes Wireshark CSV exports and detects suspicious network behavior.

---

## 🚀 Features

✅ Upload Wireshark CSV files  
✅ Executive Traffic Summary  
✅ Top Source IP Analysis  
✅ Protocol Distribution Visualization  
✅ Automated Security Alert Detection  

---

## 📊 Dashboard Capabilities

### 🔎 Executive Summary
- Total packets analyzed
- Unique source IPs
- Unique destination IPs

### 📈 Traffic Analysis
- Top 5 source IPs
- Top protocols used

### 🚨 Security Alerts
- Port Scan Detection  
- Possible DoS Detection  
- Unusual Port Activity Detection  

---

## 🧠 Detection Logic

### 🔹 Port Scan Detection
Flags an IP if it connects to more than 20 unique destination ports.

### 🔹 DoS Detection
Flags an IP if it generates more than 1000 packets.

### 🔹 Unusual Port Detection
Alerts if traffic is detected on non-standard ports (not 80, 443, 53, 22).

---

## 🛠️ Tech Stack

- Python
- Flask
- Pandas
- Chart.js
- HTML / CSS
- Git & GitHub

---

## 📂 Project Structure
