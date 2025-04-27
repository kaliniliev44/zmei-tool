# PySOC Toolkit

## Description
**PySOC Toolkit** is a modular, Python-based cybersecurity toolset designed to assist with fundamental security operations center (SOC) tasks. The project aims to provide entry-level SOC analysts and cybersecurity enthusiasts with a lightweight, easy-to-use, and educational security toolkit that runs natively on Linux systems (Ubuntu 24.04+).

The toolkit includes multiple independent modules, each performing a specific security function — from network port scanning to log analysis, real-time packet sniffing, intrusion detection, vulnerability scanning, and domain reputation checking.

## 🎯 Project Goals
- Develop hands-on skills in Python scripting for cybersecurity applications.
- Reinforce knowledge of networking, log analysis, and system monitoring.
- Create a practical and modular toolkit resembling real-world SOC workflows.
- Gain experience integrating external APIs and multi-threaded network tools.

## 🔧 Features / Modules

### 1. Port Scanner
- Scans a target host for open TCP ports within a specified range using Python sockets and multi-threading.

### 2. Log File Analyzer
- Parses Linux system logs (e.g., `/var/log/auth.log`) to detect failed login attempts, sudo escalations, and other security events.

### 3. Network Packet Sniffer
- Captures and analyzes live network traffic using Python libraries like `scapy` or `pyshark`, identifying traffic by protocol and flagging anomalies.

### 4. Simple Intrusion Detection System (IDS)
- Monitors system logs and/or network traffic in real-time to detect suspicious patterns, such as multiple failed login attempts or unauthorized access.

### 5. Vulnerability Scanner
- Performs basic vulnerability assessments by scanning open ports, grabbing service banners, and identifying potentially risky services.

### 6. Domain Reputation Checker
- Queries online threat intelligence APIs (such as AbuseIPDB or VirusTotal) to assess the reputation of IP addresses or domains.

## 📦 Technologies Used
- Python 3
- `socket`, `threading`, `argparse`
- `scapy` / `pyshark`
- `requests`
- Linux log files (`/var/log/`)
- Threat intelligence APIs (planned: AbuseIPDB, VirusTotal)

## 📌 Target Users
- Entry-level SOC Analysts
- Cybersecurity students
- Ethical hacking enthusiasts
- Anyone preparing for Security+ / CEH / junior security roles

## 📈 Future Plans
- Add web-based FastAPI dashboard for module management.
- Implement JSON and CSV reporting.
- Integrate real-time alerting via Telegram or Email.
- Package modules into installable command-line utilities.

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/PySOC-Toolkit.git
