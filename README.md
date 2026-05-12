Sniffy: Python Network Traffic Analyzer
-------------------
Sniffy is a lightweight Python network sniffer built with Scapy. It intercepts real-time traffic, analyzes IP, TCP, UDP, and ICMP protocols, and performs basic packet inspection for HTTP traffic. Designed for network diagnostics, it automatically exports all captured metadata into a structured CSV log for easy analysis.

📸 Demo
-------------------

![Sniffy in action](Screenshot.png)


🚀 Features
-------------------
Multi-Protocol Support: Deep analysis of TCP, UDP, and ICMP traffic.

Service Mapping: Automatically translates common port numbers (80, 443, 22, etc.) into service names.

Connection Tracking: Identifies TCP handshake flags like [SYN], [SYN-ACK], and [FIN].

Payload Inspection: Performs basic Deep Packet Inspection (DPI) to extract HTTP request lines (GET, POST).

Automated Logging: Saves all captured data to network_traffic_log.csv with UTF-8 encoding.

🛠️ Prerequisites
-------------------
Before running the script, ensure you have the following:

Python 3.x

Scapy Library:

Bash
pip install scapy
Network Capture Driver:

Windows: Install Npcap.

Linux/macOS: Ensure libpcap is installed (default on most systems).

💻 Usage
-------------------
Note: Accessing network interfaces requires Administrative/Root privileges.

Clone the repository:

git clone https://github.com/apachematt20/Sniffy.git
cd Sniffy

Run the sniffer (macOS/Linux):
sudo python3 Sniffy.py

Run the sniffer (Windows):
Open PowerShell as Administrator and run:

python Sniffy.py
Stop Capture: Press Ctrl + C to safely stop the sniffer and save the log.

📊 CSV Log Structure
-------------------
The script outputs to network_traffic_log.csv with the following headers:

Field	Description
Timestamp	Local time of packet arrival.
Protocol	The transport layer protocol (TCP/UDP/ICMP).
Source/Dest IP	Origin and destination addresses.
Source/Dest Port	Identified service or port number.
Action/Status	Packet intent (e.g., Connection Request, Ping).
Payload Data	Extracted snippets of raw data (e.g., HTTP headers).

⚠️ Ethical Use & Disclaimer
-------------------
This project is intended for educational and diagnostic purposes only. Intercepting network traffic that you do not own or have explicit permission to monitor is illegal. Use this tool responsibly.

📄 License
-------------------
This project is licensed under the MIT License.
