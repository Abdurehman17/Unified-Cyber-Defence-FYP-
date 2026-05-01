**Unified Cyber Defense System (UCDS)**

An intelligent, packet-level network security and intrusion detection tool built with Python, Flask, and Scapy. This tool monitors network traffic in real-time, detects anomalies (like DDoS attacks, SQL Injections, and Port Scanning), and automatically drops malicious packets.

**Features**

* Deep Packet Inspection (DPI): Analyzes raw HTTP payloads and DNS queries.
* DDoS Detection: Monitors traffic volume per IP to identify and mitigate flood attacks.
* Zero-Day Port Scan Detection: Tracks abnormal connection attempts across multiple ports.
* Real-Time Dashboard: Interactive UI built with Chart.js and Leaflet.js for live geographical threat mapping.
* Automated PDF Reporting: Generates comprehensive security audit logs.


**Technologies Used**

* Backend: Python, Flask, Scapy, SQLite3
* Frontend: HTML/CSS, JavaScript, Chart.js, Leaflet.js (Maps)
* Security: IP-API (Geo-location tracking), Custom Threat Signatures
* Installation \& Setup

**Clone the repository:**

git clone \[https://github.com/yourusername/UCDS.git](https://github.com/yourusername/UCDS.git)
cd UCDS

**Install required dependencies:**

pip install -r requirements.txt
(Note: Ensure you have scapy, flask, psutil, fpdf, and requests installed)

**Run the Application:**

Because packet sniffing requires root privileges, you must run the app as Administrator or using sudo:
sudo python3 backend/app.py

**Access the Dashboard:**

Open your web browser and navigate to http://127.0.0.1:5000

**Disclaimer**
This tool was developed as a Final Year Project (FYP) for educational and research purposes only. Do not use this tool on networks you do not have explicit permission to monitor.

