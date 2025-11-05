# 🧩 ForenX — Linux Log & Memory Analyzer

**ForenX** is a modular digital forensics and threat analysis toolkit built for cybersecurity professionals and ethical hackers.  
It focuses on analyzing Linux logs, memory dumps, PCAP files, and file artifacts to uncover potential signs of compromise, system anomalies, and malicious activity.

---

## 🚀 Features

| Module | Description |
|:--|:--|
| 🧾 **Log Analyzer** | Extracts failed/successful SSH login attempts, top brute-forced users, and attacker IPs from Linux `auth.log` files. |
| 🧠 **Memory Analyzer** | Scans memory dumps for IPs, credentials, and login traces. |
| 🌐 **Network Traffic Analyzer** | Parses `.pcap` captures to extract IPs, ports, HTTP requests, and potential credential data. |
| 📁 **File Artifact Extractor** | Identifies hidden files, calculates hashes, detects file types, extracts EXIF metadata, and lists artifacts for forensic analysis. |
| 🧩 **Process & Malware Scanner** | (In progress) Enumerates system processes, detects suspicious binaries, and checks for known malicious indicators. |

---

## 🧰 Project Structure
```bash
ForenX/
├── forenx.py # Main controller script
├── modules/
│ ├── init.py
│ ├── log_analyzer.py # Log analysis module
│ ├── memory_analyzer.py # Memory dump analysis module
│ ├── network_analyzer.py # PCAP traffic analysis module
│ ├── file_extractor.py # File artifact and metadata extraction module
│ └── process_scanner.py # (Upcoming) Process and malware scanning module
├── samples/
│ ├── auth.log # Sample authentication log
│ ├── dump.mem # Sample memory dump
│ └── capture.pcap # Sample packet capture
└── README.md


---

## ⚙️ Usage

Run the main controller script:

python3 forenx.py --action analyze --input samples/auth.log --output results.txt

Arguments

Flag	Description
--action	Action to perform (analyze, recover, etc.)
--input	Input file path (log, memory dump, pcap, etc.)
--output	Output file to store results

Example Commands
🔹 Log Analysis

python3 forenx.py --action analyze --input samples/auth.log --output results.txt

🔹 Memory Dump Analysis

python3 forenx.py --action analyze --input samples/memdump.lime --output memory_report.txt

🔹 Network Traffic Analysis

python3 forenx.py --action analyze --input samples/capture.pcap --output network_report.txt

🔹 File Artifact Extraction

python3 forenx.py --action extract --input /home/user/documents --output file_report.txt

📦 Requirements

Install dependencies before running:

pip install scapy pillow python-magic exifread

🧑‍💻 Author
Abhishek

Ethical Hacker | Cybersecurity Enthusiast | Developer
📍 Specialized in Cyber Forensics, Penetration Testing & Security Automation
🔗 GitHub: The-Abhishek1

⚠️ Disclaimer

This tool is intended for educational and ethical purposes only.
Use responsibly and only on systems you have explicit permission to test.
🧠 Future Enhancements

    ✅ Cross-platform compatibility (Linux, Windows)

    ✅ Add YARA rule-based malware detection

    ✅ Integrate SQLite or JSON reporting

    ✅ Add GUI version (ForenX Dashboard)

    ✅ Machine learning-based anomaly detection for logs and memory dumps

    “Every byte tells a story — ForenX helps you read it.”