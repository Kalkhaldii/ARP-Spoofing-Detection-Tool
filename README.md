 ARP Spoof Detector (Python)

A Python-based ARP spoofing detection tool that monitors ARP reply packets and detects possible ARP poisoning attacks using a baseline comparison method.

# Features
- Real-time ARP packet sniffing
- Baseline MAC address learning
- Detects MAC address changes for the same IP
- Logs detected attacks with timestamps
- Audible alert on detection (Windows)

# How It Works
1. Listens for ARP reply packets
2. Stores the first observed MAC address for each IP
3. Triggers an alert if the MAC address changes
4. Logs the incident for investigation

# Tools & Technologies
- Python
- Scapy
- ARP Protocol
- Network Security

# Usage
```bash
Run the script in a local or lab network environment to monitor ARP activity.
