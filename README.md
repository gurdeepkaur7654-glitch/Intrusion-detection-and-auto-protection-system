
# 🛡 Intrusion Detection and Auto-Protection System

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![Platform](https://img.shields.io/badge/platform-Windows-lightgrey) ![Tests](https://github.com/<your-username>/Intrusion-detection-and-auto-protection-system/actions/workflows/tests.yml/badge.svg)

A real-time network Intrusion Detection and Prevention tool written in Python. It sniffs live packets from a chosen network adapter, detects common attack patterns, **automatically blocks attackers through the Windows Firewall**, and shows everything on a modern dark-themed desktop dashboard.

<!-- Add a screenshot of your dashboard here. Create a `screenshots/` folder in the repo and use: -->
<!-- ![Dashboard](screenshots/dashboard.png) -->

---

## ✨ Features

- **Live packet capture** using Scapy (TCP, UDP and ICMP)
- **Attack detection**
  - Port scan
  - SYN flood
  - UDP flood
  - ICMP flood
- **🚫 Auto-protection:** one switch in the dashboard blocks attacking IPs automatically (Windows Firewall rule per attacker, with a safety whitelist and an *Unblock All* button)
- **Sliding-window detection** so normal long-running traffic doesn't cause false alarms
- **Alert cooldown** to avoid alert spam during one long attack
- **CSV alert log** (`ids_alerts.csv`) for later analysis
- **🎬 Demo mode** with synthetic attacks: no admin rights or second machine needed
- **Automated tests** (pytest + GitHub Actions)
- **GeoIP lookup** of source IPs (city and country) using the MaxMind GeoLite2 database
- **Dashboard (CustomTkinter + Matplotlib)**
  - Live traffic graph (packets per second)
  - Protocol distribution pie chart
  - Attack statistics chart
  - Threat level indicator (SAFE → CRITICAL) with a 0–100 gauge
  - Attack timeline and recent alerts
  - Top attacker IPs
  - Live packet table (last 300 packets)
  - System status: CPU, RAM, hostname, IP, selected interface, uptime
- **Choose a network adapter** from a dropdown before monitoring
- **Export a text report** of the session, **take a screenshot** of the dashboard, or **clear** everything

---

## 🔍 How Detection Works

| Attack | Rule (per source IP, within a 10-second sliding window) |
|---|---|
| Port Scan | 20 or more distinct destination ports contacted |
| SYN Flood | 50 or more pure SYN packets (SYN set, ACK not set) |
| UDP Flood | 50 or more UDP packets |
| ICMP Flood | 50 or more ICMP packets |

After an alert, the same attack type from the same IP is muted for 30 seconds. All thresholds are constants at the top of `sniffer.py`.

These are simple threshold-based heuristics, meant for learning and demonstration. They can produce false positives on busy networks.

**Threat level** is based on the total number of alerts raised:

| Alerts | Level |
|---|---|
| 0 | SAFE |
| 1–9 | LOW |
| 10–29 | MEDIUM |
| 30–59 | HIGH |
| 60+ | CRITICAL |

The gauge score is `min(alerts × 5, 100)`.

---

## 📁 Project Structure

```
├── dashboard.py          # GUI dashboard (run this file)
├── sniffer.py            # Packet capture and attack detection engine
├── firewall.py           # Auto-protection: Windows Firewall blocking
├── demo.py               # Synthetic traffic for demos (python dashboard.py --demo)
├── test.py               # Helper to list network interfaces and test capture
├── tests/
│   └── test_detection.py # Unit tests for every detector
├── requirements.txt
└── README.md
```

---

## ⚙️ Requirements

- **Python 3.9+**
- **Windows** (adapter detection uses PowerShell's `Get-NetAdapter`)
- **[Npcap](https://npcap.com/)** installed (needed by Scapy on Windows)
- **Administrator privileges** (needed for packet capture)
- A free **[MaxMind GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)** database file

Python packages are listed in `requirements.txt`.

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/Intrusion-detection-and-auto-protection-system.git
cd Intrusion-detection-and-auto-protection-system

# 2. (Optional) create a virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

**GeoIP database:** download `GeoLite2-City.mmdb` from MaxMind (free account required) and place it in the project folder, next to `sniffer.py`. It is not included in this repository because of MaxMind's license.

---

## ▶️ Usage

1. Open **Command Prompt / PowerShell as Administrator**.
2. Run:
   ```bash
   python dashboard.py
   ```
3. Select your network adapter from the dropdown.
4. Click **▶️ Start Monitoring**.
5. Use **📄 Export Logs**, **📷 Screenshot** or **🗑 Clear Dashboard** as needed.
6. Click **■ Stop Monitoring** when finished.

### 🚫 Auto-Block

Turn on the **Auto-Block** switch next to the buttons. When an attack is detected, the attacker's IP is blocked with a Windows Firewall rule named `IDS_BLOCK_<ip>`, and the block is shown in the Attack Timeline. Click **🔓 Unblock All** to remove every rule the tool created.

Safety: loopback, multicast, this machine's own addresses and anything in `firewall.WHITELIST` (add your router or DNS server there) are never blocked. Requires Administrator rights.

### 🎬 Demo mode (no admin rights, no real traffic)

```bash
python dashboard.py --demo
```

Fake port scans, SYN/UDP/ICMP floods are fed into the detector so you can show every part of the dashboard in a presentation or screen recording.

### 🧪 Run the tests

```bash
python -m pytest -v
```

Not sure which adapter to pick? Run `python test.py` to list all interfaces and check that capture works.

### Testing the detection (only on your own network or lab)

From a second machine or VM on the same network, you can generate test traffic, for example:

```bash
nmap -p 1-100 <your-ip>        # should trigger a Port Scan alert
ping -n 100 <your-ip>          # should trigger an ICMP Flood alert (Windows)
```

---

## ⚠️ Disclaimer

This project is for **educational purposes**. Only monitor networks that you own or have explicit permission to monitor. The authors are not responsible for misuse.

---

## 🗺 Roadmap

- [x] Automatic response: block attacker IPs through the Windows Firewall
- [x] Time-windowed detection for all attack types
- [ ] Linux support (`iptables` / `nftables` backend in `firewall.py`)
- [ ] Auto-unblock after a configurable time
- [ ] Email / desktop notifications for high-severity alerts
- [ ] Packaged `.exe` release

---

## 👤 Author

**Your Name**
GitHub: [@your-username](https://github.com/your-username)

---

## 📄 License

Add a license of your choice (for example MIT) via GitHub's "Add file → Create new file → LICENSE" option.
