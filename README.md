# 🛡️ WiFi Phishing Detector

**Detect Evil Twin attacks and rogue access points on Windows 10/11**

A cybersecurity desktop application that scans nearby WiFi networks,
analyzes them using multiple detection algorithms, and highlights
phishing/suspicious networks in a color-coded GUI.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Techniques](#detection-techniques)
- [Risk Scoring](#risk-scoring)
- [Project Structure](#project-structure)
- [How Evil Twin Attacks Work](#how-evil-twin-attacks-work)
- [Limitations](#limitations)

---

## Overview

An **Evil Twin attack** (also called a rogue AP or WiFi phishing) occurs when
an attacker sets up a fake WiFi hotspot that impersonates a legitimate network.
Victims connect to the fake AP, and the attacker intercepts their traffic,
steals login credentials, or serves a phishing captive portal.

This tool uses Windows built-in tools (`netsh`) to scan nearby networks
and applies seven detection algorithms to flag potential threats.

---

## Installation

### Requirements

- Windows 10 or Windows 11
- Python 3.10 or newer
- A WiFi adapter

### Step 1 — Install Python

Download from https://www.python.org/downloads/
Check "Add Python to PATH" during installation.

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install PyQt5
```

### Step 3 — (Optional) Install Npcap for advanced detection

For future packet-level detection (Scapy integration), install Npcap:

1. Download from: https://npcap.com/
2. Run installer as Administrator
3. Select "Install Npcap in WinPcap API-compatible Mode"
4. Then install Scapy: `pip install scapy`

### Step 4 — Run the application

```bash
python main.py
```

---

## Usage

### Scanning

1. Click **"Scan WiFi"** — the app scans all visible networks using `netsh wlan show networks mode=bssid`
2. Results appear in the table, color-coded by risk level
3. Click any row to see detailed analysis in the right panel

### Loading Known Networks

1. Click **"Load Known Networks"** — imports your Windows saved WiFi profiles as the trusted baseline
2. This allows the app to detect when a familiar network behaves suspiciously

### Trusting a Network

1. Select a network row
2. Click **"Trust Selected"** — adds it to `known_wifi.json` as trusted
3. Future scans will use this as a baseline

### Exporting Reports

1. Click **"Export Report"**
2. Choose HTML (human-readable) or JSON (machine-readable)
3. Share with your security team or include in an academic report

---

## Detection Techniques

### 1. 🔴 Duplicate SSID / Evil Twin Detection (+40 pts)

If the same SSID appears with multiple different BSSIDs, it may indicate
an Evil Twin attack. Legitimate enterprise deployments use multiple APs,
but combined with other indicators, this is a strong signal.

**Example:**
```
CampusWiFi   00:11:22:33:44:55   -70 dBm   Ch 6   WPA2   ← Legitimate
CampusWiFi   DE:AD:BE:EF:00:01   -30 dBm   Ch 11  Open   ← PHISHING
```

### 2. 🟡 Signal Strength Anomaly (+10 pts)

A rogue AP placed physically close to victims will appear with a much
stronger signal than the real AP. If one instance of an SSID is
≥15 dBm stronger than others, it's flagged.

### 3. 🔴 Security Protocol Mismatch (+30 pts)

If a known WPA2 network suddenly appears as Open or WPA, an attacker
may be performing a downgrade attack to capture credentials via a
captive portal.

### 4. 🟡 Unknown/Spoofed Vendor (+20 pts)

The first 3 bytes of a MAC address (OUI) identify the manufacturer.
Unknown vendors or locally-administered MACs (randomized) suggest
cheap hardware or a spoofed MAC.

### 5. 🟡 Channel Inconsistency (+10 pts)

Legitimate APs rarely change channels. If a known SSID appears on
an unexpected channel, it may be a rogue AP.

### 6. 🟡 Open Network Detection (+15 pts)

Open networks with no encryption are inherently risky. Attackers
commonly create open APs named "Airport_WiFi" or "Hotel_Guest".

### 7. 🟡 WEP Encryption (+20 pts)

WEP was broken in 2001 and can be cracked in minutes. Its presence
suggests either dangerously outdated hardware or a deliberate
impersonation attempt.

### 8. 🔴 Untrusted BSSID (+25 pts)

If we have a record of the legitimate BSSID for a network, any new
BSSID is immediately suspicious.

---

## Risk Scoring

| Detection | Points |
|-----------|--------|
| Duplicate SSID (Evil Twin) | +40 |
| Security downgrade | +30 |
| Untrusted BSSID | +25 |
| Unknown/spoofed vendor | +20 |
| WEP encryption | +20 |
| Open network | +15 |
| Channel mismatch | +10 |
| Signal anomaly | +10 |

| Score Range | Status |
|-------------|--------|
| ≥ 50 | 🔴 PHISHING |
| 25–49 | 🟡 SUSPICIOUS |
| < 25 | 🟢 SAFE |

---

## Project Structure

```
wifi_phishing_detector/
│
├── main.py              # Entry point — launches the application
├── gui.py               # PyQt5 interface — all UI code
├── scanner.py           # WiFi scanning via netsh — parses raw output
├── analyzer.py          # Detection algorithms and risk scoring
├── known_networks.py    # Trusted network database management
├── mac_vendor.py        # OUI MAC address vendor lookup
├── database.py          # Report export (JSON + HTML)
│
├── config.json          # Application settings
├── known_wifi.json      # Trusted network fingerprints database
├── oui_database.txt     # OUI vendor database (add more entries)
└── requirements.txt     # Python dependencies
```

---

## How Evil Twin Attacks Work

```
Normal Connection:
  User Device ──WiFi──► Legitimate AP ──► Internet

Evil Twin Attack:
  User Device ──WiFi──► ROGUE AP ──► Attacker's Machine ──► Internet
                                           │
                                    Credential capture
                                    Traffic inspection
                                    Phishing portal
```

**Attack steps:**
1. Attacker scans for nearby networks and picks a target SSID
2. Attacker sets up a rogue AP with identical SSID
3. Attacker optionally performs a deauthentication flood on the real AP
4. Victims see two networks with the same name; the fake AP appears stronger
5. Victims connect to the fake AP
6. Attacker captures HTTP traffic, DNS queries, or serves a fake login page

---

## Limitations

- **No packet capture by default** — relies on netsh, not live packet sniffing
- **Cannot guarantee safety** — a "SAFE" result means no detectable anomalies,
  not that the network is definitely legitimate
- **Passive detection only** — does not actively send probe requests
- **Hidden SSIDs** — cannot detect hidden Evil Twins until the victim connects
- **Enterprise AP deployments** — legitimate multi-AP networks will trigger the
  duplicate SSID check; use the Trust feature to whitelist known BSSIDs

---

## Academic Use

This tool is designed for cybersecurity education and research.
It demonstrates real-world attack detection using:
- Passive WiFi scanning
- Behavioral fingerprinting
- MAC OUI analysis
- Security protocol comparison
- Multi-indicator risk scoring

**Do not use this tool to attack or interfere with networks you do not own.**

---

*WiFi Phishing Detector v1.0 | Educational Cybersecurity Tool*
