# ICS Guard

**ICS Guard** is a lightweight network security monitoring and phishing detection dashboard for Industrial Control Systems (ICS) environments. It allows real-time scanning, ARP spoofing detection, DNS-based phishing alerts, network isolation, and rule-based control over devices in a LAN.

## Features

###  Network Scanning
- Scans a specified subnet for connected devices.
- Displays IP and MAC address of discovered devices.
- Identifies devices with MAC randomization (e.g., iPhones).

### Real-time Phishing Detection
- Uses ARP spoofing to redirect victim DNS queries.
- Sniffs DNS packets for suspicious/phishing domains.
- Automatically logs alerts to SQLite database.
- Supports severity levels (High/Medium/Low) via `phish_domains.txt`.

### Network Control Tools
- **Block IP**: Blocks all internet access to a device.
- **Isolate Node**: Blocks all LAN communication except with the admin (you).
- **Unblock** / **Unisolate**: Restores original access.
- ARP spoofing is used to enforce rules without requiring remote access.

### Device Trust Control
- Each scanned device has a “Trusted” checkbox.
- Trusted devices are saved in the database.
- Alerts or decisions can factor in trust status.

### Real-Time Dashboard
- Live alert updates every few seconds.
- Device map visualizes topology (router → devices).
- Clean, styled UI with actionable buttons for each device.

### Process Control
- Start and Stop phishing detection for any victim with one click.
- Automatically manages IP forwarding, ARP restoration, and sniffing cleanup.

---

## Tech Stack

- **Backend:** Flask, Scapy, SQLite
- **Frontend:** HTML, CSS (custom), JavaScript (for polling)
- **Sniffing/Poisoning:** ARP spoofing, DNS sniffing with Scapy
- **Database:** SQLite (no setup required)

---

## Setup Instructions

1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

2. **Run the App**
```bash
sudo python3 app.py
```
(Note: Root access is required for packet manipulation.)

3. **Interface Configuration**
- Default interface is `wlan0`. You can update this in the settings page or config file.

4. **Add Phishing Domains**
Edit `phish_domains.txt` with suspicious domains and their severity level:
```
phishing.com high
tracking-site.net medium
dns.google.com low
```

---

## TODOs

- Add email/Slack notifications on phishing alerts.
- Improve scan accuracy with OS fingerprinting.
- Include bandwidth monitoring per device.
- Export alert logs.
