import scapy.all as scapy
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP
import time
import sqlite3
import sys 

if len(sys.argv) != 2:
    print("Usage: python3 dns_sniffer.py <victim_ip>")
    sys.exit(1)

VICTIM_IP = sys.argv[1]
PHISH_FILE = "phish_domains.txt"
INTERFACE = "wlan0"  

# Load phishing domains
with open(PHISH_FILE, "r") as f:
    phishing_domains = set(line.strip().lower() for line in f if line.strip())

def log_alert(event, severity="High"):
    conn = sqlite3.connect("phishguard.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO alerts (timestamp, event, severity) VALUES (?, ?, ?)",
                   (time.strftime('%Y-%m-%d %H:%M:%S'), event, severity))
    conn.commit()
    conn.close()

def monitor_dns(pkt):
    if pkt.haslayer(DNSQR):
        ip_layer = pkt.getlayer(IP)
        if ip_layer.src != VICTIM_IP:
            return  # Skip DNS queries not from the victim

        domain = pkt[DNSQR].qname.decode().strip('.').lower()
        print(f"[DNS] {ip_layer.src} queried {domain}")
        for bad in phishing_domains:
            if bad in domain:
                print(f"[ALERT] Detected phishing domain: {domain}")
                log_alert(f"Phishing domain queried: {domain}")
                break

# Start sniffing
print(f"[INFO] Starting DNS sniffing for victim: {VICTIM_IP}...")
scapy.sniff(filter="udp port 53", iface=INTERFACE, prn=monitor_dns, store=0)
