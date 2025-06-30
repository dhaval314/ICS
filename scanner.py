# scanner.py
import scapy.all as scapy

def scan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    clients = []
    for i in answered:
        clients.append({
            "ip": i[1].psrc,
            "mac": i[1].hwsrc
        })

    return clients
