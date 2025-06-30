from scapy.all import ARP, Ether, srp

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = srp(broadcast / arp_request, timeout=2, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    return None

print(get_mac("192.168.1.1"))  # test with gateway
print(get_mac("192.168.1.34"))  # test with victim
