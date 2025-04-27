from scapy.all import sniff, DNSQR

def packet_callback(packet):
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode()
        print(f"[DNS Request] {query}")

def main():
    print("[*] Sniffing DNS requests...")
    sniff(filter="udp port 53", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
