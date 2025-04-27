import socket
import os
import re

def get_gateway_ip():
    """Auto-detect the router's IP address (gateway)"""
    if os.name == "nt":  # Windows
        output = os.popen("ipconfig").read()
        match = re.search(r"Default Gateway[ .]*: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", output)
        if match:
            return match.group(1)
    else:  # Linux/Mac
        output = os.popen("ip route show").read()
        match = re.search(r"default via ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", output)
        if match:
            return match.group(1)
    return None

def get_local_ip():
    """Get your own machine's IP address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # Connect to Google DNS
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_network_interface():
    """Auto-detect active network interface name (for Windows)"""
    output = os.popen("netsh interface show interface").read()
    lines = output.splitlines()
    for line in lines:
        # Check for connected status and account for variations like "Wi-Fi" or "WiFi"
        if "Connected" in line and ("Wi-Fi" in line or "WiFi" in line or "Ethernet" in line):
            return line.strip().split()[-1]  # Last word is interface name
    return None


# Now we add print statements to show the results
def main():
    print("[*] Detecting network information...")

    gateway_ip = get_gateway_ip()
    if gateway_ip:
        print(f"[+] Gateway IP: {gateway_ip}")
    else:
        print("[!] Could not detect Gateway IP.")

    local_ip = get_local_ip()
    print(f"[+] Local IP: {local_ip}")

    network_interface = get_network_interface()
    if network_interface:
        print(f"[+] Network Interface: {network_interface}")
    else:
        print("[!] Could not detect network interface.")

if __name__ == "__main__":
    main()
