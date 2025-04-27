import os
import subprocess
import sys
import time

def install_python():
    print("[*] Checking for Python...")
    try:
        subprocess.check_output(["python", "--version"])
        print("[+] Python is already installed.")
    except:
        print("[!] Python not found. Installing Python...")
        # Download and install python silently
        subprocess.call("powershell Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe -OutFile python_installer.exe", shell=True)
        subprocess.call(".\\python_installer.exe /quiet InstallAllUsers=1 PrependPath=1", shell=True)
        time.sleep(10)
        print("[+] Python installed.")

def install_dependencies():
    print("[*] Installing required Python packages...")
    subprocess.call("python -m pip install --upgrade pip", shell=True)
    subprocess.call("pip install flask scapy", shell=True)
    print("[+] Dependencies installed.")

def disable_firewall_prompt():
    print("[*] (Optional) Disabling Windows Firewall rules for smoother operation...")
    try:
        subprocess.call("netsh advfirewall set allprofiles state off", shell=True)
        print("[+] Firewall disabled.")
    except Exception as e:
        print(f"[!] Failed to disable firewall: {e}")

def create_shortcut():
    desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    shortcut_path = os.path.join(desktop, "Network_Watcher.lnk")
    target = os.path.abspath("dist/master.exe")
    if os.path.exists(target):
        print("[*] Creating desktop shortcut...")
        with open('create_shortcut.vbs', 'w') as f:
            f.write(f'''
Set oWS = WScript.CreateObject("WScript.Shell")
Set oLink = oWS.CreateShortcut("{shortcut_path}")
oLink.TargetPath = "{target}"
oLink.Save
''')
        subprocess.call("cscript create_shortcut.vbs", shell=True)
        os.remove('create_shortcut.vbs')
        print("[+] Shortcut created on desktop.")
    else:
        print("[!] Could not find master.exe to create shortcut.")

def main():
    print("=== Network Watcher Setup ===")
    install_python()
    install_dependencies()
    disable_firewall_prompt()
    create_shortcut()
    print("[+] Setup completed. Launch 'Network_Watcher' from your Desktop.")

if __name__ == "__main__":
    main()
