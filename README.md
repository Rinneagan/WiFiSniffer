📡 WiFi Sniffer
A complete WiFi network sniffer and control system that monitors devices, blocks access to social media apps and websites, and redirects users to a warning page saying "I'm Watching You 👀" — completely stealth and automatic.

📋 Features
🚀 Auto-detects router and network interface

🕵️ ARP spoofing (Man-in-the-Middle attack) to intercept traffic

👀 DNS spoofing to block social media websites and apps

🖥 Custom Warning Webpage — displays "I'M WATCHING YOU 👀"

📡 Live network device scan

📊 Dashboard (coming soon!)

🛡 Automatic network restoration on shutdown

🛠 Project Structure
File	Purpose
server.py	Flask server hosting the warning page
dashboard_server.py	Visual dashboard for monitoring devices (in development)
arp_spoof_all.py	ARP spoof all devices on the network
dns_spoof.py	DNS spoof social media domain requests
master.py	Launches the entire system in one click
blocked_domains.txt	List of social media domains to block
autodetect_network.py	Auto-detect gateway IP and interface
requirements.txt	Required Python libraries
README.md	Documentation (this file)
⚙️ Setup Guide
1. Install Python Libraries
bash
Copy code
pip install flask scapy netifaces
(Will soon support auto-install via requirements.txt.)

2. Requirements
Python 3.7+ installed

Npcap (included with Wireshark) installed

3. How to Launch
bash
Copy code
python master.py
That's it! WiFi Sniffer will:

Start the "I'm Watching You" warning server

Start the dashboard (coming soon)

ARP spoof the entire WiFi network

DNS spoof social media lookups

🔥 How It Works
🛠 Step 1: ARP Spoofing
Make every device think your machine is the router, and make the router think your machine is every device.

This puts you in the middle of all network communications.

🌐 Step 2: DNS Spoofing
When a device requests facebook.com, tiktok.com, or other blocked sites — they will be secretly redirected to your warning server.

🚨 Step 3: Warning Page
Instead of Facebook opening...
They see:

rust
Copy code
I'M WATCHING YOU 👀
(Styled with black background, red warning text)

🔥 Blocked Domains (Example)
Your blocked_domains.txt can contain domains like:

Copy code
facebook.com
instagram.com
snapchat.com
tiktok.com
twitter.com
youtube.com
pinterest.com
linkedin.com
reddit.com
discord.com
Feel free to add more — any domain you want to block.

⚠️ Important Notes
Only use this on networks you own (your classroom, office, lab, etc.)

ARP Spoofing might trigger antivirus alerts — expected for hacking tools.

Always CTRL+C to stop WiFi Sniffer cleanly (it restores ARP tables automatically).

🏗 Upcoming Features
📊 Interactive dashboard showing live connected devices.

🚀 One-click Windows EXE bundling (autoinstaller).

👻 Stealth mode for silent operation.

🛡 DISCLAIMER
This tool is for educational purposes only. Unauthorized use is illegal and unethical.

🧠 Built With
Python

Scapy

Flask

Netifaces

⚡ Quickstart
bash
Copy code
git clone https://github.com/yourusername/WifiSniffer.git
cd WifiSniffer
pip install -r requirements.txt
python master.py

👑 Project by
Ebenezer Kweku Essel

🎯 YOU OWN YOUR WIFI NOW.
