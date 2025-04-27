from flask import Flask, render_template_string
import threading
from scapy.all import *
from scapy.all import sniff, DNSQR

app = Flask(__name__)

# List of events (live data)
events = []

# Load blocked domains
with open("blocked_domains.txt", "r") as f:
    blocked_domains = [line.strip().lower() for line in f]

# HTML Template
html = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Watcher Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { background-color: black; color: lime; font-family: monospace; }
        h1 { text-align: center; }
        table { width: 90%; margin: auto; border-collapse: collapse; }
        td, th { border: 1px solid lime; padding: 8px; text-align: center; }
    </style>
</head>
<body>
    <h1>👀 I'M WATCHING YOU - Live Dashboard 👀</h1>
    <table>
        <tr><th>Timestamp</th><th>Student IP</th><th>Requested Domain</th></tr>
        {% for event in events %}
        <tr>
            <td>{{ event.time }}</td>
            <td>{{ event.ip }}</td>
            <td>{{ event.domain }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(html, events=events)

def packet_callback(packet):
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode().lower()
        src_ip = packet[IP].src
        for domain in blocked_domains:
            if domain in query:
                print(f"[!] {src_ip} tried to access {query}")
                events.append({"time": time.strftime("%H:%M:%S"), "ip": src_ip, "domain": query})
                if len(events) > 50:  # Keep dashboard clean
                    events.pop(0)

def sniff_dns():
    sniff(filter="udp port 53", prn=packet_callback, store=0)

if __name__ == "__main__":
    import time
    threading.Thread(target=sniff_dns, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)
