import logging
from scapy.all import IP, TCP, sr1

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def port_scan(ip, port):
    packet = IP(dst=ip) / TCP(dport=port, flags="S")
    response = sr1(packet, timeout=1, verbose=0)
    if response is None:
        return "Open"
    else:
        return "Closed"

ip = "192.168.1.245"

for port in range(1, 1001):
    status = port_scan(ip, port)
    print(f"Port {port}: {status}")
