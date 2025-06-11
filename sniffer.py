from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

# Get logging and filter preferences
store_res = input("Do you want to store result? [y/n] ").lower()
log_enabled = store_res == 'y'

filter_ip = input("Enter IP to filter (leave blank for all): ").strip()
filter_port = input("Enter port to filter (leave blank for all): ").strip()

def packet_callback(packet):
    log_data = ""

    # Apply IP filter (source or destination)
    if filter_ip and IP in packet:
        ip_layer = packet[IP]
        if ip_layer.src != filter_ip and ip_layer.dst != filter_ip:
            return  # Skip this packet

    # Apply port filter (TCP/UDP)
    if filter_port:
        port = int(filter_port)
        if TCP in packet:
            if packet[TCP].sport != port and packet[TCP].dport != port:
                return
        elif UDP in packet:
            if packet[UDP].sport != port and packet[UDP].dport != port:
                return
        else:
            return  # Not TCP/UDP, skip

    # Start logging data
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto
        log_data += f"[+] IP Packet: {src} -> {dst} | Protocol: {proto}\n"

    if TCP in packet:
        log_data += f"[+] TCP Layer: {packet[TCP].summary()}\n"
    elif UDP in packet:
        log_data += f"[+] UDP Layer: {packet[UDP].summary()}\n"
    elif ICMP in packet:
        log_data += f"[+] ICMP Layer: {packet[ICMP].summary()}\n"

    log_data += f"{packet.summary()}\n"
    log_data += "-" * 50 + "\n"

    print(log_data)

    if log_enabled:
        with open("packets_log.txt", "a") as f:
            f.write(f"{datetime.now()} - {log_data}")

print("Starting packet sniffer...\n")
sniff(prn=packet_callback)