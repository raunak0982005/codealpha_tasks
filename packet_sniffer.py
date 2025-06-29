from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def analyze_packet(packet):
    print("="*60)

    
   
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip} ➡ Destination IP: {dst_ip}")

   
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"Protocol: TCP | Source Port: {src_port} ➡ Destination Port: {dst_port}")
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print(f"Protocol: UDP | Source Port: {src_port} ➡ Destination Port: {dst_port}")
    else:
        print("Protocol: Other")

    
    if Raw in packet:
        try:
            payload = packet[Raw].load.decode(errors="ignore")
            print("Payload Data:")
            print(payload)
        except:
            print("Payload could not be decoded.")



sniff(prn=analyze_packet, count=10)
