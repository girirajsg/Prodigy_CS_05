from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        print(f"[+] Packet: {ip_src} --> {ip_dst} | Protocol: {proto}")

        if TCP in packet:
            print(f"    TCP Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}")

        if Raw in packet:
            print(f"    Payload: {packet[Raw].load}")

print("[*] Starting packet sniffer...")
sniff(prn=process_packet, store=False)
