from scapy.all import rdpcap, IP, TCP, UDP

packets = rdpcap("data/pcaps/sample.pcap")

for packet in packets:
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        timestamp = float(packet.time)

        src_port = None
        dst_port = None

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        print({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_size": packet_size,
            "timestamp": timestamp
        })
