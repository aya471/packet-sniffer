"""
Step 3: Extract key information (source/destination IP, protocol)
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP


def handle_packet(packet):
    # We only care about packets that have an IP layer
    # (e.g. ARP packets don't have one, we skip them for now)
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # The IP layer's "proto" field is a number (6=TCP, 17=UDP, 1=ICMP...)
        # but scapy also lets us directly test for layer presence
        if packet.haslayer(TCP):
            protocol = "TCP"
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            port_src = "-"
            port_dst = "-"
        else:
            protocol = "OTHER"
            port_src = "-"
            port_dst = "-"

        print(f"[{protocol}] {ip_src}:{port_src}  ->  {ip_dst}:{port_dst}")
    else:
        # Packets without an IP layer (e.g. ARP)
        print(f"[NON-IP] {packet.summary()}")


sniff(count=15, prn=handle_packet)
