"""
Step 4: Detailed analysis - TCP flags, DNS queries, raw payload
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw


def handle_packet(packet):
    if not packet.haslayer(IP):
        print(f"[NON-IP] {packet.summary()}")
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        protocol = "TCP"
        info = f"{ip_src}:{tcp.sport} -> {ip_dst}:{tcp.dport}"

        # tcp.flags is a special scapy object, printed as readable text
        # Examples: S=SYN, A=ACK, F=FIN, P=PSH, R=RST
        info += f"  [flags={tcp.flags}]"

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        protocol = "UDP"
        info = f"{ip_src}:{udp.sport} -> {ip_dst}:{udp.dport}"

        # If this is a DNS query, extract the requested domain name
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            queried_name = packet[DNSQR].qname.decode(errors="ignore")
            info += f"  [DNS Query: {queried_name}]"

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        info = f"{ip_src} -> {ip_dst}  [type={packet[ICMP].type}]"

    else:
        protocol = "OTHER"
        info = f"{ip_src} -> {ip_dst}"

    # Raw application-layer payload, if present
    payload_str = ""
    if packet.haslayer(Raw):
        chunk = packet[Raw].load
        # Show only the first 40 bytes, replacing non-printable characters
        # with a dot for a readable display
        preview = chunk[:40]
        readable_text = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
        payload_str = f"  | payload: {readable_text}"

    print(f"[{protocol}] {info}{payload_str}")


sniff(count=20, prn=handle_packet)
