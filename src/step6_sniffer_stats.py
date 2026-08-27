"""
Network packet sniffer - Final version with enriched statistics
Usage:
    sudo python3 step6_sniffer_stats.py
    sudo python3 step6_sniffer_stats.py --iface eth0
    sudo python3 step6_sniffer_stats.py --filter "tcp"
    sudo python3 step6_sniffer_stats.py --output capture.log
    sudo python3 step6_sniffer_stats.py --top 10
"""

import argparse
import datetime
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

# --- Global counters ---
protocol_counter = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
ip_counter = Counter()          # number of packets per IP (source + destination)
dns_domain_counter = Counter()  # number of times each domain was queried
dst_port_counter = Counter()    # most requested destination ports (often = targeted services)

output_file = None
top_n = 5  # number of entries shown in each ranking, overridable via --top


def format_packet(packet):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    if not packet.haslayer(IP):
        protocol_counter["ARP"] += 1
        return f"[{timestamp}] [NON-IP] {packet.summary()}"

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst

    # Track both sides of the communication in the IP stats
    ip_counter[ip_src] += 1
    ip_counter[ip_dst] += 1

    if packet.haslayer(TCP):
        protocol_counter["TCP"] += 1
        tcp = packet[TCP]
        dst_port_counter[tcp.dport] += 1
        line = f"[{timestamp}] [TCP] {ip_src}:{tcp.sport} -> {ip_dst}:{tcp.dport}  [flags={tcp.flags}]"

    elif packet.haslayer(UDP):
        protocol_counter["UDP"] += 1
        udp = packet[UDP]
        dst_port_counter[udp.dport] += 1
        line = f"[{timestamp}] [UDP] {ip_src}:{udp.sport} -> {ip_dst}:{udp.dport}"

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            queried_name = packet[DNSQR].qname.decode(errors="ignore")
            dns_domain_counter[queried_name] += 1
            line += f"  [DNS Query: {queried_name}]"

    elif packet.haslayer(ICMP):
        protocol_counter["ICMP"] += 1
        line = f"[{timestamp}] [ICMP] {ip_src} -> {ip_dst}  [type={packet[ICMP].type}]"

    else:
        protocol_counter["OTHER"] += 1
        line = f"[{timestamp}] [OTHER] {ip_src} -> {ip_dst}"

    if packet.haslayer(Raw):
        preview = packet[Raw].load[:40]
        readable_text = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
        line += f"  | payload: {readable_text}"

    return line


def handle_packet(packet):
    line = format_packet(packet)
    print(line)
    if output_file:
        output_file.write(line + "\n")
        output_file.flush()


def print_summary():
    print("\n=== Capture summary ===")
    for protocol, count in protocol_counter.items():
        print(f"{protocol}: {count} packet(s)")
    print(f"Total: {sum(protocol_counter.values())} packet(s)")

    print(f"\n=== Top {top_n} most active IPs ===")
    for ip, count in ip_counter.most_common(top_n):
        print(f"{ip}: {count} packet(s)")

    if dns_domain_counter:
        print(f"\n=== Top {top_n} queried DNS domains ===")
        for domain, count in dns_domain_counter.most_common(top_n):
            print(f"{domain}: {count} request(s)")

    if dst_port_counter:
        print(f"\n=== Top {top_n} destination ports ===")
        for port, count in dst_port_counter.most_common(top_n):
            print(f"port {port}: {count} packet(s)")


def main():
    global output_file, top_n

    parser = argparse.ArgumentParser(description="Educational network packet sniffer with statistics")
    parser.add_argument("--iface", help="Network interface to listen on (e.g. eth0). Default: all.")
    parser.add_argument("--filter", help="BPF filter, e.g. 'tcp', 'udp', 'icmp', 'port 80'")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--output", help="File to save results to")
    parser.add_argument("--top", type=int, default=5, help="Number of entries in the rankings (default: 5)")
    args = parser.parse_args()

    top_n = args.top

    if args.output:
        output_file = open(args.output, "a")

    print("Starting capture... (Ctrl+C to stop)\n")

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            count=args.count,
            prn=handle_packet,
        )
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()
        if output_file:
            output_file.close()


if __name__ == "__main__":
    main()
