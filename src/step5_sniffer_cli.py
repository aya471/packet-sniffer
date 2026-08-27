"""
Network packet sniffer - CLI version
Usage:
    sudo python3 step5_sniffer_cli.py
    sudo python3 step5_sniffer_cli.py --iface eth0
    sudo python3 step5_sniffer_cli.py --filter "tcp"
    sudo python3 step5_sniffer_cli.py --output capture.log
"""

import argparse
import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

# Global packet counter per protocol (used for the final summary)
counter = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}

output_file = None  # set in main() if the user requests logging to a file


def format_packet(packet):
    """Build the display line for a given packet."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    if not packet.haslayer(IP):
        counter["ARP"] += 1
        return f"[{timestamp}] [NON-IP] {packet.summary()}"

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst

    if packet.haslayer(TCP):
        counter["TCP"] += 1
        tcp = packet[TCP]
        line = f"[{timestamp}] [TCP] {ip_src}:{tcp.sport} -> {ip_dst}:{tcp.dport}  [flags={tcp.flags}]"

    elif packet.haslayer(UDP):
        counter["UDP"] += 1
        udp = packet[UDP]
        line = f"[{timestamp}] [UDP] {ip_src}:{udp.sport} -> {ip_dst}:{udp.dport}"
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            queried_name = packet[DNSQR].qname.decode(errors="ignore")
            line += f"  [DNS Query: {queried_name}]"

    elif packet.haslayer(ICMP):
        counter["ICMP"] += 1
        line = f"[{timestamp}] [ICMP] {ip_src} -> {ip_dst}  [type={packet[ICMP].type}]"

    else:
        counter["OTHER"] += 1
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
        output_file.flush()  # write immediately, useful if interrupted with Ctrl+C


def print_summary():
    print("\n--- Capture summary ---")
    for protocol, count in counter.items():
        print(f"{protocol}: {count} packet(s)")
    print(f"Total: {sum(counter.values())} packet(s)")


def main():
    global output_file

    parser = argparse.ArgumentParser(description="Educational network packet sniffer")
    parser.add_argument("--iface", help="Network interface to listen on (e.g. eth0). Default: all.")
    parser.add_argument("--filter", help="BPF filter, e.g. 'tcp', 'udp', 'icmp', 'port 80'")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--output", help="File to save results to")
    args = parser.parse_args()

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
