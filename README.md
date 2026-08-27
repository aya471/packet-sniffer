# Network Packet Sniffer

A Python-based network packet capture and analysis tool built with **Scapy**, developed as a step-by-step learning project covering packet capturing, protocol structure, and network traffic analysis.

## Objectives

- Capture live network traffic packets
- Analyze captured packets to understand their structure and content
- Learn how data flows through the network and the basics of protocols
- Display useful information: source/destination IPs, protocols, ports, TCP flags, DNS queries, and payloads

## What is Scapy?

**Scapy** is a Python library for network packet manipulation. It allows you to:

- **Capture** packets flowing through a network interface (like Wireshark, but in code)
- **Craft** packets from scratch, layer by layer (Ethernet, IP, TCP, UDP, ICMP...)
- **Send** packets over the network
- **Dissect** a captured packet to read every field (IP address, port, TCP flags, etc.)

### Why Scapy instead of the raw `socket` module?

- `socket` = low-level, you have to parse everything yourself in binary (tedious)
- `scapy` = high-level, every packet becomes a Python object with stacked layers, e.g. `Ether() / IP() / TCP()`, and you access fields directly (`packet.src`, `packet.dport`, etc.)

This is why Scapy is used here: it handles protocol parsing for you.

## Project Structure

```
packet-sniffer-project/
├── README.md
├── requirements.txt
├── src/
│   ├── step2_basic_capture.py       # Minimal sniffer, prints packet summaries
│   ├── step3_extract_info.py        # Extracts source/destination IP and protocol
│   ├── step4_detailed_analysis.py   # Adds TCP flags, DNS queries, payload preview
│   ├── step5_sniffer_cli.py         # CLI tool: BPF filters, file output, clean exit
│   └── step6_sniffer_stats.py       # Final version: top IPs, DNS domains, ports
└── docs/
    └── sample_output.txt            # Example capture output
```

## Development Steps

| Step | What it covers |
|------|-----------------|
| 1 | Installing Scapy |
| 2 | Basic capture with `sniff()` |
| 3 | Extracting IP/protocol info via `haslayer()` and field access |
| 4 | TCP flags, DNS queries, raw payload inspection |
| 5 | CLI structuring: BPF filters, file logging, clean shutdown |
| 6 | Statistics: top IPs, DNS domains, destination ports |

Each script builds on the previous one, so they can be read in order to follow the learning progression, or you can jump straight to `step6_sniffer_stats.py` for the complete tool.

## Requirements

- Linux (native or VM) — raw socket access needed for packet capture
- Python 3.8+
- Scapy

Install dependencies:

```bash
pip3 install -r requirements.txt
```

## Usage

Packet capture requires root privileges (raw socket access):

```bash
sudo python3 src/step6_sniffer_stats.py
```

### Options (final version)

| Flag | Description | Example |
|------|-------------|---------|
| `--iface` | Network interface to listen on | `--iface eth0` |
| `--filter` | BPF filter (same syntax as tcpdump/Wireshark) | `--filter "tcp port 80"` |
| `--count` | Number of packets to capture (0 = unlimited) | `--count 50` |
| `--output` | Save captured lines to a log file | `--output capture.log` |
| `--top` | Number of entries in each ranking | `--top 10` |

### Examples

```bash
# Capture everything, no limit
sudo python3 src/step6_sniffer_stats.py

# Only TCP traffic
sudo python3 src/step6_sniffer_stats.py --filter "tcp"

# Only DNS traffic, saved to a file
sudo python3 src/step6_sniffer_stats.py --filter "udp port 53" --output dns_capture.log

# Capture exactly 30 packets then stop automatically
sudo python3 src/step6_sniffer_stats.py --count 30
```

## Sample Output

```
[TCP] 192.168.1.10:51152 -> 142.251.209.67:443  [flags=S]
[UDP] 192.168.1.10:52001 -> 8.8.8.8:53  [DNS Query: example.com.]
[TCP] 41.110.92.160:80 -> 192.168.1.10:45572  [flags=PA]  | payload: HTTP/1.1 200 OK..Server: openresty..Date

=== Capture summary ===
TCP: 39 packet(s)
UDP: 67 packet(s)
ICMP: 0 packet(s)
ARP: 21 packet(s)
Total: 127 packet(s)

=== Top 5 most active IPs ===
192.168.1.10: 45 packet(s)
...

=== Top 5 queried DNS domains ===
example.com.: 3 request(s)
...

=== Top 5 destination ports ===
port 443: 30 packet(s)
...
```

## Security Note

This tool is for **educational purposes** on networks you own or are authorized to monitor. Capturing traffic you don't own or lack permission to inspect may be illegal depending on your jurisdiction.

One practical takeaway from this project: plaintext protocols (HTTP, unencrypted DNS) expose their full content to anyone capturing traffic on the same network segment, including credentials sent over HTTP POST requests. This is a concrete illustration of why encryption (HTTPS/TLS) matters at the transport layer.

## Author

Aya — Final year software/systems engineering project (PFE)
