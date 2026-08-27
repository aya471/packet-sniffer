"""
Step 2: Basic packet capture
Captures 10 packets and prints a one-line summary for each.
"""

from scapy.all import sniff


def handle_packet(packet):
    # .summary() gives a human-readable one-line summary of the packet
    print(packet.summary())


# sniff() is scapy's main capture function
# - count=10: capture only 10 packets then stop (handy for quick testing)
# - prn=handle_packet: callback function invoked for every captured packet
sniff(count=10, prn=handle_packet)
