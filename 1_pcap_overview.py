"""
Script 1: PCAP Overview & Basic Statistics
Topic - Data Engineering & Feature Extraction
Reads the Merit ORION PCAP file and prints a high-level summary:
  - Total packet count
  - Protocol distribution (TCP/UDP/ICMP/Other)
  - Time range of the capture
  - Top 10 source IPs and destination ports
"""

import sys
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

PCAP_FILE = "data/traffic-2025-01-20.00-1M.pcap"


def main():
    print(f"[*] Loading {PCAP_FILE} ...")
    packets = rdpcap(PCAP_FILE)
    total = len(packets)
    print(f"[+] Total packets: {total}\n")

    protocols = Counter()
    src_ips = Counter()
    dst_ports = Counter()
    timestamps = []

    for pkt in packets:
        if IP in pkt:
            timestamps.append(float(pkt.time))
            src_ips[pkt[IP].src] += 1

            if TCP in pkt:
                protocols["TCP"] += 1
                dst_ports[pkt[TCP].dport] += 1
            elif UDP in pkt:
                protocols["UDP"] += 1
                dst_ports[pkt[UDP].dport] += 1
            elif ICMP in pkt:
                protocols["ICMP"] += 1
            else:
                protocols["Other"] += 1
        else:
            protocols["Non-IP"] += 1

    if timestamps:
        import datetime

        t_start = datetime.datetime.fromtimestamp(
            min(timestamps), tz=datetime.timezone.utc
        )
        t_end = datetime.datetime.fromtimestamp(
            max(timestamps), tz=datetime.timezone.utc
        )
        duration = max(timestamps) - min(timestamps)
        print(f"[+] Capture start (UTC): {t_start}")
        print(f"[+] Capture end   (UTC): {t_end}")
        print(f"[+] Duration:            {duration:.2f} seconds\n")

    print("[+] Protocol distribution:")
    for proto, count in protocols.most_common():
        pct = 100 * count / total
        print(f"    {proto:<8} {count:>8}  ({pct:.1f}%)")

    print("\n[+] Top 10 source IPs:")
    for ip, count in src_ips.most_common(10):
        print(f"    {ip:<20} {count:>8} packets")

    print("\n[+] Top 10 destination ports:")
    for port, count in dst_ports.most_common(10):
        print(f"    Port {port:<8} {count:>8} packets")


if __name__ == "__main__":
    main()
