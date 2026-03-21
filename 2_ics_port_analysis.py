"""
Script 2: ICS/OT Port Targeting Analysis
Topic - Data Engineering & Feature Extraction
Flags packets targeting known industrial control system ports and
reports how many packets hit each ICS-relevant port. Also identifies
scanning behavior (sequential vs random IP targeting).
"""

import sys
from collections import Counter, defaultdict
from scapy.all import rdpcap, IP, TCP, UDP

PCAP_FILE = "traffic-2025-01-20.00-1M.pcap"

# Known ICS/OT protocol ports
ICS_PORTS = {
    502: "Modbus",
    20000: "DNP3",
    44818: "EtherNet/IP",
    2222: "EtherNet/IP (alt)",
    102: "S7/ISO-TSAP",
    4840: "OPC UA",
    1089: "FF Fieldbus HSE",
    1090: "FF Fieldbus HSE",
    1091: "FF Fieldbus HSE",
    2404: "IEC 60870-5-104",
    20547: "ProConOS",
    1962: "PCWorx",
    789: "Red Lion",
    9600: "OMRON FINS",
    47808: "BACnet",
    161: "SNMP (ICS mgmt)",
    162: "SNMP trap",
}


def main():
    print(f"[*] Loading {PCAP_FILE} ...")
    packets = rdpcap(PCAP_FILE)
    print(f"[+] Total packets: {len(packets)}\n")

    ics_hits = Counter()
    non_ics = 0
    src_per_ics_port = defaultdict(set)  # unique source IPs per ICS port
    dst_ips_per_port = defaultdict(list)  # dst IPs per ICS port for sequential analysis

    for pkt in packets:
        if IP not in pkt:
            continue
        port = None
        if TCP in pkt:
            port = pkt[TCP].dport
        elif UDP in pkt:
            port = pkt[UDP].dport

        if port and port in ICS_PORTS:
            proto_name = ICS_PORTS[port]
            ics_hits[proto_name] += 1
            src_per_ics_port[proto_name].add(pkt[IP].src)
            dst_ips_per_port[proto_name].append(pkt[IP].dst)
        else:
            non_ics += 1

    total_ics = sum(ics_hits.values())
    total = len(packets)

    print(
        f"[+] Total ICS-port packets: {total_ics} ({100 * total_ics / total:.2f}% of capture)"
    )
    print(f"[+] Non-ICS packets:        {non_ics}\n")

    print(f"{'Protocol':<25} {'Packets':>9} {'Unique Src IPs':>15}")
    print("-" * 55)
    for proto, count in ics_hits.most_common():
        unique_srcs = len(src_per_ics_port[proto])
        print(f"  {proto:<23} {count:>9} {unique_srcs:>15}")

    # Basic sequential scan detection: check if dst IPs per ICS port are numerically sequential
    print("\n[+] Scanning pattern analysis (per ICS port):")
    import socket, struct

    for proto, ips in dst_ips_per_port.items():
        if len(ips) < 5:
            continue
        try:
            int_ips = sorted(
                set(struct.unpack("!I", socket.inet_aton(ip))[0] for ip in ips)
            )
            diffs = [int_ips[i + 1] - int_ips[i] for i in range(len(int_ips) - 1)]
            avg_gap = sum(diffs) / len(diffs) if diffs else 0
            pattern = (
                "SEQUENTIAL (avg gap={:.1f})".format(avg_gap)
                if avg_gap <= 5
                else "RANDOM (avg gap={:.1f})".format(avg_gap)
            )
            print(f"  {proto:<23}: {pattern}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
