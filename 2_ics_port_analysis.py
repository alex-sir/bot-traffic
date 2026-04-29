"""
Script 2: ICS/OT Port Targeting Analysis

This script reads a PCAP file iteratively, identifies traffic targeting known
Industrial Control System (ICS) ports, and determines the scanning
pattern (Sequential vs. Random) based on destination IP gaps.
It outputs a high-resolution horizontal bar chart.

Usage Instructions:
    Run the script from the terminal, providing the path to your PCAP file.

    Basic usage:
        python 2_ics_port_analysis.py -p <path_to_pcap_file> -n 1000000

    Example with custom output directory:
        python 2_ics_port_analysis.py -p data/traffic-2025-01-20.00-1M.pcap -o output/ -n 71500000
"""

import argparse
import struct
import os
import gzip
import dpkt
from collections import Counter, defaultdict
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update(
    {
        "font.size": 20,
        "font.family": "serif",
        "axes.labelsize": 22,
        "axes.titlesize": 24,
        "figure.dpi": 300,
    }
)

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


def parse_args():
    parser = argparse.ArgumentParser(description="ICS Port Targeting Analysis")
    parser.add_argument("-p", "--pcap", required=True, help="Path to input PCAP")
    parser.add_argument("-o", "--outdir", default="output", help="Output directory")
    parser.add_argument(
        "-n",
        "--max-packets",
        type=int,
        default=1000000,
        help="Maximum number of packets to process",
    )
    return parser.parse_args()


def open_pcap(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(2)
    return gzip.open(file_path, "rb") if magic == b"\x1f\x8b" else open(file_path, "rb")


def get_ipv4_packet(buf, datalink):
    try:
        if datalink == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                return eth.data
        elif datalink == dpkt.pcap.DLT_LINUX_SLL:
            sll = dpkt.sll.SLL(buf)
            if isinstance(sll.data, dpkt.ip.IP):
                return sll.data
        elif datalink in (12, 14, 101, 228):
            ip = dpkt.ip.IP(buf)
            if ip.v == 4:
                return ip
    except Exception:
        pass
    return None


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_file = os.path.join(args.outdir, "ics_port_analysis.png")

    print(f"[*] Fast Streaming {args.pcap} using dpkt ...")
    ics_hits = Counter()
    dst_ips_per_port = defaultdict(list)
    total_packets = 0

    with open_pcap(args.pcap) as f:
        pcap = dpkt.pcap.Reader(f)
        datalink = pcap.datalink()
        for ts, buf in pcap:
            if total_packets >= args.max_packets:
                print(
                    f"[*] Reached {args.max_packets:,} packet limit. Moving to analysis..."
                )
                break

            total_packets += 1
            ip = get_ipv4_packet(buf, datalink)
            if not ip:
                continue

            port = None
            if ip.p in (6, 17):  # TCP or UDP
                try:
                    port = ip.data.dport
                except:
                    pass

            if port and port in ICS_PORTS:
                proto = ICS_PORTS[port]
                ics_hits[proto] += 1
                dst_ips_per_port[proto].append(ip.dst)

    if not ics_hits:
        print("[-] No ICS port traffic found in the provided PCAP.")
        return

    pattern_labels = {}
    for proto, ips in dst_ips_per_port.items():
        if len(ips) < 5:
            pattern_labels[proto] = "Insufficient Data"
            continue
        try:
            int_ips = sorted(set(struct.unpack("!I", ip_bytes)[0] for ip_bytes in ips))
            diffs = [int_ips[i + 1] - int_ips[i] for i in range(len(int_ips) - 1)]
            avg_gap = sum(diffs) / len(diffs) if diffs else 0
            pat_type = "Seq" if avg_gap <= 5 else "Rnd"
            pattern_labels[proto] = f"{pat_type} (Gap: {avg_gap:.1f})"
        except Exception:
            pattern_labels[proto] = "Error"

    fig, ax = plt.subplots(figsize=(16, 9))
    sorted_hits = ics_hits.most_common()[::-1]
    protos, counts = zip(*sorted_hits)

    bars = ax.barh(protos, counts, color="#8B0000", edgecolor="black", alpha=0.85)
    ax.set_xlabel("Packet Count", labelpad=15)
    ax.set_title("ICS Port Targeting & Scan Patterns", pad=20, fontweight="bold")
    ax.grid(axis="x", linestyle="--", alpha=0.5)
    ax.set_xlim(0, max(counts) * 1.6)

    for bar, proto, count in zip(bars, protos, counts):
        width = bar.get_width()
        pattern_text = pattern_labels.get(proto, "N/A")
        annotation = f"  {count:,} pkts | {pattern_text}"
        ax.text(
            width,
            bar.get_y() + bar.get_height() / 2,
            annotation,
            va="center",
            ha="left",
            fontsize=18,
            color="black",
        )

    plt.tight_layout()
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    print(f"[+] ICS analysis chart saved to {out_file}")


if __name__ == "__main__":
    main()
