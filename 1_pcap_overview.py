"""
Script 1: PCAP Overview & Basic Statistics Summary

This script reads a PCAP file iteratively and produces a single, high-quality,
table summarizing the core metrics of the network traffic,
including data volume and packet rates.

Usage Instructions:
    Run the script from the terminal, providing the path to your PCAP file.

    Basic usage:
        python 1_pcap_overview.py -p <path_to_pcap_file> -n 1000000

    Example with custom output directory:
        python 1_pcap_overview.py -p data/traffic-2025-01-20.00-1M.pcap -o output/ -n 71500000
"""

import argparse
import datetime
import os
import gzip
from collections import Counter
import dpkt
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({"font.family": "serif", "figure.dpi": 300})


def parse_args():
    parser = argparse.ArgumentParser(description="PCAP Overview & Basic Statistics")
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


# --- HELPER: Transparent Compressed File Handling ---
def open_pcap(file_path):
    # Network telescope data is massive and almost always stored as .pcap.gz.
    # This reads the first two "magic bytes" to determine if the file is gzipped.
    # If it is, it opens it with gzip.open; otherwise, it falls back to standard open.
    with open(file_path, "rb") as f:
        magic = f.read(2)
    return gzip.open(file_path, "rb") if magic == b"\x1f\x8b" else open(file_path, "rb")


# --- HELPER: Datalink Layer Parsing ---
def get_ipv4_packet(buf, datalink):
    # dpkt is extremely fast because it is "dumb" - it doesn't automatically figure out
    # the OSI layer structure like Scapy does. We have to manually check the datalink
    # type (Ethernet, Linux Cooked Capture, or Raw IP) to correctly extract the IPv4 layer.
    try:
        if datalink == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                return eth.data
        elif datalink == dpkt.pcap.DLT_LINUX_SLL:
            sll = dpkt.sll.SLL(buf)
            if isinstance(sll.data, dpkt.ip.IP):
                return sll.data
        elif datalink in (12, 14, 101, 228):  # Raw IP variants
            ip = dpkt.ip.IP(buf)
            if ip.v == 4:
                return ip
    except Exception:
        pass
    return None


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_file = os.path.join(args.outdir, "pcap_overview_table.png")

    print(f"[*] Fast Streaming {args.pcap} using dpkt ...")

    # Initialize metric counters
    total_packets, total_bytes = 0, 0
    protocols, src_ips, dst_ips, dst_ports = Counter(), Counter(), Counter(), Counter()
    timestamps = []

    # --- PHASE 1: Data Extraction ---
    with open_pcap(args.pcap) as f:
        pcap = dpkt.pcap.Reader(f)
        datalink = pcap.datalink()
        for ts, buf in pcap:
            # Enforce volumetric sampling limit
            if total_packets >= args.max_packets:
                print(
                    f"[*] Reached {args.max_packets:,} packet limit. Moving to analysis..."
                )
                break

            total_packets += 1
            total_bytes += len(buf)

            ip = get_ipv4_packet(buf, datalink)
            if ip:
                timestamps.append(ts)
                src_ips[ip.src] += 1
                dst_ips[ip.dst] += 1

                # Check underlying protocol (TCP=6, UDP=17, ICMP=1)
                if ip.p == 6:
                    protocols["TCP"] += 1
                    try:
                        dst_ports[ip.data.dport] += 1
                    except:
                        pass
                elif ip.p == 17:
                    protocols["UDP"] += 1
                    try:
                        dst_ports[ip.data.dport] += 1
                    except:
                        pass
                elif ip.p == 1:
                    protocols["ICMP"] += 1
                else:
                    protocols["Other"] += 1
            else:
                protocols["Non-IP"] += 1

    # --- PHASE 2: Calculation ---
    if timestamps:
        t_start = datetime.datetime.fromtimestamp(
            min(timestamps), tz=datetime.timezone.utc
        )
        duration = max(timestamps) - min(timestamps)
    else:
        t_start, duration = "N/A", 0

    # Prevent division by zero if capture is less than 1 second
    duration_sec = duration if duration > 0 else 1

    volume_mb = total_bytes / (1024 * 1024)
    # Bandwidth calculation: (Bytes * 8 bits) / 1 million = Mbps
    bandwidth_mbps = (total_bytes * 8 / 1_000_000) / duration_sec
    pkt_rate = total_packets / duration_sec
    dominant_proto = protocols.most_common(1)[0][0] if protocols else "N/A"

    # --- PHASE 3: Visualization ---
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.axis("tight")
    ax.axis("off")  # Turn off chart axes since this is just a table

    table_data = [
        ["Capture Start Time (UTC)", f"{t_start}"],
        ["Capture Duration", f"{duration:.2f} seconds"],
        ["Total Packets", f"{total_packets:,}"],
        ["Total Data Volume", f"{volume_mb:.2f} MB"],
        ["Average Packet Rate", f"{pkt_rate:.2f} pkts/sec"],
        ["Average Bandwidth", f"{bandwidth_mbps:.3f} Mbps"],
        ["Dominant Protocol", f"{dominant_proto}"],
        ["Unique Source IPs", f"{len(src_ips):,}"],
        ["Unique Destination IPs", f"{len(dst_ips):,}"],
        ["Unique Destination Ports", f"{len(dst_ports):,}"],
    ]

    table = ax.table(
        cellText=table_data, colLabels=["Metric", "Value"], loc="center", cellLoc="left"
    )
    table.auto_set_font_size(False)
    table.set_fontsize(14)
    table.scale(1, 2.2)  # Scale Y-axis of the table to give rows breathing room

    # Apply alternating row colors and formatting
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor("#DDDDDD")
        if row == 0:
            # Header row styling
            cell.set_text_props(weight="bold", color="white", size=15)
            cell.set_facecolor("#2B475D")
            cell.set_text_props(ha="center")
        else:
            # Alternating gray/white data rows
            cell.set_facecolor("#F8F9FA" if row % 2 == 0 else "#FFFFFF")
            if col == 0:
                cell.set_text_props(weight="bold", ha="left")
            else:
                cell.set_text_props(ha="right")

        # Matplotlib table text touches borders by default. This forces padding.
        cell.PAD = 0.05

    plt.title(
        "Merit ORION Network Telescope Traffic Summary",
        fontsize=18,
        fontweight="bold",
        pad=20,
    )
    plt.tight_layout()
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    print(f"[+] Summary table saved to {out_file}")


if __name__ == "__main__":
    main()
