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

# --- STANDARDIZED FONT CONFIGURATION ---
plt.rcParams.update(
    {
        "font.size": 22,
        "font.family": "serif",
        "axes.labelsize": 26,
        "xtick.labelsize": 22,
        "ytick.labelsize": 22,
        "legend.fontsize": 22,
        "figure.dpi": 300,
    }
)


def parse_args():
    parser = argparse.ArgumentParser(description="PCAP Overview & Basic Statistics")
    # --- nargs='+' allows accepting an unlimited list of files ---
    parser.add_argument(
        "-p", "--pcap", nargs="+", required=True, help="Paths to input PCAPs"
    )
    parser.add_argument("-o", "--outdir", default="output", help="Output directory")
    parser.add_argument(
        "-n", "--max-packets", type=int, default=1000000, help="Max packets per file"
    )
    return parser.parse_args()


# --- HELPER: Transparent Compressed File Handling ---
# Network telescope data is massive and almost always stored as .pcap.gz.
# This reads the first two "magic bytes" to determine if the file is gzipped.
# If it is, it opens it with gzip.open; otherwise, it falls back to standard open.
def open_pcap(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(2)
    return gzip.open(file_path, "rb") if magic == b"\x1f\x8b" else open(file_path, "rb")


# --- HELPER: Datalink Layer Parsing ---
# dpkt is extremely fast because it is "dumb" - it doesn't automatically figure out
# the OSI layer structure like Scapy does. We have to manually check the datalink
# type (Ethernet, Linux Cooked Capture, or Raw IP) to correctly extract the IPv4 layer.
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
    out_file = os.path.join(args.outdir, "pcap_overview_table.png")

    # Global tracking variables across all files
    total_packets, total_bytes = 0, 0
    protocols, src_ips, dst_ips, dst_ports = Counter(), Counter(), Counter(), Counter()

    # We must track active duration (time spent actually capturing) rather than absolute duration
    # to avoid the 11-hour "dead" gaps destroying our Packet Rate metric.
    active_duration_sec = 0
    t_start = None

    # --- PHASE 1: Data Extraction (Looping over all provided files) ---
    for pcap_file in args.pcap:
        print(f"[*] Parsing {os.path.basename(pcap_file)}...")
        packets_this_file = 0
        file_timestamps = []

        with open_pcap(pcap_file) as f:
            pcap = dpkt.pcap.Reader(f)
            datalink = pcap.datalink()

            for ts, buf in pcap:
                # Cutoff applies per file to maintain Stratified Sampling
                if packets_this_file >= args.max_packets:
                    break

                packets_this_file += 1
                total_packets += 1
                total_bytes += len(buf)

                ip = get_ipv4_packet(buf, datalink)
                if ip:
                    file_timestamps.append(ts)
                    src_ips[ip.src] += 1
                    dst_ips[ip.dst] += 1

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

        # Calculate active time spent in this specific file
        if file_timestamps:
            file_start = min(file_timestamps)
            if t_start is None or file_start < t_start:
                t_start = file_start
            active_duration_sec += max(file_timestamps) - file_start

    # --- PHASE 2: Calculation ---
    start_time_str = (
        datetime.datetime.fromtimestamp(t_start, tz=datetime.timezone.utc)
        if t_start
        else "N/A"
    )
    active_duration_sec = active_duration_sec if active_duration_sec > 0 else 1

    volume_mb = total_bytes / (1024 * 1024)
    bandwidth_mbps = (total_bytes * 8 / 1_000_000) / active_duration_sec
    pkt_rate = total_packets / active_duration_sec
    dominant_proto = protocols.most_common(1)[0][0] if protocols else "N/A"

    # --- PHASE 3: Visualization ---
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.axis("tight")
    ax.axis("off")

    table_data = [
        ["Total Files Analyzed", f"{len(args.pcap)}"],
        ["Initial Start Time (UTC)", f"{start_time_str}"],
        ["Active Capture Duration", f"{active_duration_sec:.2f} seconds"],
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
    table.set_fontsize(17)  # Standardized font size applied to the table
    table.scale(1, 3.0)

    # Cell styling block (colors, weights, etc.)
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor("#DDDDDD")
        if row == 0:
            cell.set_text_props(weight="bold", color="white", size=24)
            cell.set_facecolor("#2B475D")
            cell.set_text_props(ha="center")
        else:
            cell.set_facecolor("#F8F9FA" if row % 2 == 0 else "#FFFFFF")
            if col == 0:
                cell.set_text_props(weight="bold", ha="left")
            else:
                cell.set_text_props(ha="right")
        cell.PAD = 0.05

    plt.tight_layout()
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    print(f"[+] Summary table saved to {out_file}")


if __name__ == "__main__":
    main()
