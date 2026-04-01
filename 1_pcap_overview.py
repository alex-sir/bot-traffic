"""
Script 1: PCAP Overview & Basic Statistics Summary

This script reads a PCAP file and produces a single, high-quality,
table summarizing the core metrics of the network traffic,
including data volume and packet rates.

Usage Instructions:
    Run the script from the terminal, providing the path to your PCAP file.

    Basic usage:
        python 1_pcap_overview.py -p <path_to_pcap_file>

    Example with custom output directory:
        python 1_pcap_overview.py -p data/traffic-2025-01-20.00-1M.pcap -o output/
"""

import argparse
import datetime
import os
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Set font family
plt.rcParams.update({"font.family": "serif", "figure.dpi": 300})


def parse_args():
    parser = argparse.ArgumentParser(description="PCAP Overview & Basic Statistics")
    parser.add_argument(
        "-p", "--pcap", required=True, help="Path to the input PCAP file"
    )
    parser.add_argument(
        "-o", "--outdir", default="output", help="Directory for output files"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_file = os.path.join(args.outdir, "pcap_overview_table.png")

    print(f"[*] Loading {args.pcap} ...")
    packets = rdpcap(args.pcap)
    total_packets = len(packets)

    protocols, src_ips, dst_ips, dst_ports = Counter(), Counter(), Counter(), Counter()
    timestamps = []
    total_bytes = 0

    # Parse packets
    for pkt in packets:
        total_bytes += len(pkt)
        if IP in pkt:
            timestamps.append(float(pkt.time))
            src_ips[pkt[IP].src] += 1
            dst_ips[pkt[IP].dst] += 1

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

    # Calculate Time and Rate Metrics
    if timestamps:
        t_start = datetime.datetime.fromtimestamp(
            min(timestamps), tz=datetime.timezone.utc
        )
        duration = max(timestamps) - min(timestamps)
    else:
        t_start = "N/A"
        duration = 0

    duration_sec = duration if duration > 0 else 1  # Prevent division by zero
    volume_mb = total_bytes / (1024 * 1024)
    bandwidth_mbps = (total_bytes * 8 / 1_000_000) / duration_sec
    pkt_rate = total_packets / duration_sec
    dominant_proto = protocols.most_common(1)[0][0] if protocols else "N/A"

    # --- Plotting the Table ---
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.axis("tight")
    ax.axis("off")

    # Table Data Structure
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

    # Create Table
    table = ax.table(
        cellText=table_data, colLabels=["Metric", "Value"], loc="center", cellLoc="left"
    )

    # Stylize the Table
    table.auto_set_font_size(False)
    table.set_fontsize(14)
    table.scale(1, 2.2)  # Adjust row height

    # Iterate through cells to apply colors and borders
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor("#DDDDDD")  # Light gray borders
        if row == 0:
            # Header styling
            cell.set_text_props(weight="bold", color="white", size=15)
            cell.set_facecolor("#2B475D")  # Dark Slate Blue
            cell.set_text_props(ha="center")
        else:
            # Alternating row colors
            if row % 2 == 0:
                cell.set_facecolor("#F8F9FA")  # Very light gray
            else:
                cell.set_facecolor("#FFFFFF")  # White

            # Add padding by adjusting horizontal alignment
            if col == 0:
                cell.set_text_props(weight="bold", ha="left")
            else:
                cell.set_text_props(ha="right")

        # Inject minor padding hack for cell text
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
