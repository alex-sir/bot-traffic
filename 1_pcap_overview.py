"""
Script 1: PCAP Overview & Basic Statistics Summary

This script reads a PCAP file iteratively and produces a single, high-quality,
table summarizing the core metrics of the network traffic,
including data volume, packet rates, and ICS vs Non-ICS traffic proportions.

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

# Reference dictionary for identifying Industrial Control System ports
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
def open_pcap(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(2)
    return gzip.open(file_path, "rb") if magic == b"\x1f\x8b" else open(file_path, "rb")


# --- HELPER: Datalink Layer Parsing ---
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
    ics_packets = 0
    protocols, src_ips, dst_ips, dst_ports = Counter(), Counter(), Counter(), Counter()

    # We must track active duration (time spent actually capturing) rather than absolute duration
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

                    port = None
                    if ip.p == 6:
                        protocols["TCP"] += 1
                        try:
                            port = ip.data.dport
                            dst_ports[port] += 1
                        except:
                            pass
                    elif ip.p == 17:
                        protocols["UDP"] += 1
                        try:
                            port = ip.data.dport
                            dst_ports[port] += 1
                        except:
                            pass
                    elif ip.p == 1:
                        protocols["ICMP"] += 1
                    else:
                        protocols["Other"] += 1

                    # Check if the extracted port targets critical infrastructure
                    if port and port in ICS_PORTS:
                        ics_packets += 1

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

    # Calculate the percentage of traffic dedicated to ICS scanning vs Non-ICS
    ics_percentage = (ics_packets / total_packets) * 100 if total_packets > 0 else 0
    non_ics_packets = total_packets - ics_packets
    non_ics_percentage = (
        (non_ics_packets / total_packets) * 100 if total_packets > 0 else 0
    )

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
        ["ICS Port Traffic", f"{ics_percentage:.4f}% ({ics_packets:,} pkts)"],
        ["Non-ICS Traffic", f"{non_ics_percentage:.4f}% ({non_ics_packets:,} pkts)"],
        ["Unique Source IPs", f"{len(src_ips):,}"],
        ["Unique Destination IPs", f"{len(dst_ips):,}"],
        ["Unique Destination Ports", f"{len(dst_ports):,}"],
    ]

    table = ax.table(
        cellText=table_data, colLabels=["Metric", "Value"], loc="center", cellLoc="left"
    )
    table.auto_set_font_size(False)
    table.set_fontsize(17)  # Standardized font size applied to the table
    table.scale(1.2, 3.0)  # Horizontal scaling to fit the long timestamp string

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
