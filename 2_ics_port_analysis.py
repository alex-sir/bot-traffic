"""
Script 2: ICS Port Targeting Analysis

Generates a grouped horizontal bar chart comparing the volume and pattern
of ICS port targeting between two distinct datasets on the same axes.
Features a dynamically scaling threshold for calculating sequential vs.
random scanning patterns.

Usage Instructions:
    Run the script from the terminal, providing the paths to your PCAP files.

    Basic usage:
        python3 2_ics_port_analysis.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                       -l1 "2021" -l2 "2025" \
                                       -n 1000000

    Example with custom output directory:
        python3 2_ics_port_analysis.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                       -l1 "2021" -l2 "2025" \
                                       -o output/ \
                                       -n 1000000
"""

import argparse
import struct
import os
import gzip
import dpkt
from collections import Counter, defaultdict
import numpy as np
import matplotlib

# Use 'Agg' non-interactive backend for matplotlib so it runs headlessly
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# --- STANDARDIZED FONT CONFIGURATION ---
# Sets consistent styling across all generated charts and visualizations
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

# A mapping of well-known Industrial Control System (ICS) and IIoT destination ports
# to their respective protocol names for categorization.
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
    2404: "IEC 104",
    20547: "ProConOS",
    1962: "PCWorx",
    789: "Red Lion",
    9600: "OMRON FINS",
    47808: "BACnet",
    161: "SNMP (mgmt)",
    162: "SNMP trap",
}


def parse_args():
    """
    Parses command-line arguments to specify dataset paths, labels,
    output directory, and packet processing limits.
    """
    parser = argparse.ArgumentParser(description="Cross-Year ICS Port Analysis")
    parser.add_argument(
        "-p1", "--pcap1", nargs="+", required=True, help="Paths to Dataset 1 PCAPs"
    )
    parser.add_argument(
        "-p2", "--pcap2", nargs="+", required=True, help="Paths to Dataset 2 PCAPs"
    )
    parser.add_argument(
        "-l1", "--label1", default="Dataset 1", help="Label for Dataset 1"
    )
    parser.add_argument(
        "-l2", "--label2", default="Dataset 2", help="Label for Dataset 2"
    )
    parser.add_argument("-o", "--outdir", default="output", help="Output directory")
    parser.add_argument(
        "-n", "--max-packets", type=int, default=1000000, help="Max packets per file"
    )
    return parser.parse_args()


def open_pcap(file_path):
    """
    Opens a PCAP file, checking its magic bytes to determine if it is gzipped.
    Returns a gzip-opened stream or a standard file stream accordingly.
    """
    with open(file_path, "rb") as f:
        magic = f.read(2)
    # Magic bytes b"\x1f\x8b" indicate a Gzip compressed file
    return gzip.open(file_path, "rb") if magic == b"\x1f\x8b" else open(file_path, "rb")


def get_ipv4_packet(buf, datalink):
    """
    Extracts and returns the IPv4 packet payload from the raw frame buffer
    based on the link-layer encapsulation type (datalink).
    Returns None if the frame does not contain a valid IPv4 packet.
    """
    try:
        # Standard Ethernet encapsulation
        if datalink == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                return eth.data
        # Linux cooked capture encapsulation
        elif datalink == dpkt.pcap.DLT_LINUX_SLL:
            sll = dpkt.sll.SLL(buf)
            if isinstance(sll.data, dpkt.ip.IP):
                return sll.data
        # Raw IP encapsulations (various link-type values for raw IPv4)
        elif datalink in (12, 14, 101, 228):
            ip = dpkt.ip.IP(buf)
            if ip.v == 4:
                return ip
    except Exception:
        pass
    return None


def extract_ics_data(pcap_list, max_packets):
    """
    Parses the provided PCAPs, counts packets targeting ICS ports,
    and analyzes the IP targeting gaps to determine the scan pattern
    using a dynamically scaling threshold.
    """
    ics_hits = Counter()

    # Using a set instead of a list instantly drops duplicates upon ingestion,
    # strictly limiting the memory footprint to the unique IPs targeted.
    dst_ips_per_port = defaultdict(set)
    total_packets_parsed = 0

    # Iterate over each PCAP file
    for pcap_file in pcap_list:
        packets_this_file = 0
        try:
            with open_pcap(pcap_file) as f:
                pcap = dpkt.pcap.Reader(f)
                datalink = pcap.datalink()
                # Iterate over packets (timestamp and packet buffer) in the PCAP
                for ts, buf in pcap:
                    if packets_this_file >= max_packets:
                        break

                    # Ignore corrupt epoch 0 timestamps (1970)
                    # 946684800 is Jan 1, 2000. This blocks 1970 packets while allowing any modern PCAP.
                    if ts < 946684800:
                        continue

                    packets_this_file += 1
                    total_packets_parsed += 1

                    # Parse IPv4 packet
                    ip = get_ipv4_packet(buf, datalink)
                    if not ip:
                        continue

                    port = None
                    # TCP and UDP check
                    if ip.p in (6, 17):
                        try:
                            port = ip.data.dport
                        except:
                            pass

                    # Log the hit and uniquely store the targeted IP address
                    if port and port in ICS_PORTS:
                        proto = ICS_PORTS[port]
                        ics_hits[proto] += 1
                        dst_ips_per_port[proto].add(ip.dst)
        except Exception as e:
            print(f"[-] Error parsing {pcap_file}: {e}")

    # --- DYNAMIC THRESHOLD CALCULATION ---
    # Dynamically generates a scan threshold based on the total packets parsed
    dynamic_threshold = max(5, total_packets_parsed / 50000)

    # Calculate Scanning Patterns (Sequential vs. Random)
    patterns = {}
    for proto, ips in dst_ips_per_port.items():
        if len(ips) < 5:
            patterns[proto] = ""
            continue
        try:
            # Convert raw IP bytes to integers and sort them
            int_ips = sorted(struct.unpack("!I", ip_bytes)[0] for ip_bytes in ips)

            # Calculate the numeric distance between each sequentially targeted IP
            diffs = [int_ips[i + 1] - int_ips[i] for i in range(len(int_ips) - 1)]
            avg_gap = sum(diffs) / len(diffs) if diffs else 0

            # Compare against the dynamically generated threshold
            pat_type = "Seq" if avg_gap <= dynamic_threshold else "Rnd"

            # Format the output string with pattern and average gap size
            patterns[proto] = f"{pat_type} (Gap: {avg_gap:.1f})"
        except Exception:
            patterns[proto] = ""

    return ics_hits, patterns


def main():
    # Parse CLI arguments and establish the output path
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_file = os.path.join(args.outdir, "ics_ports.png")

    # Extract metrics for Dataset 1
    print(f"--- Extracting {args.label1} ---")
    hits1, pat1 = extract_ics_data(args.pcap1, args.max_packets)
    # Extract metrics for Dataset 2
    print(f"--- Extracting {args.label2} ---")
    hits2, pat2 = extract_ics_data(args.pcap2, args.max_packets)

    # Get a master list of all targeted protocols across both datasets
    all_protos = set(hits1.keys()).union(set(hits2.keys()))
    if not all_protos:
        print("[-] No ICS traffic found in either dataset.")
        return

    # Sort protocols based on combined volume to make the graph readable (descending order)
    sorted_protos = sorted(
        list(all_protos), key=lambda x: hits1[x] + hits2[x], reverse=True
    )

    # We invert the list so the largest bars render at the top of the horizontal chart
    sorted_protos = sorted_protos[::-1]

    counts1 = [hits1[p] for p in sorted_protos]
    counts2 = [hits2[p] for p in sorted_protos]
    patterns1 = [pat1.get(p, "") for p in sorted_protos]
    patterns2 = [pat2.get(p, "") for p in sorted_protos]

    # --- Visualization ---
    # Setup the matplotlib plot layout
    fig, ax = plt.subplots(figsize=(18, 16))
    group_spacing = 3.0
    y = np.arange(len(sorted_protos)) * group_spacing

    # Separation variables: Bars thickened (0.90), wide offset prevents text overlap
    bar_thickness = 0.90
    offset = 0.65

    # Grouped bars - Explicit offset used to create visual spacing between the datasets
    bars1 = ax.barh(
        y + offset,
        counts1,
        bar_thickness,
        label=args.label1,
        color="#4C72B0",
        edgecolor="black",
    )
    bars2 = ax.barh(
        y - offset,
        counts2,
        bar_thickness,
        label=args.label2,
        color="#C44E52",
        edgecolor="black",
    )

    # Applied specific Y-axis label to clarify the listed string names
    ax.set_ylabel("ICS Protocols / Ports", labelpad=20, fontweight="bold")
    ax.set_xlabel("Packet Count", labelpad=15, fontweight="bold")
    ax.set_yticks(y)
    ax.set_yticklabels(sorted_protos)
    ax.grid(axis="x", linestyle="--", alpha=0.5)

    max_val = max(max(counts1), max(counts2))

    # Extended X-limit (1.4x) restored so the outside text has plenty of breathing room
    ax.set_xlim(0, max_val * 1.4)

    # Remove top/right spines for a cleaner academic aesthetic
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # Annotate bars with the pattern text firmly outside to the right for dataset 1
    for i, bar in enumerate(bars1):
        width = bar.get_width()
        if width > 0 and patterns1[i]:
            ax.text(
                width + (max_val * 0.015),
                bar.get_y() + bar.get_height() / 2,
                patterns1[i],
                va="center",
                ha="left",
                fontsize=20,
                color="black",
            )

    # Annotate bars with the pattern text firmly outside to the right for dataset 2
    for i, bar in enumerate(bars2):
        width = bar.get_width()
        if width > 0 and patterns2[i]:
            ax.text(
                width + (max_val * 0.015),
                bar.get_y() + bar.get_height() / 2,
                patterns2[i],
                va="center",
                ha="left",
                fontsize=20,
                color="black",
            )

    # Render custom legend location
    ax.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1),
        ncol=2,
        framealpha=0.9,
        edgecolor="black",
    )

    plt.tight_layout()
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    print(f"[+] Combined ICS analysis chart saved to {out_file}")


if __name__ == "__main__":
    main()
