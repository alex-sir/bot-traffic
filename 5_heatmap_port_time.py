"""
Script 5: Port-over-Time Heatmap Matrix

This script creates a high-resolution, explicitly defined matrix heatmap
showing packet activity on key ICS/OT ports across 1-hour time bins.
It uses rigid gridlines to separate the data into a true table-like
matrix, with cells displaying the exact packet count if activity occurred.

Usage Instructions:
    Run the script from the terminal, providing the path to your PCAP file.

    Basic usage:
        python 5_heatmap_port_time.py -p <path_to_pcap_file> -n 1000000

    Example with custom output directory:
        python 5_heatmap_port_time.py -p data/traffic.pcap -o output/ -n 71500000
"""

import argparse
import datetime
import os
import gzip
import dpkt
from collections import defaultdict
import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

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

# --- 1 hour bins to support multi-day aggregation ---
BIN_SECS = 3600

PORTS_OF_INTEREST = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    502: "Modbus",
    102: "S7/ISO-TSAP",
    2404: "IEC 104",
    20000: "DNP3",
    44818: "EtherNet/IP",
    4840: "OPC UA",
    47808: "BACnet",
}


def parse_args():
    parser = argparse.ArgumentParser(description="Port-over-Time Heatmap")
    parser.add_argument(
        "-p", "--pcap", nargs="+", required=True, help="Paths to input PCAPs"
    )
    parser.add_argument("-o", "--outdir", default="output", help="Output directory")
    parser.add_argument(
        "-n", "--max-packets", type=int, default=1000000, help="Max packets per file"
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
    out_png = os.path.join(args.outdir, "port_heatmap_matrix.png")
    out_csv = os.path.join(args.outdir, "port_heatmap_data.csv")

    t0 = None
    port_bins = defaultdict(lambda: defaultdict(int))

    # Sort files by name to guarantee chronological processing for t0 discovery
    sorted_pcaps = sorted(args.pcap)

    # --- PHASE 1: Data Extraction & Bucketing ---
    for pcap_file in sorted_pcaps:
        print(f"[*] Parsing {os.path.basename(pcap_file)}...")
        packets_this_file = 0

        with open_pcap(pcap_file) as f:
            pcap = dpkt.pcap.Reader(f)
            datalink = pcap.datalink()
            for ts, buf in pcap:
                if packets_this_file >= args.max_packets:
                    break
                packets_this_file += 1

                # Baseline offset is set to the very first packet of the first chronologically ordered file
                if t0 is None:
                    t0 = ts

                ip = get_ipv4_packet(buf, datalink)
                if not ip:
                    continue

                port = None
                if ip.p in (6, 17):
                    try:
                        port = ip.data.dport
                    except:
                        pass

                if port and port in PORTS_OF_INTEREST:
                    bin_id = int((ts - t0) / BIN_SECS)
                    port_bins[port][bin_id] += 1

    if t0 is None:
        print("[-] No packets found to analyze.")
        return

    # --- PHASE 2: Matrix Construction ---
    max_bin = max((b for d in port_bins.values() for b in d.keys()), default=0)
    all_bins = list(range(max_bin + 1))
    port_keys = list(PORTS_OF_INTEREST.keys())
    port_labels = [f"{PORTS_OF_INTEREST[p]} ({p})" for p in port_keys]

    matrix = np.array(
        [[port_bins[p].get(b, 0) for b in all_bins] for p in port_keys], dtype=float
    )
    matrix_log = np.log1p(matrix)

    # --- PHASE 3: Visualization ---
    # Width calculation is capped to prevent massive multi-day matrices from breaking matplotlib
    fig_width = min(max(18, len(all_bins) * 0.8), 60)
    fig_height = max(12, len(port_keys) * 0.9)
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))

    im = ax.imshow(
        matrix_log,
        aspect="auto",
        cmap="YlOrRd",
        norm=mcolors.Normalize(vmin=0, vmax=matrix_log.max()),
    )

    ax.set_xticks(np.arange(-0.5, len(all_bins), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(port_keys), 1), minor=True)
    ax.grid(which="minor", color="black", linestyle="-", linewidth=1.5)
    ax.grid(which="major", visible=False)

    ax.set_yticks(range(len(port_labels)))
    ax.set_yticklabels(port_labels)
    ax.set_ylabel("Targeted Protocol / Port", labelpad=20, fontweight="bold")

    time_labels = [
        datetime.datetime.fromtimestamp(
            t0 + b * BIN_SECS, tz=datetime.timezone.utc
        ).strftime("%m-%d %H:00")
        for b in all_bins
    ]

    # Tick Label Optimizer: If there are too many columns, only show tick labels every N hours to prevent overlapping
    tick_spacing = max(1, len(all_bins) // 30)
    ax.set_xticks(range(0, len(all_bins), tick_spacing))
    ax.set_xticklabels(
        [time_labels[i] for i in range(0, len(all_bins), tick_spacing)],
        rotation=45,
        ha="right",
    )
    ax.set_xlabel("Time Bins (UTC, 1-Hour Intervals)", labelpad=20, fontweight="bold")

    # Text Overlay Guard: Only draw physical numbers inside the cells if the matrix isn't incredibly wide
    if len(all_bins) <= 48:
        for i in range(len(port_keys)):
            for j in range(len(all_bins)):
                val = int(matrix[i, j])
                if val > 0:
                    text_color = (
                        "white"
                        if matrix_log[i, j] > (matrix_log.max() * 0.6)
                        else "black"
                    )
                    ax.text(
                        j,
                        i,
                        str(val),
                        ha="center",
                        va="center",
                        color=text_color,
                        fontsize=22,  # Updated to match standardized fonts
                        fontweight="bold",
                    )

    cbar = plt.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
    cbar.set_label(
        "Log(Packet Count + 1)",
        rotation=270,
        labelpad=30,
        fontweight="bold",
        fontsize=26,  # Matched to axes.labelsize
    )
    cbar.ax.tick_params(labelsize=22)  # Matched to xtick/ytick labelsize

    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches="tight")

    df = pd.DataFrame(
        matrix.astype(int), index=port_labels, columns=[f"bin_{b}" for b in all_bins]
    )
    df.to_csv(out_csv)
    print(f"[+] Heatmap raw data saved to {out_csv}")


if __name__ == "__main__":
    main()
