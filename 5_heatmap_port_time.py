"""
Script 5: Port-over-Time Heatmap Matrix

This script creates a high-resolution, explicitly defined matrix heatmap
showing packet activity on key ICS/OT ports across 1-minute time bins.
It uses rigid gridlines to separate the data into a true table-like
matrix, with cells displaying the exact packet count if activity occurred.

Usage Instructions:
    Run the script from the terminal, providing the path to your PCAP file.

    Basic usage:
        python 5_heatmap_port_time.py -p <path_to_pcap_file>

    Example with custom output directory:
        python 5_heatmap_port_time.py -p data/traffic.pcap -o output/
"""

import argparse
import datetime
import os
from collections import defaultdict
import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from scapy.all import rdpcap, IP, TCP, UDP

plt.rcParams.update(
    {
        "font.size": 18,
        "font.family": "serif",
        "axes.labelsize": 20,
        "axes.titlesize": 24,
        "xtick.labelsize": 16,
        "ytick.labelsize": 18,
        "figure.dpi": 300,
    }
)

BIN_SECS = 60

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
    parser.add_argument("-p", "--pcap", required=True, help="Path to input PCAP")
    parser.add_argument("-o", "--outdir", default="output", help="Output directory")
    return parser.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_png = os.path.join(args.outdir, "port_heatmap_matrix.png")
    out_csv = os.path.join(args.outdir, "port_heatmap_data.csv")

    print(f"[*] Loading {args.pcap} ...")
    packets = rdpcap(args.pcap)
    if not packets:
        print("[-] No packets found to analyze.")
        return

    t0 = float(packets[0].time)
    port_bins = defaultdict(lambda: defaultdict(int))

    for pkt in packets:
        if IP not in pkt:
            continue
        t = float(pkt.time)
        bin_id = int((t - t0) / BIN_SECS)

        port = (
            pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
        )
        if port and port in PORTS_OF_INTEREST:
            port_bins[port][bin_id] += 1

    max_bin = max((b for d in port_bins.values() for b in d.keys()), default=0)
    all_bins = list(range(max_bin + 1))

    port_keys = list(PORTS_OF_INTEREST.keys())
    port_labels = [f"{PORTS_OF_INTEREST[p]} ({p})" for p in port_keys]

    # Build the matrix
    matrix = np.array(
        [[port_bins[p].get(b, 0) for b in all_bins] for p in port_keys], dtype=float
    )
    matrix_log = np.log1p(matrix)

    # --- Plotting ---
    # Increased scale multipliers to make the individual matrix cells larger
    fig_width = max(18, len(all_bins) * 1.3)
    fig_height = max(12, len(port_keys) * 0.9)
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))

    im = ax.imshow(
        matrix_log,
        aspect="auto",
        cmap="YlOrRd",
        norm=mcolors.Normalize(vmin=0, vmax=matrix_log.max()),
    )

    # --- Creating the "Actual Matrix" Grid Look ---
    # Set minor ticks exactly in between the major ticks to draw borders around cells
    ax.set_xticks(np.arange(-0.5, len(all_bins), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(port_keys), 1), minor=True)

    # Draw thick gridlines on the minor ticks to create the matrix cells
    ax.grid(which="minor", color="black", linestyle="-", linewidth=2)
    # Ensure major ticks don't draw gridlines over the text
    ax.grid(which="major", visible=False)

    # Configure Y-axis (Ports)
    ax.set_yticks(range(len(port_labels)))
    ax.set_yticklabels(port_labels)
    ax.set_ylabel("Targeted Protocol / Port", labelpad=15, fontweight="bold")

    # Configure X-axis (Time Bins)
    time_labels = [
        datetime.datetime.fromtimestamp(
            t0 + b * BIN_SECS, tz=datetime.timezone.utc
        ).strftime("%H:%M")
        for b in all_bins
    ]
    ax.set_xticks(range(len(all_bins)))
    ax.set_xticklabels(time_labels, rotation=45, ha="right")
    ax.set_xlabel("Time Bins (UTC, 1-Minute Intervals)", labelpad=15, fontweight="bold")

    ax.set_title("Port Activity Matrix (Hits per Minute)", pad=20, fontweight="bold")

    # Add numeric annotations inside the matrix cells
    for i in range(len(port_keys)):
        for j in range(len(all_bins)):
            val = int(matrix[i, j])
            if val > 0:
                # Use a dark color for text if the cell is light, white if the cell is dark
                text_color = (
                    "white" if matrix_log[i, j] > (matrix_log.max() * 0.6) else "black"
                )
                ax.text(
                    j,
                    i,
                    str(val),
                    ha="center",
                    va="center",
                    color=text_color,
                    fontsize=24,
                    fontweight="black",
                    family="sans-serif",
                )

    # Add colorbar
    cbar = plt.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
    cbar.set_label(
        "Log(Packet Count + 1)", rotation=270, labelpad=25, fontweight="bold"
    )

    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches="tight")
    print(f"[+] Matrix heatmap saved to {out_png}")

    # Save raw data alongside the image
    df = pd.DataFrame(
        matrix.astype(int), index=port_labels, columns=[f"bin_{b}" for b in all_bins]
    )
    df.to_csv(out_csv)
    print(f"[+] Heatmap raw data saved to {out_csv}")


if __name__ == "__main__":
    main()
