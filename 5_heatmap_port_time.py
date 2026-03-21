"""
Script 5: Port-over-Time Heatmap (ICS Ports Focus)
Topic - Statistical Analysis & Visualization
Creates a heatmap showing activity on key ICS/OT ports across
1-minute time bins. Rows = ports, Columns = time bins.

Usage:
    python 5_heatmap_port_time.py -p <pcap_file> -o <output_dir>
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
    9600: "OMRON FINS",
}


def parse_args():
    parser = argparse.ArgumentParser(description="Port-over-Time Heatmap")
    parser.add_argument(
        "-p", "--pcap", required=True, help="Path to the input PCAP file"
    )
    parser.add_argument(
        "-o",
        "--outdir",
        default="output",
        help="Directory for output files (default: output)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    pcap_file = args.pcap
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    output_png = os.path.join(outdir, "port_heatmap.png")
    output_csv = os.path.join(outdir, "port_heatmap_data.csv")

    print(f"[*] Loading {pcap_file} ...")
    packets = rdpcap(pcap_file)
    print(f"[+] {len(packets)} packets loaded.\n")

    t0 = float(packets[0].time)
    port_bins = defaultdict(lambda: defaultdict(int))

    for pkt in packets:
        if IP not in pkt:
            continue
        t = float(pkt.time)
        bin_id = int((t - t0) / BIN_SECS)
        port = None
        if TCP in pkt:
            port = pkt[TCP].dport
        elif UDP in pkt:
            port = pkt[UDP].dport
        if port and port in PORTS_OF_INTEREST:
            port_bins[port][bin_id] += 1

    max_bin = max(
        (b for port_d in port_bins.values() for b in port_d.keys()), default=0
    )
    all_bins = list(range(max_bin + 1))

    port_labels = [f"{PORTS_OF_INTEREST[p]} ({p})" for p in PORTS_OF_INTEREST]
    port_keys = list(PORTS_OF_INTEREST.keys())
    matrix = np.array(
        [[port_bins[p].get(b, 0) for b in all_bins] for p in port_keys], dtype=float
    )
    matrix_log = np.log1p(matrix)

    fig, ax = plt.subplots(figsize=(max(12, len(all_bins) // 3), 7))
    im = ax.imshow(
        matrix_log,
        aspect="auto",
        cmap="YlOrRd",
        norm=mcolors.Normalize(vmin=0, vmax=matrix_log.max()),
    )

    ax.set_yticks(range(len(port_labels)))
    ax.set_yticklabels(port_labels, fontsize=8)

    tick_positions = list(range(0, len(all_bins), max(1, len(all_bins) // 15)))
    tick_labels = [
        datetime.datetime.fromtimestamp(
            t0 + b * BIN_SECS, tz=datetime.timezone.utc
        ).strftime("%H:%M")
        for b in tick_positions
    ]
    ax.set_xticks(tick_positions)
    ax.set_xticklabels(tick_labels, rotation=45, ha="right", fontsize=7)
    ax.set_xlabel("Time (UTC, 1-min bins)")
    ax.set_title(
        "Port Activity Heatmap – ICS/OT & Common Ports\n(color = log(packet count + 1))"
    )

    cbar = plt.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
    cbar.set_label("log(packets + 1)")

    plt.tight_layout()
    plt.savefig(output_png, dpi=150)
    print(f"[+] Heatmap saved to {output_png}")

    df = pd.DataFrame(
        matrix.astype(int), index=port_labels, columns=[f"bin_{b}" for b in all_bins]
    )
    df.to_csv(output_csv)
    print(f"[+] Heatmap data saved to {output_csv}")


if __name__ == "__main__":
    main()
