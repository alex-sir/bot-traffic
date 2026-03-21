"""
Script 5: Port-over-Time Heatmap (ICS Ports Focus)
Topic - Statistical Analysis & Visualization
Creates a heatmap showing activity on key ICS/OT ports across
1-minute time bins. Rows = ports, Columns = time bins.
"""

import datetime
from collections import defaultdict

import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from scapy.all import rdpcap, IP, TCP, UDP

PCAP_FILE = "traffic-2025-01-20.00-1M.pcap"
BIN_SECS = 60

# Ports to include in heatmap: ICS + common scanning ports for comparison
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


def main():
    print(f"[*] Loading {PCAP_FILE} ...")
    packets = rdpcap(PCAP_FILE)
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

    # Log-scale for visibility (add 1 to avoid log(0))
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

    # X-axis: every 10th bin labelled
    tick_positions = list(range(0, len(all_bins), max(1, len(all_bins) // 15)))
    tick_labels = [
        datetime.datetime.utcfromtimestamp(t0 + b * BIN_SECS).strftime("%H:%M")
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
    plt.savefig("port_heatmap.png", dpi=150)
    print("[+] Heatmap saved to port_heatmap.png")

    # Save raw matrix as CSV
    df = pd.DataFrame(
        matrix.astype(int), index=port_labels, columns=[f"bin_{b}" for b in all_bins]
    )
    df.to_csv("port_heatmap_data.csv")
    print("[+] Heatmap data saved to port_heatmap_data.csv")


if __name__ == "__main__":
    main()
