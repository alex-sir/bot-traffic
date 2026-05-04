"""
Script 5: Cross-Year Delta Heatmap (ICS Port-over-Time)

Generates a "Difference Matrix" comparing two datasets exclusively for ICS ports.
It aligns both captures to relative time (Minute 0, Minute 1, etc.),
subtracts the traffic volume of Dataset 1 from Dataset 2, and plots the delta.
Red cells indicate a surge in traffic in Dataset 2; Blue cells indicate a drop.

Usage Instructions:
    Run the script from the terminal, providing paths to both sets of PCAP files.

    Basic usage:
        python3 5_heatmap_port_time.py -p1 data/2021/*.pcap -p2 data/2025/*.pcap \
                                       -l1 "2021" -l2 "2025" \
                                       -n 1000000

    Example with custom output directory:
        python3 5_heatmap_port_time.py -p1 data/2021/*.pcap -p2 data/2025/*.pcap \
                                       -l1 "2021" -l2 "2025" \
                                       -o output/ \
                                       -n 1000000
"""

import argparse
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

BIN_SECS = 60

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
    parser = argparse.ArgumentParser(description="Cross-Year Delta Heatmap")
    parser.add_argument(
        "-p1", "--pcap1", nargs="+", required=True, help="Dataset 1 PCAPs"
    )
    parser.add_argument(
        "-p2", "--pcap2", nargs="+", required=True, help="Dataset 2 PCAPs"
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


def extract_heatmap_data(pcap_list, max_packets):
    """
    Extracts time-binned port activity, normalizing the timeline
    so the first packet establishes Relative Time = 0.
    """
    t0 = None
    port_bins = defaultdict(lambda: defaultdict(int))
    sorted_pcaps = sorted(pcap_list)

    for pcap_file in sorted_pcaps:
        print(f"[*] Parsing {os.path.basename(pcap_file)}...")
        packets_this_file = 0

        try:
            with open_pcap(pcap_file) as f:
                pcap = dpkt.pcap.Reader(f)
                datalink = pcap.datalink()
                for ts, buf in pcap:
                    if packets_this_file >= max_packets:
                        break

                    # Ignore corrupt epoch 0 timestamps (1970)
                    if ts < 946684800 or ts > 2000000000:
                        continue

                    # Establish the baseline time for this specific dataset
                    if t0 is None:
                        t0 = ts

                    packets_this_file += 1
                    ip = get_ipv4_packet(buf, datalink)
                    if not ip:
                        continue

                    port = None
                    if ip.p in (6, 17):
                        try:
                            port = ip.data.dport
                        except:
                            pass

                    # Filter specifically for ICS ports
                    if port and port in ICS_PORTS:
                        bin_id = int((ts - t0) / BIN_SECS)

                        # 1-year continuous cap (525,600 minutes).
                        if 0 <= bin_id <= 525600:
                            port_bins[port][bin_id] += 1
        except Exception as e:
            print(f"[-] Error parsing {pcap_file}: {e}")

    max_bin = max([b for d in port_bins.values() for b in d.keys()] + [0])
    return port_bins, max_bin


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_png = os.path.join(args.outdir, "ics_heatmap_delta.png")
    out_csv = os.path.join(args.outdir, "ics_heatmap_delta.csv")

    print(f"--- Extracting {args.label1} ---")
    bins1, max_bin1 = extract_heatmap_data(args.pcap1, args.max_packets)

    print(f"--- Extracting {args.label2} ---")
    bins2, max_bin2 = extract_heatmap_data(args.pcap2, args.max_packets)

    # --- PHASE 2: Matrix Alignment & Delta Calculation ---
    global_max_bin = max(max_bin1, max_bin2)
    all_bins = list(range(global_max_bin + 1))

    port_keys = list(ICS_PORTS.keys())
    port_labels = [f"{ICS_PORTS[p]} ({p})" for p in port_keys]

    # Pre-allocate NumPy arrays of zeros instead of building massive Python lists.
    matrix1 = np.zeros((len(port_keys), global_max_bin + 1), dtype=float)
    matrix2 = np.zeros((len(port_keys), global_max_bin + 1), dtype=float)

    for i, p in enumerate(port_keys):
        for b, count in bins1[p].items():
            if b <= global_max_bin:
                matrix1[i, b] = count
        for b, count in bins2[p].items():
            if b <= global_max_bin:
                matrix2[i, b] = count

    # Calculate the Difference (Newer Dataset - Older Dataset)
    delta_matrix = matrix2 - matrix1

    # --- PHASE 3: Visualization ---
    fig_width = min(max(18, len(all_bins) * 1.2), 60)
    fig_height = max(12, len(port_keys) * 0.9)
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))

    # Calculate the maximum absolute value to center the diverging colormap strictly at 0
    abs_max = max(abs(delta_matrix.max()), abs(delta_matrix.min()))
    if abs_max == 0:
        abs_max = 1

    # RdBu_r provides a classic "Heat/Cold" visual. Red = Growth, Blue = Decline.
    im = ax.imshow(
        delta_matrix,
        aspect="auto",
        cmap="RdBu_r",
        norm=mcolors.TwoSlopeNorm(vmin=-abs_max, vcenter=0, vmax=abs_max),
    )

    # Context-aware grid lines.
    # Only draw vertical minor lines if the bin count is small enough to not crash matplotlib.
    if len(all_bins) <= 100:
        ax.set_xticks(np.arange(-0.5, len(all_bins), 1), minor=True)
        ax.set_yticks(np.arange(-0.5, len(port_keys), 1), minor=True)
        ax.grid(which="minor", color="black", linestyle="-", linewidth=1.5)
    else:
        # For large datasets, only draw horizontal gridlines to separate the ports cleanly
        ax.set_yticks(np.arange(-0.5, len(port_keys), 1), minor=True)
        ax.grid(which="minor", axis="y", color="black", linestyle="-", linewidth=1.5)

    ax.grid(which="major", visible=False)

    ax.set_yticks(range(len(port_labels)))
    ax.set_yticklabels(port_labels)
    ax.set_ylabel("Targeted Protocol / Port", labelpad=20, fontweight="bold")

    # Time labels memory optimization (only generating labels for visible ticks)
    tick_spacing = max(1, len(all_bins) // 30)
    tick_positions = list(range(0, len(all_bins), tick_spacing))
    time_labels = [f"T+{b}" for b in tick_positions]

    ax.set_xticks(tick_positions)
    ax.set_xticklabels(time_labels, rotation=0)
    ax.set_xlabel(
        f"Relative Time Bins ({BIN_SECS}-Second Intervals)",
        labelpad=20,
        fontweight="bold",
    )

    # --- Text Overlay Logic ---
    if len(all_bins) <= 48:
        for i in range(len(port_keys)):
            for j in range(len(all_bins)):
                val = int(delta_matrix[i, j])
                if val != 0:
                    text_str = f"+{val:,}" if val > 0 else f"{val:,}"
                    intensity = abs(val) / abs_max
                    text_color = "white" if intensity > 0.5 else "black"

                    ax.text(
                        j,
                        i,
                        text_str,
                        ha="center",
                        va="center",
                        color=text_color,
                        fontsize=20,
                        fontweight="bold",
                    )

    cbar = plt.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
    cbar.set_label(
        f"Δ Packet Count ({args.label2} - {args.label1})",
        rotation=270,
        labelpad=35,
        fontweight="bold",
        fontsize=26,
    )
    cbar.ax.tick_params(labelsize=22)

    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches="tight")

    # Transpose the DataFrame (.T).
    # By making the time bins rows and the ports columns, we bypass the Pandas block manager OOM issue.
    df = pd.DataFrame(
        delta_matrix.astype(int).T,
        index=[f"T+{b}" for b in all_bins],
        columns=port_labels,
    )
    df.index.name = "Relative_Time_Bin"
    df.to_csv(out_csv)
    print(f"[+] Delta Heatmap saved to {out_png}")
    print(f"[+] Heatmap CSV data saved to {out_csv}")


if __name__ == "__main__":
    main()
