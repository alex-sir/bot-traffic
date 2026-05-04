"""
Script 5: Top ICS Volume Shifts (Dumbbell Plot)

Generates a connected dot plot comparing the top ports with the most
drastic volume changes between two datasets.

It draws a line between the Dataset 1 volume and Dataset 2 volume,
visually representing the "travel" or delta.

Usage Instructions:
    Run the script from the terminal, providing paths to both sets of PCAP files.

    Basic usage:
        python3 5_ics_volume_shifts.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                       -l1 "2021" -l2 "2025" \
                                       -n 1000000

    Example with custom output directory:
        python3 5_ics_volume_shifts.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                       -l1 "2021" -l2 "2025" \
                                       -o output/ \
                                       -n 1000000
"""

import argparse
import os
import gzip
import dpkt
from collections import Counter
import pandas as pd
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

TOP_N = 15

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
    parser = argparse.ArgumentParser(description="Cross-Year Top Delta Dumbbell Plot")
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


def extract_port_volumes(pcap_list, max_packets):
    # Parse PCAPs and aggregate the total hit count per ICS port.
    port_counts = Counter()

    for pcap_file in sorted(pcap_list):
        print(f"[*] Parsing {os.path.basename(pcap_file)}...")
        packets_this_file = 0

        try:
            with open_pcap(pcap_file) as f:
                pcap = dpkt.pcap.Reader(f)
                datalink = pcap.datalink()
                for ts, buf in pcap:
                    if packets_this_file >= max_packets:
                        break

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

                    if port and port in ICS_PORTS:
                        port_counts[port] += 1

        except Exception as e:
            print(f"[-] Error parsing {pcap_file}: {e}")

    return port_counts


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_png = os.path.join(args.outdir, "ics_top_deltas.png")
    out_csv = os.path.join(args.outdir, "ics_top_deltas.csv")

    port_keys = list(ICS_PORTS.keys())

    print(f"--- Extracting {args.label1} ---")
    counts1 = extract_port_volumes(args.pcap1, args.max_packets)

    print(f"--- Extracting {args.label2} ---")
    counts2 = extract_port_volumes(args.pcap2, args.max_packets)

    # --- PHASE 2: Delta Calculation & Filtering ---
    port_stats = []
    for p in port_keys:
        v1 = counts1.get(p, 0)
        v2 = counts2.get(p, 0)
        delta = v2 - v1
        abs_delta = abs(delta)

        if abs_delta > 0:  # Only chart ports that actually changed
            port_stats.append(
                {
                    "label": f"{ICS_PORTS[p]} ({p})",
                    "v1": v1,
                    "v2": v2,
                    "delta": delta,
                    "abs_delta": abs_delta,
                }
            )

    # Sort by the sheer size of the shift (absolute delta) and isolate the top N
    port_stats.sort(key=lambda x: x["abs_delta"], reverse=True)
    top_stats = port_stats[:TOP_N]

    # Reverse so the largest change appears at the top of the Y-axis
    top_stats = top_stats[::-1]

    if not top_stats:
        print("[-] No ICS traffic changes detected to chart.")
        return

    # Extract data for plotting
    labels = [stat["label"] for stat in top_stats]
    vals1 = [stat["v1"] for stat in top_stats]
    vals2 = [stat["v2"] for stat in top_stats]
    deltas = [stat["delta"] for stat in top_stats]
    y_positions = range(len(labels))

    # --- PHASE 3: Visualization ---
    fig, ax = plt.subplots(figsize=(16, 15))

    # Add extra padding to the top and bottom of the Y-axis so the text doesn't get clipped
    ax.set_ylim(-0.8, len(labels))

    # Draw the connecting lines
    for i in y_positions:
        ax.plot(
            [vals1[i], vals2[i]],
            [i, i],
            color="#636E72",
            linewidth=4,
            zorder=1,
            alpha=0.6,
        )

    # Plot the dots for Dataset 1
    ax.scatter(
        vals1,
        y_positions,
        color="#4C72B0",
        s=400,
        edgecolor="black",
        zorder=2,
        label=args.label1,
    )

    # Plot the dots for Dataset 2
    ax.scatter(
        vals2,
        y_positions,
        color="#C44E52",
        s=400,
        edgecolor="black",
        zorder=3,
        label=args.label2,
    )

    # Text overlays: Show the actual delta value physically on the graph
    for i in y_positions:
        delta_val = deltas[i]
        text_str = f"+{delta_val:,}" if delta_val > 0 else f"{delta_val:,}"
        color = "#B33939" if delta_val > 0 else "#218C74"

        mid_x = (vals1[i] + vals2[i]) / 2

        ax.text(
            mid_x,
            i + 0.45,
            text_str,
            ha="center",
            va="center",
            color=color,
            fontsize=18,
            fontweight="bold",
        )

    # Styling the axes
    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels, fontweight="bold")
    ax.set_xlabel("Packet Volume", labelpad=20, fontweight="bold")
    ax.grid(axis="x", linestyle="--", alpha=0.5)
    ax.grid(axis="y", linestyle=":", alpha=0.3)

    # Remove top and right borders
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # Place the legend firmly at the top of the generated chart
    ax.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1),
        ncol=2,
        framealpha=0.9,
        edgecolor="black",
        fontsize=24,
    )

    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches="tight")

    # Save to CSV using the formatted labels
    df = pd.DataFrame(top_stats)
    df.to_csv(out_csv, index=False)

    print(f"[+] Top {TOP_N} Delta Dumbbell Plot saved to {out_png}")
    print(f"[+] Dumbbell CSV data saved to {out_csv}")


if __name__ == "__main__":
    main()
