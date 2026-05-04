"""
Script 3: Global Entropy & Burstiness

Calculates mathematical diversity (Entropy) and Inter-Arrival Times (Burstiness)
for two distinct datasets, rendering the results on shared, comparative graphs.

Usage Instructions:
    Run the script from the terminal, providing the paths to your PCAP files.

    Basic usage:
        python3 3_entropy_burstiness.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                        -l1 "2021" -l2 "2025" \
                                        -n 1000000

    Example with custom output directory:
        python3 3_entropy_burstiness.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                        -l1 "2021" -l2 "2025" \
                                        -o output/ \
                                        -n 1000000
"""

import argparse
import math
import os
import gzip
import dpkt
from collections import Counter
import numpy as np
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
    parser = argparse.ArgumentParser(description="Cross-Year Entropy & Burstiness")
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


def calc_entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values() if c > 0)


def extract_data(pcap_list, max_packets):
    src_ips, dst_ports = Counter(), Counter()
    all_iats = []

    for pcap_file in pcap_list:
        print(f"[*] Parsing {os.path.basename(pcap_file)}...")
        packets_this_file = 0
        file_timestamps = []

        try:
            with open_pcap(pcap_file) as f:
                pcap = dpkt.pcap.Reader(f)
                datalink = pcap.datalink()
                for ts, buf in pcap:
                    if packets_this_file >= max_packets:
                        break
                    packets_this_file += 1

                    ip = get_ipv4_packet(buf, datalink)
                    if ip:
                        file_timestamps.append(ts)
                        src_ips[ip.src] += 1
                        if ip.p in (6, 17):
                            try:
                                dst_ports[ip.data.dport] += 1
                            except:
                                pass

            file_timestamps.sort()
            if len(file_timestamps) > 1:
                all_iats.extend(np.diff(file_timestamps))
        except Exception as e:
            print(f"[-] Error parsing {pcap_file}: {e}")

    iats = np.array(all_iats)
    return calc_entropy(src_ips), calc_entropy(dst_ports), iats


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_entropy = os.path.join(args.outdir, "entropy.png")
    out_burst = os.path.join(args.outdir, "burstiness.png")

    print(f"--- Extracting {args.label1} ---")
    ip_ent1, port_ent1, iats1 = extract_data(args.pcap1, args.max_packets)

    print(f"--- Extracting {args.label2} ---")
    ip_ent2, port_ent2, iats2 = extract_data(args.pcap2, args.max_packets)

    # --- GRAPH 1: Grouped Entropy Bar Chart ---
    fig1, ax1 = plt.subplots(figsize=(10, 8))
    labels = ["Source IPs", "Destination Ports"]
    vals1 = [ip_ent1, port_ent1]
    vals2 = [ip_ent2, port_ent2]

    x = np.arange(len(labels))
    width = 0.35

    ax1.bar(
        x - width / 2,
        vals1,
        width,
        label=args.label1,
        color="#4C72B0",
        edgecolor="black",
        linewidth=1.5,
    )
    ax1.bar(
        x + width / 2,
        vals2,
        width,
        label=args.label2,
        color="#C44E52",
        edgecolor="black",
        linewidth=1.5,
    )

    ax1.set_ylabel("Shannon Entropy (Bits)", fontweight="bold", labelpad=15)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontweight="bold")
    ax1.grid(axis="y", linestyle="--", alpha=0.7)

    # Remove top/right borders
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)

    max_val = max(max(vals1), max(vals2))
    ax1.set_ylim(0, max_val * 1.3)

    # Legend placed horizontally above the graph
    ax1.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1),
        ncol=2,
        framealpha=0.9,
        edgecolor="black",
    )

    for i, v in enumerate(vals1):
        ax1.text(
            i - width / 2,
            v + (max_val * 0.02),
            f"{v:.2f}",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=20,
        )
    for i, v in enumerate(vals2):
        ax1.text(
            i + width / 2,
            v + (max_val * 0.02),
            f"{v:.2f}",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=20,
        )

    plt.tight_layout()
    plt.savefig(out_entropy, dpi=300, bbox_inches="tight")
    plt.close(fig1)

    # --- GRAPH 2: Overlaid Burstiness Histogram ---
    fig2, ax2 = plt.subplots(figsize=(14, 8))

    iats_ms1 = iats1 * 1000
    iats_ms2 = iats2 * 1000

    # Create unified logarithmic bins spanning the range of both datasets
    min_val = max(0.001, min(np.min(iats_ms1), np.min(iats_ms2)))
    max_val = max(np.max(iats_ms1), np.max(iats_ms2))
    bins = np.logspace(np.log10(min_val), np.log10(max_val), 60)

    # Overlay distributions (alpha=0.6 makes the overlap visually explicit)
    ax2.hist(
        iats_ms1,
        bins=bins,
        color="#4C72B0",
        edgecolor="black",
        alpha=0.6,
        label=args.label1,
    )
    ax2.hist(
        iats_ms2,
        bins=bins,
        color="#C44E52",
        edgecolor="black",
        alpha=0.6,
        label=args.label2,
    )

    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_xlabel(
        "Time Between Packets (Milliseconds, Log Scale)", fontweight="bold", labelpad=15
    )
    ax2.set_ylabel("Frequency (Log Scale)", fontweight="bold", labelpad=15)
    ax2.grid(True, linestyle=":", alpha=0.7)

    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    # Legend placed horizontally above the graph
    ax2.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1),
        ncol=2,
        framealpha=0.9,
        edgecolor="black",
    )

    plt.tight_layout()
    plt.savefig(out_burst, dpi=300, bbox_inches="tight")
    plt.close(fig2)

    print(f"[+] Output saved to {out_entropy} and {out_burst}")


if __name__ == "__main__":
    main()
