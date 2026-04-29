"""
Script 3: Global Entropy & Inter-Arrival Time (Burstiness) Analysis

This script calculates mathematically reliable metrics for network telescope traffic:
1. Global Shannon Entropy for Source IPs and Destination Ports.
2. Inter-Arrival Time (IAT) between packets to determine traffic burstiness.

It outputs TWO separate, high-resolution, graphs.

Usage Instructions:
    Run the script from the terminal, providing the path to your PCAP file.

    Basic usage:
        python 3_entropy_burstiness.py -p <path_to_pcap_file> -n 1000000

    Example with custom output directory:
        python 3_entropy_burstiness.py -p data/traffic.pcap -o output/ -n 71500000
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

plt.rcParams.update(
    {
        "font.size": 20,
        "font.family": "serif",
        "axes.labelsize": 22,
        "axes.titlesize": 26,
        "xtick.labelsize": 18,
        "ytick.labelsize": 18,
        "legend.fontsize": 18,
        "figure.dpi": 300,
    }
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Reliable Entropy & Burstiness Analysis"
    )
    parser.add_argument("-p", "--pcap", required=True, help="Path to input PCAP")
    parser.add_argument("-o", "--outdir", default="output", help="Output directory")
    parser.add_argument(
        "-n",
        "--max-packets",
        type=int,
        default=1000000,
        help="Maximum number of packets to process",
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
    unique_count = len(counter)
    if total == 0 or unique_count == 0:
        return 0.0, 0.0
    entropy = -sum(
        (c / total) * math.log2(c / total) for c in counter.values() if c > 0
    )
    max_entropy = math.log2(unique_count)
    return entropy, max_entropy


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_entropy = os.path.join(args.outdir, "entropy_diversity.png")
    out_burst = os.path.join(args.outdir, "burstiness_iat.png")

    print(f"[*] Fast Streaming {args.pcap} using dpkt ...")
    src_ips, dst_ports = Counter(), Counter()
    timestamps = []
    total_packets = 0

    with open_pcap(args.pcap) as f:
        pcap = dpkt.pcap.Reader(f)
        datalink = pcap.datalink()
        for ts, buf in pcap:
            if total_packets >= args.max_packets:
                print(
                    f"[*] Reached {args.max_packets:,} packet limit. Moving to analysis..."
                )
                break

            total_packets += 1
            timestamps.append(ts)
            ip = get_ipv4_packet(buf, datalink)
            if ip:
                src_ips[ip.src] += 1
                if ip.p in (6, 17):
                    try:
                        dst_ports[ip.data.dport] += 1
                    except:
                        pass

    if total_packets < 2:
        print("[-] Not enough packets to analyze burstiness.")
        return

    timestamps.sort()
    iats = np.diff(timestamps)
    mean_iat, std_iat = np.mean(iats), np.std(iats)
    cv_iat = std_iat / mean_iat if mean_iat > 0 else 0

    ip_ent, ip_max = calc_entropy(src_ips)
    port_ent, port_max = calc_entropy(dst_ports)

    print("\n--- Reliable Traffic Metrics ---")
    print(f"Total Packets:     {total_packets:,}")
    print(f"Mean IAT:          {mean_iat:.5f} seconds")
    print(f"IAT Variance (CV): {cv_iat:.3f} (>1 is Bursty)")
    print(f"Source IP Entropy: {ip_ent:.3f} bits (Max: {ip_max:.3f})")
    print(f"Dest Port Entropy: {port_ent:.3f} bits (Max: {port_max:.3f})\n")

    # GRAPH 1: Entropy
    fig1, ax1 = plt.subplots(figsize=(10, 8))
    labels, actual_vals, max_vals = (
        ["Source IPs", "Destination Ports"],
        [ip_ent, port_ent],
        [ip_max, port_max],
    )
    x, width = np.arange(len(labels)), 0.35

    ax1.bar(
        x - width / 2,
        actual_vals,
        width,
        label="Actual Entropy",
        color="#4C72B0",
        edgecolor="black",
        linewidth=1.5,
    )
    ax1.bar(
        x + width / 2,
        max_vals,
        width,
        label="Theoretical Max",
        color="#DDDDDD",
        edgecolor="black",
        hatch="//",
        linewidth=1.5,
    )
    ax1.set_ylabel("Shannon Entropy (Bits)", fontweight="bold", labelpad=15)
    ax1.set_title("Traffic Diversity (Actual vs. Maximum)", pad=20, fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontweight="bold")
    ax1.grid(axis="y", linestyle="--", alpha=0.7)
    ax1.set_ylim(0, max(max_vals) * 1.35)
    ax1.legend(loc="upper right", framealpha=0.9, edgecolor="black", borderpad=0.8)

    for i, v in enumerate(actual_vals):
        ax1.text(
            i - width / 2,
            v + (max(max_vals) * 0.02),
            f"{v:.2f}",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=18,
        )
    for i, v in enumerate(max_vals):
        ax1.text(
            i + width / 2,
            v + (max(max_vals) * 0.02),
            f"{v:.2f}",
            ha="center",
            va="bottom",
            color="#555555",
            fontsize=18,
        )

    plt.tight_layout()
    plt.savefig(out_entropy, dpi=300, bbox_inches="tight")
    plt.close(fig1)

    # GRAPH 2: Burstiness
    fig2, ax2 = plt.subplots(figsize=(12, 8))
    iats_ms = iats * 1000
    bins = np.logspace(np.log10(max(0.001, min(iats_ms))), np.log10(max(iats_ms)), 50)
    ax2.hist(
        iats_ms,
        bins=bins,
        color="#C44E52",
        edgecolor="black",
        alpha=0.85,
        linewidth=1.2,
    )
    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_xlabel(
        "Time Between Packets (Milliseconds, Log Scale)", fontweight="bold", labelpad=15
    )
    ax2.set_ylabel("Frequency (Log Scale)", fontweight="bold", labelpad=15)
    ax2.set_title(
        f"Inter-Arrival Time Distribution\n[Burstiness (CV): {cv_iat:.2f} | Mean Gap: {mean_iat * 1000:.1f} ms]",
        pad=20,
        fontweight="bold",
    )
    ax2.grid(True, linestyle=":", alpha=0.7)

    plt.tight_layout()
    plt.savefig(out_burst, dpi=300, bbox_inches="tight")
    plt.close(fig2)


if __name__ == "__main__":
    main()
