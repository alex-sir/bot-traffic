"""
Script 3: Global Entropy & Inter-Arrival Time (Burstiness) Analysis

This script calculates mathematically reliable metrics for network telescope traffic:
1. Global Shannon Entropy for Source IPs and Destination Ports.
2. Inter-Arrival Time (IAT) between packets to determine traffic burstiness.

It outputs TWO separate, high-resolution, graphs.

Usage Instructions:
    Run the script from the terminal, providing the path to your PCAP file.

    Basic usage:
        python 3_entropy_burstiness.py -p <path_to_pcap_file>

    Example with custom output directory:
        python 3_entropy_burstiness.py -p data/traffic.pcap -o output/
"""

import argparse
import math
import os
from collections import Counter
import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP, UDP

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
    return parser.parse_args()


def calc_entropy(counter):
    """Calculates actual Shannon Entropy and Theoretical Maximum Entropy."""
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

    print(f"[*] Loading {args.pcap} ...")
    packets = rdpcap(args.pcap)
    if len(packets) < 2:
        print("[-] Not enough packets to analyze burstiness.")
        return

    src_ips = Counter()
    dst_ports = Counter()
    timestamps = []

    # 1. Extract Data
    for pkt in packets:
        timestamps.append(float(pkt.time))
        if IP in pkt:
            src_ips[pkt[IP].src] += 1
            if TCP in pkt:
                dst_ports[pkt[TCP].dport] += 1
            elif UDP in pkt:
                dst_ports[pkt[UDP].dport] += 1

    # 2. Calculate Inter-Arrival Times (Burstiness)
    timestamps.sort()
    iats = np.diff(timestamps)

    mean_iat = np.mean(iats)
    std_iat = np.std(iats)
    cv_iat = std_iat / mean_iat if mean_iat > 0 else 0

    # 3. Calculate Global Entropy
    ip_ent, ip_max = calc_entropy(src_ips)
    port_ent, port_max = calc_entropy(dst_ports)

    # --- Print Hard Numbers to Terminal ---
    print("\n--- Reliable Traffic Metrics ---")
    print(f"Total Packets:     {len(packets):,}")
    print(f"Mean IAT:          {mean_iat:.5f} seconds")
    print(f"IAT Variance (CV): {cv_iat:.3f} (>1 is Bursty)")
    print(f"Source IP Entropy: {ip_ent:.3f} bits (Max: {ip_max:.3f})")
    print(f"Dest Port Entropy: {port_ent:.3f} bits (Max: {port_max:.3f})\n")

    # ==========================================
    # GRAPH 1: Entropy (Traffic Diversity)
    # ==========================================
    fig1, ax1 = plt.subplots(figsize=(10, 8))

    labels = ["Source IPs", "Destination Ports"]
    actual_vals = [ip_ent, port_ent]
    max_vals = [ip_max, port_max]

    x = np.arange(len(labels))
    width = 0.35

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

    # Add large numeric annotations to the bars
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
    print(f"[+] Entropy graph saved to {out_entropy}")
    plt.close(fig1)

    # ==========================================
    # GRAPH 2: Burstiness (Inter-Arrival Time)
    # ==========================================
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

    burst_text = f"Burstiness (CV): {cv_iat:.2f} | Mean Gap: {mean_iat * 1000:.1f} ms"
    ax2.set_title(
        f"Inter-Arrival Time Distribution\n[{burst_text}]", pad=20, fontweight="bold"
    )
    ax2.grid(True, linestyle=":", alpha=0.7)

    plt.tight_layout()
    plt.savefig(out_burst, dpi=300, bbox_inches="tight")
    print(f"[+] Burstiness graph saved to {out_burst}")
    plt.close(fig2)


if __name__ == "__main__":
    main()
