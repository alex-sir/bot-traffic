"""
Script 3: Entropy & Burstiness Analysis
Topic - Statistical Analysis & Visualization
Computes:
  - Shannon entropy of source IPs, destination ports, and protocols
    over 1-minute bins to measure traffic diversity over time.
  - Burstiness via coefficient of variation (CV) of packet rates per bin.
  - Hurst exponent estimate for long-range dependence.
Outputs CSVs and PNG plots.
"""

import math
import datetime
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

PCAP_FILE = "data/traffic-2025-01-20.00-1M.pcap"
BIN_SECS = 60  # 1-minute bins
OUTPUT_CSV = "output/entropy_burstiness.csv"


def shannon_entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values() if c > 0)


def hurst_exponent(ts):
    """R/S analysis estimate of Hurst exponent."""
    ts = np.array(ts, dtype=float)
    lags = range(2, max(3, len(ts) // 2))
    rs_vals = []
    for lag in lags:
        sub = ts[:lag]
        mean = np.mean(sub)
        dev = np.cumsum(sub - mean)
        R = np.max(dev) - np.min(dev)
        S = np.std(sub)
        if S > 0:
            rs_vals.append((lag, R / S))
    if len(rs_vals) < 2:
        return float("nan")
    lags_arr = np.log([x[0] for x in rs_vals])
    rs_arr = np.log([x[1] for x in rs_vals])
    H = np.polyfit(lags_arr, rs_arr, 1)[0]
    return H


def main():
    print(f"[*] Loading {PCAP_FILE} ...")
    packets = rdpcap(PCAP_FILE)
    print(f"[+] {len(packets)} packets loaded.\n")

    if not packets:
        print("No packets found.")
        return

    t0 = float(packets[0].time)

    bins = defaultdict(
        lambda: {
            "src_ips": Counter(),
            "dst_ports": Counter(),
            "protocols": Counter(),
            "count": 0,
        }
    )

    for pkt in packets:
        if IP not in pkt:
            continue
        t = float(pkt.time)
        bin_id = int((t - t0) / BIN_SECS)

        bins[bin_id]["src_ips"][pkt[IP].src] += 1
        bins[bin_id]["count"] += 1

        if TCP in pkt:
            bins[bin_id]["dst_ports"][pkt[TCP].dport] += 1
            bins[bin_id]["protocols"]["TCP"] += 1
        elif UDP in pkt:
            bins[bin_id]["dst_ports"][pkt[UDP].dport] += 1
            bins[bin_id]["protocols"]["UDP"] += 1
        elif ICMP in pkt:
            bins[bin_id]["protocols"]["ICMP"] += 1
        else:
            bins[bin_id]["protocols"]["Other"] += 1

    sorted_bins = sorted(bins.keys())
    records = []
    for b in sorted_bins:
        ts_label = datetime.datetime.fromtimestamp(
            t0 + b * BIN_SECS, tz=datetime.timezone.utc
        ).strftime("%H:%M")
        d = bins[b]
        records.append(
            {
                "bin": b,
                "time": ts_label,
                "packet_count": d["count"],
                "src_ip_entropy": round(shannon_entropy(d["src_ips"]), 4),
                "dst_port_entropy": round(shannon_entropy(d["dst_ports"]), 4),
                "protocol_entropy": round(shannon_entropy(d["protocols"]), 4),
            }
        )

    df = pd.DataFrame(records)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"[+] Per-bin stats saved to {OUTPUT_CSV}")

    # Burstiness (Coefficient of Variation)
    pkt_counts = df["packet_count"].values
    cv = np.std(pkt_counts) / np.mean(pkt_counts) if np.mean(pkt_counts) > 0 else 0
    print(f"[+] Burstiness (CV of packet rate): {cv:.4f}  (>1 = bursty, <1 = uniform)")

    # Hurst exponent
    H = hurst_exponent(pkt_counts)
    print(
        f"[+] Hurst exponent estimate:        {H:.4f}  (>0.5 = long-range dependence/persistent)"
    )

    # --- Plots ---
    fig, axes = plt.subplots(3, 1, figsize=(12, 10), sharex=True)
    fig.suptitle(
        "Merit ORION Telescope Traffic – Entropy & Packet Rate over Time", fontsize=13
    )

    axes[0].plot(df["bin"], df["packet_count"], color="steelblue", linewidth=0.8)
    axes[0].set_ylabel("Packets / min")
    axes[0].set_title(f"Packet Rate  (CV={cv:.2f})")
    axes[0].grid(True, alpha=0.3)

    axes[1].plot(
        df["bin"],
        df["src_ip_entropy"],
        color="darkorange",
        linewidth=0.8,
        label="Src IP",
    )
    axes[1].plot(
        df["bin"],
        df["dst_port_entropy"],
        color="green",
        linewidth=0.8,
        label="Dst Port",
    )
    axes[1].set_ylabel("Shannon Entropy (bits)")
    axes[1].set_title("Traffic Entropy")
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    axes[2].plot(df["bin"], df["protocol_entropy"], color="purple", linewidth=0.8)
    axes[2].set_ylabel("Protocol Entropy")
    axes[2].set_xlabel("Time bin (each = 1 min)")
    axes[2].set_title("Protocol Distribution Entropy")
    axes[2].grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig("output/entropy_burstiness.png", dpi=150)
    print("[+] Plot saved to output/entropy_burstiness.png")


if __name__ == "__main__":
    main()
