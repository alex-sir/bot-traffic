"""
Script 4: GeoIP Country Analysis

This script maps source IP addresses to their respective countries using
the MaxMind GeoLite2 database. It generates a high-resolution horizontal
bar chart showing the top source countries by packet volume, including
annotations for the number of unique IPs per country.

Usage Instructions:
    Run the script from the terminal, providing both the path to your PCAP
    file and the path to the MaxMind GeoLite2-Country.mmdb file.

    Basic usage:
        python 4_geo_analysis.py -p <path_to_pcap_file> -m <path_to_mmdb_file>

    Example with custom output directory:
        python 4_geo_analysis.py -p data/traffic.pcap -m data/GeoLite2-Country.mmdb -o output/
"""

import argparse
import os
import sys
from collections import Counter, defaultdict
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scapy.all import PcapReader, IP

try:
    import maxminddb
except ImportError:
    print("[!] Install maxminddb-reader-python:  pip install maxminddb")
    sys.exit(1)

plt.rcParams.update(
    {
        "font.size": 18,
        "font.family": "serif",
        "axes.labelsize": 20,
        "axes.titlesize": 24,
        "ytick.labelsize": 18,
        "figure.dpi": 300,
    }
)

TOP_N = 15  # Kept at 15 to ensure Y-axis text has plenty of breathing room


def parse_args():
    parser = argparse.ArgumentParser(description="GeoIP Country Analysis")
    parser.add_argument("-p", "--pcap", required=True, help="Path to input PCAP")
    parser.add_argument(
        "-m", "--mmdb", required=True, help="Path to GeoLite2-Country.mmdb"
    )
    parser.add_argument("-o", "--outdir", default="output", help="Output directory")
    return parser.parse_args()


def lookup_country(reader, ip):
    try:
        res = reader.get(ip)
        if res and "country" in res:
            return res["country"].get("names", {}).get("en", "Unknown")
        if res and "registered_country" in res:
            return res["registered_country"].get("names", {}).get("en", "Unknown")
    except Exception:
        pass
    return "Unknown"


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_png = os.path.join(args.outdir, "geo_country_bar.png")

    print(f"[*] Opening GeoIP database: {args.mmdb}")
    try:
        reader = maxminddb.open_database(args.mmdb)
    except FileNotFoundError:
        print(f"[-] Could not find MMDB file at {args.mmdb}")
        return

    print(f"[*] Streaming {args.pcap} ...")

    country_pkt = Counter()
    country_ip = defaultdict(set)

    with PcapReader(args.pcap) as pcap_reader:
        for pkt in pcap_reader:
            if IP not in pkt:
                continue
            src = pkt[IP].src
            c = lookup_country(reader, src)
            country_pkt[c] += 1
            country_ip[c].add(src)

    reader.close()

    if not country_pkt:
        print("[-] No valid IP traffic found to map.")
        return

    rows = [
        {"country": c, "packets": p, "unique_ips": len(country_ip[c])}
        for c, p in country_pkt.most_common(TOP_N)
    ]

    df = pd.DataFrame(rows).sort_values(by="packets", ascending=True)

    # --- Plotting ---
    # Widened figure to 14 inches to accommodate the larger annotation text
    fig, ax = plt.subplots(figsize=(14, 10))

    bars = ax.barh(
        df["country"], df["packets"], color="#4C72B0", edgecolor="black", alpha=0.9
    )

    ax.set_xlabel("Total Packet Count", labelpad=15, fontweight="bold")
    ax.set_title(f"Top Source Countries by Packet Volume", pad=20, fontweight="bold")
    ax.grid(axis="x", linestyle="--", alpha=0.5)

    # Add large text annotations on the bars
    for bar, u_ips in zip(bars, df["unique_ips"]):
        width = bar.get_width()

        # Annotation text: "  X pkts | Y IPs"
        annotation = f"  {int(width):,} pkts | {u_ips:,} IPs"

        ax.text(
            width,
            bar.get_y() + bar.get_height() / 2,
            annotation,
            va="center",
            ha="left",
            fontsize=16,
            color="black",
        )

    # Extend x-limit heavily to ensure the large text labels fit inside the graphic bounds
    ax.set_xlim(0, max(df["packets"]) * 1.45)

    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches="tight")
    print(f"[+] Geo mapping chart saved to {out_png}")


if __name__ == "__main__":
    main()
