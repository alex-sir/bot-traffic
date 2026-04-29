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
        python 4_geo_analysis.py -p <path_to_pcap_file> -m <path_to_mmdb_file> -n 1000000

    Example with custom output directory:
        python 4_geo_analysis.py -p data/traffic.pcap -m data/GeoLite2-Country.mmdb -o output/ -n 71500000
"""

import argparse
import os
import sys
import gzip
import socket
import dpkt
from collections import Counter, defaultdict
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

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
TOP_N = 15


def parse_args():
    parser = argparse.ArgumentParser(description="GeoIP Country Analysis")
    parser.add_argument(
        "-p", "--pcap", nargs="+", required=True, help="Paths to input PCAPs"
    )
    parser.add_argument(
        "-m", "--mmdb", required=True, help="Path to GeoLite2-Country.mmdb"
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

    ip_packet_counts = Counter()

    # --- PHASE 1: Memory Aggregation (Over All Files) ---
    for pcap_file in args.pcap:
        print(f"[*] Parsing {os.path.basename(pcap_file)}...")
        packets_this_file = 0

        with open_pcap(pcap_file) as f:
            pcap = dpkt.pcap.Reader(f)
            datalink = pcap.datalink()
            for ts, buf in pcap:
                if packets_this_file >= args.max_packets:
                    break
                packets_this_file += 1

                ip = get_ipv4_packet(buf, datalink)
                if ip:
                    ip_packet_counts[ip.src] += 1

    print(f"[*] Total Lookups required globally: {len(ip_packet_counts)} unique IPs.")

    # --- PHASE 2: Geographic Lookup ---
    try:
        reader = maxminddb.open_database(args.mmdb)
    except FileNotFoundError:
        print(f"[-] Could not find MMDB file at {args.mmdb}")
        return

    country_pkt = Counter()
    country_ip = defaultdict(set)

    for src_bytes, count in ip_packet_counts.items():
        src_str = socket.inet_ntoa(src_bytes)
        c = lookup_country(reader, src_str)
        country_pkt[c] += count
        country_ip[c].add(src_bytes)
    reader.close()

    if not country_pkt:
        print("[-] No valid IP traffic found to map.")
        return

    # --- PHASE 3: Visualization ---
    rows = [
        {"country": c, "packets": p, "unique_ips": len(country_ip[c])}
        for c, p in country_pkt.most_common(TOP_N)
    ]
    df = pd.DataFrame(rows).sort_values(by="packets", ascending=True)

    fig, ax = plt.subplots(figsize=(14, 10))
    bars = ax.barh(
        df["country"], df["packets"], color="#4C72B0", edgecolor="black", alpha=0.9
    )
    ax.set_xlabel("Total Packet Count", labelpad=15, fontweight="bold")
    ax.set_title(
        f"Top Source Countries by Packet Volume (Aggregated)", pad=20, fontweight="bold"
    )
    ax.grid(axis="x", linestyle="--", alpha=0.5)
    ax.set_xlim(0, max(df["packets"]) * 1.45)

    for bar, u_ips in zip(bars, df["unique_ips"]):
        width = bar.get_width()
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

    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches="tight")
    print(f"[+] Geo mapping chart saved to {out_png}")


if __name__ == "__main__":
    main()
