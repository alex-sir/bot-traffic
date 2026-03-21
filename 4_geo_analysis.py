"""
Script 4: GeoIP Country Analysis with GeoLite2-Country.mmdb
Topic - Statistical Analysis & Visualization
Uses the MaxMind GeoLite2-Country database to map source IPs
to countries. Reports top countries by packet count and unique IPs,
and produces a bar chart.

Usage:
    python 4_geo_analysis.py -p <pcap_file> -m <mmdb_file> -o <output_dir>
"""

import argparse
import os
import sys
from collections import Counter, defaultdict

import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP

try:
    import maxminddb
except ImportError:
    print("[!] Install maxminddb-reader-python:  pip install maxminddb")
    sys.exit(1)

TOP_N = 20


def parse_args():
    parser = argparse.ArgumentParser(description="GeoIP Country Analysis")
    parser.add_argument(
        "-p", "--pcap", required=True, help="Path to the input PCAP file"
    )
    parser.add_argument(
        "-m", "--mmdb", required=True, help="Path to the GeoLite2-Country.mmdb file"
    )
    parser.add_argument(
        "-o",
        "--outdir",
        default="output",
        help="Directory for output files (default: output)",
    )
    return parser.parse_args()


def lookup_country(reader, ip):
    try:
        result = reader.get(ip)
        if result and "country" in result:
            return result["country"].get("names", {}).get("en", "Unknown")
        if result and "registered_country" in result:
            return result["registered_country"].get("names", {}).get("en", "Unknown")
    except Exception:
        pass
    return "Unknown"


def main():
    args = parse_args()
    pcap_file = args.pcap
    mmdb_file = args.mmdb
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    output_csv = os.path.join(outdir, "geo_country_stats.csv")
    output_png = os.path.join(outdir, "geo_country_bar.png")

    print(f"[*] Loading {pcap_file} ...")
    packets = rdpcap(pcap_file)
    print(f"[+] {len(packets)} packets loaded.\n")

    print(f"[*] Opening GeoIP database: {mmdb_file}")
    reader = maxminddb.open_database(mmdb_file)

    country_pkt_count = Counter()
    country_ip_count = defaultdict(set)

    for pkt in packets:
        if IP not in pkt:
            continue
        src = pkt[IP].src
        country = lookup_country(reader, src)
        country_pkt_count[country] += 1
        country_ip_count[country].add(src)

    reader.close()

    rows = []
    for country, pkt_count in country_pkt_count.most_common(TOP_N):
        unique_ips = len(country_ip_count[country])
        rows.append(
            {"country": country, "packets": pkt_count, "unique_src_ips": unique_ips}
        )

    df = pd.DataFrame(rows)
    df.to_csv(output_csv, index=False)
    print(f"[+] GeoIP results saved to {output_csv}\n")

    total = sum(country_pkt_count.values())
    print(f"{'Country':<30} {'Packets':>10} {'%':>7}  {'Unique IPs':>12}")
    print("-" * 65)
    for _, row in df.iterrows():
        pct = 100 * row["packets"] / total
        print(
            f"  {row['country']:<28} {row['packets']:>10} {pct:>6.1f}%  {row['unique_src_ips']:>12}"
        )

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.barh(df["country"][::-1], df["packets"][::-1], color="steelblue")
    ax.set_xlabel("Packet Count")
    ax.set_title(f"Top {TOP_N} Source Countries – Merit ORION Telescope")
    ax.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_png, dpi=150)
    print(f"[+] Chart saved to {output_png}")


if __name__ == "__main__":
    main()
