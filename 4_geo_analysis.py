"""
Script 4: GeoIP Country Analysis with GeoLite2-Country.mmdb
Topic - Statistical Analysis & Visualization
Uses the MaxMind GeoLite2-Country database to map source IPs
to countries. Reports top countries by packet count and unique IPs,
and produces a bar chart.
"""

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

PCAP_FILE = "data/traffic-2025-01-20.00-1M.pcap"
MMDB_FILE = "data/GeoLite2-Country.mmdb"
TOP_N = 20


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
    print(f"[*] Loading {PCAP_FILE} ...")
    packets = rdpcap(PCAP_FILE)
    print(f"[+] {len(packets)} packets loaded.\n")

    print(f"[*] Opening GeoIP database: {MMDB_FILE}")
    reader = maxminddb.open_database(MMDB_FILE)

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

    # Build results table
    rows = []
    for country, pkt_count in country_pkt_count.most_common(TOP_N):
        unique_ips = len(country_ip_count[country])
        rows.append(
            {"country": country, "packets": pkt_count, "unique_src_ips": unique_ips}
        )

    df = pd.DataFrame(rows)
    df.to_csv("output/geo_country_stats.csv", index=False)
    print("[+] GeoIP results saved to output/geo_country_stats.csv\n")

    total = sum(country_pkt_count.values())
    print(f"{'Country':<30} {'Packets':>10} {'%':>7}  {'Unique IPs':>12}")
    print("-" * 65)
    for _, row in df.iterrows():
        pct = 100 * row["packets"] / total
        print(
            f"  {row['country']:<28} {row['packets']:>10} {pct:>6.1f}%  {row['unique_src_ips']:>12}"
        )

    # Bar chart
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.barh(df["country"][::-1], df["packets"][::-1], color="steelblue")
    ax.set_xlabel("Packet Count")
    ax.set_title(f"Top {TOP_N} Source Countries – Merit ORION Telescope (2025-01-20)")
    ax.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    plt.savefig("geo_country_bar.png", dpi=150)
    print("[+] Chart saved to geo_country_bar.png")


if __name__ == "__main__":
    main()
