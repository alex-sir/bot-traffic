"""
Script 4: GeoIP Country Analysis

Maps source IP addresses to their respective countries using
the MaxMind GeoLite2 database. Generates an analytical table tracking the
percent shift in geographical origins across two eras of bot traffic.

Usage Instructions:
    Run the script from the terminal, providing both the paths to your PCAP
    files and the paths to the MaxMind GeoLite2-Country.mmdb files.

    Basic usage:
        python3 4_geo_analysis.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                  -m1 data/GeoLite2-2021.mmdb -m2 data/GeoLite2-2025.mmdb \
                                  -l1 "2021" -l2 "2025" \
                                  -n 1000000

    Example with custom output directory:
        python3 4_geo_analysis.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                  -m1 data/GeoLite2-2021.mmdb -m2 data/GeoLite2-2025.mmdb \
                                  -l1 "2021 Baseline" -l2 "2025 Bot Traffic" \
                                  -o output/ \
                                  -n 1000000
"""

import argparse
import os
import sys
import gzip
import socket
import dpkt
from collections import Counter
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

try:
    import maxminddb
except ImportError:
    print("[!] Install maxminddb-reader-python:  pip install maxminddb")
    sys.exit(1)

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

# --- NORMALIZATION DICTIONARY ---
# MaxMind frequently updates country names to match geopolitical ISO changes.
# This dictionary catches split records and maps them to a single standard name.
COUNTRY_NORMALIZATION = {
    "The Netherlands": "Netherlands",
    "Türkiye": "Turkey",
    "Czechia": "Czech Republic",
    "North Macedonia": "Macedonia",
    "Republic of Korea": "South Korea",
    "Russian Federation": "Russia",
    "Eswatini": "Swaziland",
    "Syrian Arab Republic": "Syria",
    "Iran (Islamic Republic of)": "Iran",
    "Viet Nam": "Vietnam",
    "Macao": "Macau",
}


def parse_args():
    parser = argparse.ArgumentParser(description="Cross-Year GeoIP Analysis")
    parser.add_argument(
        "-p1", "--pcap1", nargs="+", required=True, help="Paths to Dataset 1 PCAPs"
    )
    parser.add_argument(
        "-p2", "--pcap2", nargs="+", required=True, help="Paths to Dataset 2 PCAPs"
    )
    parser.add_argument(
        "-m1", "--mmdb1", required=True, help="Path to GeoLite2 DB for Dataset 1"
    )
    parser.add_argument(
        "-m2", "--mmdb2", required=True, help="Path to GeoLite2 DB for Dataset 2"
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


def lookup_country(reader, ip):
    try:
        res = reader.get(ip)
        country = "Unknown"
        if res and "country" in res:
            country = res["country"].get("names", {}).get("en", "Unknown")
        elif res and "registered_country" in res:
            country = res["registered_country"].get("names", {}).get("en", "Unknown")

        # Apply normalization to fix MaxMind DB version inconsistencies
        return COUNTRY_NORMALIZATION.get(country, country)
    except Exception:
        pass
    return "Unknown"


def extract_geo(pcap_list, mmdb_path, max_packets):
    ip_packet_counts = Counter()

    # Pre-Aggregate IPs
    for pcap_file in pcap_list:
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
                    if ip:
                        ip_packet_counts[ip.src] += 1
        except Exception as e:
            print(f"[-] Error reading {pcap_file}: {e}")

    # Database Lookup
    reader = maxminddb.open_database(mmdb_path)
    country_pkt = Counter()
    for src_bytes, count in ip_packet_counts.items():
        src_str = socket.inet_ntoa(src_bytes)
        c = lookup_country(reader, src_str)
        country_pkt[c] += count
    reader.close()

    return country_pkt


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_png = os.path.join(args.outdir, "geo_analysis.png")

    print(f"--- Extracting {args.label1} ---")
    geo1 = extract_geo(args.pcap1, args.mmdb1, args.max_packets)
    print(f"--- Extracting {args.label2} ---")
    geo2 = extract_geo(args.pcap2, args.mmdb2, args.max_packets)

    # Calculate Top N based on COMBINED overall volume
    combined_geo = Counter()
    combined_geo.update(geo1)
    combined_geo.update(geo2)

    top_countries = [c[0] for c in combined_geo.most_common(TOP_N) if c[0] != "Unknown"]

    # Build Table Matrix
    table_data = []
    for c in top_countries:
        v1 = geo1.get(c, 0)
        v2 = geo2.get(c, 0)

        # Protect against ZeroDivisionError
        if v1 > 0:
            delta = ((v2 - v1) / v1) * 100
            delta_str = f"+{delta:.1f}%" if delta > 0 else f"{delta:.1f}%"
        elif v2 > 0:
            delta_str = "+INF%"
        else:
            delta_str = "0%"

        table_data.append([c, f"{v1:,}", f"{v2:,}", delta_str])

    # --- Visualization ---
    fig, ax = plt.subplots(figsize=(14, 10))
    ax.axis("tight")
    ax.axis("off")

    # Format labels dynamically: only add a newline if the combined text is too long
    header_label1 = (
        f"{args.label1}\nPkts"
        if len(f"{args.label1} Pkts") > 14
        else f"{args.label1} Pkts"
    )
    header_label2 = (
        f"{args.label2}\nPkts"
        if len(f"{args.label2} Pkts") > 14
        else f"{args.label2} Pkts"
    )
    headers = ["Country", header_label1, header_label2, "Δ (%)"]

    # Determine a single, uniform font size for the entire header row
    max_header_len = max(len(line) for h in headers for line in h.split("\n"))
    header_size = 22
    if max_header_len > 18:
        header_size = 16
    elif max_header_len > 12:
        header_size = 18

    table = ax.table(
        cellText=table_data,
        colLabels=headers,
        colWidths=[0.3, 0.25, 0.25, 0.2],  # Explicitly assign wider columns to the data
        loc="center",
        cellLoc="center",
    )

    table.auto_set_font_size(False)
    table.set_fontsize(20)
    table.scale(1.0, 3.0)

    # Colorize table elements and apply uniform dynamic font sizing
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor("#DDDDDD")

        # Explicitly increase the padding so the text doesn't touch the borders
        cell.PAD = 0.1

        if row == 0:
            # Apply the globally determined header size
            cell.set_text_props(weight="bold", color="white", size=header_size)

            if col == 0 or col == 3:
                cell.set_facecolor("#2B475D")
            elif col == 1:
                cell.set_facecolor("#4C72B0")  # Match Color for Dataset 1
            elif col == 2:
                cell.set_facecolor("#C44E52")  # Match Color for Dataset 2
        else:
            cell.set_facecolor("#F8F9FA" if row % 2 == 0 else "#FFFFFF")

            # Left align country names, center align numbers, explicitly colorize the delta
            if col == 0:
                cell.set_text_props(weight="bold", ha="left")
            elif col == 3:
                delta_val = table_data[row - 1][3]
                if "+" in delta_val:
                    cell.set_text_props(
                        color="#B33939", weight="bold"
                    )  # Red for growth
                elif "-" in delta_val:
                    cell.set_text_props(
                        color="#218C74", weight="bold"
                    )  # Green for decline

    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches="tight")
    print(f"[+] Geographic comparison table saved to {out_png}")


if __name__ == "__main__":
    main()
