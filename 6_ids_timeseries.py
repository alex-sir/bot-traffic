"""
Script 6: IDS Time-Series Extractor (Aggregated)

This script extracts the raw packet volume per 1-second interval across all provided PCAP files.
This generates the foundational data needed to simulate an anomaly-based IDS.

Usage Instructions:
    Run the script from the terminal, providing the path to your PCAP file.

    Basic usage:
        python 6_ids_timeseries.py -p <path_to_pcap_file> -n 1000000

    Example with custom output directory:
        python 6_ids_timeseries.py -p data/traffic-2025-01-20.00-1M.pcap -o output/ -n 71500000
"""

import argparse
import os
import gzip
import dpkt
from collections import defaultdict
import pandas as pd


def parse_args():
    parser = argparse.ArgumentParser(description="IDS Time-Series Extractor")
    parser.add_argument(
        "-p", "--pcap", nargs="+", required=True, help="Paths to input PCAPs"
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


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_csv = os.path.join(args.outdir, "ids_timeseries_1sec.csv")

    print("[*] Extracting 1-second traffic intervals for IDS simulation...")

    # Dictionary to hold the packet count for every second
    traffic_timeline = defaultdict(int)
    sorted_pcaps = sorted(args.pcap)

    for pcap_file in sorted_pcaps:
        packets_this_file = 0
        with open_pcap(pcap_file) as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                if packets_this_file >= args.max_packets:
                    break
                packets_this_file += 1

                # Truncate the timestamp to the nearest whole second
                sec_bin = int(ts)
                traffic_timeline[sec_bin] += 1

    if not traffic_timeline:
        print("[-] No packets processed.")
        return

    # Convert the dictionary to a pandas DataFrame and sort chronologically
    df = pd.DataFrame(
        list(traffic_timeline.items()), columns=["timestamp", "packet_count"]
    )
    df = df.sort_values(by="timestamp").reset_index(drop=True)

    df.to_csv(out_csv, index=False)
    print(f"[+] Time-series data saved to {out_csv}")


if __name__ == "__main__":
    main()
