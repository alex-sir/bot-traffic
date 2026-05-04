"""
Script 6: IDS Time-Series Extractor (Aggregated)

Extracts the raw packet volume per 1-second interval across two distinct
sets of PCAP files. This generates the foundational CSV data needed for both datasets
to simulate an anomaly-based IDS in Script 7.

Usage Instructions:
    Run the script from the terminal, providing paths to both sets of PCAP files.

    Basic usage:
        python 6_ids_timeseries.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                   -l1 "2021" -l2 "2025" \
                                   -n 1000000

    Example with custom output directory:
        python 6_ids_timeseries.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                   -l1 "2021" -l2 "2025" \
                                   -o output/ \
                                   -n 1000000
"""

import argparse
import os
import gzip
import dpkt
from collections import defaultdict
import pandas as pd


def parse_args():
    parser = argparse.ArgumentParser(description="Cross-Year IDS Time-Series Extractor")
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


def extract_timeseries(pcap_list, max_packets, label, outdir):
    """
    Extracts time-binned packet volumes for a given list of PCAPs
    and saves the output to a uniquely labeled CSV.
    """
    print(f"[*] Extracting 1-second traffic intervals for {label}...")

    # Dictionary to hold the packet count for every second
    traffic_timeline = defaultdict(int)
    sorted_pcaps = sorted(pcap_list)

    for pcap_file in sorted_pcaps:
        packets_this_file = 0
        try:
            with open_pcap(pcap_file) as f:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    if packets_this_file >= max_packets:
                        break

                    # Ignore corrupt epoch 0 timestamps (1970)
                    # 946684800 is Jan 1, 2000. This blocks 1970 packets while allowing modern PCAPs.
                    if ts < 946684800:
                        continue

                    packets_this_file += 1

                    # Truncate the timestamp to the nearest whole second
                    sec_bin = int(ts)
                    traffic_timeline[sec_bin] += 1
        except Exception as e:
            print(f"[-] Error parsing {pcap_file}: {e}")

    if not traffic_timeline:
        print(f"[-] No packets processed for {label}.")
        return

    # Convert the dictionary to a pandas DataFrame and sort chronologically
    df = pd.DataFrame(
        list(traffic_timeline.items()), columns=["timestamp", "packet_count"]
    )
    df = df.sort_values(by="timestamp").reset_index(drop=True)

    # Format the label to be file-system safe (replace spaces with underscores)
    safe_label = label.replace(" ", "_").lower()
    out_csv = os.path.join(outdir, f"{safe_label}_ids_timeseries_1sec.csv")

    df.to_csv(out_csv, index=False)
    print(f"[+] Time-series data saved to {out_csv}")


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    print(f"--- Processing {args.label1} ---")
    extract_timeseries(args.pcap1, args.max_packets, args.label1, args.outdir)

    print(f"\n--- Processing {args.label2} ---")
    extract_timeseries(args.pcap2, args.max_packets, args.label2, args.outdir)


if __name__ == "__main__":
    main()
