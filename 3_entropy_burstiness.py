"""
Script 3: Global Entropy & Burstiness

Calculates mathematical diversity (Entropy) and Inter-Arrival Times (Burstiness)
for two distinct datasets, rendering the results on shared, comparative graphs.

Usage Instructions:
    Run the script from the terminal, providing the paths to your PCAP files.

    Basic usage:
        python3 3_entropy_burstiness.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                        -l1 "2021" -l2 "2025" \
                                        -n 1000000

    Example with custom output directory:
        python3 3_entropy_burstiness.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                        -l1 "2021" -l2 "2025" \
                                        -o output/ \
                                        -n 1000000
"""

import argparse
import math
import os
import gzip
import dpkt
import array
from collections import Counter
import numpy as np
import matplotlib

# Use 'Agg' non-interactive backend for matplotlib so it runs headlessly
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# --- STANDARDIZED FONT CONFIGURATION ---
# Sets consistent styling across all generated charts and visualizations
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

# STATIC BINS: Pre-define the logarithmic bins spanning 1 microsecond (0.001 ms) to 1 second (10^3 ms).
# This frames high-volume network telescope data without leaving empty whitespace.
BINS = np.logspace(-3, 3, 60)


def parse_args():
    """
    Parses command-line arguments to specify dataset paths, labels,
    output directory, and packet processing limits.
    """
    parser = argparse.ArgumentParser(description="Cross-Year Entropy & Burstiness")
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
    """
    Opens a PCAP file, checking its magic bytes to determine if it is gzipped.
    Returns a gzip-opened stream or a standard file stream accordingly.
    """
    with open(file_path, "rb") as f:
        magic = f.read(2)
    # Magic bytes b"\x1f\x8b" indicate a Gzip compressed file
    return gzip.open(file_path, "rb") if magic == b"\x1f\x8b" else open(file_path, "rb")


def get_ipv4_packet(buf, datalink):
    """
    Extracts and returns the IPv4 packet payload from the raw frame buffer
    based on the link-layer encapsulation type (datalink).
    Returns None if the frame does not contain a valid IPv4 packet.
    """
    try:
        # Standard Ethernet encapsulation
        if datalink == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                return eth.data
        # Linux cooked capture encapsulation
        elif datalink == dpkt.pcap.DLT_LINUX_SLL:
            sll = dpkt.sll.SLL(buf)
            if isinstance(sll.data, dpkt.ip.IP):
                return sll.data
        # Raw IP encapsulations (various link-type values for raw IPv4)
        elif datalink in (12, 14, 101, 228):
            ip = dpkt.ip.IP(buf)
            if ip.v == 4:
                return ip
    except Exception:
        pass
    return None


def calc_entropy(counter):
    """
    Calculates Shannon Entropy in bits for a given counter of values.
    H(X) = -sum( P(x_i) * log2(P(x_i)) )
    """
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values() if c > 0)


def extract_data(pcap_list, max_packets):
    """
    Parses PCAPs to count occurrences of source IPs and destination ports,
    and constructs a histogram of packet Inter-Arrival Times (IAT) in milliseconds.
    """
    src_ips, dst_ports = Counter(), Counter()

    # Create a zeroed array to hold the histogram counts across the bins
    hist_counts = np.zeros(len(BINS) - 1, dtype=np.int64)

    # Loop through each PCAP file
    for pcap_file in pcap_list:
        print(f"[*] Parsing {os.path.basename(pcap_file)}...")
        packets_this_file = 0

        # Use a raw C-type double array to eliminate object overhead for the current file
        file_timestamps = array.array("d")

        try:
            with open_pcap(pcap_file) as f:
                pcap = dpkt.pcap.Reader(f)
                datalink = pcap.datalink()
                # Iterate over packets in the PCAP
                for ts, buf in pcap:
                    if packets_this_file >= max_packets:
                        break

                    # Ignore corrupt epoch 0 timestamps (1970)
                    # 946684800 is Jan 1, 2000. This blocks 1970 packets while allowing any modern PCAP.
                    if ts < 946684800:
                        continue

                    packets_this_file += 1

                    # Parse IPv4 packet
                    ip = get_ipv4_packet(buf, datalink)
                    if ip:
                        file_timestamps.append(ts)
                        src_ips[ip.src] += 1
                        if ip.p in (6, 17):
                            try:
                                dst_ports[ip.data.dport] += 1
                            except:
                                pass

            # Calculate IAT histograms if file contains multiple packets
            if len(file_timestamps) > 1:
                # Convert straight to a NumPy array for fast C-level math and sorting
                ts_arr = np.array(file_timestamps, dtype=np.float64)
                ts_arr.sort()

                # Calculate diffs and convert to milliseconds
                iats_ms = np.diff(ts_arr) * 1000.0

                # Drop the raw data into the pre-calculated bins immediately
                counts, _ = np.histogram(iats_ms, bins=BINS)
                hist_counts += counts

        except Exception as e:
            print(f"[-] Error parsing {pcap_file}: {e}")

    # Return the aggregated entropy values and IAT histogram counts
    return calc_entropy(src_ips), calc_entropy(dst_ports), hist_counts


def main():
    # Parse CLI arguments and establish the output path
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_entropy = os.path.join(args.outdir, "entropy.png")
    out_burst = os.path.join(args.outdir, "burstiness.png")

    # Extract metrics for Dataset 1
    print(f"--- Extracting {args.label1} ---")
    ip_ent1, port_ent1, hist_counts1 = extract_data(args.pcap1, args.max_packets)

    # Extract metrics for Dataset 2
    print(f"--- Extracting {args.label2} ---")
    ip_ent2, port_ent2, hist_counts2 = extract_data(args.pcap2, args.max_packets)

    # --- GRAPH 1: Grouped Entropy Bar Chart ---
    # Setup subplots for rendering the Shannon Entropy comparison
    fig1, ax1 = plt.subplots(figsize=(10, 8))
    labels = ["Source IPs", "Destination Ports"]
    vals1 = [ip_ent1, port_ent1]
    vals2 = [ip_ent2, port_ent2]

    x = np.arange(len(labels))
    width = 0.35

    # Render bars for Dataset 1
    ax1.bar(
        x - width / 2,
        vals1,
        width,
        label=args.label1,
        color="#4C72B0",
        edgecolor="black",
        linewidth=1.5,
    )
    # Render bars for Dataset 2
    ax1.bar(
        x + width / 2,
        vals2,
        width,
        label=args.label2,
        color="#C44E52",
        edgecolor="black",
        linewidth=1.5,
    )

    # Configure axes, labels, and ticks
    ax1.set_ylabel("Shannon Entropy (Bits)", fontweight="bold", labelpad=15)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontweight="bold")
    ax1.grid(axis="y", linestyle="--", alpha=0.7)

    # Remove top/right borders
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)

    max_val = max(max(vals1), max(vals2))
    ax1.set_ylim(0, max_val * 1.3)

    # Legend placed horizontally above the graph
    ax1.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1),
        ncol=2,
        framealpha=0.9,
        edgecolor="black",
    )

    # Label text annotations above each bar
    for i, v in enumerate(vals1):
        ax1.text(
            i - width / 2,
            v + (max_val * 0.02),
            f"{v:.2f}",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=20,
        )
    for i, v in enumerate(vals2):
        ax1.text(
            i + width / 2,
            v + (max_val * 0.02),
            f"{v:.2f}",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=20,
        )

    plt.tight_layout()
    plt.savefig(out_entropy, dpi=300, bbox_inches="tight")
    plt.close(fig1)

    # --- GRAPH 2: Overlaid Burstiness Histogram ---
    fig2, ax2 = plt.subplots(figsize=(14, 8))

    # Plot using the `weights` parameter to feed the pre-calculated counts directly into the histogram.
    # We use BINS[:-1] as the faux data points so Matplotlib aligns the bins correctly.
    ax2.hist(
        BINS[:-1],
        bins=BINS,
        weights=hist_counts1,
        color="#4C72B0",
        edgecolor="black",
        alpha=0.6,
        label=args.label1,
    )
    ax2.hist(
        BINS[:-1],
        bins=BINS,
        weights=hist_counts2,
        color="#C44E52",
        edgecolor="black",
        alpha=0.6,
        label=args.label2,
    )

    # Configure axes scales, labels, and ticks
    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_xlabel(
        "Time Between Packets (Milliseconds, Log Scale)", fontweight="bold", labelpad=15
    )
    ax2.set_ylabel("Frequency (Log Scale)", fontweight="bold", labelpad=15)
    ax2.grid(True, linestyle=":", alpha=0.7)

    # Clean border styling
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    # Limit the X-axis tightly to the defined bins
    ax2.set_xlim(BINS[0], BINS[-1])

    # Legend placed horizontally above the graph
    ax2.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1),
        ncol=2,
        framealpha=0.9,
        edgecolor="black",
    )

    plt.tight_layout()
    plt.savefig(out_burst, dpi=300, bbox_inches="tight")
    plt.close(fig2)

    print(f"[+] Output saved to {out_entropy} and {out_burst}")


if __name__ == "__main__":
    main()
