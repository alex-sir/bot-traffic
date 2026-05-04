"""
Script 1: Overview & Statistics Table

Processes two distinct sets of PCAP files (e.g., Year 1 and Year 2)
and generates a single, combined comparison table.

Usage Instructions:
    Run the script from the terminal, providing the paths to your PCAP files.

    Basic usage:
        python3 1_pcap_overview.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                   -l1 "2021" -l2 "2025" \
                                   -n 1000000

    Example with custom output directory:
        python3 1_pcap_overview.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                   -l1 "2021" -l2 "2025" \
                                   -o output/ \
                                   -n 1000000
"""

import argparse
import datetime
import os
import gzip
from collections import Counter
import dpkt
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

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

ICS_PORTS = {
    502: "Modbus",
    20000: "DNP3",
    44818: "EtherNet/IP",
    2222: "EtherNet/IP (alt)",
    102: "S7/ISO-TSAP",
    4840: "OPC UA",
    1089: "FF Fieldbus HSE",
    1090: "FF Fieldbus HSE",
    1091: "FF Fieldbus HSE",
    2404: "IEC 60870-5-104",
    20547: "ProConOS",
    1962: "PCWorx",
    789: "Red Lion",
    9600: "OMRON FINS",
    47808: "BACnet",
    161: "SNMP (ICS mgmt)",
    162: "SNMP trap",
}


def parse_args():
    parser = argparse.ArgumentParser(description="Cross-Year PCAP Overview")
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


def extract_stats(pcap_list, max_packets):
    """Encapsulated extraction function to process a list of files into metrics."""
    total_packets, total_bytes, ics_packets = 0, 0, 0
    protocols, src_ips, dst_ips, dst_ports = Counter(), Counter(), Counter(), Counter()
    active_duration_sec = 0
    t_start = None

    for pcap_file in pcap_list:
        print(f"[*] Parsing {os.path.basename(pcap_file)}...")
        packets_this_file = 0

        # List uses O(1) rolling markers
        file_start = None
        file_end = None

        try:
            with open_pcap(pcap_file) as f:
                pcap = dpkt.pcap.Reader(f)
                datalink = pcap.datalink()
                for ts, buf in pcap:
                    if packets_this_file >= max_packets:
                        break

                    # Ignore corrupt epoch 0 timestamps (1970)
                    # 946684800 is Jan 1, 2000. This blocks 1970 packets while allowing any modern PCAP.
                    if ts < 946684800:
                        continue

                    packets_this_file += 1
                    total_packets += 1
                    total_bytes += len(buf)

                    # Update rolling markers for duration calculations
                    if file_start is None or ts < file_start:
                        file_start = ts
                    if file_end is None or ts > file_end:
                        file_end = ts

                    ip = get_ipv4_packet(buf, datalink)
                    if ip:
                        src_ips[ip.src] += 1
                        dst_ips[ip.dst] += 1
                        port = None
                        if ip.p == 6:
                            protocols["TCP"] += 1
                            try:
                                port = ip.data.dport
                                dst_ports[port] += 1
                            except:
                                pass
                        elif ip.p == 17:
                            protocols["UDP"] += 1
                            try:
                                port = ip.data.dport
                                dst_ports[port] += 1
                            except:
                                pass
                        elif ip.p == 1:
                            protocols["ICMP"] += 1
                        else:
                            protocols["Other"] += 1

                        if port and port in ICS_PORTS:
                            ics_packets += 1
                    else:
                        protocols["Non-IP"] += 1

            if file_start is not None:
                if t_start is None or file_start < t_start:
                    t_start = file_start
                active_duration_sec += file_end - file_start
        except Exception as e:
            print(f"[-] Error parsing {pcap_file}: {e}")

    # Format output dictionary
    start_time_str = (
        datetime.datetime.fromtimestamp(t_start, tz=datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        if t_start
        else "N/A"
    )
    active_duration_sec = max(active_duration_sec, 1)

    volume_mb = total_bytes / (1024 * 1024)
    bandwidth_mbps = (total_bytes * 8 / 1_000_000) / active_duration_sec
    pkt_rate = total_packets / active_duration_sec
    dominant_proto = protocols.most_common(1)[0][0] if protocols else "N/A"

    ics_percentage = (ics_packets / total_packets) * 100 if total_packets > 0 else 0
    non_ics_packets = total_packets - ics_packets
    non_ics_percentage = (
        (non_ics_packets / total_packets) * 100 if total_packets > 0 else 0
    )

    return {
        "Files Analyzed": f"{len(pcap_list)}",
        "Initial Start (UTC)": f"{start_time_str}",
        "Active Duration": f"{active_duration_sec:.1f} sec",
        "Total Packets": f"{total_packets:,}",
        "Total Volume": f"{volume_mb:.2f} MB",
        "Avg Packet Rate": f"{pkt_rate:.1f} pkts/s",
        "Avg Bandwidth": f"{bandwidth_mbps:.3f} Mbps",
        "Dominant Protocol": f"{dominant_proto}",
        "ICS Traffic": f"{ics_percentage:.4f}% ({ics_packets:,})",
        "Non-ICS Traffic": f"{non_ics_percentage:.4f}% ({non_ics_packets:,})",
        "Unique Src IPs": f"{len(src_ips):,}",
        "Unique Dst IPs": f"{len(dst_ips):,}",
        "Unique Dst Ports": f"{len(dst_ports):,}",
    }


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    out_file = os.path.join(args.outdir, "pcap_overview.png")

    print(f"--- Extracting {args.label1} ---")
    stats1 = extract_stats(args.pcap1, args.max_packets)
    print(f"--- Extracting {args.label2} ---")
    stats2 = extract_stats(args.pcap2, args.max_packets)

    # --- Visualization ---
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.axis("tight")
    ax.axis("off")

    # Combine metrics into a 3-column table format
    table_data = []
    keys = list(stats1.keys())
    for k in keys:
        table_data.append([k, stats1[k], stats2[k]])

    table = ax.table(
        cellText=table_data,
        colLabels=["Metric", args.label1, args.label2],
        loc="center",
        cellLoc="left",
    )

    table.auto_set_font_size(False)
    table.set_fontsize(18)
    table.scale(1.2, 2.5)

    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor("#DDDDDD")
        if row == 0:
            cell.set_text_props(weight="bold", color="white", size=20)
            if col == 0:
                cell.set_facecolor("#2B475D")
            elif col == 1:
                cell.set_facecolor("#4C72B0")
            else:
                cell.set_facecolor("#C44E52")
            cell.set_text_props(ha="center")
        else:
            cell.set_facecolor("#F8F9FA" if row % 2 == 0 else "#FFFFFF")
            if col == 0:
                cell.set_text_props(weight="bold", ha="left")
            else:
                cell.set_text_props(ha="right")
        cell.PAD = 0.05

    plt.tight_layout()
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    print(f"[+] Combined summary table saved to {out_file}")


if __name__ == "__main__":
    main()
