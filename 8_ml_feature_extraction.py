"""
Script 8: ML Feature Extraction for Anomaly Detection

Reads PCAP files and compiles 3 CSVs containing extracted features
for Isolation Forest, LSTM, and Autoencoder models.

Usage Instructions:
    Run the script from the terminal, providing the paths to your PCAP files.

    Basic usage:
        python3 8_ml_feature_extraction.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                           -l1 "2021" -l2 "2025" \
                                           -n 1000000

    Example with custom output directory:
        python3 8_ml_feature_extraction.py -p1 data/2021/*.pcap.gz -p2 data/2025/*.pcap.gz \
                                           -l1 "2021" -l2 "2025" \
                                           -o output_ml/ \
                                           -n 1000000
"""

import argparse
import os
import gzip
import csv
import math
from collections import defaultdict
import dpkt


def parse_args():
    """
    Parses CLI arguments to support processing two distinct datasets (e.g., baseline vs. test).
    Allows for configurable packet limits to facilitate rapid testing before full processing.
    """
    parser = argparse.ArgumentParser(
        description="Extract ML features from PCAPs for two datasets"
    )
    parser.add_argument(
        "-p1", "--pcap1", nargs="+", required=True, help="Paths to Dataset 1 PCAPs"
    )
    parser.add_argument(
        "-p2", "--pcap2", nargs="+", required=True, help="Paths to Dataset 2 PCAPs"
    )
    parser.add_argument(
        "-l1",
        "--label1",
        default="Dataset_1",
        help="Label for Dataset 1 (used for file naming)",
    )
    parser.add_argument(
        "-l2",
        "--label2",
        default="Dataset_2",
        help="Label for Dataset 2 (used for file naming)",
    )
    parser.add_argument("-o", "--outdir", default="output_ml", help="Output directory")
    parser.add_argument(
        "-n", "--max-packets", type=int, default=1000000, help="Max packets per file"
    )
    return parser.parse_args()


def open_pcap(file_path):
    """
    Safely opens a PCAP file by checking its magic bytes.
    Automatically handles gzipped files (magic b"\x1f\x8b") from the Merit network telescope.
    """
    with open(file_path, "rb") as f:
        magic = f.read(2)
    return gzip.open(file_path, "rb") if magic == b"\x1f\x8b" else open(file_path, "rb")


def get_ipv4_packet(buf, datalink):
    """
    Extracts the IPv4 payload by resolving the link-layer encapsulation type.
    Accounts for standard Ethernet, Linux Cooked Captures (SLL), and raw IP links.
    Drops non-IPv4 traffic (e.g., IPv6, ARP) by returning None.
    """
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
    except:
        pass
    return None


def calculate_entropy(data_list):
    """
    Calculates the Shannon Entropy for a given list of values (e.g., destination ports).
    A high entropy value indicates high diversity (e.g., a bot scanning many random ports).
    A low entropy value indicates focused targeting (e.g., repeatedly hitting port 502).
    """
    if not data_list:
        return 0.0
    freq = {}
    for item in data_list:
        freq[item] = freq.get(item, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data_list)
        entropy -= p * math.log2(p)
    return entropy


def extract_features(pcap_list, label, outdir, max_packets):
    """
    Core extraction logic applied to a single list of PCAP files.
    Generates three distinct CSVs optimized for three different ML architectures.
    """

    # Establish clean file paths using the provided dataset label
    file_prefix = label.replace(" ", "_")
    iso_csv_path = os.path.join(outdir, f"{file_prefix}_isolation_forest_features.csv")
    lstm_csv_path = os.path.join(outdir, f"{file_prefix}_lstm_features.csv")
    ae_csv_path = os.path.join(outdir, f"{file_prefix}_autoencoder_features.csv")

    # --- Header Definitions ---
    # Isolation Forest looks for statistically unusual flows (aggregated connection metrics)
    iso_headers = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "proto",
        "flow_packet_count",
        "flow_bytes_total",
        "flow_mean_pkt_size",
        "flow_std_pkt_size",
        "flow_duration",
        "bytes_per_second",
        "syn_ratio",
        "rst_ratio",
        "dst_port_entropy",
        "dst_ip_entropy",
        "avg_ip_ttl",
        "avg_tcp_window_size",
    ]

    # LSTM evaluates time-ordered sequences to detect abnormal pacing/burstiness
    lstm_headers = [
        "timestamp",
        "src_ip",
        "dst_port",
        "proto",
        "inter_arrival_time",
        "frame_len",
        "tcp_time_delta",
        "tcp_flags_syn",
        "tcp_flags_ack",
        "tcp_flags_fin",
        "tcp_flags_rst",
        "flow_packet_count",
    ]

    # Autoencoder reconstructs numerical vectors per packet; poor reconstruction = anomaly
    # Integrates both packet-level data and flow/host-level context
    ae_headers = [
        "timestamp",
        "src_ip",
        "dst_port",
        "proto",
        "frame_len",
        "ip_len",
        "ip_ttl",
        "ip_flags_df",
        "ip_flags_mf",
        "tcp_flags_syn",
        "tcp_flags_ack",
        "tcp_flags_fin",
        "tcp_flags_rst",
        "tcp_flags_push",
        "tcp_window_size",
        "tcp_len",
        "udp_length",
        "icmp_type",
        "icmp_code",
        "dns_resp_len",
        "flow_bytes_total",
        "flow_duration",
        "dst_port_entropy",
        "flow_packet_count",
    ]

    with (
        open(iso_csv_path, "w", newline="") as f_iso,
        open(lstm_csv_path, "w", newline="") as f_lstm,
        open(ae_csv_path, "w", newline="") as f_ae,
    ):
        iso_writer = csv.writer(f_iso)
        lstm_writer = csv.writer(f_lstm)
        ae_writer = csv.writer(f_ae)

        # Write the headers to initialize the CSV structure
        iso_writer.writerow(iso_headers)
        lstm_writer.writerow(lstm_headers)
        ae_writer.writerow(ae_headers)

        for pcap_file in pcap_list:
            print(f"[*] Extracting features from {os.path.basename(pcap_file)}...")

            # --- Two-Tiered Data Tracking Architecture ---

            # Tier 1: Connection Flow Tracking (5-tuple)
            # Aggregates metrics specific to a single connection session.
            flows = defaultdict(
                lambda: {
                    "packets": 0,
                    "bytes": 0,
                    "start_ts": None,
                    "end_ts": None,
                    "sizes": [],
                    "syn_count": 0,
                    "rst_count": 0,
                    "ttls": [],
                    "windows": [],
                }
            )

            # Tier 2: Host Behavior Tracking (grouped solely by Source IP)
            # Tracks macroscopic behavior of a single bot across ALL its connections
            # to calculate accurate scanning entropy.
            hosts = defaultdict(lambda: {"dst_ports": [], "dst_ips": []})

            # Buffers to hold sequence/packet data in memory until the file finishes parsing.
            # This allows us to append the final calculated flow totals (like flow_packet_count) to each packet vector.
            ae_records = []
            lstm_records = []

            # Time tracking variables for inter-arrival calculations
            last_ts = None
            last_tcp_ts = None
            packets_this_file = 0

            try:
                with open_pcap(pcap_file) as f:
                    pcap = dpkt.pcap.Reader(f)
                    datalink = pcap.datalink()

                    for ts, buf in pcap:
                        if packets_this_file >= max_packets:
                            break

                        # Filter out corrupted epoch 0 (1970) timestamps often found in raw datasets
                        if ts < 946684800:
                            continue

                        packets_this_file += 1
                        ip = get_ipv4_packet(buf, datalink)
                        if not ip:
                            continue

                        frame_len = len(buf)
                        # Calculate global packet pacing (useful for detecting artificial scanner delays)
                        inter_arrival_time = (ts - last_ts) if last_ts else 0.0
                        last_ts = ts

                        # Transport layer initialization
                        sport, dport = 0, 0
                        tcp_syn = tcp_ack = tcp_fin = tcp_rst = tcp_push = 0
                        tcp_win = tcp_len = udp_len = icmp_type = icmp_code = (
                            dns_resp_len
                        ) = 0
                        tcp_time_delta = 0.0

                        # --- Parse TCP Traffic ---
                        if ip.p == dpkt.ip.IP_PROTO_TCP:
                            try:
                                tcp = ip.data
                                sport, dport = tcp.sport, tcp.dport
                                # Extract specific control flags (indicative of scans, floods, or normal teardowns)
                                tcp_syn = 1 if (tcp.flags & dpkt.tcp.TH_SYN) else 0
                                tcp_ack = 1 if (tcp.flags & dpkt.tcp.TH_ACK) else 0
                                tcp_fin = 1 if (tcp.flags & dpkt.tcp.TH_FIN) else 0
                                tcp_rst = 1 if (tcp.flags & dpkt.tcp.TH_RST) else 0
                                tcp_push = 1 if (tcp.flags & dpkt.tcp.TH_PUSH) else 0
                                tcp_win = tcp.win
                                tcp_len = len(tcp.data)
                                tcp_time_delta = (
                                    (ts - last_tcp_ts) if last_tcp_ts else 0.0
                                )
                                last_tcp_ts = ts
                            except:
                                pass

                        # --- Parse UDP Traffic ---
                        elif ip.p == dpkt.ip.IP_PROTO_UDP:
                            try:
                                udp = ip.data
                                sport, dport = udp.sport, udp.dport
                                udp_len = udp.ulen
                                # Check for DNS amplification/responses
                                if sport == 53 or dport == 53:
                                    try:
                                        dns = dpkt.dns.DNS(udp.data)
                                        if dns.qr == dpkt.dns.DNS_R:
                                            dns_resp_len = len(udp.data)
                                    except:
                                        pass
                            except:
                                pass

                        # --- Parse ICMP Traffic ---
                        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                            try:
                                icmp = ip.data
                                icmp_type = icmp.type
                                icmp_code = icmp.code
                            except:
                                pass

                        # Generate unique identifiers for dictionary lookups
                        src_ip_str = "%d.%d.%d.%d" % tuple(ip.src)
                        dst_ip_str = "%d.%d.%d.%d" % tuple(ip.dst)
                        flow_key = (src_ip_str, dst_ip_str, sport, dport, ip.p)

                        # --- UPDATE TIER 1: Flow Stats ---
                        flow = flows[flow_key]
                        flow["packets"] += 1
                        flow["bytes"] += frame_len
                        flow["sizes"].append(frame_len)
                        flow["syn_count"] += tcp_syn
                        flow["rst_count"] += tcp_rst
                        flow["ttls"].append(ip.ttl)
                        if ip.p == dpkt.ip.IP_PROTO_TCP:
                            flow["windows"].append(tcp_win)
                        if flow["start_ts"] is None:
                            flow["start_ts"] = ts
                        flow["end_ts"] = ts

                        # --- UPDATE TIER 2: Host (Source IP) Stats ---
                        host = hosts[src_ip_str]
                        host["dst_ports"].append(dport)
                        host["dst_ips"].append(dst_ip_str)

                        # --- BUFFER: LSTM Record ---
                        lstm_row = [
                            ts,
                            src_ip_str,
                            dport,
                            ip.p,
                            inter_arrival_time,
                            frame_len,
                            tcp_time_delta,
                            tcp_syn,
                            tcp_ack,
                            tcp_fin,
                            tcp_rst,
                        ]
                        lstm_records.append((flow_key, lstm_row))

                        # --- BUFFER: Autoencoder Record ---
                        # Convert explicit IP fragmentation flags to integers
                        ip_df = int(ip.df)
                        ip_mf = int(ip.mf)
                        ae_row = [
                            ts,
                            src_ip_str,
                            dport,
                            ip.p,
                            frame_len,
                            ip.len,
                            ip.ttl,
                            ip_df,
                            ip_mf,
                            tcp_syn,
                            tcp_ack,
                            tcp_fin,
                            tcp_rst,
                            tcp_push,
                            tcp_win,
                            tcp_len,
                            udp_len,
                            icmp_type,
                            icmp_code,
                            dns_resp_len,
                        ]
                        ae_records.append((src_ip_str, flow_key, ae_row))

            except Exception as e:
                print(f"[-] Error parsing {pcap_file}: {e}")

            # --- POST-PROCESSING: PRE-CALCULATE ENTROPY FOR EACH HOST ---
            # Now that the file is fully read, evaluate the diversity of each bot's targeting
            host_entropies = {}
            for src_ip, stats in hosts.items():
                host_entropies[src_ip] = {
                    "dport_ent": calculate_entropy(stats["dst_ports"]),
                    "dip_ent": calculate_entropy(stats["dst_ips"]),
                }

            # --- WRITE: Isolation Forest Records ---
            for key, stats in flows.items():
                src_ip = key[0]

                # Calculate flow duration (enforce minimum to prevent division by zero)
                duration = stats["end_ts"] - stats["start_ts"]
                duration = max(duration, 0.0001)

                stats["duration"] = duration

                # Calculate statistical profiles of the flow
                bps = stats["bytes"] / duration
                mean_size = sum(stats["sizes"]) / stats["packets"]
                variance = (
                    sum((x - mean_size) ** 2 for x in stats["sizes"]) / stats["packets"]
                )
                std_size = math.sqrt(variance)

                # Determine ratio of connection establishment (SYN) vs teardown/rejection (RST)
                syn_ratio = stats["syn_count"] / stats["packets"]
                rst_ratio = stats["rst_count"] / stats["packets"]

                # Compute average network hops and window sizes
                avg_ttl = (
                    sum(stats["ttls"]) / len(stats["ttls"]) if stats["ttls"] else 0
                )
                avg_win = (
                    sum(stats["windows"]) / len(stats["windows"])
                    if stats["windows"]
                    else 0
                )

                # Fetch the Tier 2 behavioral entropy mapped to this specific source IP
                dport_ent = host_entropies[src_ip]["dport_ent"]
                dip_ent = host_entropies[src_ip]["dip_ent"]

                iso_writer.writerow(
                    [
                        stats["start_ts"],
                        key[0],
                        key[1],
                        key[2],
                        key[3],
                        key[4],
                        stats["packets"],  # flow_packet_count
                        stats["bytes"],
                        mean_size,
                        std_size,
                        duration,
                        bps,
                        syn_ratio,
                        rst_ratio,
                        dport_ent,
                        dip_ent,
                        avg_ttl,
                        avg_win,
                    ]
                )

            # --- WRITE: LSTM Records ---
            for flow_key, lstm_row in lstm_records:
                flow_stats = flows[flow_key]
                lstm_row.append(flow_stats["packets"])  # flow_packet_count
                lstm_writer.writerow(lstm_row)

            # --- WRITE: Autoencoder Records ---
            for src_ip, flow_key, ae_row in ae_records:
                flow_stats = flows[flow_key]
                ae_row.extend(
                    [
                        flow_stats["bytes"],  # flow_bytes_total
                        flow_stats["duration"],  # flow_duration
                        host_entropies[src_ip]["dport_ent"],  # dst_port_entropy
                        flow_stats["packets"],  # flow_packet_count
                    ]
                )
                ae_writer.writerow(ae_row)

    print(f"[+] Feature extraction complete for {label}. Results saved in {outdir}/")


def main():
    """
    Main execution block.
    Triggers the feature extraction sequentially for both comparative datasets.
    """
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    print(f"--- Extracting ML Features for {args.label1} ---")
    extract_features(args.pcap1, args.label1, args.outdir, args.max_packets)

    print(f"\n--- Extracting ML Features for {args.label2} ---")
    extract_features(args.pcap2, args.label2, args.outdir, args.max_packets)


if __name__ == "__main__":
    main()
