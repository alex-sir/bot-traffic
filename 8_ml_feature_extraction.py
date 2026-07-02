"""
Script 8: ML Feature Extraction for Anomaly Detection

Reads PCAP files and compiles 3 CSVs containing extracted features
for Isolation Forest, LSTM, and Autoencoder models.

Usage Instructions:
    Run the script from the terminal, providing the paths to your PCAP files.

    Basic usage:
        python3 8_ml_feature_extraction.py -p data/2025/*.pcap.gz \
                                           -n 1000000

    Example with custom output directory:
        python3 8_ml_feature_extraction.py -p data/2025/*.pcap.gz \
                                           -o output/ \
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
    parser = argparse.ArgumentParser(description="Extract ML features from PCAPs")
    parser.add_argument(
        "-p", "--pcap", nargs="+", required=True, help="Paths to PCAP files"
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
    except:
        pass
    return None


def calculate_entropy(data_list):
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


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    iso_csv_path = os.path.join(args.outdir, "isolation_forest_features.csv")
    lstm_csv_path = os.path.join(args.outdir, "lstm_features.csv")
    ae_csv_path = os.path.join(args.outdir, "autoencoder_features.csv")

    # Define headers
    iso_headers = [
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

    lstm_headers = [
        "timestamp",
        "inter_arrival_time",
        "frame_len",
        "tcp_time_delta",
        "tcp_flags_syn",
        "tcp_flags_ack",
        "tcp_flags_fin",
        "tcp_flags_rst",
        "ip_proto",
        "tcp_dstport",
    ]

    ae_headers = [
        "timestamp",
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
    ]

    with (
        open(iso_csv_path, "w", newline="") as f_iso,
        open(lstm_csv_path, "w", newline="") as f_lstm,
        open(ae_csv_path, "w", newline="") as f_ae,
    ):
        iso_writer = csv.writer(f_iso)
        lstm_writer = csv.writer(f_lstm)
        ae_writer = csv.writer(f_ae)

        iso_writer.writerow(iso_headers)
        lstm_writer.writerow(lstm_headers)
        ae_writer.writerow(ae_headers)

        for pcap_file in args.pcap:
            print(f"[*] Extracting features from {os.path.basename(pcap_file)}...")

            flows = defaultdict(
                lambda: {
                    "packets": 0,
                    "bytes": 0,
                    "start_ts": None,
                    "end_ts": None,
                    "sizes": [],
                    "syn_count": 0,
                    "rst_count": 0,
                    "dst_ports": [],
                    "dst_ips": [],
                    "ttls": [],
                    "windows": [],
                }
            )

            last_ts = None
            last_tcp_ts = None
            packets_this_file = 0

            try:
                with open_pcap(pcap_file) as f:
                    pcap = dpkt.pcap.Reader(f)
                    datalink = pcap.datalink()

                    for ts, buf in pcap:
                        if packets_this_file >= args.max_packets:
                            break
                        if ts < 946684800:
                            continue

                        packets_this_file += 1
                        ip = get_ipv4_packet(buf, datalink)
                        if not ip:
                            continue

                        frame_len = len(buf)
                        inter_arrival_time = (ts - last_ts) if last_ts else 0.0
                        last_ts = ts

                        # Transport layer parsing
                        sport, dport = 0, 0
                        tcp_syn = tcp_ack = tcp_fin = tcp_rst = tcp_push = 0
                        tcp_win = tcp_len = udp_len = icmp_type = icmp_code = (
                            dns_resp_len
                        ) = 0
                        tcp_time_delta = 0.0

                        if ip.p == dpkt.ip.IP_PROTO_TCP:
                            try:
                                tcp = ip.data
                                sport, dport = tcp.sport, tcp.dport
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
                        elif ip.p == dpkt.ip.IP_PROTO_UDP:
                            try:
                                udp = ip.data
                                sport, dport = udp.sport, udp.dport
                                udp_len = udp.ulen
                                if sport == 53 or dport == 53:
                                    try:
                                        dns = dpkt.dns.DNS(udp.data)
                                        if dns.qr == dpkt.dns.DNS_R:
                                            dns_resp_len = len(udp.data)
                                    except:
                                        pass
                            except:
                                pass
                        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                            try:
                                icmp = ip.data
                                icmp_type = icmp.type
                                icmp_code = icmp.code
                            except:
                                pass

                        # --- LSTM Record ---
                        lstm_writer.writerow(
                            [
                                ts,
                                inter_arrival_time,
                                frame_len,
                                tcp_time_delta,
                                tcp_syn,
                                tcp_ack,
                                tcp_fin,
                                tcp_rst,
                                ip.p,
                                dport,
                            ]
                        )

                        # --- Autoencoder Record ---
                        # FIXED: Use explicit dpkt properties instead of deprecated ip.off bitmask
                        ip_df = int(ip.df)
                        ip_mf = int(ip.mf)

                        ae_writer.writerow(
                            [
                                ts,
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
                        )

                        # --- Isolation Forest (Flow Updating) ---
                        src_ip_str = "%d.%d.%d.%d" % tuple(ip.src)
                        dst_ip_str = "%d.%d.%d.%d" % tuple(ip.dst)
                        flow_key = (src_ip_str, dst_ip_str, sport, dport, ip.p)

                        flow = flows[flow_key]
                        flow["packets"] += 1
                        flow["bytes"] += frame_len
                        flow["sizes"].append(frame_len)
                        flow["syn_count"] += tcp_syn
                        flow["rst_count"] += tcp_rst
                        flow["dst_ports"].append(dport)
                        flow["dst_ips"].append(dst_ip_str)
                        flow["ttls"].append(ip.ttl)
                        if ip.p == dpkt.ip.IP_PROTO_TCP:
                            flow["windows"].append(tcp_win)

                        if flow["start_ts"] is None:
                            flow["start_ts"] = ts
                        flow["end_ts"] = ts

            except Exception as e:
                print(f"[-] Error parsing {pcap_file}: {e}")

            # Calculate and write IF flow records per PCAP
            for key, stats in flows.items():
                duration = stats["end_ts"] - stats["start_ts"]
                duration = max(duration, 0.0001)
                bps = stats["bytes"] / duration

                mean_size = sum(stats["sizes"]) / stats["packets"]
                variance = (
                    sum((x - mean_size) ** 2 for x in stats["sizes"]) / stats["packets"]
                )
                std_size = math.sqrt(variance)

                syn_ratio = stats["syn_count"] / stats["packets"]
                rst_ratio = stats["rst_count"] / stats["packets"]

                dport_ent = calculate_entropy(stats["dst_ports"])
                dip_ent = calculate_entropy(stats["dst_ips"])

                avg_ttl = (
                    sum(stats["ttls"]) / len(stats["ttls"]) if stats["ttls"] else 0
                )
                avg_win = (
                    sum(stats["windows"]) / len(stats["windows"])
                    if stats["windows"]
                    else 0
                )

                iso_writer.writerow(
                    [
                        key[0],
                        key[1],
                        key[2],
                        key[3],
                        key[4],
                        stats["packets"],
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

    print(f"[+] Feature extraction complete. Results saved in {args.outdir}/")


if __name__ == "__main__":
    main()
