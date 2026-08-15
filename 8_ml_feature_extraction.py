"""
Script 8: ML Feature Extraction for Anomaly Detection

Reads PCAP files using a parallelized two-pass stream to compile a single CSV 
containing combined extracted features for Isolation Forest, LSTM, and Autoencoder models.

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
import shutil
import tempfile
import concurrent.futures
import gc
from collections import defaultdict
import dpkt


def parse_args():
    """
    Parses CLI arguments and enforces strict, conservative CPU limits.
    """
    parser = argparse.ArgumentParser(
        description="Extract ML features from PCAPs using safe multi-core processing"
    )
    parser.add_argument(
        "-p1", "--pcap1", nargs="+", required=True, help="Paths to Dataset 1 PCAPs"
    )
    parser.add_argument(
        "-p2", "--pcap2", nargs="+", required=True, help="Paths to Dataset 2 PCAPs"
    )
    parser.add_argument(
        "-l1", "--label1", default="Dataset_1", help="Label for Dataset 1"
    )
    parser.add_argument(
        "-l2", "--label2", default="Dataset_2", help="Label for Dataset 2"
    )
    parser.add_argument("-o", "--outdir", default="output_ml", help="Output directory")
    parser.add_argument(
        "-n", "--max-packets", type=int, default=1000000, help="Max packets per file"
    )

    # Strict Limit: Use at most half the cores, and never more than 4 by default.
    total_cores = os.cpu_count() or 4
    safe_cores = max(1, min(4, total_cores // 2))

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=safe_cores,
        help=f"Number of concurrent CPU workers. Safely defaulted to {safe_cores}.",
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


def process_single_pcap(pcap_file, max_packets, temp_dir):
    """
    Worker function executed independently by a CPU core.
    """
    if hasattr(os, "nice"):
        try:
            os.nice(10)
        except AttributeError:
            pass

    base_name = os.path.basename(pcap_file)
    temp_csv_path = os.path.join(temp_dir, f"{base_name}.tmp.csv")

    # Force real-time logging to the terminal by disabling output buffering
    print(f"    [~] Worker started: {base_name}", flush=True)

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
    hosts = defaultdict(lambda: {"dst_ports": [], "dst_ips": []})

    # ==========================================
    # PASS 1: BUILD LIGHTWEIGHT METRIC DICTIONARIES
    # ==========================================
    packets_this_file = 0
    try:
        with open_pcap(pcap_file) as f:
            pcap = dpkt.pcap.Reader(f)
            datalink = pcap.datalink()

            for ts, buf in pcap:
                if packets_this_file >= max_packets:
                    break
                if ts < 946684800:
                    continue

                packets_this_file += 1
                ip = get_ipv4_packet(buf, datalink)
                if not ip:
                    continue

                frame_len = len(buf)
                sport, dport = 0, 0
                tcp_syn = tcp_rst = tcp_win = 0

                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    try:
                        tcp = ip.data
                        if isinstance(tcp, dpkt.tcp.TCP):
                            sport, dport = tcp.sport, tcp.dport
                            tcp_syn = 1 if (tcp.flags & dpkt.tcp.TH_SYN) else 0
                            tcp_rst = 1 if (tcp.flags & dpkt.tcp.TH_RST) else 0
                            tcp_win = tcp.win
                    except Exception:
                        pass
                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    try:
                        udp = ip.data
                        if isinstance(udp, dpkt.udp.UDP):
                            sport, dport = udp.sport, udp.dport
                    except Exception:
                        pass

                src_ip_str = "%d.%d.%d.%d" % tuple(ip.src)
                dst_ip_str = "%d.%d.%d.%d" % tuple(ip.dst)
                flow_key = (src_ip_str, dst_ip_str, sport, dport, ip.p)

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

                host = hosts[src_ip_str]
                host["dst_ports"].append(dport)
                host["dst_ips"].append(dst_ip_str)

    except Exception as e:
        print(
            f"    [-] Worker Warning: Pass 1 issue in {base_name}. Error: {e}",
            flush=True,
        )

    # --- POST-PASS 1: PRUNE INVALID FLOWS ---
    host_entropies = {}
    for src_ip, stats in hosts.items():
        host_entropies[src_ip] = {
            "dport_ent": calculate_entropy(stats["dst_ports"]),
            "dip_ent": calculate_entropy(stats["dst_ips"]),
        }

    valid_flows = {}
    for flow_key, stats in flows.items():
        if (
            stats["start_ts"] is None
            or stats["end_ts"] is None
            or stats["packets"] == 0
        ):
            continue

        duration = stats["end_ts"] - stats["start_ts"]
        stats["duration"] = max(duration, 0.0001)
        stats["bps"] = stats["bytes"] / stats["duration"]
        mean_size = sum(stats["sizes"]) / stats["packets"]
        stats["mean_size"] = mean_size
        variance = sum((x - mean_size) ** 2 for x in stats["sizes"]) / stats["packets"]
        stats["std_size"] = math.sqrt(variance)
        stats["syn_ratio"] = stats["syn_count"] / stats["packets"]
        stats["rst_ratio"] = stats["rst_count"] / stats["packets"]
        stats["avg_ttl"] = (
            sum(stats["ttls"]) / len(stats["ttls"]) if stats["ttls"] else 0
        )
        stats["avg_win"] = (
            sum(stats["windows"]) / len(stats["windows"]) if stats["windows"] else 0
        )

        valid_flows[flow_key] = stats
    flows = valid_flows

    # ==========================================
    # PASS 2: STREAM WRITE COMBINED ROWS TO TEMP
    # ==========================================
    last_ts = last_tcp_ts = None
    packets_this_file = 0

    try:
        with open(temp_csv_path, "w", newline="") as f_out:
            writer = csv.writer(f_out)
            with open_pcap(pcap_file) as f:
                pcap = dpkt.pcap.Reader(f)
                datalink = pcap.datalink()

                for ts, buf in pcap:
                    if packets_this_file >= max_packets:
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

                    sport, dport = 0, 0
                    tcp_syn = tcp_ack = tcp_fin = tcp_rst = tcp_push = 0
                    tcp_win = tcp_len = udp_len = icmp_type = icmp_code = (
                        dns_resp_len
                    ) = 0
                    tcp_time_delta = 0.0

                    if ip.p == dpkt.ip.IP_PROTO_TCP:
                        try:
                            tcp = ip.data
                            if isinstance(tcp, dpkt.tcp.TCP):
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
                        except Exception:
                            pass
                    elif ip.p == dpkt.ip.IP_PROTO_UDP:
                        try:
                            udp = ip.data
                            if isinstance(udp, dpkt.udp.UDP):
                                sport, dport = udp.sport, udp.dport
                                udp_len = udp.ulen
                                if sport == 53 or dport == 53:
                                    try:
                                        dns = dpkt.dns.DNS(udp.data)
                                        if dns.qr == dpkt.dns.DNS_R:
                                            dns_resp_len = len(udp.data)
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                        try:
                            icmp = ip.data
                            if isinstance(icmp, dpkt.icmp.ICMP):
                                icmp_type = icmp.type
                                icmp_code = icmp.code
                        except Exception:
                            pass

                    src_ip_str = "%d.%d.%d.%d" % tuple(ip.src)
                    dst_ip_str = "%d.%d.%d.%d" % tuple(ip.dst)
                    flow_key = (src_ip_str, dst_ip_str, sport, dport, ip.p)

                    if flow_key not in flows:
                        continue

                    flow_stats = flows[flow_key]
                    host_stats = host_entropies.get(
                        src_ip_str, {"dport_ent": 0.0, "dip_ent": 0.0}
                    )
                    ip_df = int(ip.df)
                    ip_mf = int(ip.mf)

                    writer.writerow(
                        [
                            ts,
                            src_ip_str,
                            dst_ip_str,
                            sport,
                            dport,
                            ip.p,
                            inter_arrival_time,
                            frame_len,
                            ip.len,
                            ip.ttl,
                            ip_df,
                            ip_mf,
                            tcp_time_delta,
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
                            flow_stats["packets"],
                            flow_stats["bytes"],
                            flow_stats["duration"],
                            flow_stats["mean_size"],
                            flow_stats["std_size"],
                            flow_stats["bps"],
                            flow_stats["syn_ratio"],
                            flow_stats["rst_ratio"],
                            host_stats["dport_ent"],
                            host_stats["dip_ent"],
                            flow_stats["avg_ttl"],
                            flow_stats["avg_win"],
                        ]
                    )

    except Exception as e:
        print(
            f"    [-] Worker Warning: Pass 2 issue in {base_name}. Error: {e}",
            flush=True,
        )
        return None

    # Aggressively release memory before returning to the worker pool
    del flows
    del hosts
    del valid_flows
    gc.collect()

    # Flush the success message so it appears immediately
    print(f"    [+] Worker finished: {base_name}", flush=True)
    return temp_csv_path


def extract_features(pcap_list, label, outdir, max_packets, max_workers):
    """
    Manages the multiprocessing pool and combines the temp files into the final dataset.
    """
    file_prefix = label.replace(" ", "_")
    combined_csv_path = os.path.join(outdir, f"{file_prefix}_combined_features.csv")

    combined_headers = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "proto",
        "inter_arrival_time",
        "frame_len",
        "ip_len",
        "ip_ttl",
        "ip_flags_df",
        "ip_flags_mf",
        "tcp_time_delta",
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
        "flow_packet_count",
        "flow_bytes_total",
        "flow_duration",
        "flow_mean_pkt_size",
        "flow_std_pkt_size",
        "bytes_per_second",
        "syn_ratio",
        "rst_ratio",
        "dst_port_entropy",
        "dst_ip_entropy",
        "avg_ip_ttl",
        "avg_tcp_window_size",
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        valid_temp_files = []

        print(
            f"\n[*] Spinning up {max_workers} safe background workers to process {label}..."
        )

        with concurrent.futures.ProcessPoolExecutor(
            max_workers=max_workers
        ) as executor:
            futures = {
                executor.submit(process_single_pcap, pcap, max_packets, temp_dir): pcap
                for pcap in pcap_list
            }

            for future in concurrent.futures.as_completed(futures):
                result_path = future.result()
                if result_path and os.path.exists(result_path):
                    valid_temp_files.append(result_path)

        print(
            f"[*] Aggregating {len(valid_temp_files)} threads into {combined_csv_path}..."
        )
        with open(combined_csv_path, "wb") as f_out:
            header_line = ",".join(combined_headers) + "\n"
            f_out.write(header_line.encode("utf-8"))

            for t_file in valid_temp_files:
                with open(t_file, "rb") as f_in:
                    shutil.copyfileobj(f_in, f_out)

    print(f"[+] Feature extraction complete for {label}. Results saved.")


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    print("--- Safe Parallel ML Feature Extraction Started ---")
    print(f"[*] Hardware Limit: Restricted to {args.workers} CPU Cores")

    extract_features(
        args.pcap1, args.label1, args.outdir, args.max_packets, args.workers
    )
    extract_features(
        args.pcap2, args.label2, args.outdir, args.max_packets, args.workers
    )


if __name__ == "__main__":
    main()
