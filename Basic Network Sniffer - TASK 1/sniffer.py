#!/usr/bin/env python3
"""
Basic Network Sniffer - Internship Project
--------------------------------------------
Captures live network packets, parses their structure (Ethernet/IP/
Transport/Payload), displays details, logs a summary to a file, and
saves raw captures to a .pcap file for Wireshark analysis.

Requires: scapy (pip install scapy)
Must be run with admin/root privileges.
"""
from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
from datetime import datetime
import argparse
import csv
import os
import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---------- Global state ----------
packet_count = 0
captured_packets = []          # stored for pcap export
protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
LOG_FILE = "captures/packet_log.csv"


def init_log():
    """Create the CSV log file with headers."""
    os.makedirs("captures", exist_ok=True)
    with open(LOG_FILE, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["No.", "Time", "Src IP", "Dst IP", "Protocol",
             "Src Port", "Dst Port", "Length", "Info"]
        )


def log_to_csv(row):
    with open(LOG_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(row)


def process_packet(packet):
    """Callback executed for every captured packet."""
    global packet_count
    packet_count += 1
    captured_packets.append(packet)

    timestamp = datetime.now().strftime("%H:%M:%S")
    length = len(packet)

    print(f"\n{'='*65}")
    print(f"Packet #{packet_count} | Time: {timestamp} | Length: {length} bytes")
    print(f"{'='*65}")

    # ---------------- ARP (non-IP) ----------------
    if ARP in packet:
        protocol_stats["ARP"] += 1
        print(f"Protocol       : ARP")
        print(f"Sender IP      : {packet[ARP].psrc}")
        print(f"Target IP      : {packet[ARP].pdst}")
        log_to_csv([packet_count, timestamp, packet[ARP].psrc,
                    packet[ARP].pdst, "ARP", "-", "-", length, "ARP request/reply"])
        return

# ---------------- IP Layer (IPv4 or IPv6) ----------------
    if IP in packet or IPv6 in packet:
        if IP in packet:
            ip_layer = packet[IP]
            ip_version = "IPv4"
            ttl = ip_layer.ttl
        else:
            ip_layer = packet[IPv6]
            ip_version = "IPv6"
            ttl = ip_layer.hlim  # IPv6 uses "hop limit" instead of TTL

        src_ip, dst_ip = ip_layer.src, ip_layer.dst

        print(f"IP Version     : {ip_version}")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"TTL/Hop Limit  : {ttl}")


        proto_name = "Other"
        src_port = dst_port = "-"
        info = ""

        if TCP in packet:
            proto_name = "TCP"
            tcp_layer = packet[TCP]
            src_port, dst_port = tcp_layer.sport, tcp_layer.dport
            flags = tcp_layer.flags
            print(f"Protocol       : TCP")
            print(f"Src Port       : {src_port}")
            print(f"Dst Port       : {dst_port}")
            print(f"Flags          : {flags}")
            info = f"Flags={flags}"

        elif UDP in packet:
            proto_name = "UDP"
            udp_layer = packet[UDP]
            src_port, dst_port = udp_layer.sport, udp_layer.dport
            print(f"Protocol       : UDP")
            print(f"Src Port       : {src_port}")
            print(f"Dst Port       : {dst_port}")

        elif ICMP in packet:
            proto_name = "ICMP"
            icmp_layer = packet[ICMP]
            print(f"Protocol       : ICMP")
            print(f"Type           : {icmp_layer.type}")
            print(f"Code           : {icmp_layer.code}")
            info = f"Type={icmp_layer.type}"

        else:
            print(f"Protocol       : Other (proto={ip_layer.proto})")

        protocol_stats[proto_name] = protocol_stats.get(proto_name, 0) + 1

        
        # ---------------- Payload ----------------
        if Raw in packet:
            payload = packet[Raw].load
            try:
                decoded = payload.decode("utf-8", errors="replace")
                # Keep ONLY plain ASCII printable characters (safe for Windows console)
                safe_text = "".join(
                    c if (c.isascii() and c.isprintable()) else "."
                    for c in decoded
                )
                print(f"Payload (text) : {safe_text[:100]}")
                info += f" | Payload preview: {safe_text[:50]}"
            except Exception:
                print(f"Payload (raw)  : <binary data, {len(payload)} bytes>")

        log_to_csv([packet_count, timestamp, src_ip, dst_ip,
                    proto_name, src_port, dst_port, length, info])
    else:
        print(f"Non-IP packet: {packet.summary()}")


def print_summary():
    """Print protocol statistics at the end of capture."""
    print(f"\n{'#'*65}")
    print(f"CAPTURE SUMMARY")
    print(f"{'#'*65}")
    print(f"Total packets captured: {packet_count}")
    for proto, count in protocol_stats.items():
        if count > 0:
            print(f"  {proto:10s}: {count}")
    print(f"{'#'*65}\n")


def start_sniffer(interface, count, bpf_filter, save_pcap):
    init_log()
    print("Starting packet capture... (Ctrl+C to stop early)")
    print(f"Interface: {interface or 'default'} | Filter: {bpf_filter or 'none'} | Count: {count}\n")

    try:
        sniff(
            iface=interface,
            prn=process_packet,
            count=count if count > 0 else 0,
            filter=bpf_filter,
            store=False
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print("Permission denied. Run this script with sudo/Administrator privileges.")
        return
    except Exception as e:
        print(f"Error: {e}")
        return

    print_summary()

    if save_pcap and captured_packets:
        pcap_path = f"captures/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(pcap_path, captured_packets)
        print(f"Saved raw capture to: {pcap_path} (open in Wireshark)")

    print(f"CSV log saved to: {LOG_FILE}")


def parse_args():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer")
    parser.add_argument("-i", "--interface", default=None,
                         help="Network interface (e.g., eth0, Wi-Fi). Default: system default")
    parser.add_argument("-c", "--count", type=int, default=20,
                         help="Number of packets to capture (0 = infinite). Default: 20")
    parser.add_argument("-f", "--filter", default="tcp or udp or icmp or arp",
                         help='BPF filter string, e.g. "tcp port 80". Default: tcp/udp/icmp/arp')
    parser.add_argument("--no-pcap", action="store_true",
                         help="Don't save a .pcap file")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    start_sniffer(
        interface=args.interface,
        count=args.count,
        bpf_filter=args.filter,
        save_pcap=not args.no_pcap
    )