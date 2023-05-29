from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether
from data import DatabaseManager
from termcolor import colored
import matplotlib.pyplot as plt
from scapy.all import *
import netifaces as ni
import pandas as pd
import argparse
import re


active_connections = {}
open_ports = []

db_manager = DatabaseManager('packet_database.db')
db_manager.connect()

packets = []
active_connections = {}

def packet_handler(packet):
    packets.append(packet)  # Burada paketi ekliyoruz.

    packet_info = {
        'src_ip': str(packet[IP].src),
        'dst_ip': str(packet[IP].dst),
        'src_port': str(packet[TCP].sport),
        'dst_port': str(packet[TCP].dport),
        'protocol': str(packet[IP].proto),
        'timestamp': str(packet.time),
        'packet_size': str(len(packet)),
        'raw_data': str(packet.payload),
        'src_mac': str(packet[Ether].src),  # Kaynak MAC adresi
        'dst_mac': str(packet[Ether].dst)  # Hedef MAC adresi
    }

    # Paketi veritabanına kaydeth
    db_manager.save_packet(packet_info)

    print(colored('--- Packet Summary ---', "blue"))
    print(f"Source IP       : {packet_info['src_ip']}")
    print(f"Destination IP  : {packet_info['dst_ip']}")
    print(f"Source Port     : {packet_info['src_port']}")
    print(f"Destination Port: {packet_info['dst_port']}")
    print(f"Protocol        : {packet_info['protocol']}")
    print(f"Timestamp       : {packet_info['timestamp']}")
    print(f"Packet Size     : {packet_info['packet_size']}")
    print(f"Raw Data        : {packet_info['raw_data']}")
    print(f"Source MAC      : {packet_info['src_mac']}")
    print(f"Destination MAC : {packet_info['dst_mac']}")
    print()


    update_active_connections(packet_info)
    detect_xss_sql_injection(packet_info)




def capture_traffic(filter_expr, count, save_packets=False, visualize_stats=False, live_monitor=False, target_ip=None, protocols=None, min_packet_size=None, max_packet_size=None, target_port=None):
    if live_monitor:
        plt.ion()  # Canlı izleme modunu etkinleştir

    if target_ip:
        filter_expr += f" and (src host {target_ip} or dst host {target_ip})"

    if protocols:
        protocol_filters = []
        for protocol in protocols:
            protocol_filters.append(f"proto {protocol}")
        filter_expr += " and (" + " or ".join(protocol_filters) + ")"

    if min_packet_size is not None:
        filter_expr += f" and greater {min_packet_size}"

    if max_packet_size is not None:
        filter_expr += f" and less {max_packet_size}"

    if target_port is not None:
        filter_expr += f" and (src port {target_port} or dst port {target_port})"

    global packets  # Global değişkeni kullanmak için
    packets = []  # Yakalanan paketleri sıfırla

    sniff(prn=packet_handler, filter=filter_expr, count=count)

    if save_packets:
        wrpcap('captured_packets.pcap', packets)



def update_active_connections(packet_info):
    src_ip = packet_info['src_ip']
    dst_ip = packet_info['dst_ip']
    src_port = packet_info['src_port']
    dst_port = packet_info['dst_port']
    protocol = packet_info['protocol']

    connection_key = f"{src_ip}:{src_port} > {dst_ip}:{dst_port}"

    if connection_key in active_connections:
        active_connections[connection_key]['last_seen'] = packet_info['timestamp']
    else:
        active_connections[connection_key] = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'start_time': packet_info['timestamp'],
            'last_seen': packet_info['timestamp']
        }

    print(colored('--- Active Links ---', "blue"))
    for connection_key, connection_info in active_connections.items():
        print(f"Connection          : {connection_key}")
        print(f"Source IP           : {connection_info['src_ip']}")
        print(f"Destination IP      : {connection_info['dst_ip']}")
        print(f"Source Port         : {connection_info['src_port']}")
        print(f"Destination Port    : {connection_info['dst_port']}")
        print(f"Source MAC          : {packet_info['src_mac']}")
        print(f"Destination MAC     : {packet_info['dst_mac']}")
        print(f"Protocol            : {connection_info['protocol']}")
        print(f"Packet Size         : {packet_info['packet_size']}")
        print(f"Start Time          : {connection_info['start_time']}")
        print(f"Last Seen Time      : {connection_info['last_seen']}")
        print()



def detect_xss_sql_injection(packet_info):
    if packet_info['protocol'] == 6:  # Sadece TCP protokolü üzerinde HTTP paketlerini analiz edelim
        if packet_info['dst_port'] == 80 or packet_info['dst_port'] == 8080:
            # Paketin içeriğini alalım
            payload = packet_info['raw_data']

            # SQL enjeksiyonu taraması
            sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
            for keyword in sql_keywords:
                if re.search(rf"\b{re.escape(keyword)}\b", payload, re.IGNORECASE):
                    print(colored('--- SQL Injection Detected ---', "red"))
                    print(f"Source IP           : {packet_info['src_ip']}")
                    print(f"Destination IP      : {packet_info['dst_ip']}")
                    print(f"Source Port         : {packet_info['src_port']}")
                    print(f"Destination Port    : {packet_info['dst_port']}")
                    print(f"Source MAC          : {packet_info['src_mac']}")
                    print(f"Destination MAC     : {packet_info['dst_mac']}")
                    print(f"Protocol            : {packet_info['protocol']}")
                    print(f"Packet Size         : {packet_info['packet_size']}")
                    print(f"Timestamp           : {packet_info['timestamp']}")
                    print(f"Packet Size         : {packet_info['packet_size']}")
                    print(f"Raw Data            : {packet_info['raw_data']}")
                    print()
                    break

            # XSS taraması
            xss_patterns = ['<script>', 'alert(']
            for pattern in xss_patterns:
                if pattern in payload:
                    print(colored('--- XSS Detection ---', "red"))
                    print(f"Source IP           : {packet_info['src_ip']}")
                    print(f"Destination IP      : {packet_info['dst_ip']}")
                    print(f"Source Port         : {packet_info['src_port']}")
                    print(f"Destination Port    : {packet_info['dst_port']}")
                    print(f"Source MAC          : {packet_info['src_mac']}")
                    print(f"Destination MAC     : {packet_info['dst_mac']}")
                    print(f"Protocol            : {packet_info['protocol']}")
                    print(f"Packet Size         : {packet_info['packet_size']}")
                    print(f"Timestamp           : {packet_info['timestamp']}")
                    print(f"Packet Size         : {packet_info['packet_size']}")
                    print(f"Raw Data            : {packet_info['raw_data']}")
                    print()
                    break

            # OS komutu enjeksiyonu taraması
            os_command_patterns = ['; ls', '&& cat /etc/passwd']
            for pattern in os_command_patterns:
                if pattern in payload:
                    print(colored('--- OS Command Injection Detection ---', "red"))
                    print(f"Source IP           : {packet_info['src_ip']}")
                    print(f"Destination IP      : {packet_info['dst_ip']}")
                    print(f"Source Port         : {packet_info['src_port']}")
                    print(f"Destination Port    : {packet_info['dst_port']}")
                    print(f"Source MAC          : {packet_info['src_mac']}")
                    print(f"Destination MAC     : {packet_info['dst_mac']}")
                    print(f"Protocol            : {packet_info['protocol']}")
                    print(f"Packet Size         : {packet_info['packet_size']}")
                    print(f"Timestamp           : {packet_info['timestamp']}")
                    print(f"Packet Size         : {packet_info['packet_size']}")
                    print(f"Raw Data            : {packet_info['raw_data']}")
                    print()



def validate_interface(interface):
    interfaces = ni.interfaces()
    if interface not in interfaces:
        print(f"Invalid interface: {interface}")
        print("Available interfaces:")
        for iface in interfaces:
            print(iface)
        return False
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Network Traffic Capture Tool')
    parser.add_argument('-i', '--interface', type=str, help='Network interface')
    parser.add_argument('-f', '--filter', type=str, default='tcp', help='Filter expression for capturing packets')
    parser.add_argument('-c', '--count', type=int, default=10, help='Number of packets to capture')
    parser.add_argument('-sv', '--save-packets', action='store_true', help='Save captured packets')
    parser.add_argument('-lm', '--live-monitor', action='store_true', help='Live monitoring mode')
    parser.add_argument('-tip', '--target-ip', type=str, help='Destination IP address')
    parser.add_argument('-pr', '--protocols', nargs='+', type=int, help='List of protocols')
    parser.add_argument('-tp', '--target-port', type=int, help='Target port')
    parser.add_argument('--min', type=int, help='Minimum packet size')
    parser.add_argument('--max', type=int, help='Maximum packet size')
    args = parser.parse_args()

    if args.interface:
        if not validate_interface(args.interface):
            sys.exit(1)
        else:
            conf.iface = args.interface

    capture_traffic(args.filter, args.count, args.save_packets, args.live_monitor, args.target_ip, args.protocols, args.min, args.max, args.target_port)
