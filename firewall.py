from scapy.layers.inet import IP
from scapy.all import *


class Firewall:
    def __init__(self):
        self.allowed_ips = []

    def allow_ip(self, ip_address):
        if ip_address not in self.allowed_ips:
            self.allowed_ips.append(ip_address)
            print(f"IP adresi {ip_address} güvenlik duvarına eklendi.")
        else:
            print(f"IP adresi {ip_address} zaten güvenlik duvarında bulunuyor.")

    def block_ip(self, ip_address):
        if ip_address in self.allowed_ips:
            self.allowed_ips.remove(ip_address)
            print(f"IP adresi {ip_address} güvenlik duvarından kaldırıldı.")
        else:
            print(f"IP adresi {ip_address} güvenlik duvarında bulunmuyor.")

    def is_packet_allowed(self, packet):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if ip_src in self.allowed_ips or ip_dst in self.allowed_ips:
            return True
        else:
            return False
