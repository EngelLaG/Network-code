from scapy.all import *
import ipaddress

def print_ip_cidr_broadcast(packet):
    ip_src = packet[IP].src
    src_ip_cidr, dst_ip_cidr, broadcast_ip = ip_cidr_broadcast(ip_src, ip_src)
    print(f"Source IP CIDR: {src_ip_cidr}")
    print(f"Destination IP CIDR: {dst_ip_cidr}")
    print(f"Broadcast IP: {broadcast_ip}")

def ip_cidr_broadcast(ip_src: str, ip_dst: str) -> tuple:
    src_ip_cidr = str(ipaddress.IPv4Network(ip_src + '/32', strict=False).with_prefixlen)
    dst_ip_cidr = str(ipaddress.IPv4Network(ip_dst + '/32', strict=False).with_prefixlen)
    broadcast_ip = str(ipaddress.IPv4Network(ip_dst + '/32', strict=False).broadcast_address)
    return (src_ip_cidr, dst_ip_cidr, broadcast_ip)

sniff(filter='ip', prn=print_ip_cidr_broadcast, count=1)
