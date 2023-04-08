from scapy import *

def get_layer(ip_pkt):
    # Extract the source and destination IP addresses
    ip_src = ip_pkt[IP].src
    ip_dst = ip_pkt[IP].dst

    # Determine the highest layer that the IP packet has
    if ip_pkt.haslayer(Raw):
        return "Application"
    elif ip_pkt.haslayer(TCP):
        return "Transport"
    elif ip_src.startswith("224.") or ip_dst.startswith("224."):
        return "Multicast"
    elif ip_src == "0.0.0.0" or ip_dst == "255.255.255.255":
        return "Broadcast"
    else:
        return "Network"
    
