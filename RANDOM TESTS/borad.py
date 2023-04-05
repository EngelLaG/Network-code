from scapy.all import *

def handle_packet(packet):
    # Extract the source IP address from the received packet
    src_ip = packet[IP].src
    
    # Construct the IP packet with the broadcast destination and source IP address
    ip = IP(dst="255.255.255.255", src=src_ip)
    
    # Send the packet on the network interface
    send(ip)

# Sniff for incoming packets and call handle_packet() for each packet received
sniff(prn=handle_packet)