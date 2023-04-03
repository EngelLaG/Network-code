from scapy.all import *

def analyze_packet(packet):
    # Check if the packet is a valid IP packet
    if not packet.haslayer(IP):
        print('Invalid IP packet')
        return

    # Extract IP header information
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    ip_proto = packet[IP].proto
    ip_size = len(packet[IP])
    ip_ttl = packet[IP].ttl

    # Determine if packet is unicast, multicast, or broadcast
    if ip_dst == '255.255.255.255':
        packet_type = 'Broadcast'
    elif ip_dst.startswith('224.'):
        packet_type = 'Multicast'
    else:
        packet_type = 'Unicast'

    # Determine if source and destination IP addresses are public or private
    def is_private_ip(ip_addr):
        ip_octets = ip_addr.split('.')
        return (ip_octets[0] == '10') or \
               (ip_octets[0] == '172' and 16 <= int(ip_octets[1]) <= 31) or \
               (ip_octets[0] == '192' and ip_octets[1] == '168')

    src_ip_type = 'Private' if is_private_ip(ip_src) else 'Public'
    dst_ip_type = 'Private' if is_private_ip(ip_dst) else 'Public'

    # Print packet information
    print(f'IP Packet ({packet_type})')
    print(f'\tSource: {ip_src} ({src_ip_type})')
    print(f'\tDestination: {ip_dst} ({dst_ip_type})')
    print(f'\tProtocol: {ip_proto}')
    print(f'\tSize: {ip_size} bytes')
    print(f'\tTTL: {ip_ttl}\n')

# Sniff IP packets and analyze them
sniff(filter='ip', prn=analyze_packet)