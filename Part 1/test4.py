from scapy.all import *

def analyze_packet(packet):
    # Check if the packet is a valid Ethernet packet
    if not packet.haslayer(Ether):
        print('Invalid Ethernet packet')
        return

    # Extract Ethernet header information
    eth_src = packet[Ether].src
    eth_dst = packet[Ether].dst
    eth_type = packet[Ether].type
    eth_size = len(packet)

    # Determine if packet is unicast, multicast, or broadcast
    if eth_dst == 'ff:ff:ff:ff:ff:ff':
        packet_type = 'Broadcast'
    elif (int(eth_dst.split(':')[0], 16) & 1) == 1:
        packet_type = 'Multicast'
    else:
        packet_type = 'Unicast'

    # Print packet information
    print(f'Ethernet Packet ({packet_type})')
    print(f'\tSource: {eth_src}')
    print(f'\tDestination: {eth_dst}')
    print(f'\tType: 0x{eth_type:04x}')
    print(f'\tSize: {eth_size} bytes\n')

# Sniff Ethernet packets and analyze them
sniff(filter='ether', prn=analyze_packet)