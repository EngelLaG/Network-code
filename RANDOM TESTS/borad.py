from scapy.all import *

def analyze_packet(packet):
    # Check if the packet is a valid IP packet
    if not packet.haslayer(IP):
        print('Invalid IP packet')
        return

    # Extract IP header information
    ip_src = packet[IP].src
    
    # Extract application protocol if present
    if packet.haslayer(TCP):
        app_protocol = 'TCP'
    elif packet.haslayer(UDP):
        app_protocol = 'UDP'
    else:
        app_protocol = 'Unknown'

    print(f'Source IP: {ip_src}, Application Protocol: {app_protocol}')

# Sniff IP packets and analyze them
sniff(filter='ip', prn=analyze_packet, count=1)