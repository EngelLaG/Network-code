from scapy.all import *
import ipaddress

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

    def get_network_id(ip_addr):
        # Create an IPv4Address object with the specified IP address
        ip_addr = ipaddress.IPv4Address(ip_addr)
        
        # Get the IPv4Network object for the network containing the IP address
        network = ipaddress.IPv4Network(f"{ip_addr}/24", strict=False)
        
        # Get the network ID of the IP address
        network_id = str(network.network_address)
        
        return network_id

    # Usage of Network id function
    network_id_src = get_network_id(ip_src)
    network_id_dst = get_network_id(ip_dst)

    #Creating Class Identefier Function
    def get_ip_class(ip_addr):
        if ip_addr.startswith('10.') or ip_addr.startswith('172.16.') or ip_addr.startswith('192.168.'):
            return 'Class C'
        elif ip_addr.startswith('172.') or ip_addr.startswith('192.'):
            return 'Class B'
        else:
            return 'Class A'
    
    IP_class_src = get_ip_class(ip_src)
    IP_class_dst = get_ip_class(ip_dst)

    


    

    print(f'IP Packet ({packet_type})')
    print(f'\tSource: {ip_src} ({src_ip_type})')
    print(f'\tDestination: {ip_dst} ({dst_ip_type})')
    print(f'\tProtocol: {ip_proto}')
    print(f'\tSize: {ip_size} bytes')
    print(f'\tTTL: {ip_ttl}')
    print(f'\tNetwork Source ID: {network_id_src}')
    print(f'\tNetwork Destination ID: {network_id_dst}')
    print(f'\tSource Class/Notation: {IP_class_src}')
    print(f'\tDestination Class/Notation: {IP_class_dst}\n')
   
  

# Sniff IP packets and analyze them
sniff(filter='ip', prn=analyze_packet)
