from scapy.all import *
import ipaddress

def analyze_packet_ether(packet):
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
    print(f'==================================================================================================================================================')
    print(f'Ethernet Packet ({packet_type})')
    print(f'\tSource: {eth_src}')
    print(f'\tDestination: {eth_dst}')
    print(f'\tType: 0x{eth_type:04x}')
    print(f'\tSize: {eth_size} bytes\n')

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


    ip_src_cidr = str(ipaddress.IPv4Network(ip_src + '/32', strict=False).with_prefixlen)
    ip_dst_cidr = str(ipaddress.IPv4Network(ip_dst + '/32', strict=False).with_prefixlen)
    broadcast_ip = str(ipaddress.IPv4Network(ip_dst + '/32', strict=False).broadcast_address)
    


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

    def classify_ports(packet):
        if TCP in packet:
            sport = packet[TCP].sport
            if sport < 1024:
                print(f"{packet[IP].src}:{sport} - Well-known port")
            elif sport < 49152:
                print(f"{packet[IP].src}:{sport} - Registered port")
            else:
                print(f"{packet[IP].src}:{sport} - Dynamic port")
        else:
            print("Not a TCP packet")

    def get_transport_protocol(packet):
        # List of supported transport layer protocols
        protocols = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP",
            41: "IPv6",
            89: "OSPF",
            132: "SCTP"
        }

        # Extract the protocol type
        if packet.haslayer(IP):
            protocol_num = packet[IP].proto
            protocol_name = protocols.get(protocol_num, "Unknown")
            return protocol_name
        else:
            return "Unknown"
    # Extract transport layer protocol information
    transport_proto = get_transport_protocol(packet)
        

    print(f'IP Packet ({packet_type})')
    print(f'\tSource: {ip_src} ({src_ip_type})')
    print(f'\tSource CIDR: {ip_src_cidr}')
    print(f'\tDestination: {ip_dst} ({dst_ip_type})')
    print(f'\tDestination CIDR: {ip_dst_cidr}')
    print(f'\tBroadcast IP: {broadcast_ip}')
    print(f'\tProtocol: {ip_proto}')
    print(f'\tSize: {ip_size} bytes')
    print(f'\tTTL: {ip_ttl}')
    print(f'\tNetwork Source ID: {network_id_src}')
    print(f'\tNetwork Destination ID: {network_id_dst}')
    print(f'\tSource Class/Notation: {IP_class_src}')
    print(f'\tDestination Class/Notation: {IP_class_dst}')
    print(f'\tApplication Type/Transport Protocol: {transport_proto}')
    print(f'\tPort Type:')
    classify_ports(packet)
    


# Sniff IP packets and analyze them
sniff(filter='ip', prn=analyze_packet, count = 1) 
sniff(prn=analyze_packet_ether, count = 1)

