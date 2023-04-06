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