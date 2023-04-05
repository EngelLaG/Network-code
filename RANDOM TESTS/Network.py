from scapy.all import IP

# Define a packet
packet = IP(dst="8.8.8.8")

# Extract the source IP address from the packet
src_ip = packet.src

# Split the source IP address into octets
src_ip_octets = src_ip.split(".")

# Extract the netmask from the source IP address
netmask_octets = src_ip_octets[:3] + ["0"]

# Compute the network ID by performing a bitwise AND operation between the source IP address and netmask
network_id_octets = [int(src_ip_octets[i]) & int(netmask_octets[i]) for i in range(4)]
network_id = ".".join(str(octet) for octet in network_id_octets)

# Print the network ID
print("Network ID of source IP address:", network_id)
