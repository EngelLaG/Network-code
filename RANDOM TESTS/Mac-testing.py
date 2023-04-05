from scapy.all import *

eth_iface = "eth0"  # replace with the name of your Ethernet interface

mac_address = get_if_hwaddr(eth_iface)
print(f"MAC address for Ethernet interface {eth_iface}: {mac_address}")