import subprocess

def get_arp_table():
    output = subprocess.check_output("arp -a")
    output = output.decode("utf-8")
    lines = output.strip().split("\n")
    table = []
    for line in lines:
        if line.startswith("Interface"):
            continue
        parts = line.split()
        if len(parts) == 3:
            ip_address = parts[0]
            mac_address = parts[1]
            table.append((ip_address, mac_address))
    return table

def print_arp_table(table):
    print("ARP Table:")
    print("==========")
    print("{:<20} {}".format("IP Address", "MAC Address"))
    print("-" * 40)
    for row in table:
        ip_address, mac_address = row
        print("{:<20} {}".format(ip_address, mac_address))

table = get_arp_table()
print_arp_table(table)