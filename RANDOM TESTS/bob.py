    def get_app_protocol(packet):
        if packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            return 'UDP'
        else:
            return 'Unknown'

    app_protocol_src = get_app_protocol(packet)

print(f'\tApplication type: {app_protocol_src}')
