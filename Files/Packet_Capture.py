import pcapy

def packet_handler(hdr, data):
    # This function will be called for each captured packet
    # Add code here to process the packet data

# Open the network interface and start capturing packets
cap = pcapy.open_live('eth0', 65536, 1, 0)
cap.loop(0, packet_handler)
