from scapy.all import sniff, IP, TCP, UDP, DNS
import logging

# Configure logging to save captured packets
logging.basicConfig(filename="captured_packets.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def packet_callback(packet):
    """ Function to process captured packets """
    try:
        # Print basic packet details
        print(packet.summary())
        logging.info(packet.summary())

        # Check if the packet has an IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "Unknown"

            # Check for protocol type
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif DNS in packet:
                protocol = "DNS"

            print(f"[+] Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")
            logging.info(f"[+] Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")

    except Exception as e:
        print(f"[ERROR] {e}")
        logging.error(f"[ERROR] {e}")

print("Starting packet sniffer... Press CTRL+C to stop.")

# Sniff network packets (Filter: Capture only IP packets)
sniff(filter="ip", prn=packet_callback, store=False)
