# Simple-Packet-Sniffer
A lightweight packet sniffer built using Python and Scapy. This script captures network packets, extracts basic details (such as source/destination IP and protocol type), and logs them for further analysis.

Features
Captures IP packets (TCP, UDP, and DNS traffic).
Displays captured packets in real-time.
Logs packet details to captured_packets.log.
Uses Scapy for flexible packet processing.
Prerequisites
Ensure you have Python installed and Scapy installed on your system. You can install Scapy using:

bash
Copy
Edit
pip install scapy
Usage
Run the script with administrative privileges to start sniffing packets:

bash
Copy
Edit
sudo python3 packet_sniffer.py  # Linux/Mac
python packet_sniffer.py        # Windows (Run as Administrator)
To stop the sniffer, use CTRL+C.

Output Example
The script will print and log captured packet details like:

yaml
Copy
Edit
[+] Packet: 192.168.1.10 -> 8.8.8.8 | Protocol: DNS
[+] Packet: 10.0.0.5 -> 192.168.1.20 | Protocol: TCP
