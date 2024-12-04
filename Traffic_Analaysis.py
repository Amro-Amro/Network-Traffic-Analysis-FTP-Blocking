from scapy.all import sniff
import logging

logging.basicConfig(filename='network_security.log', level=logging.INFO)

blocked_ips = ['192.168.1.100', '192.168.1.101'] #list of blocked ip addresses to prevent insecure ips

def packet_callback(packet):
    if packet.haslayer('IP'):         # Checking if the packet has an IP layer
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        
        logging.info(f"Packet from {ip_src} to {ip_dst}")
        
        if ip_src in blocked_ips:             # This is blocking traffic from specific IP addresses
            print(f"Blocked packet from {ip_src}")
            logging.info(f"Blocked packet from {ip_src}")

        
        if packet.haslayer('TCP'):         # Checking for TCP layer (to detect ports)
            dport = packet['TCP'].dport
            
            
            if dport == 1194:             # Detecting VPN traffic (OpenVPN on port 1194)
                print(f"VPN traffic detected from {ip_src}")
                logging.info(f"VPN traffic detected from {ip_src}")
            
            
            if dport == 21:               # Blocking FTP traffic (port 21) ex) of what I can block and restrict
                print(f"Blocked FTP traffic from {ip_src}")
                logging.info(f"Blocked FTP traffic from {ip_src}")

sniff(iface='Wi-Fi', prn=packet_callback, count=50) #Snifiinfin packets, for this example its on Wi-Fi
