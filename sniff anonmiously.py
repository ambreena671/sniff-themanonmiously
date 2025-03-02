import scapy.all as scapy
import threading
import time
import warnings


warnings.filterwarnings("ignore", category=UserWarning)


PCAP_FILE = "captured_traffic.pcap"
LOG_FILE = "captured_data.txt"
captured_packets = []


def display_banner():
    banner = """
    [Hacker]
    +----------------+
    |                |
    |   Network      |
    |   Sniffer      |
    |                |
    +----------------+
             |
             | Analyzing Network Traffic
             |
             v
    +----------------+
    |                |
    |   Target       |
    |                |
    +----------------+
    """
    print(banner)
    time.sleep(3)  


def packet_callback(packet):
    protocol = "UNKNOWN"

    if packet.haslayer(scapy.TCP):
        protocol = "TCP"
    elif packet.haslayer(scapy.UDP):
        protocol = "UDP"
    elif packet.haslayer(scapy.ICMP):
        protocol = "ICMP"
    elif packet.haslayer(scapy.DNS):
        protocol = "DNS"
    elif packet.haslayer(scapy.Raw):  # Generic check for unknown protocols
        raw_payload = str(packet[scapy.Raw].load).lower()
        if "ftp" in raw_payload:
            protocol = "FTP"
        elif "smtp" in raw_payload:
            protocol = "SMTP"
        elif "http" in raw_payload and "https" not in raw_payload:
            protocol = "HTTP"
        elif "https" in raw_payload:
            protocol = "HTTPS"

    captured_packets.append(packet)  
    print(f"[+] Captured {protocol} Packet: {packet.summary()}")

    
    with open(LOG_FILE, "a") as f:
        f.write(f"{protocol}: {packet.summary()}\n")


def start_sniffing():
    print("\n[*] Starting Network Sniffer... Press Ctrl+C to stop.\n")
    try:
        scapy.sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping sniffer...")
        save_packets()


def save_packets():
    if captured_packets:
        scapy.wrpcap(PCAP_FILE, captured_packets)
        print(f"[✓] Captured packets saved to {PCAP_FILE}")
        print(f"[✓] Packet details saved to {LOG_FILE}")


if __name__ == "__main__":
    banner_thread = threading.Thread(target=display_banner)
    banner_thread.start()

    
    banner_thread.join()

    start_sniffing()
