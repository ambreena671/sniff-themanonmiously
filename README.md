   Network Sniffer Tool:
   A Network Sniffer is a tool that captures, monitors, and analyzes network traffic. It helps network administrators, security analysts, and hackers inspect data packets moving across a network.


   🔧 Prerequisites
Install the required Python library before running:
pip install scapy


🎯 How to Run:
Run the script with:
python network_sniffer.py

Packets stores in:
A .pcap file (captured_traffic.pcap) for Wireshark analysis.
A text log file (captured_data.txt) with summary details.
Stops sniffing gracefully and saves captured data when the user presses Ctrl+C.


  🛠️ What Does a Network Sniffer Do?
✅ Captures network packets (TCP, UDP, ICMP, DNS, FTP, HTTP, HTTPS, etc.)
✅ Analyzes network activity in real-time
✅ Identifies protocols used in communication
✅ Monitors network security for threats
✅ Saves captured traffic for later analysis (e.g., Wireshark)

🚀 How a Network Sniffer Works
1️⃣ Listens to Network Traffic using a network interface (NIC) in promiscuous mode
2️⃣ Captures Packets (data moving between devices)
3️⃣ Extracts Packet Details (source, destination, protocol, payload, etc.)
4️⃣ Displays or Stores Packets for analysis
5️⃣ Filters and Decodes Traffic (e.g., HTTP requests, DNS queries, FTP logins)

🔬 Where Sniffers Are Used
✅ Network Security – Detect malicious activities
✅ Ethical Hacking – Penetration testing & vulnerability assessment
✅ Network Monitoring – Analyze traffic patterns & performance
✅ Forensics – Investigate cyberattacks





