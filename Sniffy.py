from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import csv

CSV_FILENAME = "network_traffic_log.csv"

# Initializer for the CSV file with headers when the script starts
with open(CSV_FILENAME, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Protocol", "Source IP", "Dest IP", "Source Port", "Dest Port", "Action/Status", "Payload Data"])

def get_service_name(port):
    """Translates common port numbers into plain English services."""
    common_ports = {
        80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
        21: "FTP", 3389: "RDP", 67: "DHCP", 68: "DHCP"
    }
    return common_ports.get(port, f"Port {port}")

def analyze_packet(packet):
    """Analyzes a packet, prints details, and logs it to a CSV."""
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # These variables are just used to store data for the CSV
        protocol = "Unknown"
        src_port, dst_port = "", ""
        action_status = ""
        payload_data = ""

        print(f"\n[{timestamp}] --- New Packet Captured ---")
        print(f"NETWORK: {src_ip} -> {dst_ip}")

        # 1. TCP Analysis & Payload Inspection
        if TCP in packet:
            protocol = "TCP"
            tcp_layer = packet[TCP]
            src_port = get_service_name(tcp_layer.sport)
            dst_port = get_service_name(tcp_layer.dport)
            
            flags = tcp_layer.flags
            if 'S' in flags and 'A' not in flags:
                action_status = "[SYN] Connection Request"
            elif 'S' in flags and 'A' in flags:
                action_status = "[SYN-ACK] Connection Acknowledged"
            elif 'F' in flags:
                action_status = "[FIN] Closing Connection"
            else:
                action_status = "Transmitting Data"

            print(f"TRANSPORT (TCP): {src_port} -> {dst_port} | Status: {action_status}")

            # DEEP PACKET INSPECTION
            if packet.haslayer(Raw):
                # Extract raw bytes and ignore characters that can't be decoded as text
                raw_bytes = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Look for common HTTP keywords in the raw text
                if "HTTP" in raw_bytes or "GET " in raw_bytes or "POST " in raw_bytes:
                    # Grab just the first line (e.g., "GET /index.html HTTP/1.1") to keep logs clean
                    first_line = raw_bytes.split('\n')[0].strip()
                    payload_data = f"HTTP Traffic: {first_line}"
                    print(f"PAYLOAD INTERCEPTED: {payload_data}")

        # 2. UDP Analysis
        elif UDP in packet:
            protocol = "UDP"
            udp_layer = packet[UDP]
            src_port = get_service_name(udp_layer.sport)
            dst_port = get_service_name(udp_layer.dport)
            action_status = "Connectionless Datagram"
            print(f"TRANSPORT (UDP): {src_port} -> {dst_port}")

        # 3. ICMP Analysis
        elif ICMP in packet:
            protocol = "ICMP"
            icmp_type = packet[ICMP].type
            if icmp_type == 8:
                action_status = "Echo Request (Ping)"
            elif icmp_type == 0:
                action_status = "Echo Reply (Pong)"
            else:
                action_status = f"Diagnostic (Type {icmp_type})"
            print(f"TRANSPORT (ICMP): {action_status}")

        with open(CSV_FILENAME, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, protocol, src_ip, dst_ip, src_port, dst_port, action_status, payload_data])

def start_sniffer():
    print(f"Starting network sniffer... (Press Ctrl+C to stop)")
    print(f"Logging data to: {CSV_FILENAME}")
    sniff(prn=analyze_packet, store=0)

if __name__ == "__main__":
    start_sniffer()