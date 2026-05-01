from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR
from datetime import datetime
import threading
import detection_engine
import firewall
import database 
from collections import defaultdict
import requests 

# CONFIGURATION
# Verify this matches your adapter. If unsure, use the IP address logic.
IFACE = "Wi-Fi" 

captured_packets = []
is_sniffing = False
port_scan_tracker = defaultdict(set) 
ip_location_cache = {} 

# === GLOBAL COUNTERS ===
total_packet_count = 0
count_tcp = 0
count_udp = 0
count_other = 0

def get_ip_location(ip_address):
    if ip_address in ip_location_cache:
        return ip_location_cache[ip_address]

    # Universal Local IP Check (Includes 172. for University Wi-Fi)
    if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172.") or ip_address == "127.0.0.1":
        loc = {"country": "Pakistan", "city": "Karachi", "lat": 24.8607, "lon": 67.0011}
        ip_location_cache[ip_address] = loc
        return loc

    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=1)
        data = response.json()
        if data.get('status') == 'fail': return None
            
        loc = {
            "country": data.get('country', 'Unknown'),
            "city": data.get('city', 'Unknown'),
            "lat": data.get('lat', 0),
            "lon": data.get('lon', 0)
        }
        ip_location_cache[ip_address] = loc
        return loc
    except:
        return None

def packet_callback(packet):
    global captured_packets, total_packet_count, count_tcp, count_udp, count_other
    
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = datetime.now().strftime("%H:%M:%S")

            # Count Protocols
            protocol_name = "Other"
            if TCP in packet: 
                protocol_name = "TCP"; count_tcp += 1
            elif UDP in packet: 
                protocol_name = "UDP"; count_udp += 1
            elif ICMP in packet: 
                protocol_name = "ICMP"; count_other += 1
            else: count_other += 1
            
            total_packet_count += 1

            # === EXTRACT PAYLOAD (Deep Packet Inspection) ===
            payload_content = "-"
            
            # 1. Check for DNS
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                try: 
                    payload_content = f"[DNS] {packet[DNSQR].qname.decode('utf-8').rstrip('.')}"
                except: pass
            
            # 2. Check for Raw Data (HTTP/Text - For SQLi/XSS)
            elif packet.haslayer(Raw):
                try:
                    # Decode bytes to string, ignoring weird characters
                    raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    # Clean up newlines for display
                    payload_content = raw_data.strip()
                except:
                    payload_content = "[Binary Data]"

            packet_data = {
                "timestamp": timestamp, "src": src_ip, "dst": dst_ip,
                "protocol": protocol_name, "payload": payload_content
            }
            
            captured_packets.append(packet_data)
            if len(captured_packets) > 500: captured_packets.pop(0)

            # === THREAT DETECTION ===
            threat = detection_engine.check_threats(packet_data)
            if threat:
                print(f"[!!! ALERT] {threat}")
                firewall.block_ip(src_ip)
                geo = get_ip_location(src_ip)
                database.log_threat(src_ip, geo, threat, "BLOCKED")

    except Exception as e:
        pass

def run_sniffer():
    global is_sniffing
    print(f">>> DPI SNIFFER STARTED ON: {IFACE}")
    while is_sniffing:
        try:
            sniff(prn=packet_callback, filter="ip", store=False, iface=IFACE, timeout=1)
        except Exception:
            is_sniffing = False
            break

def start_sniffing():
    global is_sniffing, captured_packets, total_packet_count, count_tcp, count_udp, count_other
    if not is_sniffing:
        captured_packets = []
        total_packet_count = 0
        count_tcp = 0; count_udp = 0; count_other = 0
        port_scan_tracker.clear()
        detection_engine.ip_traffic_stats.clear()
        
        is_sniffing = True
        t = threading.Thread(target=run_sniffer)
        t.daemon = True
        t.start()

def stop_sniffing():
    global is_sniffing
    is_sniffing = False
    print(">>> SNIFFER STOPPED.")