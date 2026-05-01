from collections import defaultdict
import time

# Traffic Stats for DDoS Tracking
ip_traffic_stats = defaultdict(lambda: {'count': 0, 'start_time': time.time()})

# === CONFIG: BLACKLIST ===
BLACKLISTED_IPS = ["192.168.18.200", "8.8.8.8", "1.1.1.1"]

# === CONFIG: WHITELIST ===
# Ignore DDoS checks from these IPs (e.g. Gateway)
SAFE_IPS = ["127.0.0.1", "192.168.18.128", "192.168.18.1"]

# PAYLOAD SIGNATURES
THREAT_SIGNATURES = [
    "cmd.exe", "root", "SELECT *", "DROP TABLE", "script>", "virus_test"
]

def check_threats(packet_data):
    src_ip = packet_data['src']
    
    # Strip spaces or artifacts from IP string
    clean_ip = src_ip.split(' ')[-1] if ' ' in src_ip else src_ip
    
    payload = packet_data.get('payload', "")
    current_time = time.time()

    # 1. BLACKLIST CHECK
    if clean_ip in BLACKLISTED_IPS:
        return f"Blacklisted IP Detected: {clean_ip}"

    # 2. PAYLOAD CHECK
    if payload:
        for signature in THREAT_SIGNATURES:
            if signature in payload:
                return f"Malicious Payload Detected: '{signature}'"

    # 3. DDOS CHECK
    # (Uncomment this block to whitelist local IPs from DDoS check)
    if clean_ip in SAFE_IPS:
        return None 

    stats = ip_traffic_stats[clean_ip]
    if current_time - stats['start_time'] > 1:
        stats['count'] = 0
        stats['start_time'] = current_time
    stats['count'] += 1
    
    # Threshold: 1000 packets in 1 second
    if stats['count'] > 1000:
        stats['count'] = 0 
        stats['start_time'] = current_time 
        return f"High Traffic (DDoS) from {clean_ip}"

    return None                                                                                                                                                             