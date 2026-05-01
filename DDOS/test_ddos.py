from scapy.all import send, IP, TCP
import time
import random

# ==========================================
# CONFIGURATION
# ==========================================
# This is the "Fake Hacker" IP we will simulate
FAKE_ATTACKER_IP = "10.99.99.99"
TARGET_IP = "192.168.18.128" # Your PC's IP
# ==========================================

print(f">>> SIMULATING DDOS ATTACK FROM {FAKE_ATTACKER_IP}...")
print(f">>> Target: {TARGET_IP}")

# Send 150 packets (Threshold is 100)
count = 0
for i in range(150):
    # We craft a packet that LOOKS like it comes from the fake IP
    packet = IP(src=FAKE_ATTACKER_IP, dst=TARGET_IP)/TCP(dport=80, flags="S")
    send(packet, verbose=0)
    
    count += 1
    if count % 10 == 0:
        print(f"    Sent {count} packets...")
    
    # Send fast! (No sleep)

print("\n>>> ATTACK COMPLETE.")
print(">>> Check your Dashboard for 'High Traffic' Alert!")