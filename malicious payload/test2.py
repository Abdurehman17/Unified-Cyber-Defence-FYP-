import socket

target_ip = "127.0.0.1:5000" # CHANGE THIS to your Tool's IP
ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]

print(f"Scanning {target_ip}...")
for port in ports:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        sock.connect((target_ip, port))
        sock.close()
    except:
        pass
