import subprocess
import platform
import sys
import ctypes

# WHITELIST (Never block these)
SAFE_IPS = [] 

def is_admin():
    """Checks if the script is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def block_ip(ip_address):
    if ip_address in SAFE_IPS:
        print(f"[FIREWALL] SAFEGUARD: Ignoring block request for {ip_address}")
        return False

    os_name = platform.system()
    print(f"[⚡] ATTEMPTING TO BLOCK: {ip_address}...")

    if os_name == "Windows" and not is_admin():
        print("    [!] ERROR: Script is NOT running as Administrator.")
        return False

    try:
        if os_name == "Windows":
            rule_name = f"UCDS_BLOCK_{ip_address}"
            command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address} profile=any'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"    [+] SUCCESS: Rule '{rule_name}' added to Windows Firewall.")
                return True
            else:
                print(f"    [!] FAILURE: {result.stderr.strip()} {result.stdout.strip()}") 
                return False

        elif os_name == "Linux":
            command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
            subprocess.run(command, shell=True, check=True)
            return True

    except Exception as e:
        print(f"    [!] CRITICAL ERROR: {e}")
        return False

def unblock_ip(ip_address):
    rule_name = f"UCDS_BLOCK_{ip_address}"
    if platform.system() == "Windows":
        command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    else:
        command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
        
    try:
        subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"    [-] FIREWALL: Unblocked {ip_address}")
    except:
        pass