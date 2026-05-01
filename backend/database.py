import sqlite3
import datetime

DB_NAME = "ucds_logs.db"

def init_db():
    """Initializes the database and creates the table if it doesn't exist."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS threats
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  src_ip TEXT,
                  country TEXT,
                  city TEXT,
                  lat REAL,
                  lon REAL,
                  threat_type TEXT,
                  status TEXT)''')
    conn.commit()
    conn.close()

def log_threat(src_ip, geo_info, threat_type, status="BLOCKED"):
    """Saves a detected threat to the database."""
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        country = geo_info['country'] if geo_info else "Unknown"
        city = geo_info['city'] if geo_info else "Unknown"
        lat = geo_info['lat'] if geo_info else 0.0
        lon = geo_info['lon'] if geo_info else 0.0
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        c.execute('''INSERT INTO threats 
                     (timestamp, src_ip, country, city, lat, lon, threat_type, status) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (timestamp, src_ip, country, city, lat, lon, threat_type, status))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] Database Error: {e}")

def get_recent_threats(limit=50):
    """Fetches the latest threats for the dashboard live view."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    
    result = []
    for row in rows:
        result.append({
            "timestamp": row['timestamp'],
            "ip": row['src_ip'],
            "geo": {
                "country": row['country'], 
                "city": row['city'],
                "lat": row['lat'],
                "lon": row['lon']
            },
            "attack_type": row['threat_type'],
            "status": row['status']
        })
    return result

# === NEW FUNCTION: GET ALL THREATS (FOR PDF) ===
def get_all_threats():
    """Fetches ALL threats from the database without limit."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM threats ORDER BY id DESC") # No LIMIT here
    rows = c.fetchall()
    conn.close()
    
    result = []
    for row in rows:
        result.append({
            "timestamp": row['timestamp'],
            "ip": row['src_ip'],
            "geo": {
                "country": row['country'], 
                "city": row['city'],
            },
            "attack_type": row['threat_type'],
            "status": row['status']
        })
    return result

def get_total_threat_count():
    """Returns the total number of threats ever recorded."""
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM threats")
        count = c.fetchone()[0]
        conn.close()
        return count
    except:
        return 0

def clear_threat_logs():
    """Wipes the database to start a fresh session."""
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("DELETE FROM threats")
        conn.commit()
        conn.close()
        print("[*] Database cleared for new session.")
    except Exception as e:
        print(f"[-] Error clearing DB: {e}")