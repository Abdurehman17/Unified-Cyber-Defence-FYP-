import psutil
from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for, session
import sniffer
import database
from fpdf import FPDF
import os
from datetime import timedelta
import datetime

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')

# === SECURITY CONFIG ===
app.secret_key = 'ucds_secure_key_2026'
# Session Timeout (30 Seconds)
app.permanent_session_lifetime = timedelta(seconds=30)

# Initialize DB on startup
database.init_db()

# === PASSWORD MANAGEMENT (FIXED PATH) ===
# This ensures config.txt is always created exactly in the backend folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.txt")

def get_saved_password():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            f.write("admin123")
        return "admin123"
    
    with open(CONFIG_FILE, "r") as f:
        return f.read().strip()

def save_new_password(new_pass):
    with open(CONFIG_FILE, "w") as f:
        f.write(new_pass)

# === SECURITY HOOKS ===
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds=30)

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# === ROUTES ===
@app.route('/')
def login_page():
    if session.get('logged_in'): return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    current_password = get_saved_password()
    
    if username == "admin" and password == current_password:
        session['logged_in'] = True
        session['user'] = username
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', error="Invalid Credentials. Access Denied.")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if not session.get('logged_in'): return redirect(url_for('login_page'))
    old_pass = request.form.get('old_password')
    new_pass = request.form.get('new_password')
    current_password = get_saved_password()
    
    if old_pass == current_password:
        save_new_password(new_pass)
        return jsonify({"status": "success", "message": "Password updated successfully!"})
    else:
        return jsonify({"status": "error", "message": "Incorrect Old Password!"}), 401

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'): return redirect(url_for('login_page'))
    return render_template('index.html')

@app.route('/api/start', methods=['POST'])
def start_capture():
    if not session.get('logged_in'): return jsonify({"error": "Session Expired"}), 401
    database.clear_threat_logs()
    sniffer.start_sniffing()
    return jsonify({"status": "Sniffing Started"})

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    if not session.get('logged_in'): return jsonify({"error": "Session Expired"}), 401
    sniffer.stop_sniffing()
    return jsonify({"status": "Sniffing Stopped"})

@app.route('/api/data')
def get_data():
    if not session.get('logged_in'): return jsonify({"error": "Session Expired"}), 401
    return jsonify({
        "logs": sniffer.captured_packets,
        "total_count": sniffer.total_packet_count,
        "proto_counts": {
            "TCP": sniffer.count_tcp,
            "UDP": sniffer.count_udp,
            "Other": sniffer.count_other
        }
    })

@app.route('/api/threats')
def get_threats():
    if not session.get('logged_in'): return jsonify({"error": "Session Expired"}), 401
    
    # Get recent for map (Limit 50)
    recent_threats = database.get_recent_threats(50)
    
    # Get TRUE total for counter (No limit)
    total_count = database.get_total_threat_count()
    
    return jsonify({"recent": recent_threats, "total": total_count})

@app.route('/api/system_health')
def system_health():
    if not session.get('logged_in'): return jsonify({"error": "Session Expired"}), 401
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    return jsonify({"cpu": cpu, "ram": ram})

# === UPDATED REPORT GENERATION (ALL ATTACKS) ===
@app.route('/api/download_report')
def download_report():
    if not session.get('logged_in'): return redirect(url_for('login_page'))
    
    try:
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        report_path = os.path.join(backend_dir, "UCDS_Security_Report.pdf")
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Header
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, "Unified Cyber Defense (UCDS) - Security Audit", ln=True, align='C')
        pdf.set_font("Arial", 'I', 10)
        pdf.set_text_color(100, 100, 100)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pdf.cell(0, 10, f"Generated on: {timestamp} | Classification: CONFIDENTIAL", ln=True, align='C')
        pdf.ln(5)
        
        # === GET ALL LOGS (UNLIMITED) ===
        logs = database.get_all_threats() 
        total_threats = len(logs)
        unique_ips = len(set(log['ip'] for log in logs))
        
        # Summary
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.set_font("Arial", '', 11)
        pdf.cell(0, 8, f"- Total Incidents Recorded: {total_threats}", ln=True)
        pdf.cell(0, 8, f"- Unique Attackers: {unique_ips}", ln=True)
        pdf.cell(0, 8, f"- System Status: Protected", ln=True)
        pdf.ln(10)
        
        # Table
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, "Detailed Threat Activity Log", ln=True)
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font("Arial", 'B', 10)
        
        # Table Headers
        pdf.cell(40, 10, "Timestamp", 1, 0, 'C', fill=True)
        pdf.cell(35, 10, "Source IP", 1, 0, 'C', fill=True)
        pdf.cell(35, 10, "Location", 1, 0, 'C', fill=True)
        pdf.cell(50, 10, "Attack Type", 1, 0, 'C', fill=True)
        pdf.cell(30, 10, "Status", 1, 1, 'C', fill=True)
        
        pdf.set_font("Arial", '', 9)
        
        if not logs:
            pdf.cell(190, 10, "No threats detected in this session.", 1, 1, 'C')
        else:
            for log in logs:
                time_str = str(log.get('timestamp', 'N/A'))
                ip = str(log.get('ip', 'N/A'))
                
                geo = log.get('geo', {})
                loc = geo.get('city', 'Unknown') if isinstance(geo, dict) else "Unknown"
                
                # Sanitize Strings
                attack = str(log.get('attack_type', 'Unknown')).encode('latin-1', 'replace').decode('latin-1')
                status = str(log.get('status', 'Logged'))
                loc = loc.encode('latin-1', 'replace').decode('latin-1')

                pdf.cell(40, 10, time_str, 1, 0, 'C')
                pdf.cell(35, 10, ip, 1, 0, 'C')
                pdf.cell(35, 10, loc, 1, 0, 'C')
                pdf.cell(50, 10, attack, 1, 0, 'L')
                
                if "BLOCKED" in status.upper():
                    pdf.set_text_color(200, 0, 0)
                    pdf.set_font("Arial", 'B', 9)
                pdf.cell(30, 10, status, 1, 1, 'C')
                
                pdf.set_text_color(0, 0, 0)
                pdf.set_font("Arial", '', 9)

        pdf.output(report_path)
        return send_file(report_path, as_attachment=True)
        
    except Exception as e:
        print(f"[ERROR] PDF Failed: {e}")
        return jsonify({"error": "Report Generation Failed"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')