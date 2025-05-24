import time
import requests
import json
import sqlite3
from pathlib import Path

DB_PATH = Path("honeypot_ips2.db")
LOG_FILE = Path("/home/honeypot/honeypot-dashboard/combined_logs.json")

# Create table if not exists
def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS osint (
        ip TEXT PRIMARY KEY,
        country TEXT,
        city TEXT,
        org TEXT,
        isp TEXT,
        asn TEXT,
        lat REAL,
        lon REAL,
        status TEXT
    )''')
    con.commit()
    con.close()

# Lookup from ip-api
def fetch_ip_data(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        r = requests.get(url, timeout=3)
        data = r.json()
        return {
            "ip": ip,
            "country": data.get("country"),
            "city": data.get("city"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("as"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "status": data.get("status")
        }
    except:
        return {"ip": ip, "status": "error"}

# Save into DB
def save_ip_info(ip_info):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute('''INSERT OR REPLACE INTO osint VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
        ip_info["ip"], ip_info["country"], ip_info["city"], ip_info["org"],
        ip_info["isp"], ip_info["asn"], ip_info["lat"], ip_info["lon"], ip_info["status"]
    ))
    con.commit()
    con.close()

# Check or fetch IP info
def get_ip_info(ip):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT * FROM osint WHERE ip=?", (ip,))
    row = cur.fetchone()
    con.close()

    if row:
        keys = ["ip", "country", "city", "org", "isp", "asn", "lat", "lon", "status"]
        return dict(zip(keys, row))
    else:
        ip_data = fetch_ip_data(ip)
        if ip_data.get("status") == "success":
            save_ip_info(ip_data)
        return ip_data

# Load IPs from combined_logs.json
def collect_unique_ips():
    if not LOG_FILE.exists():
        print("Log file not found.")
        return []
    with open(LOG_FILE, 'r') as f:
        try:
            logs = json.load(f)
            return list(set(entry['src_ip'] for entry in logs if 'src_ip' in entry))
        except json.JSONDecodeError:
            return []

# Run enrichment over all IPs
def enrich_all_ips():
    ips = collect_unique_ips()
    for ip in ips:
        info = get_ip_info(ip)
        print(json.dumps(info, indent=2))
        

# Remove IPs not in combined_logs.json
def cleanup_ips():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    # Get all IPs from the database
    cur.execute("SELECT ip FROM osint")
    db_ips = {row[0] for row in cur.fetchall()}

    # Get all IPs from the log file
    log_ips = set(collect_unique_ips())

    # Find IPs to remove
    ips_to_remove = db_ips - log_ips

    # Remove IPs from the database
    for ip in ips_to_remove:
        cur.execute("DELETE FROM osint WHERE ip=?", (ip,))

    con.commit()
    con.close()

# Run enrichment over all IPs and cleanup
def enrich_all_ips_with_cleanup():
    enrich_all_ips()
    cleanup_ips()

if __name__ == "__main__":
    init_db()
    while True:
        enrich_all_ips_with_cleanup()
        time.sleep(30)
