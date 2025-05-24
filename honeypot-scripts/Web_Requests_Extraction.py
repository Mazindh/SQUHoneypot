import sqlite3
import json
import time
from pathlib import Path
from datetime import datetime

# Path to Dionaea SQLite database
DIONAEA_DB = Path("/opt/dionaea/var/lib/dionaea/dionaea.sqlite")
OUTPUT_FILE = Path("/home/honeypot/honeypot-dashboard/web_requests.json")
INTERVAL_SECONDS = 10  # Interval to fetch data in seconds

def fetch_http_requests():
    """Fetch HTTP/HTTPS connection data from Dionaea database."""
    if not DIONAEA_DB.exists():
        print(f"[!] Dionaea database not found: {DIONAEA_DB}")
        return []

    con = sqlite3.connect(DIONAEA_DB)
    cur = con.cursor()

    # Query to fetch HTTP/HTTPS connection data
    query = """
    SELECT
        datetime(connection_timestamp, 'unixepoch', 'localtime') AS timestamp,
        remote_host AS src_ip,
        local_port AS port,
        connection_protocol AS protocol
    FROM connections
    WHERE connection_protocol IN ('http', 'https')
    ORDER BY connection_timestamp DESC
    """
    cur.execute(query)
    rows = cur.fetchall()
    con.close()

    # Format the data
    data = []
    for row in rows:
        timestamp, src_ip, port, protocol = row
        date, time = timestamp.split(" ")
        data.append({
            "date": date,
            "time": time,
            "src_ip": src_ip,
            "port": port,
            "protocol": protocol
        })
    return data

def save_to_json(data):
    """Save data to JSON file, avoiding duplicates and sorting by timestamp."""
    if OUTPUT_FILE.exists():
        with open(OUTPUT_FILE, 'r') as f:
            try:
                existing_data = json.load(f)
            except json.JSONDecodeError:
                existing_data = []
    else:
        existing_data = []

    # Avoid duplicates by checking if the entry already exists
    existing_set = {json.dumps(entry, sort_keys=True) for entry in existing_data}
    for entry in data:
        if json.dumps(entry, sort_keys=True) not in existing_set:
            existing_data.append(entry)

    # Sort the data by date and time
    existing_data.sort(key=lambda x: (x["date"], x["time"]), reverse=True)

    # Save updated data back to the file
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(existing_data, f, indent=2)

def main_loop():
    """Main loop to fetch and save HTTP/HTTPS requests."""
    while True:
        try:
            print(f"[{datetime.now()}] Fetching HTTP/HTTPS requests...")
            data = fetch_http_requests()
            save_to_json(data)
            print(f"[{datetime.now()}] Data saved to {OUTPUT_FILE}")
        except Exception as e:
            print(f"[{datetime.now()}] Error: {e}")
        time.sleep(INTERVAL_SECONDS)

if __name__ == "__main__":
    main_loop()