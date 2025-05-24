import json
import sqlite3
import time
from pathlib import Path
from datetime import datetime, timezone

COWRIE_LOG = Path("/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
DIONAEA_DB = Path("/opt/dionaea/var/lib/dionaea/dionaea.sqlite")
OUTPUT_FILE = Path("/home/honeypot/honeypot-dashboard/combined_logs.json")
INTERVAL_SECONDS = 1

def parse_cowrie():
    logs = []
    if not COWRIE_LOG.exists():
        return logs

    with open(COWRIE_LOG, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                timestamp_str = entry.get("timestamp")
                timestamp_dt = datetime.fromisoformat(timestamp_str.replace("Z", ""))

                # Handle login events
                if entry.get("eventid") in ["cowrie.login.failed", "cowrie.login.success"]:
                    logs.append({
                        "source": "cowrie",
                        "timestamp": timestamp_dt,
                        "event": entry["eventid"].split('.')[-1],
                        "username": entry.get("username"),
                        "password": entry.get("password"),
                        "src_ip": entry.get("src_ip"),
                        "extra": {
                            "protocol": "ssh"
                        }
                    })

                # Handle Nmap SSH version scan detection
                elif entry.get("eventid") == "cowrie.client.version" and "SSH-2.0-Nmap" in entry.get("version", ""):
                    logs.append({
                        "source": "cowrie",
                        "timestamp": timestamp_dt,
                        "event": "nmap.scan",
                        "username": "None",
                        "password": "None",
                        "src_ip": entry.get("src_ip"),
                        "extra": {
                            "protocol": "ssh",
                            "version_string": entry.get("version")
                        }
                    })

            except json.JSONDecodeError:
                continue
    return logs

ALLOWED_PORTS = {21, 22, 23, 80, 443, 2222, 3306, 5000}

def parse_dionaea():
    logs = []
    if not DIONAEA_DB.exists():
        return logs

    con = sqlite3.connect(DIONAEA_DB)
    cur = con.cursor()

    def normalize_protocol(proto, port):
        proto = proto.lower()
        if proto == "httpd":
            return "https" if port == 443 else "http"
        elif proto == "blackhole":
            return "telnet"
        return proto

    # First: log actual login attempts (as before)
    login_query = """
    SELECT
        logins.login_username,
        logins.login_password,
        connections.connection_timestamp,
        connections.connection_protocol,
        connections.remote_host,
        connections.local_port,
        connections.remote_port
    FROM logins
    LEFT JOIN connections ON logins.connection = connections.connection
    """
    for row in cur.execute(login_query):
        local_port = row[5]
        if local_port in ALLOWED_PORTS:  # Filter by allowed ports
            timestamp_local = datetime.fromtimestamp(row[2], tz=timezone.utc).astimezone().replace(tzinfo=None)
            logs.append({
                "source": "dionaea",
                "timestamp": timestamp_local,
                "event": "login.success",
                "username": row[0],
                "password": row[1],
                "src_ip": row[4],
                "extra": {
                    "protocol": row[3],
                    "local_port": local_port,
                    "remote_port": row[6]
                }
            })

    # Second: log raw connections that didn't involve login
    connection_query = """
    SELECT
        connection_timestamp,
        connection_protocol,
        remote_host,
        local_port,
        remote_port
    FROM connections
    WHERE connection NOT IN (SELECT connection FROM logins)
    """
    for row in cur.execute(connection_query):
        local_port = row[3]
        if local_port in ALLOWED_PORTS:  # Filter by allowed ports
            timestamp_local = datetime.fromtimestamp(row[0], tz=timezone.utc).astimezone().replace(tzinfo=None)
            protocol = normalize_protocol(row[1], local_port)
            logs.append({
                "source": "dionaea",
                "timestamp": timestamp_local,
                "event": "connection",
                "username": "None",
                "password": "None",
                "src_ip": row[2],
                "extra": {
                    "protocol": protocol,
                    "local_port": local_port,
                    "remote_port": row[4]
                }
            })

    con.close()
    return logs

def load_existing_logs():
    if OUTPUT_FILE.exists():
        with open(OUTPUT_FILE, 'r') as f:
            return json.load(f)
    return []

def deduplicate_and_save(existing, new):
    # Create a set of (timestamp, src_ip, source) for existing logs
    seen = set((log["timestamp"], log["src_ip"], log["source"]) for log in existing)

    # Only keep logs that aren't already in 'seen'
    unique_new = [
        log for log in new
        if (log["timestamp"].isoformat(), log["src_ip"], log["source"]) not in seen
    ]

    # Convert timestamps to ISO string and ensure all fields are JSON-serializable
    for log in unique_new:
        ts = log["timestamp"]
        if isinstance(ts, datetime):
            ts = ts.isoformat()

        if ts.endswith("Z"):
            ts = ts[:-1]
        elif ts.endswith("+04:00"):
            ts = ts[:-6]
        log["timestamp"] = ts

        # Ensure all fields are JSON-serializable
        for key, value in log.items():
            if isinstance(value, bytes):
                log[key] = value.decode("utf-8")  # Convert bytes to string
            elif isinstance(value, dict):
                # Recursively handle nested dictionaries
                log[key] = {
                    k: (v.decode("utf-8") if isinstance(v, bytes) else v)
                    for k, v in value.items()
                }

    # Merge and sort
    combined = existing + unique_new

    # Save to file
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(combined, f, indent=2)

    print(f"[{datetime.now()}] Added {len(unique_new)} new logs. Total logs: {len(combined)}")
    
def main_loop():
    while True:
        cowrie_logs = parse_cowrie()
        dionaea_logs = parse_dionaea()
        new_logs = cowrie_logs + dionaea_logs

        existing_logs = load_existing_logs()
        deduplicate_and_save(existing_logs, new_logs)

        time.sleep(INTERVAL_SECONDS)

if __name__ == "__main__":
    main_loop()
