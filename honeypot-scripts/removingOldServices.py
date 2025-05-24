import json
import sqlite3
from pathlib import Path

# Paths to log files and databases
COWRIE_LOG = Path("/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
DIONAEA_DB = Path("/opt/dionaea/var/lib/dionaea/dionaea.sqlite")
COMBINED_LOGS = Path("/home/honeypot/honeypot-dashboard/combined_logs.json")

# Ports to keep
ALLOWED_PORTS = {21, 22, 23, 80, 443, 2222, 3306, 5000}

def filter_combined_logs():
    """Filter combined logs to keep only entries with allowed ports."""
    if not COMBINED_LOGS.exists():
        print(f"[!] Combined logs file not found: {COMBINED_LOGS}")
        return

    with open(COMBINED_LOGS, 'r') as f:
        logs = json.load(f)

    filtered_logs = [
        log for log in logs
        if int(log["extra"].get("local_port", 0)) in ALLOWED_PORTS
    ]

    with open(COMBINED_LOGS, 'w') as f:
        json.dump(filtered_logs, f, indent=2)

    print(f"[+] Filtered combined logs. Remaining entries: {len(filtered_logs)}")

def main():

    filter_combined_logs()

if __name__ == "__main__":
    main()