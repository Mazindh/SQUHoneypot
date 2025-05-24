import json
from pathlib import Path
from datetime import datetime

COWRIE_LOG = Path("/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
OUTPUT_FILE = Path("/home/honeypot/honeypot-dashboard/ssh_commands.json")

def extract_ssh_commands():
    if not COWRIE_LOG.exists():
        print(f"[!] Cowrie log file not found: {COWRIE_LOG}")
        return

    sessions = {}
    existing_sessions = {}

    # Load existing data from the output file
    if OUTPUT_FILE.exists():
        with open(OUTPUT_FILE, 'r') as f:
            try:
                existing_data = json.load(f)
                # Create a dictionary of existing sessions for quick lookup
                existing_sessions = {entry["session"]: entry for entry in existing_data}
            except json.JSONDecodeError:
                existing_data = []
    else:
        existing_data = []

    # Parse the Cowrie log file
    with open(COWRIE_LOG, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                eventid = entry.get("eventid")
                session = entry.get("session")
                timestamp = entry.get("timestamp")

                # Track successful login sessions
                if eventid == "cowrie.login.success":
                    if session not in sessions:
                        sessions[session] = {
                            "src_ip": entry.get("src_ip"),
                            "username": entry.get("username"),
                            "password": entry.get("password"),
                            "commands": [],
                            "timestamp": timestamp
                        }

                # Track commands entered in active sessions
                elif eventid == "cowrie.command.input" and session in sessions:
                    command = entry.get("input")
                    if command:
                        sessions[session]["commands"].append({
                            "command": command,
                            "timestamp": timestamp
                        })

            except json.JSONDecodeError:
                continue

    # Format the output and avoid duplicates
    for session, details in sessions.items():
        if details["commands"]:  # Only process sessions with non-empty commands
            if session in existing_sessions:
                # Append only new commands to existing sessions
                existing_commands = {cmd["command"] for cmd in existing_sessions[session]["commands"]}
                for cmd in details["commands"]:
                    if cmd["command"] not in existing_commands:
                        existing_sessions[session]["commands"].append(cmd)
            else:
                # Add new session if it doesn't exist
                existing_sessions[session] = {
                    "session": session,
                    "src_ip": details["src_ip"],
                    "username": details["username"],
                    "password": details["password"],
                    "login_timestamp": details["timestamp"],
                    "commands": details["commands"]
                }

    # Save to output file
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(list(existing_sessions.values()), f, indent=2)

    print(f"[+] Extracted SSH commands saved to {OUTPUT_FILE}")

import time

def main_loop():
    while True:
        try:
            # Extract SSH commands
            extract_ssh_commands()

            # Log success
            print(f"[{datetime.now()}] SSH commands processed successfully.")
        except Exception as e:
            # Log any errors that occur
            print(f"[{datetime.now()}] Error occurred: {e}")

        # Wait for a specified interval before the next iteration
        time.sleep(10)  # Adjust the interval as needed (e.g., 10 seconds)

if __name__ == "__main__":
    main_loop()