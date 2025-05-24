import json
import time
import subprocess
import sqlite3
import threading
import os

# === CONFIG ===
COWRIE_LOG_FILE = '/home/cowrie/cowrie/var/log/cowrie/cowrie.json' #'/opt/cowrie/var/log/cowrie/cowrie.json'
DIONAEA_DB_FILE = '/opt/dionaea/var/lib/dionaea/dionaea.sqlite'
EMAIL_SCRIPT = 'sendemail3.py'  # Update this

# Cowrie event types to trigger alerts
COWRIE_EVENTS = [
    'cowrie.login.success',
    'cowrie.login.failed',
    'cowrie.session.connect'
]

# Used to track last Dionaea connection seen
LAST_ID_FILE = '/tmp/last_dionaea_id.txt'

# === EMAIL FUNCTION ===
def send_email(subject, body):
    try:
        subprocess.run(['python3', EMAIL_SCRIPT, subject, body], check=True)
        print(f"[+] Alert sent: {subject}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to send alert: {e}")

# === COWRIE MONITOR ===
def tail_f(file_path):
    with open(file_path, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.1)

def monitor_cowrie():
    print("[*] Starting Cowrie monitor...")
    for line in tail_f(COWRIE_LOG_FILE):
        try:
            event = json.loads(line.strip())
            eventid = event.get('eventid')
            if eventid in COWRIE_EVENTS:
                src_ip = event.get('src_ip')
                timestamp = event.get('timestamp')
                message = event.get('message')
                subject = f"Cowrie Alert: {eventid}"
                body = f"Source IP: {src_ip}\nTime: {timestamp}\nMessage: {message}"
                send_email(subject, body)
                print("email sent with",subject)
        except json.JSONDecodeError:
            continue

# === DIONAEA MONITOR ===
def load_last_id():
    try:
        with open(LAST_ID_FILE, 'r') as f:
            return int(f.read().strip())
    except:
        return 0

def save_last_id(conn_id):
    with open(LAST_ID_FILE, 'w') as f:
        f.write(str(conn_id))

def monitor_dionaea():
    print("[*] Starting Dionaea monitor...")
    last_id = load_last_id()
    while True:
        try:
            conn = sqlite3.connect(DIONAEA_DB_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT connection, connection_timestamp, remote_host, remote_port, connection_protocol 
                FROM connections 
                WHERE connection > ? ORDER BY connection ASC
            """, (last_id,))
            rows = cursor.fetchall()
            for row in rows:
                conn_id, ts, ip, port, proto = row
                subject = "Dionaea Alert: New Connection"
                body = f"Source IP: {ip}\nPort: {port}\nProtocol: {proto}\nTime: {ts}"
                send_email(subject, body)
                last_id = conn_id
                save_last_id(last_id)
            conn.close()
        except Exception as e:
            print(f"[!] Error reading Dionaea DB: {e}")
        time.sleep(5)  # Poll interval

# === MAIN ===
if __name__ == '__main__':
    # Run Cowrie and Dionaea monitoring in parallel threads
    cowrie_thread = threading.Thread(target=monitor_cowrie, daemon=True)
    dionaea_thread = threading.Thread(target=monitor_dionaea, daemon=True)

    cowrie_thread.start()
    dionaea_thread.start()

    print("[*] Honeypot alerting started. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)

