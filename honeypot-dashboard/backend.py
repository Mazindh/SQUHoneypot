from flask import Flask, render_template, request, redirect, send_file
import os
import json
from collections import Counter
from datetime import datetime
from collections import defaultdict
from flask import render_template
import sqlite3
from datetime import datetime, timezone


app = Flask(__name__)

LOG_FILE = os.path.join(os.path.dirname(__file__), "combined_logs.json")

def get_all_ip_info():
    ip_info = {}
    con = sqlite3.connect("/home/honeypot/honeypot-scripts/honeypot_ips2.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM osint")
    rows = cur.fetchall()
    for row in rows:
        ip_info[row[0]] = {
            "country": row[1],
            "city": row[2],
            "org": row[3],
            "isp": row[4],
            "asn": row[5],
            "lat": row[6],
            "lon": row[7],
            "status": row[8]
        }
    con.close()
    return ip_info

# Helper to parse logs
def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        try:
            logs = json.load(f)
            return logs
        except json.JSONDecodeError:
            return []

@app.route("/")
def dashboard():
    logs = read_logs()
    total_attacks = len(logs)
    ip_counter = Counter([entry["src_ip"] for entry in logs])
    top_ips = ip_counter.most_common(5)
    ip_info = get_all_ip_info()
    username_counter = Counter([entry["username"] for entry in logs if entry.get("username")])
    top_usernames = username_counter.most_common(5)

    # Load session data from ssh_commands.json
    ssh_commands_file = os.path.join(os.path.dirname(__file__), "ssh_commands.json")
    if os.path.exists(ssh_commands_file):
        with open(ssh_commands_file, "r") as f:
            sessions = json.load(f)
            # Sort commands by timestamp for each session
            for session in sessions:
                session["commands"] = sorted(session.get("commands", []), key=lambda c: c.get("timestamp", ""))
                
    else:
        sessions = []

    # Create the chart data for the Top Usernames Attempted
    usernames_chart = {
        "labels": [u for u, _ in top_usernames],  # Extract the usernames
        "data": [c for _, c in top_usernames]     # Extract the counts
    }

    protocol_counter = Counter([entry.get("extra", {}).get("protocol") for entry in logs if entry.get("extra", {}).get("protocol")])
    attacks_by_protocol = dict(protocol_counter)

    parsed_logs = []
    attacks_per_day = defaultdict(int)
    for entry in logs:
        dt = datetime.fromisoformat(entry["timestamp"].replace("Z", ""))
        day = dt.date().isoformat()
        attacks_per_day[day] += 1

        parsed_logs.append({
            "timestamp": dt,
            "source": entry.get("source"),
            "event": entry.get("event"),
            "username": entry.get("username"),
            "password": entry.get("password"),
            "src_ip": entry.get("src_ip"),
            "protocol": entry.get("extra", {}).get("protocol"),
        })

    parsed_logs.sort(key=lambda x: x["timestamp"], reverse=True)

    parsed_logs = parsed_logs[:20]

    attacks_chart = {
        "labels": list(attacks_per_day.keys()),
        "data": list(attacks_per_day.values())
    }

    # Prepare the data for the protocol chart
    protocols_chart = {
        "labels": list(attacks_by_protocol.keys()),
        "data": list(attacks_by_protocol.values())
    }

    print("OSINT info loaded:", ip_info.keys())

    # Render the dashboard template with all the necessary data
    return render_template("dashboard.html", logs=parsed_logs, total=total_attacks,
                           top_ips=top_ips, top_usernames=top_usernames,
                           attacks_chart=attacks_chart,
                           protocols_chart=protocols_chart,
                           usernames_chart=usernames_chart,
                           ip_info=ip_info,
                           sessions=sessions)

@app.route("/download-logs")
def download():
    return send_file(LOG_FILE, as_attachment=True)

@app.route("/clear")
def clear_logs():
    with open(LOG_FILE, 'w') as f:
        json.dump([], f)
    return redirect("/")

@app.route("/api/logs")
def api_logs():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    start = (page - 1) * limit
    end = start + limit

    logs = read_logs()
    parsed_logs = []
    for entry in logs:
        parsed_logs.append({
            "timestamp": datetime.fromisoformat(entry["timestamp"].replace("Z", "+04:00")),
            "source": entry.get("source"),
            "event": entry.get("event"),
            "username": entry.get("username"),
            "password": entry.get("password"),
            "src_ip": entry.get("src_ip"),
            "protocol": entry.get("extra", {}).get("protocol"),
        })

    parsed_logs.sort(key=lambda x: x["timestamp"], reverse=True)
    paginated = parsed_logs[start:end]

    return json.dumps({
        "logs": paginated,
        "total": len(parsed_logs)
    }, default=str)

@app.route("/download-osint")
def download_osint_csv():
    import sqlite3, csv
    from io import StringIO
    con = sqlite3.connect("/home/honeypot/honeypot-scripts/honeypot_ips2.db")
    cur = con.cursor()
    cur.execute("SELECT ip, country, city, org, isp, asn, lat, lon FROM osint")
    rows = cur.fetchall()
    con.close()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["IP", "Country", "City", "Org", "ISP", "ASN", "Lat", "Lon"])
    cw.writerows(rows)
    output = si.getvalue()
    return output, 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=osint_data.csv"
    }
@app.route("/download-session/<session_id>")
def download_session(session_id):
    import csv
    from io import StringIO

    # Load the ssh_commands.json file
    ssh_commands_file = os.path.join(os.path.dirname(__file__), "ssh_commands.json")
    if not os.path.exists(ssh_commands_file):
        return "No SSH commands file found", 404

    with open(ssh_commands_file, "r") as f:
        sessions = json.load(f)
        # Sort commands by timestamp for each session
        for session in sessions:
            session["commands"] = sorted(session.get("commands", []), key=lambda c: c.get("timestamp", ""))

    # Find the session and sort commands by timestamp
    session_data = next((s for s in sessions if s["session"] == session_id), None)
    if not session_data:
        return f"No session found with ID {session_id}", 404

    commands = sorted(session_data.get("commands", []), key=lambda c: c.get("timestamp", ""))

    # Prepare CSV data
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["Command", "Timestamp"])  # CSV headers
    for command in commands:
        cw.writerow([command.get("command", "N/A"), command.get("timestamp", "N/A")])

    output = si.getvalue()
    return output, 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": f"attachment; filename=session_{session_id}_commands.csv"
    }
    
@app.route("/session-commands")
def session_commands():
    # Load session data from ssh_commands.json
    ssh_commands_file = os.path.join(os.path.dirname(__file__), "ssh_commands.json")
    if os.path.exists(ssh_commands_file):
        with open(ssh_commands_file, "r") as f:
            sessions = json.load(f)
            # Sort commands by timestamp for each session
            for session in sessions:
                session["commands"] = sorted(session.get("commands", []), key=lambda c: c.get("timestamp", ""))
    else:
        sessions = []

    return render_template("session_commands.html", sessions=sessions)


@app.route("/download-all-sessions")
def download_all_sessions():
    import csv
    from io import StringIO
    import os
    import json

    # Path to the ssh_commands.json file
    ssh_commands_file = os.path.join(os.path.dirname(__file__), "ssh_commands.json")
    if not os.path.exists(ssh_commands_file):
        return "No session commands file found", 404

    # Load session data
    with open(ssh_commands_file, "r") as f:
        sessions = json.load(f)

    # Prepare CSV data
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["Session ID", "Source IP", "Command", "Timestamp"])  # CSV headers
    for session in sessions:
        for command in session.get("commands", []):
            cw.writerow([
                session.get("session", "N/A"),
                session.get("src_ip", "N/A"),
                command.get("command", "N/A"),
                command.get("timestamp", "N/A")
            ])

    # Return the CSV file as a downloadable response
    output = si.getvalue()
    return output, 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=all_sessions_commands.csv"
    }
    
@app.route("/api/session-commands")
def api_session_commands():
    # Load session data from ssh_commands.json
    ssh_commands_file = os.path.join(os.path.dirname(__file__), "ssh_commands.json")
    if os.path.exists(ssh_commands_file):
        with open(ssh_commands_file, "r") as f:
            sessions = json.load(f)
            # Sort commands by timestamp for each session
            for session in sessions:
                session["commands"] = sorted(session.get("commands", []), key=lambda c: c.get("timestamp", ""))
    else:
        sessions = []

    return {"sessions": sessions}
if __name__ == "__main__":
    app.run(debug=True, host='100.64.42.86', port=5000)
