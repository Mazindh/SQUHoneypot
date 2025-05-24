#!/bin/bash

# === Clear Cowrie log ===
COWRIE_LOG="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
if [ -f "$COWRIE_LOG" ]; then
    sudo truncate -s 0 "$COWRIE_LOG"
    echo "[+] Cowrie log cleared: $COWRIE_LOG"
else
    echo "[!] Cowrie log not found at: $COWRIE_LOG"
fi

# === Clear Dionaea SQLite DB tables ===
DIONAEA_DB="/opt/dionaea/var/lib/dionaea/dionaea.sqlite"
if [ -f "$DIONAEA_DB" ]; then
    echo "[+] Clearing Dionaea logs..."
    sudo sqlite3 "$DIONAEA_DB" <<EOF
DELETE FROM connections;
DELETE FROM logins;
VACUUM;
EOF
    echo "[+] Dionaea database cleared: $DIONAEA_DB"
else
    echo "[!] Dionaea database not found at: $DIONAEA_DB"
fi
