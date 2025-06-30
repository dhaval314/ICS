# init_db.py
import sqlite3
from datetime import datetime

# Create or connect to the SQLite database file
conn = sqlite3.connect("phishguard.db")
cur = conn.cursor()

# Create logs table (if not already exists)
cur.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    timestamp TEXT,
    message TEXT
)
""")

# Insert sample log entries
cur.executemany("INSERT INTO logs (type, timestamp, message) VALUES (?, ?, ?)", [
    ("phishing", datetime.now().isoformat(), "Blocked suspicious domain: evilsite.ru"),
    ("anomaly", datetime.now().isoformat(), "Unexpected behavior detected from PLC-02."),
    ("firmware", datetime.now().isoformat(), "Firmware update on PLC-01 failed signature verification."),
])

conn.commit()
conn.close()
print("phishguard.db initialized with sample data.")
