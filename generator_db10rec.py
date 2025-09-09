import sqlite3
import random
from datetime import datetime, timedelta

conn = sqlite3.connect("activity_logs.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT,
    timestamp TEXT,
    ip_address TEXT,
    device TEXT
)
""")

usernames = [f"user{i}" for i in range(1, 999)]
actions = ["login", "logout", "upload_file", "download_file", "delete_file", "view_dashboard", "update_profile", "send_message"]
devices = ["Windows 11", "Windows 10", "Ubuntu Linux", "macOS", "iPhone 15", "Samsung Galaxy S23", "iPad Pro", "Android Tablet"]

def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def random_date():
    start = datetime.now() - timedelta(days=90)
    random_days = random.randint(0, 90)
    random_seconds = random.randint(0, 86400)
    return (start + timedelta(days=random_days, seconds=random_seconds)).strftime("%Y-%m-%d %H:%M:%S")

for _ in range(1000000):
    username = random.choice(usernames)
    action = random.choice(actions)
    timestamp = random_date()
    ip_address = random_ip()
    device = random.choice(devices)

    cur.execute("INSERT INTO logs (username, action, timestamp, ip_address, device) VALUES (?, ?, ?, ?, ?)",
                (username, action, timestamp, ip_address, device))

conn.commit()
conn.close()

print("ok")