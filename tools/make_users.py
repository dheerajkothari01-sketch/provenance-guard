"""
Create config/users.json with the demo accounts (hashed passwords).
    python tools/make_users.py
Edit DEMO below to change names or passwords, then rerun.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine.auth import USERS_FILE, hash_password  # noqa: E402

DEMO = [
    ("madhavi", "Madhavi Sundar", "finance_manager", "Madhavi@2026"),
    ("farah", "Farah Dsouza", "accountant", "Farah@2026"),
    ("aditi", "Aditi Kapoor", "it_security", "Aditi@2026"),
    ("auditor", "Audit Committee", "auditor", "Audit@2026"),
]

users = {}
for username, name, role, pw in DEMO:
    salt, h = hash_password(pw)
    users[username] = dict(name=name, role=role, salt=salt, hash=h)
USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
USERS_FILE.write_text(json.dumps(users, indent=2))
print(f"wrote {len(users)} users to {USERS_FILE}")
