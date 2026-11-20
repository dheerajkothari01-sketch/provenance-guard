"""
Sign-in, roles and staff accounts. Passwords are stored only as salted PBKDF2 hashes.
Starting accounts live in config/users.json; accounts created, disabled or reset by IT Security are kept in
state/accounts.json. There is no self-sign-up: only IT Security can create an account.
For a real deployment this would sit behind the company's SSO instead.
"""
import re
import threading
from datetime import datetime, timezone
import hashlib
import hmac
import json
import secrets
from pathlib import Path

USERS_FILE = Path(__file__).resolve().parent.parent / "config" / "users.json"
ITERATIONS = 200_000

ROLES = {
    "finance_manager": dict(
        title="Finance Manager",
        can={"view", "release", "block", "clear", "escalate"},
        duty="Makes the final call: releases a held change after a call-back, or blocks it."),
    "accountant": dict(
        title="Senior Accountant",
        can={"view", "callback", "clear", "escalate"},
        duty="Calls the vendor on the number already on file and records the result."),
    "it_security": dict(
        title="IT Security Administrator",
        can={"view", "block", "escalate", "settings", "manage_users"},
        duty="Owns the detection rules and creates staff accounts. Can block or escalate, never release money."),
    "auditor": dict(
        title="Audit Committee (read-only)",
        can={"view"},
        duty="Sees every decision and the full audit trail. Changes nothing."),
}


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS).hex()
    return salt, h


ACCOUNTS_FILE = Path(__file__).resolve().parent.parent / "state" / "accounts.json"
_LOCK = threading.RLock()
NAME_OK = re.compile(r"^[a-z][a-z0-9._-]{2,30}$")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _overrides() -> dict:
    try:
        return json.loads(ACCOUNTS_FILE.read_text())
    except (FileNotFoundError, ValueError):
        return {}


def load_users() -> dict:
    users = {k: dict(v, active=True, must_change=False, created_by="initial setup")
             for k, v in json.loads(USERS_FILE.read_text()).items()}
    for k, v in _overrides().items():
        users[k] = dict(users.get(k, {}), **v)
    return users


def _save(username: str, **fields):
    with _LOCK:
        o = _overrides()
        o[username] = dict(o.get(username, {}), **fields)
        ACCOUNTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        ACCOUNTS_FILE.write_text(json.dumps(o, indent=2))


def password_problem(pw: str) -> str | None:
    if len(pw) < 10:
        return "at least 10 characters"
    if not (re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw) and re.search(r"\d", pw)
            and re.search(r"[^A-Za-z0-9]", pw)):
        return "upper- and lower-case letters, a number and a symbol"
    return None


def create_user(admin: dict, username: str, name: str, role: str, temp_password: str) -> str | None:
    """IT Security only. Returns an error message, or None on success."""
    if not can(admin, "manage_users"):
        return "Only IT Security can create accounts."
    username = username.strip().lower()
    if not NAME_OK.match(username):
        return "Username: 3-31 characters, lower-case letters, numbers, dot, dash or underscore, starting with a letter."
    if username in load_users():
        return "That username already exists."
    if role not in ROLES:
        return "Unknown role."
    if not name.strip():
        return "Enter the person's full name."
    bad = password_problem(temp_password)
    if bad:
        return f"Temporary password needs {bad}."
    salt, h = hash_password(temp_password)
    _save(username, name=name.strip(), role=role, salt=salt, hash=h, active=True, must_change=True,
          created_by=admin["username"], created_at=_now())
    return None


def set_active(admin: dict, username: str, active: bool) -> str | None:
    if not can(admin, "manage_users"):
        return "Only IT Security can change accounts."
    if username == admin["username"]:
        return "You can't disable your own account."
    if username not in load_users():
        return "No such account."
    _save(username, active=active, changed_by=admin["username"], changed_at=_now())
    return None


def reset_password(admin: dict, username: str, temp_password: str) -> str | None:
    if not can(admin, "manage_users"):
        return "Only IT Security can reset passwords."
    if username not in load_users():
        return "No such account."
    bad = password_problem(temp_password)
    if bad:
        return f"Temporary password needs {bad}."
    salt, h = hash_password(temp_password)
    _save(username, salt=salt, hash=h, must_change=True, changed_by=admin["username"], changed_at=_now())
    return None


def change_own_password(user: dict, old: str, new: str) -> str | None:
    if not verify(user["username"], old):
        return "Current password is wrong."
    if old == new:
        return "Choose a different password from the temporary one."
    bad = password_problem(new)
    if bad:
        return f"New password needs {bad}."
    salt, h = hash_password(new)
    _save(user["username"], salt=salt, hash=h, must_change=False, changed_at=_now())
    return None


def verify(username: str, password: str) -> dict | None:
    users = load_users()
    u = users.get(username.strip().lower())
    if not u or not u.get("active", True):
        hash_password(password)  # same work on unknown or disabled users, so timing doesn't reveal valid names
        return None
    _, h = hash_password(password, u["salt"])
    if hmac.compare_digest(h, u["hash"]):
        return dict(username=username.strip().lower(), name=u["name"], role=u["role"],
                    must_change=bool(u.get("must_change")))
    return None


def can(user: dict | None, action: str) -> bool:
    return bool(user) and action in ROLES.get(user["role"], {}).get("can", set())
