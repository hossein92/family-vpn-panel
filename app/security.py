"""Authentication: Argon2id password hashes, server-side sessions, CSRF tokens,
login rate limiting / lockout."""
import hashlib
import hmac
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from . import db

ph = PasswordHasher()  # argon2id, library defaults (t=3, m=64 MiB, p=4)
_DUMMY_HASH = ph.hash(secrets.token_urlsafe(16))

MAX_FAILS_PER_USER = 5
MAX_FAILS_PER_IP = 15
LOCKOUT_MINUTES = 15
MIN_PASSWORD_LEN = 12


def _sha(token):
    return hashlib.sha256(token.encode()).hexdigest()


def password_problems(pw, username=""):
    problems = []
    if len(pw) < MIN_PASSWORD_LEN:
        problems.append(f"at least {MIN_PASSWORD_LEN} characters")
    if username and username.lower() in pw.lower():
        problems.append("must not contain the username")
    if len(set(pw)) < 6:
        problems.append("too few distinct characters")
    return problems


def hash_password(pw):
    return ph.hash(pw)


def is_locked_out(username, ip):
    since = (db.now_utc() - timedelta(minutes=LOCKOUT_MINUTES)).isoformat(timespec="seconds")
    u = db.q1("SELECT COUNT(*) n FROM login_attempts WHERE success = 0 AND ts > ? AND username = ? COLLATE NOCASE",
              since, username)["n"]
    i = db.q1("SELECT COUNT(*) n FROM login_attempts WHERE success = 0 AND ts > ? AND ip = ?", since, ip)["n"]
    return u >= MAX_FAILS_PER_USER or i >= MAX_FAILS_PER_IP


def authenticate(username, password, ip):
    """Returns admin row or None. Always performs one Argon2 verification so
    response time does not reveal whether a username exists."""
    row = db.q1("SELECT * FROM admins WHERE username = ? AND enabled = 1", username)
    ok = False
    try:
        ok = ph.verify(row["password_hash"] if row else _DUMMY_HASH, password) and row is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        ok = False
    db.ex("INSERT INTO login_attempts(ts, ip, username, success) VALUES (?,?,?,?)",
          db.now_iso(), ip, username[:64], 1 if ok else 0)
    if not ok:
        return None
    if ph.check_needs_rehash(row["password_hash"]):
        db.ex("UPDATE admins SET password_hash = ? WHERE id = ?", ph.hash(password), row["id"])
    db.ex("UPDATE admins SET last_login_at = ? WHERE id = ?", db.now_iso(), row["id"])
    return row


def create_session(admin_id, ip, user_agent):
    token = secrets.token_urlsafe(32)
    ts = db.now_iso()
    db.ex("INSERT INTO sessions(id, admin_id, csrf, created_at, last_seen_at, ip, user_agent) VALUES (?,?,?,?,?,?,?)",
          _sha(token), admin_id, secrets.token_urlsafe(32), ts, ts, ip, (user_agent or "")[:200])
    return token


def load_session(token):
    """Validate idle + absolute timeouts; slide the idle window. Returns row with admin username."""
    if not token or len(token) > 100:
        return None
    row = db.q1("SELECT s.*, a.username FROM sessions s JOIN admins a ON a.id = s.admin_id "
                "WHERE s.id = ? AND a.enabled = 1", _sha(token))
    if not row:
        return None
    now = db.now_utc()
    idle = timedelta(minutes=int(db.setting("session_idle_minutes")))
    absolute = timedelta(hours=int(db.setting("session_absolute_hours")))
    from .engine import parse_iso
    if now - parse_iso(row["last_seen_at"]) > idle or now - parse_iso(row["created_at"]) > absolute:
        db.ex("DELETE FROM sessions WHERE id = ?", row["id"])
        return None
    db.ex("UPDATE sessions SET last_seen_at = ? WHERE id = ?", now.isoformat(timespec="seconds"), row["id"])
    return row


def destroy_session(token):
    if token:
        db.ex("DELETE FROM sessions WHERE id = ?", _sha(token))


def destroy_all_sessions(admin_id, except_token=None):
    keep = _sha(except_token) if except_token else ""
    db.ex("DELETE FROM sessions WHERE admin_id = ? AND id != ?", admin_id, keep)


def csrf_ok(expected, given):
    return bool(expected) and bool(given) and hmac.compare_digest(expected, given)
