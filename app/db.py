"""SQLite storage. Plain sqlite3 (no ORM) keeps the dependency surface small."""
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,            -- sha256(token); the raw token only lives in the cookie
    admin_id     INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf         TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    ip           TEXT,
    user_agent   TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id       INTEGER PRIMARY KEY,
    ts       TEXT NOT NULL,
    ip       TEXT,
    username TEXT,
    success  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS login_attempts_ts ON login_attempts(ts);

CREATE TABLE IF NOT EXISTS policies (
    id                  INTEGER PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    kind                TEXT NOT NULL CHECK (kind IN ('ADULT','CHILD','GUEST')),
    description         TEXT NOT NULL DEFAULT '',
    builtin             INTEGER NOT NULL DEFAULT 0,
    block_malware       INTEGER NOT NULL DEFAULT 1,
    block_adult         INTEGER NOT NULL DEFAULT 0,
    block_gambling      INTEGER NOT NULL DEFAULT 0,
    block_tracking      INTEGER NOT NULL DEFAULT 0,
    block_encrypted_dns INTEGER NOT NULL DEFAULT 0,
    safesearch          INTEGER NOT NULL DEFAULT 0,
    youtube_restricted  INTEGER NOT NULL DEFAULT 0,
    enforce_schedule    INTEGER NOT NULL DEFAULT 0,
    service_rules       TEXT NOT NULL DEFAULT '{}',   -- {group: {mode: allow|block|window, start, end}}
    extra_services      TEXT NOT NULL DEFAULT '[]',   -- extra AdGuard service ids, always blocked
    custom_block        TEXT NOT NULL DEFAULT '',
    custom_allow        TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS family_members (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    type       TEXT NOT NULL CHECK (type IN ('ADULT','CHILD','GUEST')),
    policy_id  INTEGER NOT NULL REFERENCES policies(id),
    notes      TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id                      INTEGER PRIMARY KEY,
    family_member_id        INTEGER NOT NULL REFERENCES family_members(id),
    display_name            TEXT NOT NULL,
    common_name             TEXT NOT NULL UNIQUE,
    certificate_serial      TEXT,
    certificate_not_after   TEXT,
    vpn_ipv4                TEXT NOT NULL UNIQUE,     -- never reused while the record exists
    policy_id               INTEGER REFERENCES policies(id),  -- NULL = inherit from owner
    enabled                 INTEGER NOT NULL DEFAULT 1,
    internet_enabled        INTEGER NOT NULL DEFAULT 1,
    panel_access            INTEGER NOT NULL DEFAULT 0,
    revoked                 INTEGER NOT NULL DEFAULT 0,
    revoked_at              TEXT,
    expires_at              TEXT,
    imported                INTEGER NOT NULL DEFAULT 0,
    notes                   TEXT NOT NULL DEFAULT '',
    created_at              TEXT NOT NULL,
    last_seen               TEXT,
    last_connected_ip       TEXT,
    last_connected_at       TEXT,
    bytes_received          INTEGER NOT NULL DEFAULT 0,   -- server perspective: from device (upload)
    bytes_sent              INTEGER NOT NULL DEFAULT 0,   -- server perspective: to device (download)
    profile_enc             BLOB,                         -- encrypted .ovpn, purged after the download window
    profile_available_until TEXT,
    profile_downloads       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vpn_certificates (
    id            INTEGER PRIMARY KEY,
    device_id     INTEGER REFERENCES devices(id),
    common_name   TEXT NOT NULL,
    serial        TEXT NOT NULL UNIQUE,
    not_before    TEXT,
    not_after     TEXT,
    status        TEXT NOT NULL DEFAULT 'valid' CHECK (status IN ('valid','revoked','expired')),
    issued_at     TEXT NOT NULL,
    revoked_at    TEXT,
    revoke_reason TEXT
);

CREATE TABLE IF NOT EXISTS access_schedules (
    id               INTEGER PRIMARY KEY,
    family_member_id INTEGER NOT NULL UNIQUE REFERENCES family_members(id) ON DELETE CASCADE,
    enabled          INTEGER NOT NULL DEFAULT 1,
    timezone         TEXT NOT NULL,
    windows          TEXT NOT NULL DEFAULT '[]',   -- allowed windows [{days:[0..6], start:"HH:MM", end:"HH:MM"}]
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schedule_overrides (
    id               INTEGER PRIMARY KEY,
    family_member_id INTEGER NOT NULL REFERENCES family_members(id) ON DELETE CASCADE,
    kind             TEXT NOT NULL CHECK (kind IN ('allow','block')),
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    cancelled_at     TEXT,
    created_by       TEXT,
    note             TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS connection_sessions (
    id                  INTEGER PRIMARY KEY,
    device_id           INTEGER REFERENCES devices(id),
    common_name         TEXT NOT NULL,
    client_id           INTEGER NOT NULL,
    real_address        TEXT,
    vpn_ipv4            TEXT,
    connected_at        TEXT NOT NULL,
    disconnected_at     TEXT,
    bytes_received      INTEGER NOT NULL DEFAULT 0,
    bytes_sent          INTEGER NOT NULL DEFAULT 0,
    last_counter_rx     INTEGER NOT NULL DEFAULT 0,
    last_counter_tx     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_open ON connection_sessions(disconnected_at);
CREATE INDEX IF NOT EXISTS sessions_device ON connection_sessions(device_id, connected_at);

CREATE TABLE IF NOT EXISTS traffic_stats (
    device_id      INTEGER NOT NULL REFERENCES devices(id),
    hour           TEXT NOT NULL,                  -- UTC, 'YYYY-MM-DDTHH'
    bytes_received INTEGER NOT NULL DEFAULT 0,
    bytes_sent     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, hour)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id           INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT,
    target_id    INTEGER,
    target_label TEXT,
    details      TEXT NOT NULL DEFAULT '{}',
    ip           TEXT
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit_logs(ts);
"""

BUILTIN_POLICIES = [
    dict(name="Adult — unrestricted", kind="ADULT",
         description="Full internet access with standard malware & phishing protection.",
         block_malware=1),
    dict(name="Child — standard", kind="CHILD",
         description="Adult content, gambling and malware blocked. SafeSearch and YouTube Restricted Mode enforced.",
         block_malware=1, block_adult=1, block_gambling=1, block_encrypted_dns=1,
         safesearch=1, youtube_restricted=1,
         service_rules={"gambling": {"mode": "block"}, "dating": {"mode": "block"}}),
    dict(name="Child — strict", kind="CHILD",
         description="Everything in Standard, plus social media, gaming and trackers blocked and an access schedule enforced.",
         block_malware=1, block_adult=1, block_gambling=1, block_tracking=1, block_encrypted_dns=1,
         safesearch=1, youtube_restricted=1, enforce_schedule=1,
         service_rules={"social_network": {"mode": "block"}, "gaming": {"mode": "block"},
                        "gambling": {"mode": "block"}, "dating": {"mode": "block"}}),
    dict(name="Guest", kind="GUEST",
         description="Internet access only, malware protection, no access to private resources. Time-limited profiles.",
         block_malware=1),
]

_local = threading.local()
_init_lock = threading.Lock()


def now_utc():
    return datetime.now(timezone.utc)


def now_iso():
    return now_utc().isoformat(timespec="seconds")


def connect():
    conn = sqlite3.connect(config.DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def get():
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _local.conn = connect()
    return conn


@contextmanager
def tx():
    conn = get()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def q(sql, *args):
    return get().execute(sql, args).fetchall()


def q1(sql, *args):
    return get().execute(sql, args).fetchone()


def ex(sql, *args):
    return get().execute(sql, args)


def init():
    with _init_lock:
        conn = get()
        conn.executescript(SCHEMA)
        for k, v in config.DEFAULT_SETTINGS.items():
            conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, v))
        if not conn.execute("SELECT 1 FROM policies LIMIT 1").fetchone():
            ts = now_iso()
            for p in BUILTIN_POLICIES:
                p = dict(p)
                rules = json.dumps(p.pop("service_rules", {}))
                cols = ["builtin", "service_rules", "created_at", "updated_at"] + list(p)
                vals = [1, rules, ts, ts] + list(p.values())
                conn.execute(
                    f"INSERT INTO policies({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)  # noqa: S608 - fixed column names/fragments only; values are bound parameters


def setting(key):
    row = q1("SELECT value FROM settings WHERE key = ?", key)
    return row["value"] if row else config.DEFAULT_SETTINGS.get(key, "")


def set_setting(key, value):
    ex("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
       key, str(value))
