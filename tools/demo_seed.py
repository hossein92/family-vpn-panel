"""Seed a local DEMO database with fictional people and devices.

    VPNPANEL_FAKE=1 python tools/demo_seed.py
    VPNPANEL_FAKE=1 uvicorn app.main:app --port 8765     # sign in: demo / demo-password-123

Demo mode never touches OpenVPN, AdGuard, sudo or the network.
"""
import os
import sys
from pathlib import Path

os.environ["VPNPANEL_FAKE"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, engine, security  # noqa: E402

PEOPLE = [
    ("Alex", "ADULT", "Adult — unrestricted", [("Laptop", True), ("Phone", True)]),
    ("Sam", "ADULT", "Adult — unrestricted", [("Phone", False)]),
    ("Child One", "CHILD", "Child — standard", [("Tablet", False), ("Phone", False)]),
    ("Child Two", "CHILD", "Child — strict", [("Tablet", False)]),
    ("Guest", "GUEST", "Guest", [("Phone", False)]),
]


def main():
    db.init()
    if not db.q1("SELECT 1 FROM admins WHERE username = 'demo'"):
        db.ex("INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
              "demo", security.hash_password("demo-password-123"), db.now_iso())
    for name, mtype, policy, devices in PEOPLE:
        row = db.q1("SELECT id FROM family_members WHERE name = ?", name)
        if row:
            continue
        pid = db.q1("SELECT id FROM policies WHERE name = ?", policy)["id"]
        mid = db.ex("INSERT INTO family_members(name, type, policy_id, created_at) VALUES (?, ?, ?, ?)",
                    name, mtype, pid, db.now_iso()).lastrowid
        for dev, panel in devices:
            engine.create_device(mid, dev, None, None, panel, "demo", "127.0.0.1")
    # Synthetic traffic history (14 days, evening peaks) so the charts have something to show.
    import random
    from datetime import timedelta
    rnd = random.Random(7)
    now = db.now_utc()
    if db.q1("SELECT COUNT(*) n FROM traffic_stats")["n"] < 100:
        for d in db.q("SELECT id FROM devices"):
            scale = rnd.uniform(0.3, 1.5)
            for h in range(14 * 24):
                t = now - timedelta(hours=h)
                peak = 3.0 if 17 <= t.hour <= 22 else (0.2 if t.hour < 7 else 1.0)
                down = int(rnd.uniform(5, 40) * 1_000_000 * peak * scale)
                db.ex("INSERT OR IGNORE INTO traffic_stats(device_id, hour, bytes_received, bytes_sent) VALUES (?,?,?,?)",
                      d["id"], t.strftime("%Y-%m-%dT%H"), down // 8, down)
    print("demo data ready — sign in with demo / demo-password-123")


if __name__ == "__main__":
    main()
