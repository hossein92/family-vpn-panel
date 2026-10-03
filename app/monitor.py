"""Background worker: connection/traffic accounting from the OpenVPN management
interface, schedule & expiry enforcement, and housekeeping. Metadata only —
no packet capture, no content inspection."""
import logging
import threading
import time
from datetime import timedelta

from . import audit, db, engine, helper

log = logging.getLogger("vpnpanel.monitor")

POLL_SECONDS = 15
_live = {"clients": [], "ts": 0, "error": None}
_stop = threading.Event()


def live_clients():
    return _live


def _hour(ts):
    return ts.strftime("%Y-%m-%dT%H")


def poll_connections():
    st = helper.mgmt_status()
    now = db.now_utc()
    now_s = now.isoformat(timespec="seconds")
    hour = _hour(now)
    devices = {r["common_name"]: r for r in db.q("SELECT id, common_name FROM devices")}
    open_rows = {(r["common_name"], r["client_id"]): r
                 for r in db.q("SELECT * FROM connection_sessions WHERE disconnected_at IS NULL")}
    seen = set()
    with db.tx() as c:
        for cl in st["clients"]:
            key = (cl["cn"], cl["client_id"])
            seen.add(key)
            dev = devices.get(cl["cn"])
            dev_id = dev["id"] if dev else None
            since = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(cl["connected_since"]))
            row = open_rows.get(key)
            if row is None or row["connected_at"] != since:
                if row is not None:  # client id reused after a server restart
                    c.execute("UPDATE connection_sessions SET disconnected_at = ? WHERE id = ?", (now_s, row["id"]))
                c.execute("INSERT INTO connection_sessions(device_id, common_name, client_id, real_address, vpn_ipv4, "
                          "connected_at, last_counter_rx, last_counter_tx) VALUES (?,?,?,?,?,?,0,0)",
                          (dev_id, cl["cn"], cl["client_id"], cl["real_address"], cl["vpn_ipv4"], since))
                row = c.execute("SELECT * FROM connection_sessions WHERE id = last_insert_rowid()").fetchone()
                if dev_id:
                    c.execute("UPDATE devices SET last_connected_at = ?, last_connected_ip = ? WHERE id = ?",
                              (since, cl["real_address"].rsplit(":", 1)[0], dev_id))
            drx = max(0, cl["bytes_received"] - row["last_counter_rx"])
            dtx = max(0, cl["bytes_sent"] - row["last_counter_tx"])
            c.execute("UPDATE connection_sessions SET bytes_received = bytes_received + ?, bytes_sent = bytes_sent + ?, "
                      "last_counter_rx = ?, last_counter_tx = ? WHERE id = ?",
                      (drx, dtx, cl["bytes_received"], cl["bytes_sent"], row["id"]))
            if dev_id:
                c.execute("UPDATE devices SET last_seen = ?, bytes_received = bytes_received + ?, "
                          "bytes_sent = bytes_sent + ? WHERE id = ?", (now_s, drx, dtx, dev_id))
                if drx or dtx:
                    c.execute("INSERT INTO traffic_stats(device_id, hour, bytes_received, bytes_sent) VALUES (?,?,?,?) "
                              "ON CONFLICT(device_id, hour) DO UPDATE SET bytes_received = bytes_received + excluded.bytes_received, "
                              "bytes_sent = bytes_sent + excluded.bytes_sent", (dev_id, hour, drx, dtx))
        for key, row in open_rows.items():
            if key not in seen:
                c.execute("UPDATE connection_sessions SET disconnected_at = ? WHERE id = ?", (now_s, row["id"]))
    _live.update(clients=st["clients"], ts=st["ts"], error=None)


def enforce_expiry():
    """Mark devices whose guest lifetime ended; apply() then disables them in CCD."""
    now = db.now_iso()
    rows = db.q("SELECT id, common_name FROM devices WHERE revoked = 0 AND enabled = 1 AND expires_at IS NOT NULL "
                "AND expires_at <= ? AND id NOT IN (SELECT target_id FROM audit_logs WHERE action = 'device.expired' "
                "AND target_id IS NOT NULL)", now)
    for r in rows:
        audit.log("system", "device.expired", "device", r["id"], r["common_name"])


def housekeeping():
    now = db.now_utc()
    db.ex("UPDATE devices SET profile_enc = NULL, profile_available_until = NULL "
          "WHERE profile_available_until IS NOT NULL AND profile_available_until < ?", now.isoformat(timespec="seconds"))
    db.ex("DELETE FROM sessions WHERE last_seen_at < ?", (now - timedelta(days=2)).isoformat(timespec="seconds"))
    db.ex("DELETE FROM login_attempts WHERE ts < ?", (now - timedelta(days=30)).isoformat(timespec="seconds"))
    db.ex("DELETE FROM traffic_stats WHERE hour < ?", _hour(now - timedelta(days=400)))


def run():
    log.info("monitor started")
    last = {"apply": 0, "house": 0, "daily": 0}
    _stop.wait(3)  # let uvicorn start listening: AdGuard fetches category lists from us
    try:
        engine.apply(force=True)
    except Exception:  # noqa: BLE001
        log.exception("initial apply failed")
    while not _stop.is_set():
        t = time.time()
        try:
            poll_connections()
        except Exception as e:  # noqa: BLE001
            _live["error"] = str(e)
            log.warning("poll failed: %s", e)
        try:
            if t - last["apply"] >= 30:
                enforce_expiry()
                engine.apply()           # schedules, overrides, category windows, expiry
                last["apply"] = t
            if t - last["house"] >= 600:
                housekeeping()
                last["house"] = t
            if t - last["daily"] >= 6 * 3600:
                changed = engine.refresh_sources()
                helper.crl_refresh()
                if changed:
                    engine.apply()
                last["daily"] = t
        except Exception:  # noqa: BLE001
            log.exception("monitor tick failed")
        _stop.wait(POLL_SECONDS)


def start():
    th = threading.Thread(target=run, name="vpnpanel-monitor", daemon=True)
    th.start()
    return th


def stop():
    _stop.set()
