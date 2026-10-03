"""Thin wrapper around the root helper (/usr/local/sbin/vpnpanel-helper)."""
import json
import subprocess
import time

from . import config


class HelperError(RuntimeError):
    pass


def call(verb, *args, stdin=None, timeout=60):
    if config.FAKE:
        return _fake(verb, *args, stdin=stdin)
    p = subprocess.run(config.HELPER + [verb, *map(str, args)], input=stdin,
                       capture_output=True, text=True, timeout=timeout)
    try:
        res = json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as e:
        raise HelperError(f"helper {verb}: no response ({p.returncode})") from e
    if not res.get("ok"):
        raise HelperError(res.get("error") or f"helper {verb} failed")
    return res


def issue(cn, days, display):
    return call("issue", cn, days, display)


def revoke(cn, reason="cessationOfOperation"):
    return call("revoke", cn, reason)


def ccd_write(cn, ip, enabled):
    return call("ccd-write", cn, ip, 1 if enabled else 0)


def ccd_list():
    return call("ccd-list")["ccd"]


def pki_list():
    return call("pki-list")


def crl_refresh():
    return call("crl-refresh")


def mgmt_status():
    return call("mgmt-status", timeout=15)


def mgmt_kill(client_id):
    return call("mgmt-kill", int(client_id), timeout=15)


def nft_apply(state):
    return call("nft-apply", stdin=json.dumps(state))


def health():
    return call("health", timeout=20)


# ---------------------------------------------------------------- fake backend (local UI dev only)

_FAKE = {"ccd": {}, "certs": {}, "clients": {}, "start": int(time.time())}


def _fake(verb, *args, stdin=None):
    import secrets
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    if verb == "issue":
        cn, days = args[0], int(args[1])
        serial = secrets.token_hex(16).upper()
        na = (now + timedelta(days=days)).isoformat()
        _FAKE["certs"][cn] = {"cn": cn, "serial": serial, "status": "valid", "not_after": na, "revoked_at": None}
        profile = (f"# Family VPN profile — {args[2]} (DEMO, not a working profile)\nclient\n"
                   f"remote {config.VPN_PUBLIC_HOST} {config.VPN_PUBLIC_PORT}\n")
        return {"ok": True, "cn": cn, "serial": serial, "not_before": now.isoformat(), "not_after": na, "profile": profile}
    if verb == "revoke":
        c = _FAKE["certs"].get(args[0])
        if c:
            c.update(status="revoked", revoked_at=now.isoformat())
        return {"ok": True, "cn": args[0], "serial": c and c["serial"], "sessions_killed": 0}
    if verb == "ccd-write":
        _FAKE["ccd"][args[0]] = {"ip": args[1], "disabled": str(args[2]) == "0"}
        return {"ok": True}
    if verb == "ccd-list":
        return {"ok": True, "ccd": _FAKE["ccd"]}
    if verb == "pki-list":
        certs = [{"cn": "server", "serial": "0DEC0DE0000000000000000000000001", "status": "valid",
                  "not_after": "2029-01-01T00:00:00+00:00", "revoked_at": None},
                 {"cn": "legacy-shared", "serial": "0DEC0DE0000000000000000000000002", "status": "valid",
                  "not_after": "2029-01-01T00:00:00+00:00", "revoked_at": None}] + list(_FAKE["certs"].values())
        return {"ok": True, "certs": certs, "crl_next_update": "Jan  1 00:00:00 2036 GMT",
                "ca_not_after": "2036-01-01T00:00:00+00:00"}
    if verb == "mgmt-status":
        t = int(time.time()) - _FAKE["start"]
        clients = []
        for i, (cn, v) in enumerate(_FAKE["ccd"].items()):
            if v["disabled"] or cn in _FAKE["clients"]:
                continue
            if i % 2 == 0:
                clients.append({"cn": cn, "real_address": f"{('198.51.100', '203.0.113')[i % 2]}.{20 + i}:5{i}321", "vpn_ipv4": v["ip"],
                                "vpn_ipv6": "", "bytes_received": 4_000_000 + t * 9000 * (i + 1),
                                "bytes_sent": 30_000_000 + t * 60000 * (i + 1),
                                "connected_since": _FAKE["start"] - 3600 * (i + 1), "client_id": 100 + i,
                                "cipher": "AES-256-GCM"})
        return {"ok": True, "clients": clients, "ts": int(time.time())}
    if verb == "mgmt-kill":
        return {"ok": True}
    if verb == "health":
        return {"ok": True, "services": {s: "active" for s in ("openvpn-server@server", "adguardhome", "vpnpanel",
                                                                 "nginx", "ufw", "vpnpanel-nft", "ssh")},
                "ufw_active": True, "nat_ok": True, "nat_rules": 1, "listening_vpn": True,
                "ip_forward": True, "nft_table": True}
    return {"ok": True}
