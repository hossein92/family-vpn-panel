"""Minimal AdGuard Home REST client (local-only API on 127.0.0.1:3080)."""
import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from . import config


class AdGuardError(RuntimeError):
    pass


def _env():
    env = {}
    if config.ADGUARD_ENV and config.ADGUARD_ENV.exists():
        for line in config.ADGUARD_ENV.read_text().splitlines():
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env


_ENV = None


def _req(method, path, body=None, timeout=15):
    global _ENV
    if config.FAKE:
        return _fake(method, path, body)
    if _ENV is None:
        _ENV = _env()
    url = _ENV.get("ADGUARD_URL") or config.ADGUARD_URL
    url += path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    token = base64.b64encode(f"{_ENV.get('ADGUARD_USER')}:{_ENV.get('ADGUARD_PASSWORD')}".encode()).decode()
    req.add_header("Authorization", "Basic " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise AdGuardError(f"{method} {path}: HTTP {e.code} {e.read()[:200]!r}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise AdGuardError(f"{method} {path}: {e}") from e
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")


def status():
    return _req("GET", "/control/status")


def clients():
    return (_req("GET", "/control/clients") or {}).get("clients") or []


def client_add(data):
    _req("POST", "/control/clients/add", data)


def client_update(name, data):
    _req("POST", "/control/clients/update", {"name": name, "data": data})


def client_delete(name):
    _req("POST", "/control/clients/delete", {"name": name})


def filtering_status():
    return _req("GET", "/control/filtering/status") or {}


def filter_add(name, url):
    _req("POST", "/control/filtering/add_url", {"name": name, "url": url, "whitelist": False}, timeout=120)


def filter_set_url(old_url, new_url, name):
    """Point a list at a new URL; AdGuard downloads it immediately."""
    _req("POST", "/control/filtering/set_url",
         {"url": old_url, "whitelist": False, "data": {"name": name, "url": new_url, "enabled": True}}, timeout=120)


def ensure_rewrite(domain, answer):
    if config.FAKE:
        return
    have = _req("GET", "/control/rewrite/list") or []
    if not any(r.get("domain") == domain and r.get("answer") == answer for r in have):
        _req("POST", "/control/rewrite/add", {"domain": domain, "answer": answer})


def set_rules(rules):
    _req("POST", "/control/filtering/set_rules", {"rules": rules}, timeout=60)


def querylog(search="", client="", limit=100, response_status="all"):
    """AdGuard's `search` matches either domain or client, so filter by client
    server-side and by domain substring here."""
    params = {"limit": limit if not (client and search) else 1000, "response_status": response_status}
    if client or search:
        params["search"] = client or search
    data = (_req("GET", "/control/querylog?" + urllib.parse.urlencode(params)) or {}).get("data") or []
    if client:
        data = [e for e in data if e.get("client") == client]
    if client and search:
        data = [e for e in data if search.lower() in e.get("question", {}).get("name", "").lower()]
    return data[:limit]


def stats():
    return _req("GET", "/control/stats") or {}


def check_host(name, client=""):
    params = {"name": name}
    if client:
        params["client"] = client
    return _req("GET", "/control/filtering/check_host?" + urllib.parse.urlencode(params))


_SERVICES = {"ts": 0, "data": None}


def services_catalog():
    if _SERVICES["data"] is None or time.time() - _SERVICES["ts"] > 86400:
        d = _req("GET", "/control/blocked_services/all") or {}
        _SERVICES["data"] = [{"id": s["id"], "name": s["name"], "group": s.get("group_id", "")}
                             for s in d.get("blocked_services", [])]
        _SERVICES["ts"] = time.time()
    return _SERVICES["data"]


# ---------------------------------------------------------------- fake backend (local UI dev only)

_F = {"clients": {}, "filters": [], "rules": []}


def _fake(method, path, body):
    import random
    if path == "/control/status":
        return {"version": "v0.107.79 (demo)", "running": True, "protection_enabled": True}
    if path == "/control/clients":
        return {"clients": list(_F["clients"].values())}
    if path == "/control/clients/add":
        _F["clients"][body["name"]] = body
        return None
    if path == "/control/clients/update":
        _F["clients"].pop(body["name"], None)
        _F["clients"][body["data"]["name"]] = body["data"]
        return None
    if path == "/control/clients/delete":
        _F["clients"].pop(body["name"], None)
        return None
    if path == "/control/filtering/status":
        return {"enabled": True, "user_rules": _F["rules"], "filters": _F["filters"] or [
            {"id": 101, "name": "[global] HaGeZi Threat Intelligence Feeds (medium)", "rules_count": 705866,
             "enabled": True, "url": "https://raw.githubusercontent.com/hagezi/...", "last_updated": "2026-01-15T03:00:00Z"},
            {"id": 102, "name": "[global] URLHaus malicious URLs", "rules_count": 3225, "enabled": True,
             "url": "https://adguardteam.github.io/...", "last_updated": "2026-01-15T03:00:00Z"}]}
    if path.startswith("/control/filtering/set_rules"):
        _F["rules"] = body["rules"]
        return None
    if path.startswith("/control/filtering/"):
        return None
    if path.startswith("/control/querylog"):
        rnd = random.Random(42)
        child_ips = [config.host(50), config.host(51), config.host(52)]
        ok_doms = ["en.wikipedia.org", "www.google.com", "i.ytimg.com", "cdn.example.net", "school.example.org",
                   "maps.example.com", "news.example.com"]
        child_blocked = ["adult-content.example", "casino-bets.example", "mask.icloud.com", "game-chat.example"]
        data = []
        for i in range(40):
            ip = rnd.choice(child_ips + [config.host(10), config.host(12)])
            blocked = ip in child_ips and rnd.random() < 0.35
            d = rnd.choice(child_blocked if blocked else ok_doms)
            data.append({"time": f"2026-01-15T18:{59 - i:02d}:00Z", "question": {"name": d, "type": "A"}, "client": ip,
                         "reason": "FilteredBlackList" if blocked else "NotFilteredNotFound",
                         "rules": [{"text": f"||{d}^$client={ip}"}] if blocked else [], "elapsedMs": "1.2"})
        return {"data": data}
    if path == "/control/stats":
        return {"num_dns_queries": 18234, "num_blocked_filtering": 1422, "num_replaced_safebrowsing": 3,
                "num_replaced_parental": 12, "avg_processing_time": 0.004}
    if path.startswith("/control/filtering/check_host"):
        return {"reason": "FilteredBlackList", "rules": [{"text": "||example^", "filter_list_id": 1}]}
    if path == "/control/blocked_services/all":
        demo = {"social_network": ["facebook", "instagram", "tiktok", "snapchat", "discord", "reddit", "twitter"],
                "gaming": ["roblox", "minecraft", "steam", "epic_games", "playstation", "xboxlive"],
                "streaming": ["youtube", "netflix", "twitch", "spotify"], "messenger": ["whatsapp", "telegram"],
                "dating": ["tinder"], "gambling": ["betway"], "ai": ["chatgpt"], "shopping": ["amazon"],
                "privacy": ["icloud_private_relay", "proton"]}
        return {"blocked_services": [{"id": s, "name": s.replace("_", " ").title(), "group_id": g}
                                     for g, ids in demo.items() for s in ids]}
    return None
