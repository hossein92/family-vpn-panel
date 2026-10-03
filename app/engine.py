"""Policy engine: turns the database (members, devices, policies, schedules)
into enforcement state and pushes it to OpenVPN (CCD), nftables and AdGuard.

Everything is idempotent: `apply()` computes the full desired state and only
pushes components whose content changed since the last successful apply.
"""
import hashlib
import ipaddress
import json
import logging
import math
import re
import threading
import unicodedata
import urllib.request
from datetime import datetime, timedelta, timezone

from . import adguard, audit, config, db, helper, schedule, vault

log = logging.getLogger("vpnpanel.engine")
_lock = threading.RLock()
_applied = {}          # component -> content hash of last successful push
_ccd_cache = None      # cn -> {"ip", "disabled"} as last seen on disk

SAFESEARCH_ENGINES = ("bing", "duckduckgo", "ecosia", "google", "pixabay", "yandex")

SERVICE_GROUPS = {
    "social_network": "Social media",
    "gaming": "Gaming",
    "streaming": "Video & music streaming",
    "messenger": "Messaging apps",
    "dating": "Dating",
    "gambling": "Gambling services",
    "ai": "AI chatbots",
    "shopping": "Shopping",
}

CATEGORY_LISTS = {
    "adult": ("Adult content", "HaGeZi NSFW",
              "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt"),
    "gambling": ("Gambling", "HaGeZi Gambling (medium)",
                 "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.medium-onlydomains.txt"),
    "tracking": ("Ads & trackers", "HaGeZi Light",
                 "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt"),
    "encrypted_dns": ("Encrypted DNS / VPN / proxy bypass", "HaGeZi DoH-VPN-Proxy-Bypass",
                      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt"),
}
CATEGORY_FLAG = {"adult": "block_adult", "gambling": "block_gambling",
                 "tracking": "block_tracking", "encrypted_dns": "block_encrypted_dns"}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
CN_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


class EngineError(RuntimeError):
    pass


# ---------------------------------------------------------------- helpers

def parse_iso(s):
    if not s:
        return None
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def policy_dict(row):
    p = dict(row)
    p["service_rules"] = json.loads(p.get("service_rules") or "{}")
    p["extra_services"] = json.loads(p.get("extra_services") or "[]")
    return p


def slug(text):
    t = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()
    t = re.sub(r"[^a-z0-9]+", "-", t).strip("-")
    return t[:40] or "device"


def unique_cn(base):
    base = slug(base)[:56]
    if len(base) < 2:
        base = f"device-{base}"
    cn, n = base, 2
    while db.q1("SELECT 1 FROM devices WHERE common_name = ?", cn) or cn in ("server", "ca"):
        cn = f"{base}-{n}"
        n += 1
    return cn


def parse_domains(text):
    """Validate a custom block/allow list. Returns (domains, invalid_lines)."""
    good, bad = [], []
    for raw in (text or "").splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^(https?://)?", "", line).split("/")[0]
        if line.startswith("*."):
            line = line[2:]
        if DOMAIN_RE.match(line):
            good.append(line)
        else:
            bad.append(raw.strip())
    return sorted(set(good)), bad


def allocate_ip(member_type):
    used = {r["vpn_ipv4"] for r in db.q("SELECT vpn_ipv4 FROM devices")}
    ccd = _ccd_cache or {}
    used |= {v["ip"] for v in ccd.values() if v.get("ip")}
    for rng in (config.IP_RANGES[member_type], config.IP_RANGES["OVERFLOW"]):
        for offset in range(rng[0], rng[1] + 1):
            ip = config.host(offset)
            if ip not in used:
                return ip
    raise EngineError("No free VPN addresses left in this range")


# ---------------------------------------------------------------- schedule / state evaluation

def member_schedule(member, policy):
    """Returns (windows, tz, source) or (None, tz, None) when unrestricted."""
    tz = db.setting("display_timezone")
    row = db.q1("SELECT * FROM access_schedules WHERE family_member_id = ?", member["id"])
    if row and row["enabled"]:
        return json.loads(row["windows"]), row["timezone"], "custom"
    if policy["enforce_schedule"]:
        return schedule.DEFAULT_WINDOWS, (row["timezone"] if row else tz), "policy-default"
    return None, (row["timezone"] if row else tz), None


def active_override(member_id, now=None):
    now = now or db.now_utc()
    return db.q1("SELECT * FROM schedule_overrides WHERE family_member_id = ? AND cancelled_at IS NULL "
                 "AND expires_at > ? ORDER BY id DESC LIMIT 1", member_id, now.isoformat(timespec="seconds"))


def schedule_state(member, policy, now=None):
    """-> dict(allowed, reason, next_change, override, windows, tz, source)"""
    now = now or db.now_utc()
    windows, tz, source = member_schedule(member, policy)
    ov = active_override(member["id"], now)
    st = {"windows": windows, "tz": tz, "source": source, "override": ov, "next_change": None}
    if ov is not None:
        st.update(allowed=ov["kind"] == "allow",
                  reason=("Extra time until " if ov["kind"] == "allow" else "Paused until ") + ov["expires_at"])
        return st
    if not windows:
        st.update(allowed=True, reason="No schedule")
        return st
    allowed = schedule.allowed_by_windows(windows, tz, now)
    st.update(allowed=allowed, reason="Within allowed hours" if allowed else "Outside allowed hours",
              next_change=schedule.next_change(windows, tz, now))
    return st


def blocked_service_ids(policy, tz, now=None):
    now = now or db.now_utc()
    catalog = adguard.services_catalog()
    groups = set()
    for g, rule in policy["service_rules"].items():
        mode = rule.get("mode", "allow")
        if mode == "block":
            groups.add(g)
        elif mode == "window" and rule.get("start") and rule.get("end"):
            local = now.astimezone(schedule.ZoneInfo(tz))
            if schedule.in_window(local, list(range(7)), rule["start"], rule["end"]):
                groups.add(g)
    if policy["block_gambling"]:
        groups.add("gambling")
    if policy["block_encrypted_dns"]:
        groups.add("privacy")  # iCloud Private Relay, Proton … can tunnel around the filter
    ids = {s["id"] for s in catalog if s["group"] in groups}
    ids |= set(policy["extra_services"])
    return sorted(ids)


def load_world():
    members = {r["id"]: dict(r) for r in db.q("SELECT * FROM family_members")}
    policies = {r["id"]: policy_dict(r) for r in db.q("SELECT * FROM policies")}
    devices = [dict(r) for r in db.q("SELECT * FROM devices ORDER BY id")]
    return members, policies, devices


def device_status(d, member, now=None):
    """Lifecycle status: revoked > expired > disabled > owner-disabled > active."""
    now = now or db.now_utc()
    if d["revoked"]:
        return "revoked"
    exp = parse_iso(d["expires_at"])
    if exp and exp <= now:
        return "expired"
    na = parse_iso(d["certificate_not_after"])
    if na and na <= now:
        return "expired"
    if not d["enabled"]:
        return "disabled"
    if not member["enabled"]:
        return "owner-disabled"
    return "active"


def evaluate(now=None):
    """Full desired state for every device."""
    now = now or db.now_utc()
    members, policies, devices = load_world()
    sched_cache = {}
    out = []
    for d in devices:
        m = members[d["family_member_id"]]
        p = policies[d["policy_id"] or m["policy_id"]]
        status = device_status(d, m, now)
        if m["id"] not in sched_cache:
            sched_cache[m["id"]] = schedule_state(m, policies[m["policy_id"]], now)
        st = sched_cache[m["id"]]
        internet = bool(d["internet_enabled"]) and st["allowed"]
        if not d["internet_enabled"]:
            internet_reason = "Internet disabled by admin"
        elif not st["allowed"]:
            internet_reason = st["reason"]
        else:
            internet_reason = st["reason"] if st["windows"] or st["override"] else "Allowed"
        out.append({
            "device": d, "member": m, "policy": p, "status": status, "active": status == "active",
            "internet": internet and status == "active", "internet_reason": internet_reason,
            "schedule": st, "child": m["type"] == "CHILD" or p["kind"] == "CHILD",
        })
    return out


# ---------------------------------------------------------------- apply

def _h(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def adguard_client_data(d, p, tz, now=None):
    yt = bool(p["youtube_restricted"])
    ss = bool(p["safesearch"])
    return {
        "name": d["common_name"],
        "ids": [d["vpn_ipv4"]],
        "use_global_settings": False,
        "filtering_enabled": True,
        "parental_enabled": bool(p["block_adult"]),
        "safebrowsing_enabled": bool(p["block_malware"]),
        "safe_search": {"enabled": ss or yt, "youtube": yt, **{e: ss for e in SAFESEARCH_ENGINES}},
        "use_global_blocked_services": False,
        "blocked_services": blocked_service_ids(p, tz, now),
        "blocked_services_schedule": {"time_zone": "UTC"},
        "upstreams": [],
        "tags": ["user_child"] if p["kind"] == "CHILD" else ["user_regular"],
        "ignore_querylog": False,
        "ignore_statistics": False,
        "upstreams_cache_enabled": False,
        "upstreams_cache_size": 0,
    }


def desired_state(now=None):
    now = now or db.now_utc()
    ev = evaluate(now)
    ccd, clients, lists = {}, {}, {c: [] for c in CATEGORY_LISTS}
    nft = {"no_internet": [], "children": [], "panel_admins": []}
    rules = {"block": {}, "allow": {}}
    for e in ev:
        d, p, m = e["device"], e["policy"], e["member"]
        if d["revoked"]:
            ccd[d["common_name"]] = (d["vpn_ipv4"], False)
            continue
        ip = d["vpn_ipv4"]
        ccd[d["common_name"]] = (ip, e["active"])
        if not e["internet"]:
            nft["no_internet"].append(ip)
        if e["child"]:
            nft["children"].append(ip)
        if e["active"] and m["type"] == "ADULT" and d["panel_access"]:
            nft["panel_admins"].append(ip)
        clients[d["common_name"]] = adguard_client_data(d, p, e["schedule"]["tz"], now)
        for cat, flag in CATEGORY_FLAG.items():
            if p[flag]:
                lists[cat].append(ip)
        for kind, field in (("block", "custom_block"), ("allow", "custom_allow")):
            for dom in parse_domains(p[field])[0]:
                rules[kind].setdefault(dom, []).append(ip)
    user_rules = ["! Managed by vpnpanel — edit in the admin panel, not in AdGuard."]
    for dom, ips in sorted(rules["block"].items()):
        user_rules.append(f"||{dom}^$client={'|'.join(sorted(set(ips)))}")
    for dom, ips in sorted(rules["allow"].items()):
        user_rules.append(f"@@||{dom}^$important,client={'|'.join(sorted(set(ips)))}")
    g_block, _ = parse_domains(db.setting("global_custom_rules"))
    user_rules += [f"||{dom}^" for dom in g_block]
    for k in nft:
        nft[k] = sorted(set(nft[k]))
    return {"ccd": ccd, "nft": nft, "clients": clients, "lists": {k: sorted(v) for k, v in lists.items()},
            "user_rules": user_rules}


def apply(force=False, now=None):
    """Push changed components. Returns list of component names pushed. Errors are
    collected per component so one failing subsystem never blocks the others."""
    global _ccd_cache
    with _lock:
        want = desired_state(now)
        pushed, errors = [], []

        # 1. OpenVPN client-config-dir
        try:
            if _ccd_cache is None or force:
                _ccd_cache = helper.ccd_list()
            for cn, (ip, enabled) in want["ccd"].items():
                cur = _ccd_cache.get(cn)
                if force or cur is None or cur.get("ip") != ip or cur.get("disabled") == enabled:
                    helper.ccd_write(cn, ip, enabled)
                    _ccd_cache[cn] = {"ip": ip, "disabled": not enabled}
                    pushed.append(f"ccd:{cn}")
        except Exception as e:  # noqa: BLE001
            errors.append(f"ccd: {e}")
            _ccd_cache = None

        # 2. nftables sets
        try:
            if force or _applied.get("nft") != _h(want["nft"]):
                helper.nft_apply(want["nft"])
                _applied["nft"] = _h(want["nft"])
                pushed.append("nft")
        except Exception as e:  # noqa: BLE001
            errors.append(f"nft: {e}")

        # 3. AdGuard persistent clients (one per device, keyed by its static VPN IP)
        try:
            if force or _applied.get("clients") != _h(want["clients"]):
                existing = {c["name"]: c for c in adguard.clients()}
                net = ipaddress.ip_network(config.VPN_NET)
                for name, data in want["clients"].items():
                    if name not in existing:
                        # an older client may still hold this IP
                        for oname, oc in list(existing.items()):
                            if data["ids"][0] in oc.get("ids", []) and oname not in want["clients"]:
                                adguard.client_delete(oname)
                                existing.pop(oname)
                        adguard.client_add(data)
                    elif _client_differs(existing[name], data):
                        adguard.client_update(name, data)
                for name, c in existing.items():
                    managed = any(_in_net(i, net) for i in c.get("ids", []))
                    if managed and name not in want["clients"]:
                        adguard.client_delete(name)
                _applied["clients"] = _h(want["clients"])
                pushed.append("adguard-clients")
        except Exception as e:  # noqa: BLE001
            errors.append(f"adguard clients: {e}")

        # 4. Category lists (served at /internal/adguard/<cat>.txt). AdGuard only re-downloads a
        #    list when its URL changes, so the URL carries a content version.
        try:
            ensure_filters()
            current = {f["url"].split("?")[0]: f["url"] for f in adguard.filtering_status().get("filters") or []}
            for cat, ips in want["lists"].items():
                base = f"{config.INTERNAL_LIST_BASE}/{cat}.txt"
                url = f"{base}?v={_h([ips, source_version(cat)])[:12]}"
                if force or current.get(base) != url:
                    adguard.filter_set_url(current.get(base, base), url, filter_name(cat))
                    pushed.append(f"list:{cat}")
        except Exception as e:  # noqa: BLE001
            errors.append(f"adguard lists: {e}")

        # 5. AdGuard custom rules
        try:
            if force or _applied.get("rules") != _h(want["user_rules"]):
                adguard.set_rules(want["user_rules"])
                _applied["rules"] = _h(want["user_rules"])
                pushed.append("adguard-rules")
        except Exception as e:  # noqa: BLE001
            errors.append(f"adguard rules: {e}")

        if errors:
            log.error("apply errors: %s", "; ".join(errors))
        if pushed:
            log.info("applied: %s", ", ".join(pushed))
        return pushed, errors


def _in_net(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _client_differs(cur, want):
    for k, v in want.items():
        c = cur.get(k)
        if isinstance(v, list):
            if sorted(c or []) != sorted(v):
                return True
        elif isinstance(v, dict):
            if any((c or {}).get(kk) != vv for kk, vv in v.items()):
                return True
        elif c != v:
            return True
    return False


# ---------------------------------------------------------------- category list sources

def filter_name(cat):
    return f"[vpnpanel] {CATEGORY_LISTS[cat][0]} ({CATEGORY_LISTS[cat][1]})"


_filters_ok = False


def ensure_filters():
    global _filters_ok
    if _filters_ok:
        return
    adguard.ensure_rewrite(config.env("ADMIN_DNS_NAME", "vpn-panel.home.arpa"), config.SERVER_VPN_IP)
    have = {f["url"].split("?")[0] for f in adguard.filtering_status().get("filters") or []}
    for cat in CATEGORY_LISTS:
        url = f"{config.INTERNAL_LIST_BASE}/{cat}.txt"
        if url not in have:
            adguard.filter_add(filter_name(cat), url)
    _filters_ok = True


def source_path(cat):
    return config.LIST_CACHE / f"{cat}.txt"


def source_version(cat):
    p = source_path(cat)
    return int(p.stat().st_mtime) if p.exists() else 0


def refresh_sources(max_age_hours=24):
    """Download upstream category lists (domains only) into the local cache."""
    config.LIST_CACHE.mkdir(parents=True, exist_ok=True)
    changed = []
    for cat, (_, _, url) in CATEGORY_LISTS.items():
        p = source_path(cat)
        if p.exists() and (datetime.now().timestamp() - p.stat().st_mtime) < max_age_hours * 3600:
            continue
        if config.FAKE:
            p.write_text("adult-content.example\ncasino-bets.example\n")
            changed.append(cat)
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vpnpanel/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read(64 * 1024 * 1024).decode(errors="ignore")
            doms = [ln.strip().lower() for ln in raw.splitlines()
                    if ln.strip() and not ln.startswith("#") and DOMAIN_RE.match(ln.strip().lower())]
            if len(doms) < 50:
                raise EngineError(f"suspiciously small list ({len(doms)} entries)")
            tmp = p.with_suffix(".tmp")
            tmp.write_text("\n".join(doms) + "\n")
            tmp.replace(p)
            changed.append(cat)
        except Exception as e:  # noqa: BLE001
            log.warning("list %s download failed: %s", cat, e)
    return changed


_list_cache = {}


def render_list(cat):
    """AdGuard-syntax list for one category, restricted to the devices that have it on."""
    want_ips = desired_state()["lists"].get(cat, [])
    key = (cat, tuple(want_ips), source_version(cat))
    if _list_cache.get(cat, (None,))[0] == key:
        return _list_cache[cat][1]
    head = [f"! Title: {filter_name(cat)}", "! Generated by vpnpanel — applies only to listed VPN clients",
            f"! Clients: {', '.join(want_ips) or 'none'}",
            "||vpnpanel-placeholder.invalid^"]  # AdGuard rejects lists without any rule
    body = []
    if want_ips and source_path(cat).exists():
        mod = "$client=" + "|".join(want_ips)
        body = [f"||{dom}^{mod}" for dom in source_path(cat).read_text().split()]
    text = "\n".join(head + body) + "\n"
    _list_cache[cat] = (key, text)
    return text


# ---------------------------------------------------------------- device lifecycle

def _cert_days_for(expires_at):
    if expires_at:
        delta = parse_iso(expires_at) - db.now_utc()
        return max(1, math.ceil(delta.total_seconds() / 86400))
    return int(db.setting("default_cert_days"))


def _store_profile(device_id, profile):
    hours = int(db.setting("profile_download_hours"))
    until = (db.now_utc() + timedelta(hours=hours)).isoformat(timespec="seconds")
    db.ex("UPDATE devices SET profile_enc = ?, profile_available_until = ? WHERE id = ?",
          vault.seal(profile), until, device_id)


def create_device(member_id, display_name, policy_id, expires_at, panel_access, actor, ip, cn=None, notes=""):
    member = db.q1("SELECT * FROM family_members WHERE id = ?", member_id)
    if not member:
        raise EngineError("Unknown family member")
    display_name = display_name.strip()[:80]
    if not display_name:
        raise EngineError("Device name is required")
    if cn:
        cn = cn.strip().lower()
        if not CN_RE.match(cn) or cn in ("server", "ca"):
            raise EngineError("Common name must be 2–63 chars: lowercase letters, digits and dashes")
        if db.q1("SELECT 1 FROM devices WHERE common_name = ?", cn):
            raise EngineError("That common name is already in use")
    else:
        cn = unique_cn(f"{member['name']}-{display_name}")
    if member["type"] == "GUEST" and not expires_at:
        expires_at = (db.now_utc() + timedelta(days=int(db.setting("default_guest_days")))).isoformat(timespec="seconds")
    panel_access = 1 if (panel_access and member["type"] == "ADULT") else 0
    with _lock:
        vpn_ip = allocate_ip(member["type"])
        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO devices(family_member_id, display_name, common_name, vpn_ipv4, policy_id, "
                "panel_access, expires_at, notes, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (member_id, display_name, cn, vpn_ip, policy_id or None, panel_access, expires_at, notes, db.now_iso()))
            device_id = cur.lastrowid
        try:
            helper.ccd_write(cn, vpn_ip, True)
            if _ccd_cache is not None:
                _ccd_cache[cn] = {"ip": vpn_ip, "disabled": False}
            res = helper.issue(cn, _cert_days_for(expires_at), display_name)
        except Exception:
            db.ex("DELETE FROM devices WHERE id = ?", device_id)
            try:
                helper.call("ccd-delete", cn)
            except Exception:  # noqa: BLE001, S110 - best-effort cleanup; the original error is re-raised
                pass
            raise
        profile = res.pop("profile")
        db.ex("UPDATE devices SET certificate_serial = ?, certificate_not_after = ? WHERE id = ?",
              res["serial"], res["not_after"], device_id)
        db.ex("INSERT INTO vpn_certificates(device_id, common_name, serial, not_before, not_after, issued_at) "
              "VALUES (?,?,?,?,?,?)", device_id, cn, res["serial"], res["not_before"], res["not_after"], db.now_iso())
        _store_profile(device_id, profile)
        del profile
    audit.log(actor, "device.created", "device", device_id, cn, ip, owner=member["name"], vpn_ip=vpn_ip,
              display_name=display_name, expires_at=expires_at)
    audit.log(actor, "certificate.created", "device", device_id, cn, ip, serial=res["serial"],
              not_after=res["not_after"])
    apply()
    return device_id


def reissue_device(device_id, actor, ip):
    d = db.q1("SELECT * FROM devices WHERE id = ?", device_id)
    if not d or d["revoked"]:
        raise EngineError("Device is revoked — create a new device instead")
    with _lock:
        old = d["certificate_serial"]
        helper.revoke(d["common_name"], "superseded")
        if old:
            db.ex("UPDATE vpn_certificates SET status='revoked', revoked_at=?, revoke_reason='superseded' "
                  "WHERE serial = ?", db.now_iso(), old)
        res = helper.issue(d["common_name"], _cert_days_for(d["expires_at"]), d["display_name"])
        profile = res.pop("profile")
        db.ex("UPDATE devices SET certificate_serial = ?, certificate_not_after = ?, profile_downloads = 0 WHERE id = ?",
              res["serial"], res["not_after"], device_id)
        db.ex("INSERT INTO vpn_certificates(device_id, common_name, serial, not_before, not_after, issued_at) "
              "VALUES (?,?,?,?,?,?)", device_id, d["common_name"], res["serial"], res["not_before"],
              res["not_after"], db.now_iso())
        _store_profile(device_id, profile)
        del profile
    audit.log(actor, "certificate.revoked", "device", device_id, d["common_name"], ip, serial=old, reason="superseded")
    audit.log(actor, "certificate.created", "device", device_id, d["common_name"], ip, serial=res["serial"],
              not_after=res["not_after"], reissue=True)
    apply()


def revoke_device(device_id, reason, actor, ip):
    d = db.q1("SELECT * FROM devices WHERE id = ?", device_id)
    if not d:
        raise EngineError("Unknown device")
    if d["revoked"]:
        raise EngineError("Already revoked")
    with _lock:
        res = helper.revoke(d["common_name"], reason)
        ts = db.now_iso()
        db.ex("UPDATE devices SET revoked = 1, enabled = 0, revoked_at = ?, profile_enc = NULL, "
              "profile_available_until = NULL WHERE id = ?", ts, device_id)
        db.ex("UPDATE vpn_certificates SET status='revoked', revoked_at=?, revoke_reason=? "
              "WHERE device_id = ? AND status = 'valid'", ts, reason, device_id)
    audit.log(actor, "certificate.revoked", "device", device_id, d["common_name"], ip,
              serial=res.get("serial") or d["certificate_serial"], reason=reason,
              sessions_killed=res.get("sessions_killed"))
    apply()


def set_device_enabled(device_id, enabled, actor, ip):
    d = db.q1("SELECT * FROM devices WHERE id = ?", device_id)
    if not d or d["revoked"]:
        raise EngineError("Device not found or revoked")
    db.ex("UPDATE devices SET enabled = ? WHERE id = ?", 1 if enabled else 0, device_id)
    audit.log(actor, "device.enabled" if enabled else "device.disabled", "device", device_id, d["common_name"], ip)
    apply()


def adopt_certificate(cn, member_id, display_name, panel_access, actor, ip):
    """Bring a certificate that was issued outside the panel under management."""
    if not CN_RE.match(cn) or db.q1("SELECT 1 FROM devices WHERE common_name = ?", cn):
        raise EngineError("Invalid or already managed common name")
    member = db.q1("SELECT * FROM family_members WHERE id = ?", member_id)
    if not member:
        raise EngineError("Unknown family member")
    pki = {c["cn"]: c for c in helper.pki_list()["certs"]}
    cert = pki.get(cn)
    if not cert or cert["status"] != "valid":
        raise EngineError("No valid certificate with that common name")
    global _ccd_cache
    with _lock:
        if _ccd_cache is None:
            _ccd_cache = helper.ccd_list()
        existing_ip = (_ccd_cache.get(cn) or {}).get("ip")
        vpn_ip = existing_ip if existing_ip and not db.q1("SELECT 1 FROM devices WHERE vpn_ipv4=?", existing_ip) \
            else allocate_ip(member["type"])
        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO devices(family_member_id, display_name, common_name, vpn_ipv4, certificate_serial, "
                "certificate_not_after, panel_access, imported, created_at) VALUES (?,?,?,?,?,?,?,1,?)",
                (member_id, display_name.strip()[:80] or cn, cn, vpn_ip, cert["serial"], cert["not_after"],
                 1 if (panel_access and member["type"] == "ADULT") else 0, db.now_iso()))
            device_id = cur.lastrowid
            c.execute("INSERT OR IGNORE INTO vpn_certificates(device_id, common_name, serial, not_after, issued_at) "
                      "VALUES (?,?,?,?,?)", (device_id, cn, cert["serial"], cert["not_after"], db.now_iso()))
    audit.log(actor, "device.adopted", "device", device_id, cn, ip, owner=member["name"], vpn_ip=vpn_ip,
              serial=cert["serial"])
    apply()
    return device_id
