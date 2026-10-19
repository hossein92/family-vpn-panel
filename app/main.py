"""FastAPI application: routes for every admin panel section."""
import json
import logging
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from . import adguard, audit, config, db, engine, helper, monitor, schedule, security, sysinfo, vault
from .engine import EngineError, parse_iso
from .web import Ctx, LoginRequired, admin_ctx, admin_post, client_ip, redirect, render, templates

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("vpnpanel")

OPERATIONAL_ERRORS = (EngineError, helper.HelperError, adguard.AdGuardError, ValueError)


@asynccontextmanager
async def lifespan(app):
    db.init()
    monitor.start()
    yield
    monitor.stop()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(config.BASE / "static")), name="static")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if not request.url.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, exc):
    nxt = request.url.path if request.method == "GET" else "/"
    return RedirectResponse(f"/login?next={nxt}", status_code=303)


@app.exception_handler(HTTPException)
async def _http_error(request: Request, exc: HTTPException):
    return templates.TemplateResponse(request, "error.html", {"code": exc.status_code, "detail": exc.detail},
                                      status_code=exc.status_code)


Admin = Depends(admin_ctx)
AdminPost = Depends(admin_post)


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def back(ctx, fallback="/"):
    ref = ctx.request.headers.get("referer", "")
    host = ctx.request.headers.get("host", "")
    return ref if host and f"//{host}/" in ref else fallback


_NEXT_RE = re.compile(r"^/(?![/\\])[A-Za-z0-9._~!$&'()*+,;=:@/?%-]*$")


def safe_next(value):
    """Only same-origin absolute paths. Rejects scheme/host forms, backslashes, control characters
    and percent-encoded slashes that some browsers or proxies normalise into a host."""
    if not isinstance(value, str) or len(value) > 512 or not _NEXT_RE.match(value):
        return "/"
    decoded = unquote(value)
    if decoded.startswith(("//", "/\\")) or "\\" in decoded or any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded):
        return "/"
    return value


def get_or_404(sql, *args):
    row = db.q1(sql, *args)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def tz_now():
    return datetime.now(ZoneInfo(db.setting("display_timezone")))


def traffic_between(start_utc, end_utc, device_id=None):
    sql = ("SELECT COALESCE(SUM(bytes_received),0) rx, COALESCE(SUM(bytes_sent),0) tx FROM traffic_stats "
           "WHERE hour >= ? AND hour < ?")
    args = [start_utc.strftime("%Y-%m-%dT%H"), end_utc.strftime("%Y-%m-%dT%H")]
    if device_id:
        sql += " AND device_id = ?"
        args.append(device_id)
    r = db.q1(sql, *args)
    return {"rx": r["rx"], "tx": r["tx"], "total": r["rx"] + r["tx"]}


def period_bounds(period):
    local = tz_now()
    day0 = local.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "today":
        start = day0
    elif period == "7d":
        start = day0 - timedelta(days=6)
    elif period == "30d":
        start = day0 - timedelta(days=29)
    elif period == "month":
        start = day0.replace(day=1)
    else:
        start = day0
    end = day0 + timedelta(days=1)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc), start, end


def device_rows(ev=None, live=None):
    """Joined device view used by several pages."""
    ev = ev or engine.evaluate()
    live = live if live is not None else {c["cn"]: c for c in monitor.live_clients()["clients"]}
    rows = []
    for e in ev:
        d = e["device"]
        rows.append({**e, "d": d, "m": e["member"], "p": e["policy"], "online": d["common_name"] in live,
                     "live": live.get(d["common_name"])})
    return rows


# ================================================================ auth

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/"):
    tok = secrets.token_urlsafe(24)
    resp = templates.TemplateResponse(request, "login.html", {"login_csrf": tok, "next": safe_next(next), "error": None,
                                                              "fake": config.FAKE})
    resp.set_cookie(config.LOGIN_CSRF_COOKIE, tok, httponly=True, secure=config.SECURE_COOKIES,
                    samesite="strict", max_age=900, path="/")
    return resp


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    ip = client_ip(request)
    username = (form.get("username") or "").strip()[:64]
    password = form.get("password") or ""
    nxt = safe_next(form.get("next") or "/")

    def fail(msg, code=400):
        tok = secrets.token_urlsafe(24)
        r = templates.TemplateResponse(request, "login.html", {"login_csrf": tok, "next": nxt, "error": msg,
                                                               "fake": config.FAKE}, status_code=code)
        r.set_cookie(config.LOGIN_CSRF_COOKIE, tok, httponly=True, secure=config.SECURE_COOKIES,
                     samesite="strict", max_age=900, path="/")
        return r

    if not security.csrf_ok(request.cookies.get(config.LOGIN_CSRF_COOKIE), form.get("login_csrf")):
        return fail("Your login form expired. Please try again.")
    if security.is_locked_out(username, ip):
        audit.log(username or "?", "admin.login_locked", ip=ip)
        return fail(f"Too many failed attempts. Try again in {security.LOCKOUT_MINUTES} minutes.", 429)
    admin = security.authenticate(username, password, ip)
    if not admin:
        audit.log(username or "?", "admin.login_failed", ip=ip)
        return fail("Incorrect username or password.", 401)
    token = security.create_session(admin["id"], ip, request.headers.get("user-agent"))
    audit.log(admin["username"], "admin.login", ip=ip)
    resp = RedirectResponse(nxt, status_code=303)
    resp.set_cookie(config.SESSION_COOKIE, token, httponly=True, secure=config.SECURE_COOKIES,
                    samesite="strict", path="/")
    resp.delete_cookie(config.LOGIN_CSRF_COOKIE, path="/")
    return resp


@app.post("/logout")
def logout(ctx: Ctx = AdminPost):
    security.destroy_session(ctx.token)
    audit.log(ctx.admin, "admin.logout", ip=ctx.ip)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(config.SESSION_COOKIE, path="/")
    return resp


# ================================================================ dashboard

@app.get("/", response_class=HTMLResponse)
def dashboard(ctx: Ctx = Admin):
    rows = device_rows()
    snap = sysinfo.snapshot()
    s_today, e_today, *_ = period_bounds("today")
    s_month, e_month, *_ = period_bounds("month")
    counts = {
        "online": sum(1 for r in rows if r["online"]),
        "registered": sum(1 for r in rows if r["status"] != "revoked"),
        "disabled": sum(1 for r in rows if r["status"] in ("disabled", "owner-disabled", "expired")),
        "revoked": sum(1 for r in rows if r["status"] == "revoked"),
        "no_internet": sum(1 for r in rows if r["active"] and not r["internet"]),
        "members": db.q1("SELECT COUNT(*) n FROM family_members")["n"],
    }
    recent = db.q("SELECT s.*, d.display_name, d.id did, m.name owner FROM connection_sessions s "
                  "LEFT JOIN devices d ON d.id = s.device_id LEFT JOIN family_members m ON m.id = d.family_member_id "
                  "ORDER BY s.connected_at DESC LIMIT 8")
    actions = db.q("SELECT * FROM audit_logs WHERE actor != 'system' ORDER BY id DESC LIMIT 8")
    return render(ctx, "dashboard.html", "dashboard", snap=snap, counts=counts, rows=rows,
                  today=traffic_between(s_today, e_today), month=traffic_between(s_month, e_month),
                  recent=recent, actions=actions,
                  live_error=monitor.live_clients().get("error"))


# ================================================================ family members

def policies_by_kind():
    return [engine.policy_dict(p) for p in db.q("SELECT * FROM policies ORDER BY kind, builtin DESC, name")]


@app.get("/members", response_class=HTMLResponse)
def members(ctx: Ctx = Admin):
    rows = device_rows()
    ms = []
    for m in db.q("SELECT m.*, p.name policy_name FROM family_members m JOIN policies p ON p.id = m.policy_id "
                  "ORDER BY CASE m.type WHEN 'ADULT' THEN 0 WHEN 'CHILD' THEN 1 ELSE 2 END, m.name"):
        mine = [r for r in rows if r["m"]["id"] == m["id"]]
        st = engine.schedule_state(m, engine.policy_dict(db.q1("SELECT * FROM policies WHERE id=?", m["policy_id"])))
        ms.append({"m": m, "devices": [r for r in mine if r["status"] != "revoked"],
                   "online": sum(1 for r in mine if r["online"]), "sched": st})
    return render(ctx, "members.html", "members", members=ms, policies=policies_by_kind())


@app.post("/members")
def member_create(ctx: Ctx = AdminPost):
    name, mtype = ctx.f("name")[:60], ctx.f("type")
    if not name or mtype not in ("ADULT", "CHILD", "GUEST"):
        return redirect("/members", ctx, "Name and type are required.", "error")
    policy_id = _int(ctx.f("policy_id"))
    if not policy_id:
        default = {"ADULT": "Adult — unrestricted", "CHILD": "Child — standard", "GUEST": "Guest"}[mtype]
        policy_id = db.q1("SELECT id FROM policies WHERE name = ?", default)["id"]
    if db.q1("SELECT 1 FROM family_members WHERE name = ? COLLATE NOCASE", name):
        return redirect("/members", ctx, f"A family member called “{name}” already exists.", "error")
    cur = db.ex("INSERT INTO family_members(name, type, policy_id, notes, created_at) VALUES (?,?,?,?,?)",
                name, mtype, policy_id, ctx.f("notes")[:500], db.now_iso())
    audit.log(ctx.admin, "member.created", "member", cur.lastrowid, name, ctx.ip, type=mtype, policy_id=policy_id)
    engine.apply()
    return redirect(f"/members/{cur.lastrowid}", ctx, f"{name} added. Now add their devices.")


@app.get("/members/{mid}", response_class=HTMLResponse)
def member_detail(mid: int, ctx: Ctx = Admin):
    m = get_or_404("SELECT * FROM family_members WHERE id = ?", mid)
    pol = engine.policy_dict(db.q1("SELECT * FROM policies WHERE id = ?", m["policy_id"]))
    rows = [r for r in device_rows() if r["m"]["id"] == mid]
    s_month, e_month, *_ = period_bounds("month")
    usage = {r["d"]["id"]: traffic_between(s_month, e_month, r["d"]["id"]) for r in rows}
    return render(ctx, "member_detail.html", "members", m=m, policy=pol, rows=rows, usage=usage,
                  sched=engine.schedule_state(m, pol), policies=policies_by_kind())


@app.post("/members/{mid}")
def member_update(mid: int, ctx: Ctx = AdminPost):
    m = get_or_404("SELECT * FROM family_members WHERE id = ?", mid)
    name = ctx.f("name")[:60] or m["name"]
    mtype = ctx.f("type") if ctx.f("type") in ("ADULT", "CHILD", "GUEST") else m["type"]
    policy_id = _int(ctx.f("policy_id"), m["policy_id"])
    if not db.q1("SELECT 1 FROM policies WHERE id = ?", policy_id):
        return redirect(f"/members/{mid}", ctx, "Unknown policy.", "error")
    if db.q1("SELECT 1 FROM family_members WHERE name = ? COLLATE NOCASE AND id != ?", name, mid):
        return redirect(f"/members/{mid}", ctx, "Another member already has that name.", "error")
    db.ex("UPDATE family_members SET name=?, type=?, policy_id=?, notes=? WHERE id=?",
          name, mtype, policy_id, ctx.f("notes")[:500], mid)
    if mtype != "ADULT":
        db.ex("UPDATE devices SET panel_access = 0 WHERE family_member_id = ?", mid)
    changes = {k: v for k, v in (("name", name), ("type", mtype), ("policy_id", policy_id)) if m[k] != v}
    if "policy_id" in changes:
        audit.log(ctx.admin, "policy.assigned", "member", mid, name, ctx.ip, policy_id=policy_id,
                  previous=m["policy_id"])
    audit.log(ctx.admin, "member.updated", "member", mid, name, ctx.ip, **changes)
    engine.apply()
    return redirect(f"/members/{mid}", ctx, "Saved.")


@app.post("/members/{mid}/enabled")
def member_toggle(mid: int, ctx: Ctx = AdminPost):
    m = get_or_404("SELECT * FROM family_members WHERE id = ?", mid)
    new = 0 if m["enabled"] else 1
    db.ex("UPDATE family_members SET enabled = ? WHERE id = ?", new, mid)
    audit.log(ctx.admin, "member.enabled" if new else "member.disabled", "member", mid, m["name"], ctx.ip)
    engine.apply()
    return redirect(f"/members/{mid}", ctx,
                    f"{m['name']} {'enabled' if new else 'disabled — all their devices are blocked'}.")


# ================================================================ devices

@app.get("/devices", response_class=HTMLResponse)
def devices(ctx: Ctx = Admin, show: str = "current"):
    rows = device_rows()
    if show == "current":
        rows = [r for r in rows if r["status"] != "revoked"]
    elif show == "revoked":
        rows = [r for r in rows if r["status"] == "revoked"]
    rows.sort(key=lambda r: (not r["online"], r["m"]["name"].lower(), r["d"]["display_name"].lower()))
    return render(ctx, "devices.html", "devices", rows=rows, show=show)


@app.get("/devices/new", response_class=HTMLResponse)
def device_new(ctx: Ctx = Admin, member: int = 0):
    ms = db.q("SELECT m.*, p.name policy_name FROM family_members m JOIN policies p ON p.id=m.policy_id "
              "WHERE m.enabled = 1 ORDER BY m.name")
    return render(ctx, "device_new.html", "devices", members=ms, member_id=member, policies=policies_by_kind(),
                  guest_days=db.setting("default_guest_days"))


@app.post("/devices")
def device_create(ctx: Ctx = AdminPost):
    expires_at = None
    if ctx.f("expires_on"):
        try:
            tz = ZoneInfo(db.setting("display_timezone"))
            day = datetime.strptime(ctx.f("expires_on"), "%Y-%m-%d").replace(hour=23, minute=59, tzinfo=tz)
            if day <= datetime.now(tz):
                raise ValueError
            expires_at = day.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            return redirect("/devices/new", ctx, "Expiry must be a future date.", "error")
    try:
        did = engine.create_device(
            member_id=_int(ctx.f("member_id")), display_name=ctx.f("display_name"),
            policy_id=_int(ctx.f("policy_id")), expires_at=expires_at, panel_access=ctx.checked("panel_access"),
            actor=ctx.admin, ip=ctx.ip, cn=ctx.f("common_name") or None, notes=ctx.f("notes")[:500])
    except OPERATIONAL_ERRORS as e:
        return redirect(f"/devices/new?member={ctx.f('member_id')}", ctx, f"Could not create device: {e}", "error")
    return redirect(f"/devices/{did}?created=1", ctx, "VPN profile created. Download it below and install it on this device only.")


@app.get("/devices/{did}", response_class=HTMLResponse)
def device_detail(did: int, ctx: Ctx = Admin, created: int = 0):
    get_or_404("SELECT id FROM devices WHERE id = ?", did)
    row = next(r for r in device_rows() if r["d"]["id"] == did)
    d = row["d"]
    sessions = db.q("SELECT * FROM connection_sessions WHERE device_id = ? ORDER BY connected_at DESC LIMIT 15", did)
    certs = db.q("SELECT * FROM vpn_certificates WHERE device_id = ? ORDER BY issued_at DESC", did)
    since = (datetime.now(timezone.utc) - timedelta(days=13)).strftime("%Y-%m-%dT00")
    daily = _daily_series(did, 14)
    queries, q_err = [], None
    if not d["revoked"]:
        try:
            queries = adguard.querylog(client=d["vpn_ipv4"], limit=40)
        except adguard.AdGuardError as e:
            q_err = str(e)
    s_month, e_month, *_ = period_bounds("month")
    return render(ctx, "device_detail.html", "devices", r=row, d=d, sessions=sessions, certs=certs, daily=daily,
                  queries=queries, q_err=q_err, created=created, policies=policies_by_kind(),
                  members=db.q("SELECT id, name, type FROM family_members ORDER BY name"),
                  month=traffic_between(s_month, e_month, did), since=since,
                  profile_ready=bool(d["profile_enc"]) and parse_iso(d["profile_available_until"]) and
                  parse_iso(d["profile_available_until"]) > datetime.now(timezone.utc))


def _daily_series(device_id, days):
    day0 = tz_now().replace(hour=0, minute=0, second=0, microsecond=0)
    out = []
    for i in range(days - 1, -1, -1):
        s = day0 - timedelta(days=i)
        t = traffic_between(s.astimezone(timezone.utc), (s + timedelta(days=1)).astimezone(timezone.utc), device_id)
        out.append({"label": s.strftime("%a %d"), "day": s.strftime("%Y-%m-%d"), **t})
    return out


@app.post("/devices/{did}/update")
def device_update(did: int, ctx: Ctx = AdminPost):
    d = get_or_404("SELECT * FROM devices WHERE id = ?", did)
    if d["revoked"]:
        return redirect(f"/devices/{did}", ctx, "Revoked devices cannot be changed.", "error")
    member_id = _int(ctx.f("member_id"), d["family_member_id"])
    member = db.q1("SELECT * FROM family_members WHERE id = ?", member_id)
    if not member:
        return redirect(f"/devices/{did}", ctx, "Unknown owner.", "error")
    policy_id = _int(ctx.f("policy_id")) or None
    name = ctx.f("display_name")[:80] or d["display_name"]
    panel = ctx.checked("panel_access") if member["type"] == "ADULT" else 0
    expires_at = d["expires_at"]
    if "expires_on" in ctx.form:
        if ctx.f("expires_on"):
            try:
                tz = ZoneInfo(db.setting("display_timezone"))
                day = datetime.strptime(ctx.f("expires_on"), "%Y-%m-%d").replace(hour=23, minute=59, tzinfo=tz)
                expires_at = day.astimezone(timezone.utc).isoformat(timespec="seconds")
            except ValueError:
                return redirect(f"/devices/{did}", ctx, "Invalid expiry date.", "error")
        else:
            expires_at = None
    db.ex("UPDATE devices SET display_name=?, family_member_id=?, policy_id=?, panel_access=?, expires_at=?, notes=? "
          "WHERE id=?", name, member_id, policy_id, panel, expires_at, ctx.f("notes")[:500], did)
    changes = {}
    for k, v in (("display_name", name), ("family_member_id", member_id), ("policy_id", policy_id),
                 ("panel_access", panel), ("expires_at", expires_at)):
        if d[k] != v:
            changes[k] = v
    if "policy_id" in changes:
        audit.log(ctx.admin, "policy.assigned", "device", did, d["common_name"], ctx.ip, policy_id=policy_id)
    if changes:
        audit.log(ctx.admin, "device.updated", "device", did, d["common_name"], ctx.ip, **changes)
    pushed, errors = engine.apply()
    if errors:
        return redirect(f"/devices/{did}", ctx, "Saved, but some settings could not be applied: " + "; ".join(errors), "error")
    return redirect(f"/devices/{did}", ctx, "Device updated.")


@app.post("/devices/{did}/internet")
def device_internet(did: int, ctx: Ctx = AdminPost):
    d = get_or_404("SELECT * FROM devices WHERE id = ?", did)
    new = 0 if d["internet_enabled"] else 1
    db.ex("UPDATE devices SET internet_enabled = ? WHERE id = ?", new, did)
    audit.log(ctx.admin, "device.internet_enabled" if new else "device.internet_disabled", "device", did,
              d["common_name"], ctx.ip)
    engine.apply()
    return redirect(back(ctx, f"/devices/{did}"), ctx,
                    "Internet enabled." if new else "Internet disabled — the device stays on the VPN (DNS/filter only).")


@app.post("/devices/{did}/enable")
def device_enable(did: int, ctx: Ctx = AdminPost):
    try:
        engine.set_device_enabled(did, True, ctx.admin, ctx.ip)
    except OPERATIONAL_ERRORS as e:
        return redirect(back(ctx), ctx, str(e), "error")
    return redirect(back(ctx, f"/devices/{did}"), ctx, "Device re-enabled. It can connect again.")


@app.post("/devices/{did}/disable")
def device_disable(did: int, ctx: Ctx = AdminPost):
    try:
        engine.set_device_enabled(did, False, ctx.admin, ctx.ip)
    except OPERATIONAL_ERRORS as e:
        return redirect(back(ctx), ctx, str(e), "error")
    return redirect(back(ctx, f"/devices/{did}"), ctx, "Device disabled and disconnected. Its certificate stays valid; re-enable any time.")


@app.post("/devices/{did}/revoke")
def device_revoke(did: int, ctx: Ctx = AdminPost):
    d = get_or_404("SELECT * FROM devices WHERE id = ?", did)
    if ctx.f("confirm_cn") != d["common_name"]:
        return redirect(f"/devices/{did}", ctx, "Type the device's common name exactly to confirm revocation.", "error")
    reason = ctx.f("reason") if ctx.f("reason") in ("cessationOfOperation", "keyCompromise", "superseded",
                                                     "affiliationChanged", "unspecified") else "cessationOfOperation"
    try:
        engine.revoke_device(did, reason, ctx.admin, ctx.ip)
    except OPERATIONAL_ERRORS as e:
        return redirect(f"/devices/{did}", ctx, f"Revocation failed: {e}", "error")
    return redirect(f"/devices/{did}", ctx, "Certificate revoked and added to the CRL. The device can no longer connect.")


@app.post("/devices/{did}/reissue")
def device_reissue(did: int, ctx: Ctx = AdminPost):
    try:
        engine.reissue_device(did, ctx.admin, ctx.ip)
    except OPERATIONAL_ERRORS as e:
        return redirect(f"/devices/{did}", ctx, f"Could not regenerate: {e}", "error")
    return redirect(f"/devices/{did}?created=1", ctx, "New profile generated. The old one no longer works — install the new file on the device.")


@app.post("/devices/{did}/disconnect")
def device_disconnect(did: int, ctx: Ctx = AdminPost):
    d = get_or_404("SELECT * FROM devices WHERE id = ?", did)
    n = 0
    for c in monitor.live_clients()["clients"]:
        if c["cn"] == d["common_name"]:
            helper.mgmt_kill(c["client_id"])
            n += 1
    audit.log(ctx.admin, "device.disconnected", "device", did, d["common_name"], ctx.ip, sessions=n)
    return redirect(back(ctx, f"/devices/{did}"), ctx,
                    f"Disconnected {n} session(s). The device may reconnect unless disabled." if n else "Device was not connected.")


@app.post("/devices/{did}/profile")
def device_profile(did: int, ctx: Ctx = AdminPost):
    d = get_or_404("SELECT * FROM devices WHERE id = ?", did)
    until = parse_iso(d["profile_available_until"])
    if d["revoked"] or not d["profile_enc"] or not until or until < datetime.now(timezone.utc):
        return redirect(f"/devices/{did}", ctx, "The download window has closed. Use “Regenerate profile” to issue a new one.", "error")
    content = vault.unseal(d["profile_enc"])
    db.ex("UPDATE devices SET profile_downloads = profile_downloads + 1 WHERE id = ?", did)
    audit.log(ctx.admin, "profile.downloaded", "device", did, d["common_name"], ctx.ip,
              serial=d["certificate_serial"])
    return Response(content, media_type="application/x-openvpn-profile", headers={
        "Content-Disposition": f'attachment; filename="{d["common_name"]}.ovpn"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


# ================================================================ profiles

@app.get("/profiles", response_class=HTMLResponse)
def profiles(ctx: Ctx = Admin):
    rows = [r for r in device_rows() if r["status"] != "revoked"]
    now = datetime.now(timezone.utc)
    for r in rows:
        u = parse_iso(r["d"]["profile_available_until"])
        r["download_open"] = bool(r["d"]["profile_enc"]) and u and u > now
        na = parse_iso(r["d"]["certificate_not_after"])
        r["cert_days_left"] = (na - now).days if na else None
    rows.sort(key=lambda r: (not r["download_open"], r["m"]["name"].lower()))
    return render(ctx, "profiles.html", "profiles", rows=rows, hours=db.setting("profile_download_hours"),
                  endpoint=f"{config.VPN_PUBLIC_HOST}:{config.VPN_PUBLIC_PORT}/{config.VPN_PROTOCOL}")


# ================================================================ connections

@app.get("/connections", response_class=HTMLResponse)
def connections(ctx: Ctx = Admin):
    live = monitor.live_clients()
    devs = {r["common_name"]: r for r in db.q("SELECT d.*, m.name owner, m.type mtype FROM devices d "
                                                "JOIN family_members m ON m.id = d.family_member_id")}
    now = datetime.now(timezone.utc).timestamp()
    rows = [{**c, "dev": devs.get(c["cn"]), "duration": now - c["connected_since"]} for c in live["clients"]]
    rows.sort(key=lambda r: r["connected_since"])
    return render(ctx, "connections.html", "connections", rows=rows, ts=live["ts"], error=live.get("error"))


@app.get("/connections.json")
def connections_json(ctx: Ctx = Admin):
    live = monitor.live_clients()
    return {"ts": live["ts"], "count": len(live["clients"])}


@app.post("/connections/{client_id}/kill")
def connection_kill(client_id: int, ctx: Ctx = AdminPost):
    cn = next((c["cn"] for c in monitor.live_clients()["clients"] if c["client_id"] == client_id), None)
    if cn is None:
        return redirect("/connections", ctx, "That session is no longer connected.", "error")
    try:
        helper.mgmt_kill(client_id)
    except OPERATIONAL_ERRORS as e:
        return redirect("/connections", ctx, f"Disconnect failed: {e}", "error")
    d = db.q1("SELECT id FROM devices WHERE common_name = ?", cn)
    audit.log(ctx.admin, "device.disconnected", "device", d["id"] if d else None, cn, ctx.ip, client_id=client_id)
    return redirect("/connections", ctx, f"{cn} disconnected.")


# ================================================================ policies

@app.get("/policies", response_class=HTMLResponse)
def policies(ctx: Ctx = Admin):
    pols = policies_by_kind()
    usage = {}
    for p in pols:
        usage[p["id"]] = {
            "members": db.q("SELECT id, name FROM family_members WHERE policy_id = ?", p["id"]),
            "devices": db.q1("SELECT COUNT(*) n FROM devices WHERE policy_id = ? AND revoked = 0", p["id"])["n"],
        }
    return render(ctx, "policies.html", "policies", pols=pols, usage=usage, groups=engine.SERVICE_GROUPS)


@app.get("/policies/{pid}", response_class=HTMLResponse)
def policy_edit(pid: int, ctx: Ctx = Admin):
    p = engine.policy_dict(get_or_404("SELECT * FROM policies WHERE id = ?", pid))
    try:
        catalog = adguard.services_catalog()
    except adguard.AdGuardError:
        catalog = []
    return render(ctx, "policy_edit.html", "policies", p=p, groups=engine.SERVICE_GROUPS, catalog=catalog,
                  categories=engine.CATEGORY_LISTS)


@app.post("/policies")
def policy_create(ctx: Ctx = AdminPost):
    src = engine.policy_dict(get_or_404("SELECT * FROM policies WHERE id = ?", _int(ctx.f("clone_from"))))
    name = ctx.f("name")[:60] or f"{src['name']} (copy)"
    if db.q1("SELECT 1 FROM policies WHERE name = ?", name):
        return redirect("/policies", ctx, "A policy with that name exists.", "error")
    cols = ["kind", "description", "block_malware", "block_adult", "block_gambling", "block_tracking",
            "block_encrypted_dns", "safesearch", "youtube_restricted", "enforce_schedule", "custom_block",
            "custom_allow"]
    ts = db.now_iso()
    cur = db.ex(f"INSERT INTO policies(name, builtin, service_rules, extra_services, created_at, updated_at, {','.join(cols)}) "  # noqa: S608 - fixed column names/fragments only; values are bound parameters
                f"VALUES (?,0,?,?,?,?,{','.join('?' * len(cols))})", name, json.dumps(src["service_rules"]),
                json.dumps(src["extra_services"]), ts, ts, *[src[c] for c in cols])
    audit.log(ctx.admin, "policy.created", "policy", cur.lastrowid, name, ctx.ip, cloned_from=src["name"])
    return redirect(f"/policies/{cur.lastrowid}", ctx, f"Policy “{name}” created from “{src['name']}”.")


@app.post("/policies/{pid}")
def policy_save(pid: int, ctx: Ctx = AdminPost):
    old = engine.policy_dict(get_or_404("SELECT * FROM policies WHERE id = ?", pid))
    rules = {}
    for g in engine.SERVICE_GROUPS:
        mode = ctx.f(f"svc_{g}") or "allow"
        if mode not in ("allow", "block", "window"):
            mode = "allow"
        rule = {"mode": mode}
        if mode == "window":
            try:
                rule["start"], rule["end"] = ctx.f(f"svc_{g}_start"), ctx.f(f"svc_{g}_end")
                schedule.minutes(rule["start"]), schedule.minutes(rule["end"])
            except ValueError:
                return redirect(f"/policies/{pid}", ctx, f"Invalid time window for {engine.SERVICE_GROUPS[g]}.", "error")
        if mode != "allow":
            rules[g] = rule
    extra = sorted(set(ctx.flist("extra_services")))
    block_doms, bad1 = engine.parse_domains(ctx.f("custom_block"))
    allow_doms, bad2 = engine.parse_domains(ctx.f("custom_allow"))
    if bad1 or bad2:
        return redirect(f"/policies/{pid}", ctx, "Not valid domains: " + ", ".join((bad1 + bad2)[:5]), "error")
    name = ctx.f("name")[:60] or old["name"]
    if db.q1("SELECT 1 FROM policies WHERE name = ? AND id != ?", name, pid):
        return redirect(f"/policies/{pid}", ctx, "Another policy has that name.", "error")
    kind = ctx.f("kind") if ctx.f("kind") in ("ADULT", "CHILD", "GUEST") else old["kind"]
    new = dict(name=name, kind=kind, description=ctx.f("description")[:300],
               block_malware=ctx.checked("block_malware"), block_adult=ctx.checked("block_adult"),
               block_gambling=ctx.checked("block_gambling"), block_tracking=ctx.checked("block_tracking"),
               block_encrypted_dns=ctx.checked("block_encrypted_dns"), safesearch=ctx.checked("safesearch"),
               youtube_restricted=ctx.checked("youtube_restricted"), enforce_schedule=ctx.checked("enforce_schedule"),
               custom_block="\n".join(block_doms), custom_allow="\n".join(allow_doms))
    db.ex(f"UPDATE policies SET {', '.join(k + '=?' for k in new)}, service_rules=?, extra_services=?, updated_at=? "  # noqa: S608 - fixed column names/fragments only; values are bound parameters
          "WHERE id=?", *new.values(), json.dumps(rules), json.dumps(extra), db.now_iso(), pid)
    diff = {k: v for k, v in new.items() if old.get(k) != v}
    if old["service_rules"] != rules:
        diff["service_rules"] = rules
    if old["extra_services"] != extra:
        diff["extra_services"] = extra
    audit.log(ctx.admin, "policy.changed", "policy", pid, name, ctx.ip, **diff)
    pushed, errors = engine.apply()
    if errors:
        return redirect(f"/policies/{pid}", ctx, "Saved, but applying failed: " + "; ".join(errors), "error")
    return redirect(f"/policies/{pid}", ctx, "Policy saved and applied to all affected devices.")


@app.post("/policies/{pid}/delete")
def policy_delete(pid: int, ctx: Ctx = AdminPost):
    p = get_or_404("SELECT * FROM policies WHERE id = ?", pid)
    if p["builtin"]:
        return redirect(f"/policies/{pid}", ctx, "Built-in templates cannot be deleted.", "error")
    if db.q1("SELECT 1 FROM family_members WHERE policy_id = ?", pid) or db.q1("SELECT 1 FROM devices WHERE policy_id = ?", pid):
        return redirect(f"/policies/{pid}", ctx, "Policy is in use. Reassign members/devices first.", "error")
    db.ex("DELETE FROM policies WHERE id = ?", pid)
    audit.log(ctx.admin, "policy.deleted", "policy", pid, p["name"], ctx.ip)
    return redirect("/policies", ctx, "Policy deleted.")


# ================================================================ DNS filtering

@app.get("/dns", response_class=HTMLResponse)
def dns(ctx: Ctx = Admin, device: int = 0, q: str = "", blocked: int = 0):
    err = None
    fstatus, stats, ag_status, log_rows = {}, {}, {}, []
    rows = [r for r in device_rows() if r["status"] != "revoked"]
    sel = next((r for r in rows if r["d"]["id"] == device), None)
    try:
        ag_status = adguard.status()
        fstatus = adguard.filtering_status()
        stats = adguard.stats()
        log_rows = adguard.querylog(search=q.strip()[:100], client=sel["d"]["vpn_ipv4"] if sel else "",
                                    limit=150, response_status="blocked" if blocked else "all")
    except adguard.AdGuardError as e:
        err = str(e)
    by_ip = {r["d"]["vpn_ipv4"]: r for r in rows}
    want = engine.desired_state()["lists"]
    return render(ctx, "dns.html", "dns", err=err, fstatus=fstatus, stats=stats, ag=ag_status, log=log_rows,
                  by_ip=by_ip, rows=rows, sel=sel, q=q, blocked=blocked, lists=want, cats=engine.CATEGORY_LISTS,
                  global_rules=db.setting("global_custom_rules"))


@app.post("/dns/rules")
def dns_rules(ctx: Ctx = AdminPost):
    doms, bad = engine.parse_domains(ctx.f("global_custom_rules"))
    if bad:
        return redirect("/dns", ctx, "Not valid domains: " + ", ".join(bad[:5]), "error")
    db.set_setting("global_custom_rules", "\n".join(doms))
    audit.log(ctx.admin, "dns.global_rules_changed", ip=ctx.ip, count=len(doms))
    engine.apply()
    return redirect("/dns", ctx, f"Global blocklist saved ({len(doms)} domains).")


@app.post("/dns/check")
def dns_check(ctx: Ctx = AdminPost):
    domain = ctx.f("domain").lower()[:253]
    did = _int(ctx.f("device_id"))
    d = db.q1("SELECT * FROM devices WHERE id = ?", did) if did else None
    try:
        res = adguard.check_host(domain, d["vpn_ipv4"] if d else "")
    except adguard.AdGuardError as e:
        return redirect("/dns", ctx, f"Check failed: {e}", "error")
    reason = res.get("reason", "?")
    blocked = reason in ("FilteredBlackList", "FilteredSafeBrowsing", "FilteredParental",
                         "FilteredBlockedService", "FilteredInvalid")
    who = f" for {d['display_name']}" if d else " (global rules)"
    rule = (res.get("rules") or [{}])[0].get("text", "") or res.get("service_name", "")
    msg = f"{domain}{who}: {'BLOCKED' if blocked else 'allowed'} — {reason}" + (f" ({rule})" if rule else "")
    return redirect(f"/dns?device={did or 0}", ctx, msg, "error" if blocked else "ok")


# ================================================================ schedules

@app.get("/schedules", response_class=HTMLResponse)
def schedules(ctx: Ctx = Admin):
    items = []
    for m in db.q("SELECT m.*, p.name policy_name FROM family_members m JOIN policies p ON p.id = m.policy_id "
                  "ORDER BY CASE m.type WHEN 'CHILD' THEN 0 WHEN 'GUEST' THEN 1 ELSE 2 END, m.name"):
        pol = engine.policy_dict(db.q1("SELECT * FROM policies WHERE id = ?", m["policy_id"]))
        row = db.q1("SELECT * FROM access_schedules WHERE family_member_id = ?", m["id"])
        items.append({"m": m, "pol": pol, "row": row, "st": engine.schedule_state(m, pol),
                      "windows": json.loads(row["windows"]) if row else [],
                      "devices": db.q1("SELECT COUNT(*) n FROM devices WHERE family_member_id=? AND revoked=0",
                                       m["id"])["n"]})
    return render(ctx, "schedules.html", "schedules", items=items, describe=schedule.describe,
                  days=schedule.DAY_NAMES, timezones=schedule.timezones())


@app.get("/schedules/{mid}", response_class=HTMLResponse)
def schedule_edit(mid: int, ctx: Ctx = Admin):
    m = get_or_404("SELECT * FROM family_members WHERE id = ?", mid)
    pol = engine.policy_dict(db.q1("SELECT * FROM policies WHERE id = ?", m["policy_id"]))
    row = db.q1("SELECT * FROM access_schedules WHERE family_member_id = ?", mid)
    windows = json.loads(row["windows"]) if row else schedule.DEFAULT_WINDOWS
    overrides = db.q("SELECT * FROM schedule_overrides WHERE family_member_id = ? ORDER BY id DESC LIMIT 10", mid)
    return render(ctx, "schedule_edit.html", "schedules", m=m, pol=pol, row=row, windows=windows,
                  st=engine.schedule_state(m, pol), overrides=overrides, days=schedule.DAY_NAMES,
                  timezones=schedule.timezones(), default_tz=db.setting("display_timezone"),
                  describe=schedule.describe, now=datetime.now(timezone.utc).isoformat())


@app.post("/schedules/{mid}")
def schedule_save(mid: int, ctx: Ctx = AdminPost):
    m = get_or_404("SELECT * FROM family_members WHERE id = ?", mid)
    tz = ctx.f("timezone")
    if not schedule.valid_tz(tz):
        return redirect(f"/schedules/{mid}", ctx, "Unknown timezone.", "error")
    windows = []
    for i in range(12):
        if not ctx.f(f"w{i}_start"):
            continue
        days = sorted({int(x) for x in ctx.flist(f"w{i}_days") if x.isdigit() and 0 <= int(x) <= 6})
        start, end = ctx.f(f"w{i}_start"), ctx.f(f"w{i}_end")
        try:
            schedule.minutes(start), schedule.minutes(end)
        except ValueError:
            return redirect(f"/schedules/{mid}", ctx, f"Invalid time in row {i + 1}.", "error")
        if days:
            windows.append({"days": days, "start": start, "end": end})
    enabled = ctx.checked("enabled")
    if enabled and not windows:
        return redirect(f"/schedules/{mid}", ctx, "Add at least one allowed time window (or disable the schedule).", "error")
    db.ex("INSERT INTO access_schedules(family_member_id, enabled, timezone, windows, updated_at) VALUES (?,?,?,?,?) "
          "ON CONFLICT(family_member_id) DO UPDATE SET enabled=excluded.enabled, timezone=excluded.timezone, "
          "windows=excluded.windows, updated_at=excluded.updated_at", mid, enabled, tz, json.dumps(windows), db.now_iso())
    audit.log(ctx.admin, "schedule.changed", "member", mid, m["name"], ctx.ip, enabled=enabled, timezone=tz,
              windows=schedule.describe(windows))
    engine.apply()
    return redirect(f"/schedules/{mid}", ctx, "Schedule saved and applied.")


@app.post("/schedules/{mid}/override")
def schedule_override(mid: int, ctx: Ctx = AdminPost):
    m = get_or_404("SELECT * FROM family_members WHERE id = ?", mid)
    kind = ctx.f("kind") if ctx.f("kind") in ("allow", "block") else "allow"
    minutes_ = _int(ctx.f("minutes"), 60)
    if not 5 <= minutes_ <= 24 * 60:
        return redirect(back(ctx), ctx, "Duration must be between 5 minutes and 24 hours.", "error")
    now = db.now_utc()
    db.ex("UPDATE schedule_overrides SET cancelled_at = ? WHERE family_member_id = ? AND cancelled_at IS NULL "
          "AND expires_at > ?", now.isoformat(timespec="seconds"), mid, now.isoformat(timespec="seconds"))
    exp = (now + timedelta(minutes=minutes_)).isoformat(timespec="seconds")
    db.ex("INSERT INTO schedule_overrides(family_member_id, kind, created_at, expires_at, created_by, note) "
          "VALUES (?,?,?,?,?,?)", mid, kind, now.isoformat(timespec="seconds"), exp, ctx.admin, ctx.f("note")[:200])
    audit.log(ctx.admin, "override.created", "member", mid, m["name"], ctx.ip, kind=kind, minutes=minutes_, expires_at=exp)
    engine.apply()
    verb = f"gets {minutes_} extra minutes of internet" if kind == "allow" else f"is paused for {minutes_} minutes"
    return redirect(back(ctx, "/schedules"), ctx, f"{m['name']} {verb}.")


@app.post("/schedules/{mid}/override/cancel")
def schedule_override_cancel(mid: int, ctx: Ctx = AdminPost):
    m = get_or_404("SELECT * FROM family_members WHERE id = ?", mid)
    db.ex("UPDATE schedule_overrides SET cancelled_at = ? WHERE family_member_id = ? AND cancelled_at IS NULL",
          db.now_iso(), mid)
    audit.log(ctx.admin, "override.cancelled", "member", mid, m["name"], ctx.ip)
    engine.apply()
    return redirect(back(ctx, "/schedules"), ctx, "Override cancelled — the normal schedule applies again.")


# ================================================================ traffic

@app.get("/traffic", response_class=HTMLResponse)
def traffic(ctx: Ctx = Admin, period: str = "7d"):
    if period not in ("today", "7d", "30d", "month"):
        period = "7d"
    s_utc, e_utc, s_loc, e_loc = period_bounds(period)
    per = db.q("SELECT d.id, d.display_name, d.common_name, d.revoked, m.name owner, m.id mid, "
               "COALESCE(SUM(t.bytes_received),0) rx, COALESCE(SUM(t.bytes_sent),0) tx "
               "FROM devices d JOIN family_members m ON m.id = d.family_member_id "
               "LEFT JOIN traffic_stats t ON t.device_id = d.id AND t.hour >= ? AND t.hour < ? "
               "GROUP BY d.id ORDER BY (rx + tx) DESC", s_utc.strftime("%Y-%m-%dT%H"), e_utc.strftime("%Y-%m-%dT%H"))
    owners = {}
    for r in per:
        o = owners.setdefault(r["mid"], {"name": r["owner"], "rx": 0, "tx": 0})
        o["rx"] += r["rx"]
        o["tx"] += r["tx"]
    days = max(1, (e_loc - s_loc).days)
    series = []
    for i in range(days):
        a = s_loc + timedelta(days=i)
        b = a + timedelta(days=1)
        t = traffic_between(a.astimezone(timezone.utc), b.astimezone(timezone.utc))
        series.append({"label": a.strftime("%a %d" if days <= 14 else "%d"), "day": a.strftime("%Y-%m-%d"), **t})
    if period == "today":
        series = []
        for h in range(24):
            a = s_loc + timedelta(hours=h)
            t = traffic_between(a.astimezone(timezone.utc), (a + timedelta(hours=1)).astimezone(timezone.utc))
            series.append({"label": f"{h:02d}", "day": a.strftime("%H:00"), **t})
    total = {"rx": sum(r["rx"] for r in per), "tx": sum(r["tx"] for r in per)}
    sessions = db.q("SELECT s.*, d.display_name, m.name owner FROM connection_sessions s "
                    "LEFT JOIN devices d ON d.id = s.device_id LEFT JOIN family_members m ON m.id = d.family_member_id "
                    "WHERE s.connected_at >= ? ORDER BY s.connected_at DESC LIMIT 50", s_utc.isoformat(timespec="seconds"))
    return render(ctx, "traffic.html", "traffic", per=per, owners=sorted(owners.values(), key=lambda o: -(o["rx"] + o["tx"])),
                  series=series, period=period, total=total, sessions=sessions, s_loc=s_loc, e_loc=e_loc)


# ================================================================ security / revocation

@app.get("/security", response_class=HTMLResponse)
def security_page(ctx: Ctx = Admin):
    err, pki = None, {"certs": [], "crl_next_update": "?", "ca_not_after": None}
    try:
        pki = helper.pki_list()
    except OPERATIONAL_ERRORS as e:
        err = str(e)
    managed = {r["common_name"]: r for r in db.q("SELECT d.*, m.name owner FROM devices d JOIN family_members m "
                                                 "ON m.id = d.family_member_id")}
    serial_map = {r["serial"]: r for r in db.q("SELECT * FROM vpn_certificates")}
    unmanaged = [c for c in pki["certs"] if c["cn"] not in managed and c["cn"] != "server" and c["status"] == "valid"]
    since = (db.now_utc() - timedelta(hours=24)).isoformat(timespec="seconds")
    fails = db.q("SELECT * FROM login_attempts WHERE success = 0 AND ts > ? ORDER BY id DESC LIMIT 20", since)
    sessions = db.q("SELECT s.*, a.username FROM sessions s JOIN admins a ON a.id = s.admin_id ORDER BY last_seen_at DESC")
    from .security import _sha
    crl_days = None
    try:
        crl_days = (datetime.strptime(pki["crl_next_update"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    - datetime.now(timezone.utc)).days
    except (ValueError, KeyError):
        pass
    return render(ctx, "security.html", "security", err=err, pki=pki, managed=managed, serial_map=serial_map,
                  unmanaged=unmanaged, fails=fails, sessions=sessions, my_sid=_sha(ctx.token), crl_days=crl_days,
                  members=db.q("SELECT id, name, type FROM family_members WHERE enabled = 1 ORDER BY name"))


@app.post("/security/adopt")
def security_adopt(ctx: Ctx = AdminPost):
    try:
        did = engine.adopt_certificate(ctx.f("cn"), _int(ctx.f("member_id")), ctx.f("display_name"),
                                       ctx.checked("panel_access"), ctx.admin, ctx.ip)
    except OPERATIONAL_ERRORS as e:
        return redirect("/security", ctx, f"Could not adopt: {e}", "error")
    return redirect(f"/devices/{did}", ctx, "Certificate adopted. This device is now managed by the panel.")


@app.post("/security/sessions/revoke-others")
def revoke_other_sessions(ctx: Ctx = AdminPost):
    security.destroy_all_sessions(ctx.admin_id, except_token=ctx.token)
    audit.log(ctx.admin, "admin.sessions_revoked", ip=ctx.ip)
    return redirect("/security", ctx, "All other admin sessions have been signed out.")


# ================================================================ health

@app.get("/health", response_class=HTMLResponse)
def health(ctx: Ctx = Admin):
    snap = sysinfo.snapshot()
    sysinfo._health["ts"] = 0  # always fresh on this page
    snap["health"] = sysinfo.health()
    ag, ag_err = {}, None
    try:
        ag = adguard.status()
    except adguard.AdGuardError as e:
        ag_err = str(e)
    live = monitor.live_clients()
    return render(ctx, "health.html", "health", snap=snap, ag=ag, ag_err=ag_err, live=live)


# ================================================================ audit

@app.get("/audit", response_class=HTMLResponse)
def audit_page(ctx: Ctx = Admin, q: str = "", action: str = "", page: int = 1):
    page = max(1, page)
    where, args = [], []
    if action:
        where.append("action LIKE ?")
        args.append(action.replace("%", "") + "%")
    if q:
        where.append("(actor LIKE ? OR target_label LIKE ? OR details LIKE ? OR ip LIKE ?)")
        args += [f"%{q[:80]}%"] * 4
    sql_where = ("WHERE " + " AND ".join(where)) if where else ""
    total = db.q1(f"SELECT COUNT(*) n FROM audit_logs {sql_where}", *args)["n"]  # noqa: S608 - fixed column names/fragments only; values are bound parameters
    rows = db.q(f"SELECT * FROM audit_logs {sql_where} ORDER BY id DESC LIMIT 100 OFFSET ?", *args, (page - 1) * 100)  # noqa: S608 - fixed column names/fragments only; values are bound parameters
    actions = [r["a"] for r in db.q("SELECT DISTINCT substr(action, 1, instr(action, '.') - 1) a FROM audit_logs ORDER BY a")]
    return render(ctx, "audit.html", "audit", rows=rows, q=q, action=action, page=page, total=total,
                  pages=max(1, (total + 99) // 100), actions=actions, loads=json.loads)


# ================================================================ settings

SETTING_FIELDS = {
    "display_timezone": "tz", "profile_download_hours": (1, 720), "session_idle_minutes": (5, 240),
    "session_absolute_hours": (1, 72), "default_cert_days": (30, 3650), "default_guest_days": (1, 365),
}


@app.get("/settings", response_class=HTMLResponse)
def settings(ctx: Ctx = Admin):
    vals = {k: db.setting(k) for k in config.DEFAULT_SETTINGS}
    admins = db.q("SELECT id, username, created_at, last_login_at, enabled FROM admins ORDER BY id")
    return render(ctx, "settings.html", "settings", vals=vals, timezones=schedule.timezones(), admins=admins)


@app.post("/settings")
def settings_save(ctx: Ctx = AdminPost):
    changed = {}
    for k, rule in SETTING_FIELDS.items():
        v = ctx.f(k)
        if rule == "tz":
            if not schedule.valid_tz(v):
                return redirect("/settings", ctx, "Unknown timezone.", "error")
        else:
            iv = _int(v)
            if iv is None or not rule[0] <= iv <= rule[1]:
                return redirect("/settings", ctx, f"{k.replace('_', ' ')} must be between {rule[0]} and {rule[1]}.", "error")
            v = str(iv)
        if db.setting(k) != v:
            db.set_setting(k, v)
            changed[k] = v
    if changed:
        audit.log(ctx.admin, "settings.changed", ip=ctx.ip, **changed)
        engine.apply()
    return redirect("/settings", ctx, "Settings saved." if changed else "No changes.")


@app.post("/settings/password")
def settings_password(ctx: Ctx = AdminPost):
    row = db.q1("SELECT * FROM admins WHERE id = ?", ctx.admin_id)
    try:
        security.ph.verify(row["password_hash"], ctx.form.get("current") or "")
    except Exception:  # noqa: BLE001
        audit.log(ctx.admin, "admin.password_change_failed", ip=ctx.ip)
        return redirect("/settings", ctx, "Current password is incorrect.", "error")
    new, again = ctx.form.get("new") or "", ctx.form.get("again") or ""
    if new != again:
        return redirect("/settings", ctx, "New passwords do not match.", "error")
    problems = security.password_problems(new, ctx.admin)
    if problems:
        return redirect("/settings", ctx, "Password needs: " + ", ".join(problems) + ".", "error")
    db.ex("UPDATE admins SET password_hash = ? WHERE id = ?", security.hash_password(new), ctx.admin_id)
    security.destroy_all_sessions(ctx.admin_id, except_token=ctx.token)
    audit.log(ctx.admin, "admin.password_changed", ip=ctx.ip)
    return redirect("/settings", ctx, "Password changed. Other sessions were signed out.")


# ================================================================ internal (AdGuard list feed, localhost only)

@app.get("/internal/adguard/{name}")
def internal_list(name: str, request: Request):
    via_proxy = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
    if via_proxy or not request.client or request.client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(404, "Not found")
    cat = name.split("?")[0].removesuffix(".txt")
    if cat not in engine.CATEGORY_LISTS:
        raise HTTPException(404, "Not found")
    return PlainTextResponse(engine.render_list(cat))
