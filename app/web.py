"""Shared web plumbing: templates, auth/CSRF dependencies, flash messages, formatting."""
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote
from zoneinfo import ZoneInfo

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from . import config, db, security
from .engine import parse_iso

templates = Jinja2Templates(directory=str(config.BASE / "templates"))

NAV = [
    ("Overview", [("dashboard", "/", "Dashboard", "grid")]),
    ("Family", [
        ("members", "/members", "Family members", "users"),
        ("devices", "/devices", "Devices", "device"),
        ("profiles", "/profiles", "VPN profiles", "file"),
        ("connections", "/connections", "Connected clients", "pulse"),
    ]),
    ("Protection", [
        ("policies", "/policies", "Child profiles & policies", "shield"),
        ("dns", "/dns", "DNS filtering", "filter"),
        ("schedules", "/schedules", "Access schedules", "clock"),
    ]),
    ("Insights", [
        ("traffic", "/traffic", "Traffic usage", "chart"),
        ("security", "/security", "Security & revocation", "lock"),
        ("health", "/health", "Server health", "server"),
        ("audit", "/audit", "Audit log", "list"),
    ]),
    ("System", [("settings", "/settings", "Settings", "gear")]),
]

_flash = {}
_flash_lock = threading.Lock()


@dataclass
class Ctx:
    request: Request
    admin: str
    admin_id: int
    csrf: str
    token: str
    ip: str
    form: dict = field(default_factory=dict)

    def f(self, name, default=""):
        v = self.form.get(name, default)
        return v.strip() if isinstance(v, str) else v

    def flist(self, name):
        return [v for v in self.form.getlist(name)] if hasattr(self.form, "getlist") else []

    def checked(self, name):
        return 1 if self.form.get(name) in ("on", "1", "true", "yes") else 0


class LoginRequired(Exception):
    pass


def client_ip(request: Request):
    # uvicorn runs with --proxy-headers trusting only 127.0.0.1 (nginx), so this is the real peer.
    return request.client.host if request.client else "?"


def admin_ctx(request: Request) -> Ctx:
    token = request.cookies.get(config.SESSION_COOKIE)
    row = security.load_session(token)
    if not row:
        raise LoginRequired()
    return Ctx(request=request, admin=row["username"], admin_id=row["admin_id"], csrf=row["csrf"],
               token=token, ip=client_ip(request))


async def admin_post(request: Request) -> Ctx:
    ctx = admin_ctx(request)
    origin = request.headers.get("origin")
    if origin and origin != "null":
        host = request.headers.get("host", "")
        if origin.split("://", 1)[-1] != host:
            raise HTTPException(403, "Cross-origin request blocked")
    ctx.form = await request.form()
    if not security.csrf_ok(ctx.csrf, ctx.form.get("csrf_token")):
        raise HTTPException(403, "Invalid or missing CSRF token — reload the page and try again")
    return ctx


def flash(ctx_or_token, message, kind="ok"):
    token = ctx_or_token.token if isinstance(ctx_or_token, Ctx) else ctx_or_token
    with _flash_lock:
        _flash.setdefault(token, []).append((kind, message))


def pop_flash(token):
    with _flash_lock:
        return _flash.pop(token, [])


def redirect(url, ctx=None, message=None, kind="ok"):
    if ctx and message:
        flash(ctx, message, kind)
    return RedirectResponse(url, status_code=303)


def render(ctx: Ctx, template, active, **kw):
    kw.update(request=ctx.request, admin=ctx.admin, csrf=ctx.csrf, nav=NAV, active=active,
              flashes=pop_flash(ctx.token), tz=db.setting("display_timezone"), fake=config.FAKE)
    resp = templates.TemplateResponse(ctx.request, template, kw)
    return resp


# ---------------------------------------------------------------- formatting filters

def _tz():
    try:
        return ZoneInfo(db.setting("display_timezone"))
    except Exception:  # noqa: BLE001
        return timezone.utc


def fmt_dt(value, fmt="%Y-%m-%d %H:%M"):
    dt = parse_iso(value) if isinstance(value, str) else value
    if not dt:
        return "—"
    return dt.astimezone(_tz()).strftime(fmt)


def fmt_ago(value):
    dt = parse_iso(value) if isinstance(value, str) else value
    if not dt:
        return "never"
    s = int((datetime.now(timezone.utc) - dt).total_seconds())
    future = s < 0
    s = abs(s)
    if s < 60:
        txt = "just now" if not future else "in <1 min"
        return txt
    for unit, n in (("d", 86400), ("h", 3600), ("min", 60)):
        if s >= n:
            v = s // n
            return f"in {v} {unit}" if future else f"{v} {unit} ago"
    return "—"


def fmt_duration(seconds):
    seconds = int(seconds or 0)
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return "—"


def session_duration(s):
    a = parse_iso(s["connected_at"])
    b = parse_iso(s["disconnected_at"]) or datetime.now(timezone.utc)
    return (b - a).total_seconds() if a else 0


templates.env.globals.update(session_duration=session_duration)
templates.env.filters.update(dt=fmt_dt, ago=fmt_ago, bytes=fmt_bytes, duration=fmt_duration, urlq=quote)
class _Cfg:
    """Read-only deployment values for templates (no secrets)."""
    public_host = config.VPN_PUBLIC_HOST
    public_port = config.VPN_PUBLIC_PORT
    protocol = config.VPN_PROTOCOL
    endpoint = f"{config.VPN_PUBLIC_HOST}:{config.VPN_PUBLIC_PORT}/{config.VPN_PROTOCOL}"
    subnet = config.VPN_NET
    server_ip = config.SERVER_VPN_IP
    vpn_iface = config.VPN_INTERFACE
    public_iface = config.PUBLIC_INTERFACE
    admin_url = f"https://{config.ADMIN_BIND_HOST}:{config.ADMIN_PORT}"
    label = config.SERVER_LABEL or config.VPN_PUBLIC_HOST
    ranges = {k: (config.host(a), config.host(b)) for k, (a, b) in config.IP_RANGES.items()}


templates.env.globals.update(token_hex=secrets.token_hex, cfg=_Cfg)
