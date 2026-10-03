"""Runtime configuration.

Deployment values come from environment variables or from the shared config
file (default ``/etc/vpnpanel/panel.env``, see ``.env.example``). Environment
variables win over the file. ``VPNPANEL_FAKE=1`` runs a self-contained demo
(no sudo, no OpenVPN, no AdGuard) for local UI development and tests.
"""
import ipaddress
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent
FAKE = os.environ.get("VPNPANEL_FAKE") == "1"
ENV_FILE = Path(os.environ.get("VPNPANEL_ENV_FILE", "/etc/vpnpanel/panel.env"))


def load_env_file(path):
    """Parse a simple KEY=VALUE file (comments and blank lines ignored, optional quotes)."""
    values = {}
    try:
        text = Path(path).read_text()
    except (FileNotFoundError, PermissionError):
        return values
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        values[key.strip()] = val
    return values


_FILE = {} if FAKE else load_env_file(ENV_FILE)


def env(key, default=""):
    return os.environ.get(key, _FILE.get(key, default))


class ConfigError(RuntimeError):
    pass


# ---------------------------------------------------------------- VPN
VPN_PUBLIC_HOST = env("VPN_PUBLIC_HOST", "vpn.example.com")
VPN_PUBLIC_PORT = int(env("VPN_PUBLIC_PORT", "443"))
VPN_PROTOCOL = env("VPN_PROTOCOL", "tcp").lower()
VPN_IPV4_SUBNET = env("VPN_IPV4_SUBNET", "10.8.0.0/24")
VPN_IPV6_SUBNET = env("VPN_IPV6_SUBNET", "fd00:8:0:1::/64")
VPN_INTERFACE = env("VPN_INTERFACE", "tun0")
PUBLIC_INTERFACE = env("PUBLIC_INTERFACE", "eth0")
SERVER_LABEL = env("SERVER_LABEL", "")

_net = ipaddress.ip_network(VPN_IPV4_SUBNET, strict=True)
if _net.prefixlen > 24:
    raise ConfigError("VPN_IPV4_SUBNET must be /24 or larger (static ranges use host offsets up to 250)")
VPN_NET = str(_net)
SERVER_VPN_IP = env("VPN_SERVER_ADDRESS", str(_net.network_address + 1))


def host(offset):
    """Address at a host offset inside the VPN subnet (offset 10 -> x.x.x.10 for a /24)."""
    return str(_net.network_address + offset)


# Static address plan as host offsets inside the subnet.
IP_RANGES = {
    "ADULT": (10, 49),
    "CHILD": (50, 149),
    "GUEST": (150, 199),
    "OVERFLOW": (200, 250),
}

# ---------------------------------------------------------------- admin panel / services
ADMIN_BIND_HOST = env("ADMIN_BIND_HOST", SERVER_VPN_IP)
ADMIN_PORT = int(env("ADMIN_PORT", "8443"))
APP_PORT = int(env("APP_PORT", "8090"))
OPENVPN_CONFIG_DIR = Path(env("OPENVPN_CONFIG_DIR", "/etc/openvpn/server"))
EASYRSA_DIR = Path(env("EASYRSA_DIR", "/etc/openvpn/easy-rsa"))
ADGUARD_URL = env("ADGUARD_URL", "http://127.0.0.1:3080")
LOCAL_TIMEZONE = env("LOCAL_TIMEZONE", "UTC")
BACKUP_DIR = Path(env("BACKUP_DIR", "/var/backups/family-vpn-panel"))

HELPER = ["sudo", "-n", "/usr/local/sbin/vpnpanel-helper"]

if FAKE:
    _var = Path(os.environ.get("VPNPANEL_VAR", BASE.parent / ".devdata"))
    _var.mkdir(parents=True, exist_ok=True)
    DB_PATH = _var / "vpnpanel.db"
    SECRET_KEY_FILE = _var / "secret.key"
    LIST_CACHE = _var / "lists"
    ADGUARD_ENV = None
else:
    DB_PATH = Path(env("DATABASE_PATH", "/var/lib/vpnpanel/vpnpanel.db"))
    SECRET_KEY_FILE = Path(env("SECRET_KEY_FILE", "/etc/vpnpanel/secret.key"))
    LIST_CACHE = Path(env("LIST_CACHE_DIR", "/var/lib/vpnpanel/lists"))
    ADGUARD_ENV = Path(env("ADGUARD_CREDENTIALS_FILE", "/etc/vpnpanel/adguard.env"))

SECURE_COOKIES = not FAKE
SESSION_COOKIE = "__Host-vpnpanel" if SECURE_COOKIES else "vpnpanel"
LOGIN_CSRF_COOKIE = "__Host-vpnpanel-login" if SECURE_COOKIES else "vpnpanel-login"

# URL AdGuard Home uses to fetch the generated per-client category lists (loopback only).
INTERNAL_LIST_BASE = f"http://127.0.0.1:{APP_PORT}/internal/adguard"

DEFAULT_SETTINGS = {
    "display_timezone": LOCAL_TIMEZONE,
    "profile_download_hours": "72",
    "session_idle_minutes": "30",
    "session_absolute_hours": "12",
    "default_cert_days": "825",
    "default_guest_days": "7",
    "global_custom_rules": "",
}
