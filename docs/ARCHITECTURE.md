# Architecture

## Components

| Component | Runs as | Listens on | Role |
|---|---|---|---|
| OpenVPN (`openvpn-server@server`) | root → `nobody` | public `VPN_PUBLIC_PORT` | VPN; reads per-device `ccd/` files and the CRL |
| Management interface | (OpenVPN) | `/run/openvpn-server/management.sock` (root-only dir) | live sessions, per-session disconnect |
| AdGuard Home | `adguard` | `VPN_SERVER_ADDRESS:53`, `127.0.0.1:53`, API `127.0.0.1:3080` | DNS filtering |
| Panel (`vpnpanel`, FastAPI + uvicorn) | `vpnpanel` | `127.0.0.1:APP_PORT` | UI, policy engine, monitor |
| nginx | `www-data` | `ADMIN_BIND_HOST:ADMIN_PORT`, `127.0.0.1:ADMIN_PORT` | TLS termination, rate limiting |
| Root helper `/usr/local/sbin/vpnpanel-helper` | root (via sudo) | — | the only privileged code |
| nftables table `inet vpnpanel` | kernel | — | per-device restrictions |
| UFW (iptables-nft) | kernel | — | authoritative firewall + NAT |

## Data model

```
admins ── sessions
family_members (ADULT | CHILD | GUEST) ── policy ── access_schedules ── schedule_overrides
   └── devices (CN, static IPv4, enabled, internet_enabled, panel_access, expires_at, revoked)
          ├── vpn_certificates (every serial ever issued, with revocation reason)
          ├── connection_sessions (connect/disconnect, public IP, bytes)
          └── traffic_stats (hourly UTC buckets)
policies (filters, service rules + windows, custom lists, enforce_schedule)
audit_logs, login_attempts, settings
```

SQLite (WAL) at `DATABASE_PATH`. Private keys are never stored; a freshly generated profile is kept
**encrypted** (Fernet key in `/etc/vpnpanel/secret.key`) only for the download window.

## Policy engine

`app/engine.py` evaluates the whole household on every change and every 30 seconds:

1. **Status** per device: revoked > expired > disabled > owner paused > active.
2. **Internet** per device: device switch AND (override OR schedule windows), evaluated in the
   schedule's IANA timezone (`zoneinfo`, DST-correct). The server itself stays on UTC.
3. **Desired state**
   * OpenVPN CCD: `ifconfig-push` (static IPv4), `ifconfig-ipv6-push`, `disable` when inactive.
   * nftables sets: `no_internet`, `children`, `panel_admins`.
   * AdGuard persistent client per device (keyed by IP): Safe Browsing, Parental Control,
     SafeSearch / YouTube restricted, blocked services (current time window applied).
   * Category lists served at `http://127.0.0.1:APP_PORT/internal/adguard/<category>.txt` with
     `$client=` rules; their URL carries a content version so AdGuard re-downloads only on change.
   * Custom per-policy block/allow rules as AdGuard user rules with `$client=`.
4. **Apply** only the components whose content hash changed; each component fails independently.

## Monitor

A background thread polls the management interface every 15 s (session start/end, byte deltas →
hourly traffic), enforces expiry, purges expired profile downloads and old sessions, refreshes the
category list sources and renews the CRL when less than a year remains.

## Privilege separation

The web process can only run `sudo -n /usr/local/sbin/vpnpanel-helper <verb> [args]`. Verbs:
`issue`, `revoke`, `ccd-write`, `ccd-delete`, `ccd-list`, `pki-list`, `crl-refresh`, `mgmt-status`,
`mgmt-kill`, `nft-apply`, `nft-counters`, `health`. The helper validates every argument (CN regex,
IPs inside the VPN subnet, reasons from a fixed list), reads deployment values only from the
root-owned `/etc/vpnpanel/panel.env`, runs Python in isolated mode, and returns JSON.

## Request flow (admin)

`browser → nginx (TLS, allow-list, /login rate limit) → uvicorn (127.0.0.1) → session + CSRF check →
route → engine/helper → audit log`.

## Network flow (client)

```
device ──OpenVPN──▶ tun ──▶ nftables vpnpanel (prerouting: DNS → VPN_SERVER_ADDRESS)
                         ├─▶ input:   AdGuard (53), panel (ADMIN_PORT, admins only)
                         └─▶ forward: drop spoofed · reject IPv6 · reject no_internet
                                      · reject private ranges/metadata · reject child DoT
                                      ─▶ UFW route allow ─▶ NAT (MASQUERADE) ─▶ internet
```
