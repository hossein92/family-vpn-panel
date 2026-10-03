# Configuration

Deployment settings live in **`/etc/vpnpanel/panel.env`** (`root:vpnpanel`, mode 0640), created from
[`.env.example`](../.env.example). Format: one `KEY=VALUE` per line, comments on their own lines.
The file is parsed, never executed. Both the panel and the root helper read it; the helper reads it
directly (it does not trust the caller's environment).

After changing it: `sudo deploy/install.sh` (re-renders nginx/TLS-dependent pieces) or at least
`sudo systemctl restart vpnpanel`.

| Variable | Default | Meaning |
|---|---|---|
| `VPN_PUBLIC_HOST` | — (required) | Public IP or DNS name written into client profiles (`remote`). |
| `VPN_PUBLIC_PORT` | `443` | OpenVPN port. |
| `VPN_PROTOCOL` | `tcp` | `tcp` or `udp`. |
| `VPN_IPV4_SUBNET` | `10.8.0.0/24` | Tunnel subnet; must be /24 or larger. |
| `VPN_SERVER_ADDRESS` | first host | Server address inside the tunnel (DNS resolver, panel). |
| `VPN_IPV6_SUBNET` | random ULA | Unique-local /64 used only to capture and refuse client IPv6. The installer replaces the example value with a random `fdXX:…` prefix. |
| `VPN_INTERFACE` | `tun0` | OpenVPN interface name. |
| `PUBLIC_INTERFACE` | `eth0` | Interface that reaches the internet (NAT). |
| `ADMIN_BIND_HOST` | `VPN_SERVER_ADDRESS` | Where nginx serves the panel. Keep it on the VPN address. |
| `ADMIN_PORT` | `8443` | Panel HTTPS port. |
| `ADMIN_DNS_NAME` | `vpn-panel.home.arpa` | Name AdGuard resolves to the server; included in the panel certificate. |
| `APP_PORT` | `8090` | Loopback port of the app behind nginx. |
| `SERVER_LABEL` | public host | Text under the logo. |
| `LOCAL_TIMEZONE` | `UTC` | Default display timezone (IANA name); changeable in *Settings*. |
| `OPENVPN_CONFIG_DIR` | `/etc/openvpn/server` | Contains `server.conf`, `ccd/`, `crl.pem`, `tls-crypt.key`. |
| `EASYRSA_DIR` | `/etc/openvpn/easy-rsa` | Easy-RSA installation with `pki/`. |
| `DATABASE_PATH` | `/var/lib/vpnpanel/vpnpanel.db` | SQLite database. |
| `BACKUP_DIR` | `/var/backups/family-vpn-panel` | Nightly backup destination (0700). |
| `ADGUARD_URL` | `http://127.0.0.1:3080` | AdGuard Home API (loopback). |

Other files in `/etc/vpnpanel/`:

| File | Content |
|---|---|
| `adguard.env` | `ADGUARD_USER`, `ADGUARD_PASSWORD` for the local API (0640 root:vpnpanel) |
| `secret.key` | Fernet key that encrypts profiles during their download window |
| `tls/` | Panel CA and certificate (root-only); `panel-ca.crt` is the public CA to trust |
| `vpnpanel.nft` | Last applied nftables table (generated) |

## Address plan

Static addresses are host offsets inside `VPN_IPV4_SUBNET`:

| Offsets | Use |
|---|---|
| 1 | server |
| 10–49 | adults |
| 50–149 | children |
| 150–199 | guests |
| 200–250 | overflow when a range is full |

Addresses are never reused while a device record exists (revoked devices keep theirs for history).

## In-panel settings

*Settings* holds runtime preferences stored in the database: display timezone, profile download
window (default 72 h), certificate lifetime (825 days), default guest lifetime (7 days), session idle
timeout (30 min) and maximum session age (12 h).
