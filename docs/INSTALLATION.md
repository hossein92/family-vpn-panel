# Installation

This guide sets up a **new** server. If OpenVPN is already running on it, read
[OPENVPN.md](OPENVPN.md) first — the installer never overwrites an existing `server.conf` or PKI.

## Requirements

* Ubuntu **24.04 LTS** (other versions: untested), amd64 or arm64, 1 vCPU / 1 GB RAM minimum
  (2 GB recommended: AdGuard Home with the default lists uses ~150–250 MB).
* A public IPv4 address (or DNS name) and one free port for OpenVPN (default TCP 443).
* SSH access with **key authentication** and a user with `sudo`.
* Outbound HTTPS (packages, AdGuard Home release, block lists, PyPI).

The installer adds: `openvpn`, `easy-rsa`, `nginx`, `python3-venv`, `python3-yaml`, `sqlite3`,
`nftables`, `curl`, `dnsutils`, `openssl` (and `ufw` with `--configure-firewall`). Python
dependencies are installed into `/opt/vpnpanel/venv` from the pinned `requirements.txt`.
AdGuard Home is downloaded from its official GitHub release and its SHA-256 checksum verified.

## 1. Get the code

```bash
git clone https://github.com/<you>/family-vpn-panel.git
cd family-vpn-panel
```

## 2. Create the configuration

```bash
sudo deploy/install.sh        # creates /etc/vpnpanel/panel.env from .env.example and stops
sudo nano /etc/vpnpanel/panel.env
```

Set at least `VPN_PUBLIC_HOST` (your server's public IP or DNS name). Check `PUBLIC_INTERFACE`
(`ip route get 1.1.1.1` shows it). See [CONFIGURATION.md](CONFIGURATION.md) for all options.

## 3. Install

```bash
sudo deploy/install.sh --setup-openvpn --setup-adguard --configure-firewall
```

What each flag does:

| Flag | Actions | Safety |
|---|---|---|
| `--setup-openvpn` | New Easy-RSA PKI (CA, server cert), tls-crypt key, 10-year CRL, `server.conf` from `deploy/templates/server.conf.in`, IPv4 forwarding | Refuses if `server.conf` or a PKI already exists |
| `--setup-adguard` | AdGuard Home release (checksum-verified), dedicated user, hardened systemd unit, DNS on the VPN address + loopback, random admin credentials in `/etc/vpnpanel/adguard.env` | First-run wizard port is firewalled to loopback during setup |
| `--configure-firewall` | UFW rules for SSH, the VPN port, DNS/panel on the VPN interface, VPN egress; NAT in `/etc/ufw/before.rules` (backup kept) | Detects your SSH port(s) and allows them **first**; asks before enabling an inactive UFW; never edits SSH config |
| *(always)* | Panel code, venv, root helper + sudoers rule, secrets, name-constrained TLS CA, systemd units, nginx site, nightly backup timer | Idempotent; safe to re-run for upgrades |

Add `--yes` to skip confirmation prompts (not recommended on the first run).

## 4. Create the first admin

```bash
sudo vpnpanel-admin create-admin alex
```

Passwords need at least 12 characters; Argon2id is used for hashing.

## 5. Open the panel

The installer prints the panel CA fingerprint. Copy `/etc/vpnpanel/panel-ca.crt` to your admin
computer/phone and trust it (macOS: Keychain Access → *Always Trust*; iOS: install profile, then
*Settings → General → About → Certificate Trust Settings*). The CA is X.509 name-constrained to the
panel's own addresses, so it cannot be abused for other sites. Never install it on children's devices
— it isn't needed there.

Before any device is flagged for panel access, use an SSH tunnel:

```bash
ssh -L 8443:127.0.0.1:8443 you@your-server      # then open https://127.0.0.1:8443
```

## 6. First steps in the panel

1. **Family members → Add** each person (Adult / Child / Guest).
2. **Add device** for every phone, tablet and computer → download its `.ovpn` and import it into
   OpenVPN Connect (iOS/Android/Windows/macOS) or Tunnelblick — one profile per device.
3. Tick *May open this admin panel* on your own devices to reach `https://10.8.0.1:8443` over the VPN.
4. Review **Child profiles & policies** and **Access schedules**.

## Verify

```bash
systemctl is-active openvpn-server@server adguardhome vpnpanel nginx vpnpanel-nft
sudo ss -tlnup | grep -E ':(443|53|8443|8090|3080) '
sudo ufw status verbose
```

Only the VPN port and SSH should be reachable from the internet. On a connected device, check
<https://test-ipv6.com> (no IPv6 address should be visible) and the extended test on
<https://dnsleaktest.com> (only your server's resolvers should appear).

## Upgrading

```bash
cd family-vpn-panel && git pull
sudo deploy/install.sh
```

Re-running the installer replaces only the application code, helper and templates; the database,
PKI, CA and keys are kept (take a backup first: `sudo vpnpanel-backup`). Schema changes, if any,
will be described in the release notes.
