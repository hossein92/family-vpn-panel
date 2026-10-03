# Operations

## Accessing the panel

* Over the VPN from a device flagged *May open this admin panel*: `https://ADMIN_BIND_HOST:ADMIN_PORT`
  (default `https://10.8.0.1:8443`, or `https://vpn-panel.home.arpa:8443`).
* From anywhere: `ssh -L 8443:127.0.0.1:8443 you@server`, then `https://127.0.0.1:8443`.

## CLI (`sudo vpnpanel-admin …`)

| Command | |
|---|---|
| `create-admin <name>` | Create an admin (prompts for the password) |
| `reset-password <name>` | New password, clears lockout, signs out all sessions |
| `disable-admin <name>` | Disable an admin |
| `list-admins` | List admins and last sign-in |
| `adopt <cn> --member NAME [--type ADULT\|CHILD\|GUEST] [--name LABEL] [--panel]` | Manage a certificate issued outside the panel |
| `apply` | Re-push the full state (CCD, nftables, AdGuard) |

## Health checks

```bash
systemctl status openvpn-server@server adguardhome vpnpanel nginx vpnpanel-nft
sudo ss -tlnup | grep -E ':(443|53|8443|8090|3080) '
sudo iptables -t nat -S POSTROUTING | grep MASQUERADE     # one rule for your subnet
sudo nft list table inet vpnpanel
sudo journalctl -u vpnpanel -u openvpn-server@server --since -1h
```

The *Server health* page shows the same checks. Avoid `ufw reload`: UFW does not flush the nat
table and duplicates the MASQUERADE rule each time (harmless but untidy; a reboot cleans it up).

## Routine tasks

| Task | Where |
|---|---|
| New device / profile | Family member → Add device |
| Lost or stolen device | Device → Revoke certificate (reason "Lost / stolen") |
| Profile download window expired | Device → Regenerate profile |
| Guest access | Add a Guest member, add device, set *Expires on* |
| Extra screen time | Access schedules → +60 min |
| Who is online | Connected clients (disconnect per session) |
| Certificates expiring | VPN profiles (warning below 30 days) → Regenerate |
| Unknown certificates | Security & revocation → Unmanaged certificates |

## Backup

`vpnpanel-backup.timer` runs nightly (03:15 UTC) and keeps 14 archives in `BACKUP_DIR`
(default `/var/backups/family-vpn-panel`, mode 0700). Run it manually any time:

```bash
sudo vpnpanel-backup
```

Each `vpn-backup-<UTC>.tgz` (mode 0600, with a `.sha256` file) contains:

* `etc.tgz` — `/etc/openvpn` (**including the PKI and CA private key**), `/etc/vpnpanel`, UFW and
  sysctl configuration, nginx site, systemd units, sudoers rule, AdGuard Home config, helper scripts;
* `vpnpanel.db` — consistent online copy of the panel database;
* firewall dumps (`iptables-save`, `nft list ruleset`, `ufw status`).

**Protect backups like the CA key itself.** Copy them off the server only encrypted, e.g.

```bash
sudo tar -C /var/backups -c family-vpn-panel | gpg --symmetric --cipher-algo AES256 > panel-backups.tar.gpg
```

## Restore

On the same or a freshly installed server (run the installer first on a new machine):

```bash
sudo -i
mkdir /root/restore && tar -xzf /var/backups/family-vpn-panel/vpn-backup-<TS>.tgz -C /root/restore
systemctl stop vpnpanel nginx adguardhome
tar -xzf /root/restore/etc.tgz -C /
install -o vpnpanel -g vpnpanel -m 600 /root/restore/vpnpanel.db /var/lib/vpnpanel/vpnpanel.db
systemctl daemon-reload
systemctl restart openvpn-server@server vpnpanel-nft adguardhome vpnpanel nginx
vpnpanel-admin apply
```

Then check *Server health* and connect one device. Existing client profiles keep working because the
CA, server certificate and tls-crypt key are restored unchanged.

To roll back only an OpenVPN configuration change, restore `server.conf` from the archive and
`systemctl restart openvpn-server@server`.

## Upgrades

* **Panel:** `git pull && sudo deploy/install.sh` (keeps data and keys).
* **OS packages:** unattended-upgrades is recommended.
* **AdGuard Home:** set `ADGUARD_VERSION=vX.Y.Z`, remove `/opt/AdGuardHome/AdGuardHome`, run
  `sudo ADGUARD_VERSION=vX.Y.Z deploy/install.sh --setup-adguard` (configuration is kept; the
  checksum is verified).
