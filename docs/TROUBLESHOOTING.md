# Troubleshooting

**Two devices keep disconnecting each other.**
They share a certificate. Create a separate device (profile) for each and revoke the shared one.

**A device can't connect after enabling `ccd-exclusive`.**
Its CN has no CCD file. Adopt the certificate (*Security & revocation → Unmanaged certificates*) or
issue a new device profile. Check `journalctl -u openvpn-server@server` for
`client-config-dir authentication failed`.

**Every client is rejected with "CRL has expired".**
Regenerate it: `cd /etc/openvpn/easy-rsa && sudo EASYRSA_BATCH=1 EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
&& sudo install -m 644 pki/crl.pem /etc/openvpn/server/crl.pem`. The panel normally renews it.

**Connected, but no internet.**
Check, in order: the device's *Internet* badge (schedule / switched off / expired); `sysctl
net.ipv4.ip_forward`; `sudo iptables -t nat -S POSTROUTING` contains
`-s <subnet> -o <PUBLIC_INTERFACE> -j MASQUERADE`; `sudo ufw status` shows the route rule
`ALLOW FWD` from the VPN interface; `PUBLIC_INTERFACE` is right (`ip route get 1.1.1.1`).

**Connected, but nothing resolves.**
`systemctl status adguardhome`; `dig @10.8.0.1 example.com` on the server; UFW must allow port 53 on
the VPN interface. AdGuard waits for the VPN address at boot (`wait-for-vpn-ip`).

**Filtering doesn't apply to a device.**
*DNS filtering → Test a domain* as that device. After adding devices, AdGuard rebuilds its engine
(a few seconds). `sudo vpnpanel-admin apply` re-pushes everything. Browsers with their own
DNS-over-HTTPS bypass DNS filters unless "Prevent filter bypass" is enabled for the policy.

**Panel unreachable.**
Over the VPN, the device must be an adult device with *May open this admin panel*. Otherwise use the
SSH tunnel. `systemctl status nginx vpnpanel`; nginx starts only after the VPN address exists.
Browser certificate warning: trust `/etc/vpnpanel/panel-ca.crt` and use the exact address in the
certificate (VPN address, `127.0.0.1` or `ADMIN_DNS_NAME`).

**Locked out of the panel.**
`sudo vpnpanel-admin reset-password <name>` (also clears the lockout).

**"Profile download window has closed".**
Keys are not stored. Use *Regenerate profile*; the old profile stops working.

**Duplicate MASQUERADE rules.**
Caused by `ufw reload`; harmless. Remove extras with `sudo iptables -t nat -D POSTROUTING -s <subnet>
-o <iface> -j MASQUERADE` or reboot.

**Windows client shows DNS from the local network.**
Make sure `push "block-outside-dns"` is in `server.conf` (OpenVPN GUI ≥ 2.4).

**Linux client logs "Unrecognized option … block-outside-dns".**
Harmless: that pushed option is Windows-only and ignored elsewhere.
