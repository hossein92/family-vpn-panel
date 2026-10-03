# Security

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability
reporting: repository **Security** tab → **Report a vulnerability**. Include steps
to reproduce and the affected version/commit. You will get an acknowledgement as soon as possible;
fixes are released before details are published.

## Threat model

Protects against: strangers on the internet, a curious or determined child on a filtered device,
a lost or stolen family device, accidental exposure of management services, DNS/IPv6 leaks.
Out of scope: a compromised server (root on the VPN server can see everything the server sees),
malware already running on a client device, and nation-state adversaries.

## Admin panel

* Reachable only on the VPN address and loopback (nginx). UFW opens `ADMIN_PORT` only on the VPN
  interface; the nftables table rejects VPN clients that are not flagged as admin devices; nginx has
  an allow-list. Do **not** bind it to a public address.
* TLS from a private CA with X.509 **name constraints** (VPN address, 127.0.0.1, `ADMIN_DNS_NAME`),
  so trusting it cannot enable interception of other sites. Never install it on children's devices.
* Argon2id password hashes; minimum 12 characters; constant-time login path (dummy hash for unknown
  users).
* Server-side sessions (only a SHA-256 of the token is stored), cookies `__Host-`, `Secure`,
  `HttpOnly`, `SameSite=Strict`; 30-minute idle and 12-hour absolute timeout.
* CSRF token on every form plus an `Origin` check; login form has its own double-submit token.
* Lockout after 5 failed logins per username or 15 per address within 15 minutes; nginx rate limit
  on `/login`.
* Strict Content-Security-Policy (no inline scripts or styles), `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
* Audit log of logins, device/certificate/policy/schedule changes, downloads and overrides.

## Privileged helper

The web process runs as `vpnpanel` with no special rights. One sudoers rule allows exactly
`/usr/local/sbin/vpnpanel-helper`, which

* accepts a fixed set of verbs, at most 4 short arguments, and validates each one
  (Common Name `^[a-z0-9][a-z0-9-]{1,62}$`, IPs inside the VPN subnet, revocation reasons from a list);
* reads its configuration only from the root-owned `/etc/vpnpanel/panel.env`, runs Python in isolated
  mode with a fixed `PATH` and `umask 077`;
* never prints key material; read-only polling verbs are excluded from sudo logging, all changing
  verbs are logged.

## OpenVPN

* **Unique certificates per device; never `duplicate-cn`.**
* `ccd-exclusive`: only devices known to the panel can connect; disable = CCD `disable`.
* Revocation via Easy-RSA + `crl-verify`; the CRL is valid for 10 years and renewed automatically
  (an expired CRL would lock out every client).
* `tls-crypt`, TLS ≥ 1.2, AEAD ciphers, `verify-x509-name server name` in profiles.
* Management interface on a Unix socket in a root-only directory — **never on TCP**.
* Client private keys are shredded right after the profile is built (including Easy-RSA's
  `inline/` and `reqs/` copies). Profiles are encrypted at rest during the download window and the
  download itself is a POST with CSRF protection and `no-store`.

## Network isolation

* UFW stays authoritative; the `inet vpnpanel` nftables table can only drop, reject or redirect.
* VPN clients cannot reach RFC 1918, CGNAT, link-local (incl. cloud metadata `169.254.169.254`),
  loopback or other VPN clients; spoofed sources are dropped.
* DNS from the tunnel is always redirected to the filtering resolver; children cannot use DoT/DoQ.
* IPv6: captured in the tunnel and refused (`block-ipv6`) instead of leaking outside the VPN.
* AdGuard Home and the panel app listen on loopback / the VPN address only.

## Installer safety

* Never edits SSH configuration. Detects the SSH port(s) and allows them before enabling UFW, and
  asks before enabling an inactive firewall.
* Never overwrites an existing `server.conf` or PKI; all keys are generated on the machine.
* Parses `panel.env` as data, never executes it.
* Verifies the AdGuard Home release checksum; Python packages are pinned.

## Privacy

This is a parental/network access-control tool, **not spyware**. It stores connection metadata,
byte counters, DNS query names (7 days) and an audit log. It never captures passwords, HTTPS
contents, messages, banking data or decrypted TLS traffic. See
[PARENTAL-CONTROLS.md](PARENTAL-CONTROLS.md#what-is-recorded).

## Recommendations

1. Keep SSH key-only (`PasswordAuthentication no`, `PermitRootLogin no`); consider fail2ban or
   restricting port 22 to known addresses. Check `sshd -T`, since cloud images sometimes ship drop-in
   files that re-enable password login.
2. Treat backups like the CA key: root-only on the server, encrypted when copied elsewhere.
3. Consider keeping the CA key offline if you rarely add devices.
4. Revoke lost devices immediately; review *Security & revocation* and the audit log occasionally.
5. Keep the OS updated (unattended-upgrades) and update AdGuard Home deliberately.
