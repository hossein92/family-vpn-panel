# OpenVPN

## One certificate per device

OpenVPN identifies clients by the certificate Common Name. When two devices share a profile, the
second connection with the same CN replaces the first — the classic "my phones keep kicking each
other off" problem. `duplicate-cn` would hide the symptom but makes devices indistinguishable and
impossible to revoke individually. Family VPN Panel therefore issues a separate certificate, key,
CN and static address for every device and **never uses `duplicate-cn`**.

## Required server directives

A server created with `--setup-openvpn` already has these (see
[`deploy/templates/server.conf.in`](../deploy/templates/server.conf.in)):

```
topology subnet
server 10.8.0.0 255.255.255.0
server-ipv6 fdXX:XXXX:XXXX:1::/64          # ULA, only to capture client IPv6
client-config-dir /etc/openvpn/server/ccd   # static address + enable/disable per device
ccd-exclusive                               # only devices known to the panel may connect
crl-verify /etc/openvpn/server/crl.pem      # revocation
management /run/openvpn-server/management.sock unix   # local-only, root-only directory
block-ipv6
push "redirect-gateway def1 ipv6 bypass-dhcp"
push "block-ipv6"
push "dhcp-option DNS 10.8.0.1"             # the VPN resolver (AdGuard Home)
push "block-outside-dns"                    # Windows DNS-leak protection
```

Never expose the management interface on TCP. The systemd unit's runtime directory
`/run/openvpn-server` is `root`-only, which protects the socket.

## Adopting an existing OpenVPN server

The installer does not modify an existing `server.conf`; it only reports missing directives. Plan a
short maintenance window and keep a root SSH session open.

1. **Back up** `/etc/openvpn` (and your firewall config).
2. **Install the panel** without `--setup-openvpn`:
   `sudo deploy/install.sh --setup-adguard --configure-firewall`.
3. **Generate a CRL** if you have none, with a long validity, and copy it:
   ```bash
   cd /etc/openvpn/easy-rsa
   sudo EASYRSA_BATCH=1 EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
   sudo install -m 644 pki/crl.pem /etc/openvpn/server/crl.pem
   ```
   An expired CRL makes OpenVPN reject **every** client; the panel renews it automatically when less
   than a year remains.
4. **Adopt existing certificates** *before* enabling `ccd-exclusive`: create the owner in the panel,
   then *Security & revocation → Unmanaged certificates → Adopt* (or
   `sudo vpnpanel-admin adopt <cn> --member "Alex" --name "Laptop"`). Adoption writes the CCD file.
5. **Add the directives** above to `server.conf`, validate them with a throw-away instance on another
   port/device if you like, then `sudo systemctl restart openvpn-server@server`. A restart (not a
   reload) is required because the server drops privileges after binding its port.
6. **Replace shared profiles**: create one new device per phone/computer, install the new profiles,
   then revoke the old shared certificate.

## Revocation workflow

*Device → Revoke certificate* (type the CN to confirm):

1. `easyrsa revoke <cn> <reason>` and `easyrsa gen-crl` (10-year validity);
2. the CRL is atomically replaced in `OPENVPN_CONFIG_DIR` — OpenVPN re-reads it on every new handshake;
3. the live session is killed through the management socket (`client-kill <id> HALT`);
4. the CCD file gets `disable`; the device record and its history remain.

*Disable* is the reversible alternative (CCD `disable` + disconnect, certificate stays valid).
*Regenerate profile* revokes the current certificate (reason `superseded`) and issues a new one for
the same CN.

## Profiles

Generated profiles contain `remote VPN_PUBLIC_HOST VPN_PUBLIC_PORT`, `remote-cert-tls server`,
`verify-x509-name server name`, TLS ≥ 1.2, AES-GCM/ChaCha20, and inline CA, client certificate,
client key and tls-crypt key. The client key exists on the server only between Easy-RSA writing it
and the helper shredding it (milliseconds); the finished profile is stored encrypted for the
download window (default 72 h), then purged.

## IPv6 and DNS leaks

* Clients route IPv6 into the tunnel (`redirect-gateway ipv6`) where it is answered with
  "no route" (`block-ipv6`), so dual-stack networks cannot leak IPv6 around the VPN. The server does
  not need public IPv6 and IPv6 is not disabled globally.
* All DNS (UDP/TCP 53) arriving from the tunnel is redirected to the VPN resolver by the nftables
  table, whatever server the device asks. Children additionally cannot use DNS-over-TLS (853), and
  child policies block known DoH/VPN/proxy endpoints by DNS.
