#!/bin/bash
# Family VPN Panel installer (Ubuntu 24.04). Idempotent; run as root from the
# repository checkout:
#
#   sudo deploy/install.sh [--setup-openvpn] [--setup-adguard] [--configure-firewall] [--yes]
#
#   (no flags)            install / update only the panel. Requires a working OpenVPN
#                         server prepared as described in docs/OPENVPN.md, and AdGuard Home.
#   --setup-openvpn       create a NEW OpenVPN server (fresh PKI + server.conf). Refuses to
#                         touch an existing server.conf or PKI.
#   --setup-adguard       install AdGuard Home (official release, checksum verified) and
#                         bind it to the VPN address + loopback only.
#   --configure-firewall  add the required UFW rules and NAT. Verifies the SSH port is
#                         allowed first and asks before enabling an inactive UFW.
#   --yes                 assume "yes" for confirmation prompts.
#
# The installer never modifies SSH configuration and never generates or copies
# keys from anywhere else: all keys are created fresh on this machine.
set -euo pipefail
umask 022

SRC=$(cd "$(dirname "$0")/.." && pwd)
ENV_FILE=/etc/vpnpanel/panel.env
ADGUARD_VERSION=${ADGUARD_VERSION:-v0.107.79}
SETUP_OPENVPN=0; SETUP_ADGUARD=0; CONFIGURE_FW=0; ASSUME_YES=0

for arg in "$@"; do
  case "$arg" in
    --setup-openvpn) SETUP_OPENVPN=1 ;;
    --setup-adguard) SETUP_ADGUARD=1 ;;
    --configure-firewall) CONFIGURE_FW=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

# Read KEY=VALUE lines without executing the file as shell code.
load_env() {
  local k v
  while IFS='=' read -r k v || [ -n "$k" ]; do
    [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
    v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
    printf -v "$k" '%s' "$v"
    export "${k?}"
  done < "$1"
}
say()  { printf '\n== %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  read -r -p "$1 [y/N] " ans; [[ "$ans" =~ ^[Yy]$ ]]
}

# ------------------------------------------------------------------ preflight
say "preflight"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
. /etc/os-release
[ "${ID:-}" = ubuntu ] || warn "tested on Ubuntu 24.04; detected ${PRETTY_NAME:-unknown}"
[ "${VERSION_ID:-}" = "24.04" ] || warn "tested on Ubuntu 24.04; detected ${PRETTY_NAME:-unknown}"

if [ ! -f "$ENV_FILE" ]; then
  install -d -m 750 /etc/vpnpanel
  install -m 640 "$SRC/.env.example" "$ENV_FILE"
  die "created $ENV_FILE from .env.example — edit it (at least VPN_PUBLIC_HOST) and run again"
fi
load_env "$ENV_FILE"
: "${VPN_PUBLIC_HOST:?}" "${VPN_IPV4_SUBNET:=10.8.0.0/24}" "${VPN_INTERFACE:=tun0}" "${PUBLIC_INTERFACE:=eth0}"
: "${VPN_PUBLIC_PORT:=443}" "${VPN_PROTOCOL:=tcp}" "${ADMIN_PORT:=8443}" "${APP_PORT:=8090}"
: "${OPENVPN_CONFIG_DIR:=/etc/openvpn/server}" "${EASYRSA_DIR:=/etc/openvpn/easy-rsa}"
: "${ADMIN_DNS_NAME:=vpn-panel.home.arpa}" "${ADGUARD_URL:=http://127.0.0.1:3080}"
[ "$VPN_PUBLIC_HOST" != "vpn.example.com" ] || die "set VPN_PUBLIC_HOST in $ENV_FILE (it is still the example value)"
case "$VPN_PROTOCOL" in tcp|udp) ;; *) die "VPN_PROTOCOL must be tcp or udp" ;; esac

read -r VPN_NETWORK VPN_NETMASK VPN_SERVER_DEFAULT <<<"$(python3 - "$VPN_IPV4_SUBNET" <<'PY'
import ipaddress, sys
n = ipaddress.ip_network(sys.argv[1], strict=True)
assert n.prefixlen <= 24, "VPN_IPV4_SUBNET must be /24 or larger"
print(n.network_address, n.netmask, n.network_address + 1)
PY
)" || die "invalid VPN_IPV4_SUBNET"
VPN_SERVER_ADDRESS=${VPN_SERVER_ADDRESS:-$VPN_SERVER_DEFAULT}
ADMIN_BIND_HOST=${ADMIN_BIND_HOST:-$VPN_SERVER_ADDRESS}
ip link show "$PUBLIC_INTERFACE" >/dev/null 2>&1 || die "PUBLIC_INTERFACE '$PUBLIC_INTERFACE' does not exist"

# Replace the documentation IPv6 example with a random unique-local /64.
if [ "${VPN_IPV6_SUBNET:-fd00:8:0:1::/64}" = "fd00:8:0:1::/64" ]; then
  VPN_IPV6_SUBNET=$(python3 -c 'import secrets; r=secrets.token_hex(5); print(f"fd{r[:2]}:{r[2:6]}:{r[6:10]}:1::/64")')
  if grep -q '^VPN_IPV6_SUBNET=' "$ENV_FILE"; then
    sed -i "s#^VPN_IPV6_SUBNET=.*#VPN_IPV6_SUBNET=$VPN_IPV6_SUBNET#" "$ENV_FILE"
  else
    echo "VPN_IPV6_SUBNET=$VPN_IPV6_SUBNET" >> "$ENV_FILE"
  fi
  echo "generated VPN_IPV6_SUBNET=$VPN_IPV6_SUBNET"
fi

say "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openvpn easy-rsa nginx python3-venv python3-yaml sqlite3 nftables curl dnsutils openssl >/dev/null
rm -f /etc/nginx/sites-enabled/default

# ------------------------------------------------------------------ OpenVPN
cat > /usr/local/sbin/wait-for-vpn-ip <<EOF
#!/bin/sh
# Wait (max 90 s) until the OpenVPN server address exists so services can bind to it.
i=0
while [ \$i -lt 90 ]; do
  ip -4 -o addr show dev $VPN_INTERFACE 2>/dev/null | grep -q " $VPN_SERVER_ADDRESS/" && exit 0
  i=\$((i+1)); sleep 1
done
echo "$VPN_SERVER_ADDRESS not present on $VPN_INTERFACE" >&2; exit 1
EOF
chmod 755 /usr/local/sbin/wait-for-vpn-ip

if [ "$SETUP_OPENVPN" = 1 ]; then
  say "OpenVPN: new server"
  if [ -e "$OPENVPN_CONFIG_DIR/server.conf" ]; then
    warn "$OPENVPN_CONFIG_DIR/server.conf already exists — NOT modified. See docs/OPENVPN.md to adapt it."
  elif [ -e "$EASYRSA_DIR/pki" ]; then
    die "$EASYRSA_DIR/pki exists but there is no server.conf. Refusing to reuse or overwrite an unknown PKI."
  else
    install -d -m 755 "$EASYRSA_DIR"
    cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR/"
    cd "$EASYRSA_DIR"
    export EASYRSA_BATCH=1 EASYRSA_PKI="$EASYRSA_DIR/pki" EASYRSA_CRL_DAYS=3650
    ./easyrsa init-pki >/dev/null
    EASYRSA_REQ_CN="Family VPN CA" ./easyrsa build-ca nopass >/dev/null
    ./easyrsa build-server-full server nopass >/dev/null
    ./easyrsa gen-crl >/dev/null
    rm -f "$EASYRSA_DIR/pki/inline/server.inline"
    install -d -m 755 "$OPENVPN_CONFIG_DIR" "$OPENVPN_CONFIG_DIR/ccd"
    install -m 644 pki/ca.crt "$OPENVPN_CONFIG_DIR/ca.crt"
    install -m 644 pki/issued/server.crt "$OPENVPN_CONFIG_DIR/server.crt"
    install -m 600 pki/private/server.key "$OPENVPN_CONFIG_DIR/server.key"
    install -m 644 pki/crl.pem "$OPENVPN_CONFIG_DIR/crl.pem"
    openvpn --genkey tls-crypt "$OPENVPN_CONFIG_DIR/tls-crypt.key"
    chmod 600 "$OPENVPN_CONFIG_DIR/tls-crypt.key"
    OVPN_PROTO=$([ "$VPN_PROTOCOL" = tcp ] && echo tcp-server || echo udp)
    sed -e "s#@VPN_PUBLIC_PORT@#$VPN_PUBLIC_PORT#" -e "s#@OVPN_PROTO@#$OVPN_PROTO#" \
        -e "s#@VPN_INTERFACE@#$VPN_INTERFACE#" -e "s#@VPN_NETWORK@#$VPN_NETWORK#" \
        -e "s#@VPN_NETMASK@#$VPN_NETMASK#" -e "s#@VPN_IPV6_SUBNET@#$VPN_IPV6_SUBNET#" \
        -e "s#@OPENVPN_CONFIG_DIR@#$OPENVPN_CONFIG_DIR#g" -e "s#@VPN_SERVER_ADDRESS@#$VPN_SERVER_ADDRESS#" \
        "$SRC/deploy/templates/server.conf.in" > "$OPENVPN_CONFIG_DIR/server.conf"
    cd "$SRC"
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-vpnpanel-forward.conf
    sysctl -q -p /etc/sysctl.d/99-vpnpanel-forward.conf
    systemctl enable --now openvpn-server@server
    /usr/local/sbin/wait-for-vpn-ip || die "OpenVPN did not come up; see journalctl -u openvpn-server@server"
    echo "OpenVPN server created (CA, server cert and tls-crypt key generated on this machine)."
  fi
fi

say "OpenVPN: compatibility check"
CONF="$OPENVPN_CONFIG_DIR/server.conf"
[ -f "$CONF" ] || die "$CONF not found. Re-run with --setup-openvpn or prepare it (docs/OPENVPN.md)."
missing=0
for d in "client-config-dir" "ccd-exclusive" "crl-verify" "management /run/openvpn-server/management.sock unix"; do
  grep -qE "^[[:space:]]*$d" "$CONF" || { warn "server.conf lacks: $d"; missing=1; }
done
grep -qE '^[[:space:]]*duplicate-cn' "$CONF" && warn "server.conf enables duplicate-cn — remove it (one certificate per device)."
[ "$missing" = 0 ] || warn "the panel needs these directives — follow docs/OPENVPN.md (adopt existing certificates BEFORE enabling ccd-exclusive)."
install -d -m 755 "$OPENVPN_CONFIG_DIR/ccd"

# ------------------------------------------------------------------ AdGuard Home
if [ "$SETUP_ADGUARD" = 1 ]; then
  say "AdGuard Home $ADGUARD_VERSION"
  /usr/local/sbin/wait-for-vpn-ip || die "the VPN address must exist before AdGuard can bind to it"
  id adguard >/dev/null 2>&1 || useradd --system --home /var/lib/adguardhome --shell /usr/sbin/nologin adguard
  install -d -m 750 -o adguard -g adguard /var/lib/adguardhome
  if [ ! -x /opt/AdGuardHome/AdGuardHome ]; then
    case "$(dpkg --print-architecture)" in
      amd64) AG_ARCH=amd64 ;; arm64) AG_ARCH=arm64 ;; armhf) AG_ARCH=armv7 ;;
      *) die "unsupported architecture for AdGuard Home: $(dpkg --print-architecture)" ;;
    esac
    T=$(mktemp -d)
    pkg="AdGuardHome_linux_${AG_ARCH}.tar.gz"
    base="https://github.com/AdguardTeam/AdGuardHome/releases/download/$ADGUARD_VERSION"
    curl -fsSL -o "$T/$pkg" "$base/$pkg"
    curl -fsSL -o "$T/checksums.txt" "$base/checksums.txt"
    (cd "$T" && grep " ./$pkg$" checksums.txt | sha256sum -c -) || die "AdGuard checksum mismatch"
    tar -xzf "$T/$pkg" -C "$T"
    install -d -m 755 /opt/AdGuardHome
    install -m 755 "$T/AdGuardHome/AdGuardHome" /opt/AdGuardHome/AdGuardHome
    rm -rf "$T"
  fi
  cat > /etc/systemd/system/adguardhome.service <<'EOF'
[Unit]
Description=AdGuard Home DNS filter (VPN-internal only)
After=network-online.target openvpn-server@server.service
Wants=network-online.target openvpn-server@server.service

[Service]
User=adguard
Group=adguard
ExecStartPre=+/usr/local/sbin/wait-for-vpn-ip
ExecStart=/opt/AdGuardHome/AdGuardHome --no-check-update -w /var/lib/adguardhome -c /var/lib/adguardhome/AdGuardHome.yaml
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/var/lib/adguardhome
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  AG_PORT=$(python3 -c "import sys,urllib.parse as u; print(u.urlparse(sys.argv[1]).port or 3080)" "$ADGUARD_URL")
  if [ ! -s /var/lib/adguardhome/AdGuardHome.yaml ]; then
    # The first-run wizard listens on 0.0.0.0:3000. Block it from the network while it runs,
    # even if UFW is not active yet.
    nft -f - <<'EOF'
table inet vpnpanel_setup {
  chain input { type filter hook input priority -20; policy accept; iifname != "lo" tcp dport 3000 drop; }
}
EOF
    trap 'nft delete table inet vpnpanel_setup 2>/dev/null || true' EXIT
    systemctl start adguardhome
    for _ in $(seq 1 30); do curl -fs -o /dev/null http://127.0.0.1:3000/control/install/get_addresses && break; sleep 1; done
    AG_USER=vpnpanel
    AG_PASS=$(openssl rand -base64 30 | tr -d '/+=' | cut -c1-32)
    # Configure the wizard immediately: web UI on loopback, DNS on the VPN address.
    curl -fsS -X POST http://127.0.0.1:3000/control/install/configure -H 'Content-Type: application/json' \
      -d "{\"web\":{\"ip\":\"127.0.0.1\",\"port\":$AG_PORT},\"dns\":{\"ip\":\"$VPN_SERVER_ADDRESS\",\"port\":53},\"username\":\"$AG_USER\",\"password\":\"$AG_PASS\"}" >/dev/null
    umask 027
    printf 'ADGUARD_USER=%s\nADGUARD_PASSWORD=%s\n' "$AG_USER" "$AG_PASS" > /etc/vpnpanel/adguard.env
    umask 022
    unset AG_PASS
    sleep 3
    systemctl stop adguardhome
    python3 - "$VPN_SERVER_ADDRESS" "$VPN_IPV4_SUBNET" <<'PY'
import sys, yaml
server_ip, subnet = sys.argv[1], sys.argv[2]
p = "/var/lib/adguardhome/AdGuardHome.yaml"
c = yaml.safe_load(open(p))
d = c["dns"]
d.update(bind_hosts=[server_ip, "127.0.0.1"],
         upstream_dns=["https://dns.quad9.net/dns-query", "https://cloudflare-dns.com/dns-query"],
         bootstrap_dns=["9.9.9.9", "149.112.112.112", "1.1.1.1"], fallback_dns=["9.9.9.9", "1.1.1.1"],
         ratelimit=300, ratelimit_subnet_len_ipv4=32, cache_optimistic=True,
         private_networks=[subnet], use_private_ptr_resolvers=False)
c["querylog"]["interval"] = "168h"
c["statistics"]["interval"] = "168h"
c["clients"]["runtime_sources"].update(whois=False, arp=False, rdns=False, dhcp=False, hosts=True)
c["filters"] = [
    {"enabled": True, "id": 101, "name": "[global] HaGeZi Threat Intelligence Feeds (medium)",
     "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt"},
    {"enabled": True, "id": 102, "name": "[global] URLHaus malicious URLs",
     "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt"},
    {"enabled": True, "id": 103, "name": "[global] Phishing URL Blocklist",
     "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt"},
]
f = c["filtering"]
f["blocked_services"]["schedule"]["time_zone"] = "UTC"
f.update(safebrowsing_enabled=True, parental_enabled=False)
f["safe_search"]["enabled"] = False
yaml.safe_dump(c, open(p, "w"), sort_keys=False)
PY
    chown adguard:adguard /var/lib/adguardhome/AdGuardHome.yaml; chmod 600 /var/lib/adguardhome/AdGuardHome.yaml
    nft delete table inet vpnpanel_setup 2>/dev/null || true
  fi
  systemctl enable --now adguardhome >/dev/null 2>&1
fi
[ -f /etc/vpnpanel/adguard.env ] || warn "/etc/vpnpanel/adguard.env missing — use --setup-adguard or create it (ADGUARD_USER/ADGUARD_PASSWORD)."

# ------------------------------------------------------------------ firewall
if [ "$CONFIGURE_FW" = 1 ]; then
  say "firewall (UFW)"
  command -v ufw >/dev/null || apt-get install -y -qq ufw >/dev/null
  # Determine SSH port(s): effective sshd config, then live listeners, then ssh.socket.
  mapfile -t SSH_PORTS < <(sshd -T 2>/dev/null | awk '/^port /{print $2}' | sort -u)
  [ "${#SSH_PORTS[@]}" -gt 0 ] || mapfile -t SSH_PORTS < <(ss -Htlnp 2>/dev/null | awk '/"sshd"/{n=split($4,a,":"); print a[n]}' | sort -u)
  [ "${#SSH_PORTS[@]}" -gt 0 ] || mapfile -t SSH_PORTS < <(systemctl show -p Listen ssh.socket 2>/dev/null | grep -oE ':[0-9]+ ' | tr -d ': ' | sort -u)
  [ "${#SSH_PORTS[@]}" -gt 0 ] || die "could not determine the SSH port(s) — refusing to touch the firewall (allow your SSH port in UFW manually, then re-run)"
  echo "SSH port(s) detected: ${SSH_PORTS[*]}"
  for p in "${SSH_PORTS[@]}"; do
    if ! ufw show added 2>/dev/null | grep -qE "ufw (allow|limit) ($p/tcp|$p)( |$)"; then
      echo "adding SSH rule for port $p before anything else"
      ufw allow "$p/tcp" comment "SSH"
    fi
  done
  ufw allow "$VPN_PUBLIC_PORT/$VPN_PROTOCOL" comment "OpenVPN"
  ufw allow in on "$VPN_INTERFACE" to "$VPN_SERVER_ADDRESS" port 53 proto udp comment "VPN DNS"
  ufw allow in on "$VPN_INTERFACE" to "$VPN_SERVER_ADDRESS" port 53 proto tcp comment "VPN DNS"
  ufw allow in on "$VPN_INTERFACE" to "$ADMIN_BIND_HOST" port "$ADMIN_PORT" proto tcp comment "VPN admin panel"
  ufw route allow in on "$VPN_INTERFACE" out on "$PUBLIC_INTERFACE" comment "VPN egress"
  NAT_RULE="-A POSTROUTING -s $VPN_IPV4_SUBNET -o $PUBLIC_INTERFACE -j MASQUERADE"
  if ! grep -qF -- "$NAT_RULE" /etc/ufw/before.rules; then
    cp -p /etc/ufw/before.rules "/etc/ufw/before.rules.vpnpanel-$(date -u +%Y%m%dT%H%M%SZ)"
    python3 - "$NAT_RULE" <<'PY'
import sys
rule = sys.argv[1]
p = "/etc/ufw/before.rules"
s = open(p).read()
if "*nat" in s:
    s = s.replace(":POSTROUTING ACCEPT [0:0]", ":POSTROUTING ACCEPT [0:0]\n" + rule, 1)
else:
    s = f"# NAT for the VPN (added by Family VPN Panel installer)\n*nat\n:POSTROUTING ACCEPT [0:0]\n{rule}\nCOMMIT\n\n" + s
open(p, "w").write(s)
PY
    echo "NAT rule added to /etc/ufw/before.rules (backup kept next to it)"
  fi
  grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.d/*.conf 2>/dev/null || {
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-vpnpanel-forward.conf; sysctl -q -p /etc/sysctl.d/99-vpnpanel-forward.conf; }
  if ufw status | grep -q "Status: active"; then
    # `ufw allow` already applied the filter rules live. Do NOT `ufw reload`: UFW does not flush
    # the nat table, so a reload duplicates the MASQUERADE rule. Add it live only if missing.
    read -r -a NAT_ARGS <<<"${NAT_RULE#-A }"
    iptables -t nat -C "${NAT_ARGS[@]}" 2>/dev/null || iptables -t nat -A "${NAT_ARGS[@]}"
  else
    ufw status verbose | sed -n '1,40p'
    echo "SSH port(s) allowed: ${SSH_PORTS[*]}"
    if confirm "UFW is inactive. Enable it now with the rules above?"; then
      ufw --force enable
    else
      warn "UFW left inactive. Enable it yourself after checking the rules: ufw enable"
    fi
  fi
fi

# ------------------------------------------------------------------ panel
say "panel: users & directories"
id vpnpanel >/dev/null 2>&1 || useradd --system --home /var/lib/vpnpanel --shell /usr/sbin/nologin vpnpanel
install -d -m 755 -o root -g root /opt/vpnpanel
install -d -m 750 -o vpnpanel -g vpnpanel /var/lib/vpnpanel /var/lib/vpnpanel/lists
install -d -m 750 -o root -g vpnpanel /etc/vpnpanel
chown root:vpnpanel "$ENV_FILE"; chmod 640 "$ENV_FILE"

say "panel: application code (root-owned, read-only for the service)"
rm -rf /opt/vpnpanel/app.new
cp -r "$SRC/app" /opt/vpnpanel/app.new
find /opt/vpnpanel/app.new -name '__pycache__' -prune -exec rm -rf {} +
chown -R root:root /opt/vpnpanel/app.new; chmod -R u=rwX,go=rX /opt/vpnpanel/app.new
rm -rf /opt/vpnpanel/app.old; [ -d /opt/vpnpanel/app ] && mv /opt/vpnpanel/app /opt/vpnpanel/app.old
mv /opt/vpnpanel/app.new /opt/vpnpanel/app
install -m 644 "$SRC/requirements.txt" /opt/vpnpanel/requirements.txt
[ -x /opt/vpnpanel/venv/bin/python ] || python3 -m venv /opt/vpnpanel/venv
/opt/vpnpanel/venv/bin/pip install -q --upgrade pip
/opt/vpnpanel/venv/bin/pip install -q -r /opt/vpnpanel/requirements.txt
/opt/vpnpanel/venv/bin/python -m compileall -q /opt/vpnpanel/app

say "panel: root helper, sudoers, tools"
install -m 750 -o root -g vpnpanel "$SRC/helper/vpnpanel-helper" /usr/local/sbin/vpnpanel-helper
SUDOERS_TMP=$(mktemp /etc/sudoers.d/.vpnpanel.XXXXXX)  # root-only directory, unpredictable name
cat > "$SUDOERS_TMP" <<'EOF'
# Family VPN Panel: the web service may run ONLY its validating root helper.
# Read-only polling verbs (every 15 s) are not logged; all changing verbs are.
Cmnd_Alias VPNPANEL_READ = /usr/local/sbin/vpnpanel-helper mgmt-status, \
                           /usr/local/sbin/vpnpanel-helper health, \
                           /usr/local/sbin/vpnpanel-helper ccd-list, \
                           /usr/local/sbin/vpnpanel-helper pki-list, \
                           /usr/local/sbin/vpnpanel-helper nft-counters
Defaults!VPNPANEL_READ !log_allowed, !pam_session
vpnpanel ALL=(root) NOPASSWD: /usr/local/sbin/vpnpanel-helper
EOF
visudo -cf "$SUDOERS_TMP" >/dev/null || { rm -f "$SUDOERS_TMP"; die "generated sudoers rule failed visudo -c"; }
install -m 440 -o root -g root "$SUDOERS_TMP" /etc/sudoers.d/50-vpnpanel; rm -f "$SUDOERS_TMP"
install -m 755 "$SRC/deploy/vpnpanel-admin" /usr/local/sbin/vpnpanel-admin
install -m 700 "$SRC/deploy/vpnpanel-backup" /usr/local/sbin/vpnpanel-backup
install -m 700 "$SRC/tools/vpn-nstest" /usr/local/sbin/vpn-nstest

say "panel: secrets"
if [ ! -s /etc/vpnpanel/secret.key ]; then
  /opt/vpnpanel/venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > /etc/vpnpanel/secret.key
fi
chown root:vpnpanel /etc/vpnpanel/secret.key; chmod 640 /etc/vpnpanel/secret.key
[ -f /etc/vpnpanel/adguard.env ] && { chown root:vpnpanel /etc/vpnpanel/adguard.env; chmod 640 /etc/vpnpanel/adguard.env; }

say "panel: TLS (name-constrained private CA, generated here)"
[ -s /etc/vpnpanel/tls/panel.crt ] || bash "$SRC/deploy/make-panel-tls.sh"

say "panel: systemd units"
install -m 644 "$SRC/deploy/vpnpanel.service" /etc/systemd/system/vpnpanel.service
cat > /etc/systemd/system/vpnpanel-nft.service <<'EOF'
[Unit]
Description=Family VPN Panel nftables restrictions (table inet vpnpanel)
After=ufw.service
Wants=ufw.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/vpnpanel/vpnpanel.nft
ExecStop=/usr/sbin/nft delete table inet vpnpanel

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/vpnpanel-backup.service <<'EOF'
[Unit]
Description=Nightly backup of VPN, PKI, panel database and filter config
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vpnpanel-backup
EOF
cat > /etc/systemd/system/vpnpanel-backup.timer <<'EOF'
[Unit]
Description=Nightly Family VPN Panel backup
[Timer]
OnCalendar=*-*-* 03:15:00 UTC
RandomizedDelaySec=15min
Persistent=true
[Install]
WantedBy=timers.target
EOF
install -d /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/vpnpanel.conf <<'EOF'
# nginx binds the VPN address, which exists only once OpenVPN is up.
[Unit]
After=openvpn-server@server.service
Wants=openvpn-server@server.service
[Service]
ExecStartPre=/usr/local/sbin/wait-for-vpn-ip
Restart=on-failure
RestartSec=5
EOF
systemctl daemon-reload
if [ ! -s /etc/vpnpanel/vpnpanel.nft ]; then
  echo '{"no_internet":[],"children":[],"panel_admins":[]}' | /usr/local/sbin/vpnpanel-helper nft-apply >/dev/null
fi
systemctl enable --now vpnpanel-nft.service >/dev/null 2>&1
systemctl enable --now vpnpanel-backup.timer >/dev/null 2>&1

say "panel: nginx"
sed -e "s#@ADMIN_BIND_HOST@#$ADMIN_BIND_HOST#g" -e "s#@ADMIN_PORT@#$ADMIN_PORT#g" \
    -e "s#@ADMIN_DNS_NAME@#$ADMIN_DNS_NAME#g" -e "s#@APP_PORT@#$APP_PORT#g" \
    -e "s#@VPN_IPV4_SUBNET@#$VPN_IPV4_SUBNET#g" \
    "$SRC/deploy/templates/nginx-vpnpanel.conf.in" > /etc/nginx/sites-available/vpnpanel
cat > /etc/nginx/vpnpanel-proxy.conf <<'EOF'
proxy_http_version 1.1;
proxy_set_header Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header Connection "";
proxy_read_timeout 120s;
proxy_buffering off;
EOF
ln -sf /etc/nginx/sites-available/vpnpanel /etc/nginx/sites-enabled/vpnpanel
nginx -t

say "panel: start"
systemctl enable vpnpanel.service nginx >/dev/null 2>&1
systemctl restart vpnpanel.service nginx
sleep 2
systemctl is-active vpnpanel nginx

if command -v ufw >/dev/null && ! ufw status | grep -q "$ADMIN_PORT/tcp on $VPN_INTERFACE"; then
  warn "no UFW rule for the admin panel on $VPN_INTERFACE — run with --configure-firewall or add it manually"
fi

cat <<EOF

Done. Next steps:
  1. Create the first admin:   sudo vpnpanel-admin create-admin <name>
  2. Trust /etc/vpnpanel/panel-ca.crt on your admin device(s) (fingerprint printed above).
  3. Open https://$ADMIN_BIND_HOST:$ADMIN_PORT over the VPN, or via an SSH tunnel:
       ssh -L $ADMIN_PORT:127.0.0.1:$ADMIN_PORT <user>@<server>  ->  https://127.0.0.1:$ADMIN_PORT
  4. Existing certificates issued before the panel: adopt them under Security & revocation.
EOF
