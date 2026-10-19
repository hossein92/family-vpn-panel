#!/bin/bash
# Disposable Docker lab for the integration tests. Creates ONLY resources named fvpsec-*:
#   network fvpsec-net (203.0.113.0/24, documentation range), containers fvpsec-server and
#   fvpsec-ext, image fvpsec-server. Never touches other containers, networks or the host firewall.
#
#   tests/integration/lab/run-lab.sh up       build + start + install the panel in the lab server
#   tests/integration/lab/run-lab.sh e2e      run tests/integration/e2e_server.py inside the lab
#   tests/integration/lab/run-lab.sh drills   backup/restore, restart and failure drills (lab only)
#   tests/integration/lab/run-lab.sh down     remove every fvpsec-* resource
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../../.." && pwd)
NET=fvpsec-net; SRV=fvpsec-server; EXT=fvpsec-ext
SRV_IP=203.0.113.10; EXT_IP=203.0.113.20
# The ext container also answers for this public-resolver address inside the lab only.
RESOLVER=1.1.1.1
x() { docker exec "$SRV" bash -c "$*"; }
xi() { docker exec -i "$SRV" bash -c "$*"; }

up() {
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet 203.0.113.0/24 "$NET" >/dev/null
  docker build -q -t fvpsec-server -f "$HERE/Dockerfile.server" "$HERE" >/dev/null
  docker rm -f "$SRV" "$EXT" >/dev/null 2>&1 || true
  docker run -d --name "$EXT" --network "$NET" --ip "$EXT_IP" --cap-add NET_ADMIN \
    -v "$HERE/ext_services.py:/ext.py:ro" python:3.12-slim sleep infinity >/dev/null
  docker exec "$EXT" sh -c "apt-get update -qq && apt-get install -y -qq iproute2 >/dev/null && ip addr add $RESOLVER/32 dev lo"
  docker exec -d "$EXT" python3 /ext.py
  docker run -d --name "$SRV" --hostname vpnlab --network "$NET" --ip "$SRV_IP" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --device /dev/net/tun fvpsec-server >/dev/null
  for _ in $(seq 1 30); do x "systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'" && break; sleep 1; done
  x "ip route add $RESOLVER/32 via $EXT_IP"  # lab-only: the stand-in resolver lives on the ext container
  docker cp "$REPO/." "$SRV:/opt/src"
  xi "rm -rf /opt/src/.venv /opt/src/.git && install -d -m 750 /etc/vpnpanel && cat > /etc/vpnpanel/panel.env" <<ENV
VPN_PUBLIC_HOST=$SRV_IP
VPN_PUBLIC_PORT=443
VPN_PROTOCOL=tcp
VPN_IPV4_SUBNET=10.8.0.0/24
VPN_SERVER_ADDRESS=10.8.0.1
VPN_INTERFACE=tun0
PUBLIC_INTERFACE=eth0
ADMIN_BIND_HOST=10.8.0.1
ADMIN_PORT=8443
APP_PORT=8090
LOCAL_TIMEZONE=UTC
ENV
  x "cd /opt/src && deploy/install.sh --setup-openvpn --setup-adguard --configure-firewall --yes" | tail -15
  admin
  echo "lab up"
}

admin() {
  x "cd /opt/vpnpanel && runuser -u vpnpanel -- /opt/vpnpanel/venv/bin/python -c \"
from app import db, security
db.init()
if not db.q1('SELECT 1 FROM admins WHERE username = ?', 'e2e-test'):
    db.ex('INSERT INTO admins(username, password_hash, created_at) VALUES (?,?,?)', 'e2e-test',
          security.hash_password('lab-only-e2e-password'), db.now_iso())
\" && printf 'lab-only-e2e-password\n' > /root/e2e-password.txt && chmod 600 /root/e2e-password.txt"
}

e2e() {
  admin
  x "for n in ea ec ed eg; do /usr/local/sbin/vpn-nstest down \$n >/dev/null; done; python3 /opt/src/tests/integration/e2e_server.py --cleanup >/dev/null"
  x "cd /opt/src && EXPECTED_EGRESS_IP=$SRV_IP EGRESS_CHECK_URL=http://$EXT_IP/ip WEB_CHECK_URL=http://$EXT_IP/ \
     DOT_TEST_HOST=$EXT_IP RESOLVER_TEST_IP=$RESOLVER TUNNEL_TEST_HOST=$EXT_IP \
     python3 tests/integration/e2e_server.py --i-am-on-the-vpn-server e2e-test /root/e2e-password.txt"
}

drills() {
  # Previous release, for the rollback-compatibility drill.
  local old; old=$(mktemp -d)
  git -C "$REPO" archive 1985b66 app helper/vpnpanel-helper | tar -x -C "$old"
  x "rm -rf /root/old && mkdir -p /root/old"
  docker cp "$old/app" "$SRV:/root/old/app"; docker cp "$old/helper/vpnpanel-helper" "$SRV:/root/old/helper"
  rm -rf "$old"
  x "chown -R root:root /root/old && chmod 755 /root /root/old && chmod -R a+rX /root/old/app"
  docker cp "$HERE/drills.sh" "$SRV:/root/drills.sh"; x "bash /root/drills.sh"
}

down() {
  docker rm -f "$SRV" "$EXT" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "lab removed"
}

case "${1:-}" in
  up|e2e|drills|down) "$1" ;;
  *) sed -n '2,9p' "$0"; exit 1 ;;
esac
