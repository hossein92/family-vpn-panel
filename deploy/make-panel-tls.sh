#!/bin/bash
# Creates a private CA that is X.509 *name-constrained* to the panel's own
# addresses (ADMIN_BIND_HOST, 127.0.0.1, ADMIN_DNS_NAME). Trusting it on an
# admin device is safe: it cannot vouch for any other website.
# It is NOT used for traffic interception and must never be installed on
# children's devices.
set -euo pipefail
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
load_env /etc/vpnpanel/panel.env
ADMIN_BIND_HOST=${ADMIN_BIND_HOST:-${VPN_SERVER_ADDRESS:-10.8.0.1}}
ADMIN_DNS_NAME=${ADMIN_DNS_NAME:-vpn-panel.home.arpa}
D=/etc/vpnpanel/tls
umask 077
install -d -m 700 "$D"
cd "$D"
if [ ! -s ca.key ]; then
  openssl req -x509 -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 \
    -keyout ca.key -out ca.crt -days 3650 -subj "/CN=Family VPN Panel CA (${ADMIN_BIND_HOST} only)" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "nameConstraints=critical,permitted;IP:${ADMIN_BIND_HOST}/255.255.255.255,permitted;IP:127.0.0.1/255.255.255.255,permitted;DNS:${ADMIN_DNS_NAME}"
fi
openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 \
  -keyout panel.key -out panel.csr -subj "/CN=${ADMIN_BIND_HOST}"
cat > panel.ext <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=IP:${ADMIN_BIND_HOST},IP:127.0.0.1,DNS:${ADMIN_DNS_NAME}
EXT
# 825 days = the maximum Apple platforms accept for TLS server certificates.
openssl x509 -req -in panel.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days 825 \
  -extfile panel.ext -out panel.crt
rm -f panel.csr panel.ext
chmod 600 ca.key panel.key; chmod 644 ca.crt panel.crt
install -m 644 ca.crt /etc/vpnpanel/panel-ca.crt
echo "Panel CA fingerprint (verify when installing it on your admin devices):"
openssl x509 -in ca.crt -noout -fingerprint -sha256
