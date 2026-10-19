#!/bin/bash
# Lab-only drills (destructive to panel state; NEVER run on a real server). Run inside fvpsec-server.
set -uo pipefail
DB=/var/lib/vpnpanel/vpnpanel.db; DEST=/var/backups/family-vpn-panel
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1${2:+  — $2}"; fail=$((fail+1)); }
chk() { if eval "$2"; then ok "$1"; else bad "$1" "${3:-}"; fi; }
panel_up() { for _ in $(seq 1 20); do curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/login | grep -q 200 && return 0; sleep 1; done; return 1; }
q() { runuser -u vpnpanel -- sqlite3 "$DB" "$1"; }
latest() { ls -1t "$DEST"/vpn-backup-*.tgz | head -1; }

echo "== backup runs without leaving root-owned files next to the database"
admins_before=$(q "SELECT COUNT(*) FROM admins")
systemctl stop vpnpanel
# Checkpoint as the panel user so no -wal/-shm exist (never delete them: they hold committed data).
runuser -u vpnpanel -- sqlite3 "$DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
[ -e "$DB-wal" ] && echo "      (note: -wal still present after checkpoint)"
chk "backup succeeds while the panel is stopped" "/usr/local/sbin/vpnpanel-backup >/dev/null"
chk "panel data intact after the backup" "[ \"\$(q 'SELECT COUNT(*) FROM admins')\" = '$admins_before' ] && [ '$admins_before' -ge 1 ]"
chk "no root-owned files in /var/lib/vpnpanel" "[ -z \"\$(find /var/lib/vpnpanel -xdev -user root)\" ]" "$(find /var/lib/vpnpanel -user root)"
systemctl start vpnpanel
chk "panel starts and serves after the backup" panel_up
A=$(latest)
chk "archive is 0600 in a 0700 directory" "[ \"\$(stat -c %a $A)\" = 600 ] && [ \"\$(stat -c %a $DEST)\" = 700 ]"
chk "archive checksum verifies" "(cd $DEST && sha256sum -c $(basename "$A").sha256 >/dev/null)"
T=$(mktemp -d); tar -xzf "$A" -C "$T"
chk "archived database passes integrity_check" "[ \"\$(sqlite3 $T/vpnpanel.db 'PRAGMA integrity_check')\" = ok ]"
tar -tzf "$T/etc.tgz" > "$T/list"
chk "archive contains etc.tgz with PKI and panel config" "grep -q '^etc/openvpn/easy-rsa/pki/ca.crt' $T/list && grep -q '^etc/vpnpanel/panel.env' $T/list"
rm -rf "$T"

echo "== a panel-controlled symlink cannot make root copy other files"
systemctl stop vpnpanel
runuser -u vpnpanel -- mv "$DB" "$DB.real"; runuser -u vpnpanel -- ln -s /etc/shadow "$DB"
n_before=$(ls "$DEST"/vpn-backup-*.tgz | wc -l)
sleep 1
if /usr/local/sbin/vpnpanel-backup >/dev/null 2>&1; then bad "backup refuses a database symlinked to a root-only file"; else ok "backup refuses a database symlinked to a root-only file"; fi
newest=$(latest); T=$(mktemp -d)
if [ "$(ls "$DEST"/vpn-backup-*.tgz | wc -l)" -gt "$n_before" ]; then tar -xzf "$newest" -C "$T"; fi
chk "no shadow content captured in any new archive" "! grep -rqs '^root:' $T"
rm -rf "$T"; runuser -u vpnpanel -- rm "$DB"; runuser -u vpnpanel -- mv "$DB.real" "$DB"
systemctl start vpnpanel; panel_up

echo "== restore round-trip"
/usr/local/sbin/vpnpanel-backup >/dev/null; A=$(latest)
counts() { q "SELECT (SELECT COUNT(*) FROM family_members)||'/'||(SELECT COUNT(*) FROM devices)||'/'||(SELECT COUNT(*) FROM policies)"; }
orig=$(counts)
q "INSERT INTO family_members(name, type, policy_id, created_at) VALUES ('Drill temp', 'ADULT', 1, 'x')"
chk "change made after the backup is visible" "[ \"\$(q \"SELECT COUNT(*) FROM family_members WHERE name='Drill temp'\")\" = 1 ]"
systemctl stop vpnpanel
T=$(mktemp -d); tar -xzf "$A" -C "$T" vpnpanel.db
install -o vpnpanel -g vpnpanel -m 600 "$T/vpnpanel.db" "$DB"; rm -f "$DB-wal" "$DB-shm"; rm -rf "$T"
systemctl start vpnpanel
chk "panel serves after restore" panel_up
chk "restored counts match the backup ($orig)" "[ \"\$(counts)\" = '$orig' ]" "$(counts)"
chk "post-backup change is gone after restore" "[ \"\$(q \"SELECT COUNT(*) FROM family_members WHERE name='Drill temp'\")\" = 0 ]"
chk "vpnpanel-admin apply works after restore" "vpnpanel-admin apply >/dev/null"

echo "== service restarts"
for s in adguardhome vpnpanel-nft nginx vpnpanel openvpn-server@server; do
  systemctl restart "$s"; sleep 3
  chk "$s active after restart" "systemctl is-active --quiet $s"
done
sleep 5
chk "nft table present after restarts" "nft list table inet vpnpanel >/dev/null"
chk "panel serves after restarts" panel_up

echo "== rollback compatibility with the previous release (1985b66)"
if [ -f /root/old/helper ]; then
  cp -p /usr/local/sbin/vpnpanel-helper /root/helper.new
  install -m 750 -o root -g vpnpanel /root/old/helper /usr/local/sbin/vpnpanel-helper
  state='{"no_internet":[],"children":["10.8.0.50"],"panel_admins":["10.8.0.10"],"bypass_protected":["10.8.0.50"],"tunnel_blocked":["10.8.0.50"]}'
  chk "old helper accepts the new panel's firewall state" "echo '$state' | sudo -u vpnpanel sudo -n /usr/local/sbin/vpnpanel-helper nft-apply | grep -q '\"ok\": true'"
  nft list table inet vpnpanel > /root/nft.old
  chk "old helper renders the previous table (no new sets)" "! grep -q bypass_protected /root/nft.old"
  install -m 750 -o root -g vpnpanel /root/helper.new /usr/local/sbin/vpnpanel-helper
  vpnpanel-admin apply >/dev/null; nft list table inet vpnpanel > /root/nft.new
  chk "new helper restores the new table" "grep -q bypass_protected /root/nft.new"
  chk "previous app version works against the migrated database" \
    "cd /root/old && runuser -u vpnpanel -- /opt/vpnpanel/venv/bin/python -c 'from app import db, engine; db.init(); engine.desired_state(); print(1)' >/dev/null"
else
  bad "rollback compatibility" "/root/old not provided"
fi

echo; echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
