#!/usr/bin/env python3
"""Opt-in integration test — run as root ON your own VPN server (never in CI).

Drives the installed admin panel over HTTPS (verifying the panel CA), creates
"E2E ..." test members/devices, downloads their profiles, connects real
OpenVPN clients in network namespaces (tools/vpn-nstest) and checks
enforcement. Prints PASS/FAIL lines; --cleanup removes the test data again.

Usage:
  sudo python3 e2e_server.py --i-am-on-the-vpn-server <admin-user> <password-file>
  sudo python3 e2e_server.py --cleanup

All targets come from /etc/vpnpanel/panel.env on the machine it runs on.
Exit-IP checks compare against EXPECTED_EGRESS_IP (env var) when set.
"""
import http.cookiejar
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request


def _env():
    vals = {}
    with open("/etc/vpnpanel/panel.env") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                vals[k.strip()] = v.strip().strip("\"'")
    return vals


ENV = _env() if os.path.exists("/etc/vpnpanel/panel.env") else {}
ADMIN_PORT = ENV.get("ADMIN_PORT", "8443")
SERVER = ENV.get("VPN_SERVER_ADDRESS", "10.8.0.1")
PUBLIC_HOST = ENV.get("VPN_PUBLIC_HOST", "")
PUBLIC_PORT = ENV.get("VPN_PUBLIC_PORT", "443")
ADGUARD_PORT = ENV.get("ADGUARD_URL", "http://127.0.0.1:3080").rsplit(":", 1)[-1].strip("/")
EGRESS = os.environ.get("EXPECTED_EGRESS_IP", "")
# External targets (override for isolated test networks).
EGRESS_URL = os.environ.get("EGRESS_CHECK_URL", "https://api.ipify.org")   # must return the caller's IP
WEB_URL = os.environ.get("WEB_CHECK_URL", "https://www.wikipedia.org")      # any reachable site
DOT_HOST = os.environ.get("DOT_TEST_HOST", "1.1.1.1")                       # host with TCP 853 open
WORK = "/root/vpnpanel-e2e"
BASE = f"https://127.0.0.1:{ADMIN_PORT}"
CTX = ssl.create_default_context(cafile="/etc/vpnpanel/panel-ca.crt")
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=CTX))
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""), flush=True)


def get(path):
    with opener.open(BASE + path, timeout=60) as r:
        return r.read().decode(), r.geturl()


def post(path, data, raw=False):
    body = urllib.parse.urlencode(data, doseq=True).encode()
    req = urllib.request.Request(BASE + path, data=body, headers={"Origin": BASE.replace("https://", "https://")})
    with opener.open(req, timeout=120) as r:
        content = r.read()
        return (content if raw else content.decode()), r.geturl()


def csrf(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def sh(cmd, check_rc=False, timeout=60):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    if check_rc and p.returncode:
        raise RuntimeError(f"{cmd}: {p.stderr}")
    return p.stdout.strip()


def ns(name, cmd, timeout=30):
    return sh(f"/usr/local/sbin/vpn-nstest exec {name} {cmd}", timeout=timeout)


def dig(name, domain, server=SERVER):
    return ns(name, f"dig +short +time=3 +tries=1 @{server} {domain}").splitlines()


BLOCKED = (["0.0.0.0"], [], ["94.140.14.35"])  # null answer, NXDOMAIN, or AdGuard's parental block page


def blocked(ans):
    return ans in BLOCKED or (ans and ans[-1] in ("0.0.0.0", "94.140.14.35"))


def device_id(html_url):
    return int(re.search(r"/devices/(\d+)", html_url).group(1))


def cleanup():
    """Remove E2E test members/devices (certificates are revoked, PKI history stays)."""
    db = "/var/lib/vpnpanel/vpnpanel.db"
    rows = sh(f"sqlite3 {db} \"SELECT d.common_name, d.revoked FROM devices d JOIN family_members m ON m.id = d.family_member_id WHERE m.name LIKE 'E2E %'\"")
    for line in filter(None, rows.splitlines()):
        cn, rev = line.split("|")
        if rev == "0":
            sh(f"sudo -u vpnpanel sudo -n /usr/local/sbin/vpnpanel-helper revoke {cn} cessationOfOperation")
        sh(f"sudo -u vpnpanel sudo -n /usr/local/sbin/vpnpanel-helper ccd-delete {cn}")
    sh(f"""sqlite3 {db} "PRAGMA foreign_keys=ON;
      DELETE FROM traffic_stats WHERE device_id IN (SELECT d.id FROM devices d JOIN family_members m ON m.id=d.family_member_id WHERE m.name LIKE 'E2E %');
      DELETE FROM connection_sessions WHERE device_id IN (SELECT d.id FROM devices d JOIN family_members m ON m.id=d.family_member_id WHERE m.name LIKE 'E2E %');
      UPDATE vpn_certificates SET device_id = NULL WHERE device_id IN (SELECT d.id FROM devices d JOIN family_members m ON m.id=d.family_member_id WHERE m.name LIKE 'E2E %');
      DELETE FROM devices WHERE family_member_id IN (SELECT id FROM family_members WHERE name LIKE 'E2E %');
      DELETE FROM family_members WHERE name LIKE 'E2E %';" """)
    sh(f"rm -f {WORK}/e2e-*.ovpn")
    print("cleanup done")


def main():
    if os.geteuid() != 0 or not ENV:
        sys.exit("run as root on the VPN server (needs /etc/vpnpanel/panel.env)")
    if len(sys.argv) >= 2 and sys.argv[1] == "--cleanup":
        return cleanup()
    if len(sys.argv) != 4 or sys.argv[1] != "--i-am-on-the-vpn-server":
        sys.exit(__doc__)
    os.makedirs(WORK, mode=0o700, exist_ok=True)
    user, pwfile = sys.argv[2], sys.argv[3]
    password = open(pwfile).read().strip()

    # ---- login (TLS verified against the panel CA)
    html, url = get("/login")
    lc = re.search(r'name="login_csrf" value="([^"]+)"', html).group(1)
    html, url = post("/login", {"username": user, "password": password, "login_csrf": lc, "next": "/"})
    check("panel login over verified HTTPS", url.rstrip("/") == BASE, url)
    t = csrf(html)

    # ---- members + devices through the panel
    def member(name, mtype):
        h, u = post("/members", {"name": name, "type": mtype, "csrf_token": t})
        return int(re.search(r"/members/(\d+)", u).group(1))

    def device(mid, name, panel=False):
        data = {"member_id": mid, "display_name": name, "csrf_token": t}
        if panel:
            data["panel_access"] = "on"
        h, u = post("/devices", data)
        did = device_id(u)
        prof, _ = post(f"/devices/{did}/profile", {"csrf_token": t}, raw=True)
        cn = re.search(r"Device CN: (\S+)", prof.decode()).group(1)
        path = f"{WORK}/{cn}.ovpn"
        with open(path, "wb") as f:
            f.write(prof)
        sh(f"chmod 600 {path}")
        return did, cn, path

    adult_m = member("E2E Adult", "ADULT")
    child_m = member("E2E Child", "CHILD")
    a_id, a_cn, a_prof = device(adult_m, "Laptop", panel=True)
    c_id, c_cn, c_prof = device(child_m, "Tablet")
    c2_id, c2_cn, c2_prof = device(child_m, "Phone")
    check("unique CNs per device", len({a_cn, c_cn, c2_cn}) == 3, f"{a_cn}, {c_cn}, {c2_cn}")
    check(f"profiles embed remote {PUBLIC_HOST} {PUBLIC_PORT}",
          all(f"remote {PUBLIC_HOST} {PUBLIC_PORT}" in open(p).read()
              for p in (a_prof, c_prof, c2_prof)))
    check("private keys not left in PKI",
          not sh(f"ls /etc/openvpn/easy-rsa/pki/private /etc/openvpn/easy-rsa/pki/inline | grep -E '{a_cn}|{c_cn}|{c2_cn}'"))

    # ---- connect all three simultaneously
    for n, p in (("ea", a_prof), ("ec", c_prof), ("ed", c2_prof)):
        sh(f"/usr/local/sbin/vpn-nstest down {n}")
        out = sh(f"/usr/local/sbin/vpn-nstest up {n} {p}", timeout=120)
        check(f"client {n} connects", "connected" in out and "NOT" not in out, out.splitlines()[-1] if out else "")
    time.sleep(20)  # let the panel poll the management interface
    html, _ = get("/connections")
    check("three devices connected simultaneously",
          all(cn in html for cn in (a_cn, c_cn, c2_cn)) and "3 connected" in html.replace("&nbsp; ", "").replace("\n", " ")
          or all(cn in html for cn in (a_cn, c_cn, c2_cn)))
    ips = {n: ns(n, "ip -4 -o addr show dev tun0").split()[3] for n in ("ea", "ec", "ed")}
    check("distinct static VPN IPs", len(set(ips.values())) == 3, json.dumps(ips))
    for n in ("ea", "ec"):
        exit_ip = ns(n, f"curl -4 -s -m 10 {EGRESS_URL}")
        check(f"{n} egress through the VPN server", exit_ip == EGRESS if EGRESS else bool(exit_ip), exit_ip)

    # ---- filtering
    t0 = time.time()  # AdGuard reloads the child's category lists and rebuilds its engine
    while time.time() - t0 < 120 and dig("ec", "bet365.com") != ["0.0.0.0"]:
        time.sleep(5)
    print(f"      (filters active after {time.time() - t0:.0f}s)")
    porn_child = dig("ec", "pornhub.com")
    porn_adult = dig("ea", "pornhub.com")
    check("adult site blocked for child", blocked(porn_child), str(porn_child))
    xv = dig("ec", "xvideos.com")
    check("second adult domain blocked by NSFW list", xv == ["0.0.0.0"], str(xv))
    check("adult device unaffected", porn_adult and not blocked(porn_adult), str(porn_adult[:1]))
    gamb = dig("ec", "bet365.com")
    check("gambling blocked for child", blocked(gamb), str(gamb))
    gamb_a = dig("ea", "bet365.com")
    check("gambling allowed for adult", gamb_a and not blocked(gamb_a), str(gamb_a[:1]))
    g = dig("ec", "www.google.com")
    check("SafeSearch enforced for child (google → forcesafesearch)", "216.239.38.120" in g, str(g[:2]))
    y = dig("ec", "www.youtube.com")
    check("YouTube Restricted Mode for child", any(ip in y for ip in ("216.239.38.120", "216.239.38.119")), str(y[:2]))
    g_a = dig("ea", "www.google.com")
    check("no SafeSearch rewrite for adult", "216.239.38.120" not in g_a, str(g_a[:1]))
    bad = sh("grep -m1 -oP '^\\|\\|\\K[a-z0-9.-]+(?=\\^$)' /var/lib/adguardhome/data/filters/101.txt")
    mal = dig("ea", bad)
    check(f"global threat feed blocks for adults too ({bad})", blocked(mal), str(mal))
    bypass = ns("ec", "dig +short +time=3 +tries=1 @8.8.8.8 pornhub.com").splitlines()
    check("DNS to 8.8.8.8 is redirected to the filter", blocked(bypass), str(bypass))
    dot = sh(f"/usr/local/sbin/vpn-nstest exec ec timeout 5 bash -c 'echo > /dev/tcp/{DOT_HOST}/853' && echo open || echo closed")
    dot_a = sh(f"/usr/local/sbin/vpn-nstest exec ea timeout 5 bash -c 'echo > /dev/tcp/{DOT_HOST}/853' && echo open || echo closed")
    check("DNS-over-TLS blocked for child only", dot.endswith("closed") and dot_a.endswith("open"), f"child={dot} adult={dot_a}")

    # ---- strict policy: social media blocked (Child B scenario)
    pols, _ = get("/policies")
    strict_id = int(re.search(r'href="/policies/(\d+)">Child — strict', pols).group(1))
    post(f"/members/{child_m}", {"name": "E2E Child", "type": "CHILD", "policy_id": strict_id, "notes": "", "csrf_token": t})
    time.sleep(8)
    tk = dig("ec", "www.tiktok.com")
    check("Child strict: social media (TikTok) blocked", blocked(tk), str(tk[:1]))
    tk_a = dig("ea", "www.tiktok.com")
    check("adult can still reach TikTok", tk_a and not blocked(tk_a), str(tk_a[:1]))

    # ---- schedule: block now, then +60 min override
    now_h = time.gmtime().tm_hour
    start, end = f"{(now_h + 2) % 24:02d}:00", f"{(now_h + 3) % 24:02d}:00"  # allowed window not containing now
    post(f"/schedules/{child_m}", {"csrf_token": t, "enabled": "on", "timezone": "UTC",
                                   "w0_days": [str(d) for d in range(7)], "w0_start": start, "w0_end": end})
    time.sleep(3)
    blk = ns("ec", f"curl -4 -s -m 6 -o /dev/null -w '%{{http_code}}' {WEB_URL}") or "000"
    dns_ok = dig("ec", "wikipedia.org")
    check("schedule: outside allowed hours → no internet", blk == "000", blk)
    check("schedule: VPN + DNS keep working while blocked", bool(dns_ok) and dns_ok != ["0.0.0.0"], str(dns_ok[:1]))
    other = ns("ea", f"curl -4 -s -m 6 -o /dev/null -w '%{{http_code}}' {WEB_URL}")
    check("schedule does not affect adult", other in ("200", "301", "302"), other)
    post(f"/schedules/{child_m}/override", {"csrf_token": t, "kind": "allow", "minutes": "60"})
    time.sleep(3)
    allowed = ns("ec", f"curl -4 -s -m 8 -o /dev/null -w '%{{http_code}}' {WEB_URL}")
    check("override +60 min restores internet", allowed in ("200", "301", "302"), allowed)
    post(f"/schedules/{child_m}", {"csrf_token": t, "timezone": "UTC"})  # disable schedule

    # ---- per-device internet off (VPN-only)
    post(f"/devices/{a_id}/internet", {"csrf_token": t})
    time.sleep(3)
    off = ns("ea", f"curl -4 -s -m 6 -o /dev/null -w '%{{http_code}}' {WEB_URL}") or "000"
    check("internet disabled → VPN-only (no egress)", off == "000", off)
    post(f"/devices/{a_id}/internet", {"csrf_token": t})
    time.sleep(3)
    on = ns("ea", f"curl -4 -s -m 8 -o /dev/null -w '%{{http_code}}' {WEB_URL}")
    check("internet re-enabled", on in ("200", "301", "302"), on)

    # ---- panel reachability by device role
    pa = ns("ea", f"curl -sk -m 6 -o /dev/null -w '%{{http_code}}' https://{SERVER}:{ADMIN_PORT}/login")
    pc = ns("ec", f"curl -sk -m 6 -o /dev/null -w '%{{http_code}}' https://{SERVER}:{ADMIN_PORT}/login") or "000"
    check("admin panel reachable from adult device with panel access", pa == "200", pa)
    check("admin panel NOT reachable from child device", pc == "000", pc)
    meta = ns("ea", "curl -s -m 5 -o /dev/null -w '%{http_code}' http://169.254.169.254/") or "000"
    check("cloud metadata service blocked from VPN", meta == "000", meta)
    ag = ns("ea", f"curl -s -m 5 -o /dev/null -w '%{{http_code}}' http://{SERVER}:{ADGUARD_PORT}/") or "000"
    check("AdGuard admin UI not reachable from VPN", ag == "000", ag)

    # ---- IPv6 leak protection
    v6 = ns("ec", "ping -6 -c1 -W2 2606:4700:4700::1111 2>&1")
    check("IPv6 captured in tunnel and refused", "unreachable" in v6.lower() or "No route" in v6, v6.splitlines()[-1] if v6 else "")

    # ---- disable / disconnect / revoke via the panel
    post(f"/devices/{c2_id}/disable", {"csrf_token": t})
    time.sleep(4)
    st = json.loads(sh("sudo -u vpnpanel sudo -n /usr/local/sbin/vpnpanel-helper mgmt-status"))
    check("disable kicks the device", c2_cn not in [c["cn"] for c in st["clients"]])
    sh("/usr/local/sbin/vpn-nstest down ed")
    out = sh(f"/usr/local/sbin/vpn-nstest up ed {c2_prof}", timeout=150)
    check("disabled device cannot reconnect", "NOT connected" in out, out.splitlines()[0] if out else "")
    sh("/usr/local/sbin/vpn-nstest down ed")
    post(f"/devices/{c2_id}/enable", {"csrf_token": t})
    time.sleep(2)
    out = sh(f"/usr/local/sbin/vpn-nstest up ed {c2_prof}", timeout=150)
    check("re-enabled device reconnects", "connected" in out and "NOT" not in out, out.splitlines()[0] if out else "")

    post(f"/devices/{c_id}/revoke", {"csrf_token": t, "confirm_cn": c_cn, "reason": "cessationOfOperation"})
    time.sleep(4)
    st = json.loads(sh("sudo -u vpnpanel sudo -n /usr/local/sbin/vpnpanel-helper mgmt-status"))
    names = [c["cn"] for c in st["clients"]]
    check("revoked device dropped, others stay", c_cn not in names and a_cn in names and c2_cn in names, str(names))
    sh("/usr/local/sbin/vpn-nstest down ec")
    out = sh(f"/usr/local/sbin/vpn-nstest up ec {c_prof}", timeout=150)
    crl = sh(f"journalctl -u openvpn-server@server --since '-1min' --no-pager | grep -c 'certificate revoked: CN={c_cn}'")
    check("revoked device cannot reconnect (CRL)", "NOT connected" in out and int(crl or 0) >= 1, f"crl rejects={crl}")
    exit_ip = ns("ea", f"curl -4 -s -m 10 {EGRESS_URL}")
    check("other device still functional", exit_ip == EGRESS if EGRESS else bool(exit_ip), exit_ip)
    html, _ = get(f"/devices/{c_id}")
    check("revoked device history still visible", "Revoked" in html and "Connection history" in html)

    # ---- audit log
    html, _ = get("/audit?q=E2E")
    html2, _ = get("/audit")
    for a in ("device.created", "certificate.created", "certificate.revoked", "device.disabled", "profile.downloaded",
              "policy.assigned", "schedule.changed", "override.created", "admin.login"):
        check(f"audit: {a}", a in html2 or a in html)
    leak = sh("sqlite3 /var/lib/vpnpanel/vpnpanel.db \"SELECT COUNT(*) FROM audit_logs WHERE details LIKE '%PRIVATE KEY%' OR details LIKE '%<key>%'\"")
    check("no private key material in audit log", leak == "0", leak)
    logs = sh("journalctl -u vpnpanel -u nginx --since '-30min' --no-pager | grep -c 'PRIVATE KEY'")
    check("no private key material in service logs", logs in ("0", ""), logs)

    for n in ("ea", "ec", "ed"):
        sh(f"/usr/local/sbin/vpn-nstest down {n}")
    passed = sum(ok for _, ok in results)
    print(f"\n{passed}/{len(results)} checks passed")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
