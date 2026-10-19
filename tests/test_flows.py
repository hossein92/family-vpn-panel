"""End-to-end HTTP flows against the fake backend (no network, no root)."""
import re

import pytest
from fastapi.testclient import TestClient

from app import config, db, engine, main, monitor, security

PASSWORD = "a-long-test-password"


def csrf(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login_csrf(html):
    return re.search(r'name="login_csrf" value="([^"]+)"', html).group(1)


@pytest.fixture(scope="module")
def client():
    monitor.start = lambda: None  # no background thread in tests
    with TestClient(main.app, base_url="http://testserver") as c:
        if not db.q1("SELECT 1 FROM admins WHERE username = 'tester'"):
            db.ex("INSERT INTO admins(username, password_hash, created_at) VALUES ('tester', ?, ?)",
                  security.hash_password(PASSWORD), db.now_iso())
        yield c


@pytest.fixture(scope="module")
def token(client):
    r = client.get("/")
    assert r.url.path == "/login"
    r = client.post("/login", data={"username": "tester", "password": "wrong", "login_csrf": login_csrf(r.text)})
    assert r.status_code == 401
    r = client.post("/login", data={"username": "tester", "password": PASSWORD, "login_csrf": login_csrf(r.text)},
                    follow_redirects=False)
    assert r.status_code == 303
    return csrf(client.get("/").text)


def test_all_pages_render(client, token):
    for page in ["/", "/members", "/devices", "/devices/new", "/profiles", "/connections", "/policies",
                 "/policies/1", "/dns", "/schedules", "/traffic", "/traffic?period=today", "/security",
                 "/health", "/audit", "/settings"]:
        r = client.get(page)
        assert r.status_code == 200, page
        assert "Something went wrong" not in r.text


def test_csrf_is_enforced(client, token):
    assert client.post("/members", data={"name": "X", "type": "ADULT"}).status_code == 403
    assert client.post("/members", data={"name": "X", "type": "ADULT", "csrf_token": "bad"}).status_code == 403
    r = client.post("/members", data={"name": "X", "type": "ADULT", "csrf_token": token},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_member_device_lifecycle(client, token):
    t = token
    r = client.post("/members", data={"name": "Child One", "type": "CHILD", "csrf_token": t})
    assert "Child One added" in r.text
    mid = db.q1("SELECT id FROM family_members WHERE name = 'Child One'")["id"]

    r = client.post("/devices", data={"member_id": mid, "display_name": "Tablet", "csrf_token": t})
    assert "VPN profile created" in r.text
    d = db.q1("SELECT * FROM devices WHERE common_name = 'child-one-tablet'")
    assert d["vpn_ipv4"] == config.host(50)
    client.post("/devices", data={"member_id": mid, "display_name": "Tablet", "csrf_token": t})
    assert db.q1("SELECT vpn_ipv4 FROM devices WHERE common_name = 'child-one-tablet-2'")["vpn_ipv4"] == config.host(51)

    r = client.post(f"/devices/{d['id']}/profile", data={"csrf_token": t})
    assert r.status_code == 200 and "client" in r.text
    assert 'filename="child-one-tablet.ovpn"' in r.headers["content-disposition"]
    assert r.headers["cache-control"] == "no-store"

    assert "Internet disabled" in client.post(f"/devices/{d['id']}/internet", data={"csrf_token": t}).text
    assert "Device disabled" in client.post(f"/devices/{d['id']}/disable", data={"csrf_token": t}).text
    assert "re-enabled" in client.post(f"/devices/{d['id']}/enable", data={"csrf_token": t}).text
    assert "New profile generated" in client.post(f"/devices/{d['id']}/reissue", data={"csrf_token": t}).text

    r = client.post(f"/devices/{d['id']}/revoke", data={"csrf_token": t, "confirm_cn": "nope"})
    assert "Type the device" in r.text
    r = client.post(f"/devices/{d['id']}/revoke",
                    data={"csrf_token": t, "confirm_cn": "child-one-tablet", "reason": "keyCompromise"})
    assert "Certificate revoked" in r.text
    assert db.q1("SELECT revoked FROM devices WHERE id = ?", d["id"])["revoked"] == 1
    assert db.q1("SELECT COUNT(*) n FROM vpn_certificates WHERE device_id = ? AND status = 'revoked'", d["id"])["n"] == 2


def test_policy_schedule_and_rules(client, token):
    t = token
    mid = db.q1("SELECT id FROM family_members WHERE name = 'Child One'")["id"]
    pid = db.q1("SELECT id FROM policies WHERE name = 'Child — standard'")["id"]
    r = client.post(f"/policies/{pid}", data={
        "csrf_token": t, "name": "Child — standard", "kind": "CHILD", "block_adult": "on",
        "svc_gaming": "window", "svc_gaming_start": "21:00", "svc_gaming_end": "06:00",
        "custom_block": "game.example\nhttps://videos.example.net/x", "custom_allow": "school.example.org"})
    assert "Policy saved" in r.text
    assert "Not valid domains" in client.post(f"/policies/{pid}", data={"csrf_token": t, "custom_block": "not a domain!"}).text

    r = client.post(f"/schedules/{mid}", data={"csrf_token": t, "enabled": "on", "timezone": "Europe/Berlin",
                                               "w0_days": ["0", "1", "2", "3", "4"], "w0_start": "06:30", "w0_end": "21:30"})
    assert "Schedule saved" in r.text
    assert "60 extra minutes" in client.post(f"/schedules/{mid}/override",
                                             data={"csrf_token": t, "kind": "allow", "minutes": "60"}).text
    assert "cancelled" in client.post(f"/schedules/{mid}/override/cancel", data={"csrf_token": t}).text

    st = engine.desired_state()
    live = config.host(51)  # child-one-tablet-2 (the first tablet was revoked)
    assert f"||game.example^$client={live}" in st["user_rules"]
    assert any(r.startswith("@@||school.example.org^$important,client=") for r in st["user_rules"])
    assert live in st["nft"]["children"] and live in st["lists"]["adult"]


def test_guest_defaults_and_settings(client, token):
    t = token
    client.post("/members", data={"name": "Visitor", "type": "GUEST", "csrf_token": t})
    gid = db.q1("SELECT id FROM family_members WHERE name = 'Visitor'")["id"]
    client.post("/devices", data={"member_id": gid, "display_name": "Phone", "csrf_token": t})
    row = db.q1("SELECT expires_at, vpn_ipv4 FROM devices WHERE common_name = 'visitor-phone'")
    assert row["vpn_ipv4"] == config.host(150) and row["expires_at"]
    r = client.post("/settings", data={"csrf_token": t, "display_timezone": "Europe/Berlin", "profile_download_hours": "48",
                                       "session_idle_minutes": "30", "session_absolute_hours": "12",
                                       "default_cert_days": "825", "default_guest_days": "7"})
    assert "Settings saved" in r.text
    assert "incorrect" in client.post("/settings/password", data={"csrf_token": t, "current": "x", "new": "y", "again": "y"}).text


def test_internal_list_is_loopback_only(client):
    assert client.get("/internal/adguard/adult.txt", headers={"x-forwarded-for": "198.51.100.7"}).status_code == 404


def test_audit_log_has_actions_and_no_key_material(client, token):
    acts = {r["action"] for r in db.q("SELECT action FROM audit_logs")}
    for a in ["admin.login", "admin.login_failed", "device.created", "certificate.created", "certificate.revoked",
              "device.disabled", "policy.changed", "schedule.changed", "profile.downloaded", "override.created"]:
        assert a in acts, a
    assert not db.q1("SELECT 1 FROM audit_logs WHERE details LIKE '%BEGIN%' OR details LIKE '%<key>%'")


def test_security_headers(client, token):
    r = client.get("/")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_logout(client, token):
    assert client.post("/logout", data={"csrf_token": token}, follow_redirects=False).status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 303


SAFE_NEXT = ["/devices", "/devices/3?created=1", "/dns?device=2&q=a.example"]
UNSAFE_NEXT = ["//evil.example", "/\\evil.example", "/\\/evil.example", "/\t/evil.example", "/\n/evil.example",
               "https://evil.example", "javascript:alert(1)", "evil.example", "/%5C%5Cevil.example", "/%2F/evil.example"]


def _login_with_next(nxt):
    with TestClient(main.app, base_url="http://testserver") as c:
        r = c.get("/login")
        return c.post("/login", data={"username": "tester", "password": PASSWORD, "login_csrf": login_csrf(r.text),
                                      "next": nxt}, follow_redirects=False)


@pytest.mark.parametrize("nxt", SAFE_NEXT)
def test_login_redirect_keeps_local_paths(client, nxt):
    r = _login_with_next(nxt)
    assert r.status_code == 303 and r.headers["location"] == nxt


@pytest.mark.parametrize("nxt", UNSAFE_NEXT)
def test_login_redirect_rejects_non_local_targets(client, nxt):
    r = _login_with_next(nxt)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_login_page_escapes_next(client):
    r = client.get("/login", params={"next": '"><script>alert(1)</script>'})
    assert "<script>alert(1)" not in r.text


@pytest.mark.parametrize("referer,expected", [
    ("http://testserver/devices?show=all", "/devices?show=all"),
    ("https://evil.example/?x=//testserver/", "/schedules"),
    ("https://evil.example//testserver/devices", "/schedules"),
    ("http://testserver.evil.example/devices", "/schedules"),
    ("", "/schedules"),
])
def test_back_redirect_only_follows_same_origin_referer(client, referer, expected):
    with TestClient(main.app, base_url="http://testserver") as c:
        r = c.get("/login")
        c.post("/login", data={"username": "tester", "password": PASSWORD, "login_csrf": login_csrf(r.text)})
        token = csrf(c.get("/").text)
        if not db.q1("SELECT 1 FROM family_members WHERE name = 'Ref Test'"):
            c.post("/members", data={"csrf_token": token, "name": "Ref Test", "type": "ADULT"})
        mid = db.q1("SELECT id FROM family_members WHERE name = 'Ref Test'")["id"]
        r = c.post(f"/schedules/{mid}/override/cancel", data={"csrf_token": token},
                    headers={"referer": referer} if referer else {}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == expected
