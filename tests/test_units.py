"""Unit tests: schedules, config parsing, domain validation, security helpers, root helper."""
import importlib.machinery
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app import config, engine, schedule, security

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- schedules

def test_window_same_day():
    dt = datetime(2026, 3, 2, 10, 0)  # Monday
    assert schedule.in_window(dt, [0], "06:30", "21:30")
    assert not schedule.in_window(dt, [1], "06:30", "21:30")
    assert not schedule.in_window(dt.replace(hour=22), [0], "06:30", "21:30")


def test_window_past_midnight_belongs_to_start_day():
    tue_early = datetime(2026, 3, 3, 0, 30)  # Tuesday 00:30
    assert schedule.in_window(tue_early, [0], "20:00", "01:00")      # Monday's window continues
    assert not schedule.in_window(tue_early, [1], "20:00", "01:00")


def test_schedule_respects_timezone_and_dst():
    windows = [{"days": list(range(7)), "start": "08:00", "end": "20:00"}]
    # 2026-03-29 is the EU DST switch: 07:30 UTC = 09:30 CEST (allowed); in winter it would be 08:30 CET.
    assert schedule.allowed_by_windows(windows, "Europe/Berlin", datetime(2026, 3, 29, 7, 30, tzinfo=timezone.utc))
    assert not schedule.allowed_by_windows(windows, "Europe/Berlin", datetime(2026, 1, 10, 6, 30, tzinfo=timezone.utc))


def test_next_change():
    windows = [{"days": list(range(7)), "start": "08:00", "end": "20:00"}]
    nxt = schedule.next_change(windows, "UTC", datetime(2026, 5, 1, 19, 0, tzinfo=timezone.utc))
    assert nxt == datetime(2026, 5, 1, 20, 0, tzinfo=timezone.utc)


def test_invalid_time_rejected():
    with pytest.raises(ValueError):
        schedule.minutes("25:00")


# ---------------------------------------------------------------- config / engine helpers

def test_env_file_parsing(tmp_path):
    f = tmp_path / "panel.env"
    f.write_text('# comment\nVPN_PUBLIC_HOST="203.0.113.10"\n\nVPN_PUBLIC_PORT=1194\nBROKEN LINE\n')
    vals = config.load_env_file(f)
    assert vals == {"VPN_PUBLIC_HOST": "203.0.113.10", "VPN_PUBLIC_PORT": "1194"}


def test_example_env_contains_only_documentation_values():
    vals = config.load_env_file(ROOT / ".env.example")
    assert vals["VPN_PUBLIC_HOST"] == "vpn.example.com"
    assert "ADGUARD_PASSWORD" not in vals


def test_host_offsets():
    assert config.host(10) == "10.8.0.10" and config.SERVER_VPN_IP == "10.8.0.1"


def test_parse_domains():
    good, bad = engine.parse_domains("Example.COM\nhttps://sub.example.org/path\n*.wild.example.net\n# c\nnot a domain\n")
    assert good == ["example.com", "sub.example.org", "wild.example.net"]
    assert bad == ["not a domain"]


def test_slug():
    assert engine.slug("Child One — iPad") == "child-one-ipad"
    assert engine.slug("Ünïcodé") == "unicode"


# ---------------------------------------------------------------- security

def test_password_policy():
    assert security.password_problems("short")
    assert security.password_problems("tester-password-1", "tester")
    assert not security.password_problems("correct horse battery staple")


def test_csrf_compare():
    assert security.csrf_ok("abc", "abc")
    assert not security.csrf_ok("abc", "abd")
    assert not security.csrf_ok("", "")


# ---------------------------------------------------------------- root helper (pure functions only)

@pytest.fixture(scope="module")
def helper():
    import os
    path, umask = os.environ.get("PATH", ""), os.umask(0o022)
    os.umask(umask)
    loader = importlib.machinery.SourceFileLoader("vpnpanel_helper", str(ROOT / "helper" / "vpnpanel-helper"))
    spec = importlib.util.spec_from_loader("vpnpanel_helper", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    os.environ["PATH"] = path  # the helper hardens PATH/umask for itself; undo for the test process
    os.umask(umask)
    mod.configure({"VPN_PUBLIC_HOST": "203.0.113.10", "VPN_IPV4_SUBNET": "10.8.0.0/24",
                   "VPN_IPV6_SUBNET": "fd00:db8:1:1::/64"})
    return mod


def test_helper_validates_common_names(helper):
    assert helper.check_cn("alex-phone") == "alex-phone"
    for bad in ["../etc", "Alex", "server", "a", "x" * 70, "a b"]:
        with pytest.raises(helper.HelperError):
            helper.check_cn(bad)


def test_helper_validates_client_ips(helper):
    assert helper.check_client_ip("10.8.0.42") == "10.8.0.42"
    for bad in ["10.8.0.1", "10.8.0.0", "10.8.0.255", "10.8.1.5", "192.0.2.1", "nonsense"]:
        with pytest.raises(helper.HelperError):
            helper.check_client_ip(bad)


def test_helper_ipv6_mapping(helper):
    assert helper.ipv6_for("10.8.0.10") == "fd00:db8:1:1::10"


def test_helper_rejects_bad_interface(helper):
    with pytest.raises(ValueError):
        helper.configure({"VPN_INTERFACE": "tun0; rm -rf /"})
    helper.configure({"VPN_PUBLIC_HOST": "203.0.113.10", "VPN_IPV6_SUBNET": "fd00:db8:1:1::/64"})


def test_helper_nft_rendering(helper):
    text = helper.NFT_TEMPLATE.format(
        no_internet=helper._elements(["10.8.0.51"]), children=helper._elements(["10.8.0.51", "10.8.0.50"]),
        panel_admins="", vpn_if="tun0", server_ip=helper.SERVER_IP, vpn_net=helper.VPN_NET,
        admin_port=8443, adguard_port=3080)
    assert "elements = { 10.8.0.50, 10.8.0.51 }" in text
    assert "dnat ip to 10.8.0.1" in text and "169.254.0.0/16" in text
    assert "flush ruleset" not in text


def test_helper_env_reader(helper, tmp_path):
    f = tmp_path / "panel.env"
    f.write_text("VPN_PUBLIC_HOST='vpn.example.com'\n#X=1\n")
    assert helper.read_env_file(str(f)) == {"VPN_PUBLIC_HOST": "vpn.example.com"}


def test_helper_output_is_json(helper, capsys):
    helper.out({"ok": True})
    assert json.loads(capsys.readouterr().out) == {"ok": True}
