"""Test configuration: everything runs against the built-in fake backend.

* VPNPANEL_FAKE=1 — no sudo, no OpenVPN, no AdGuard, no real config files.
* Network guard — any attempt to open a socket to a non-loopback address fails
  the test, so the suite can never contact a real server.
"""
import ipaddress
import os
import socket
import tempfile

os.environ["VPNPANEL_FAKE"] = "1"
os.environ.setdefault("VPNPANEL_VAR", tempfile.mkdtemp(prefix="vpnpanel-test-"))
os.environ["VPNPANEL_ENV_FILE"] = "/nonexistent/panel.env"
# Documentation values only (RFC 5737 / example.com).
os.environ.setdefault("VPN_PUBLIC_HOST", "vpn.example.com")

import pytest  # noqa: E402

collect_ignore = ["integration"]

_real_connect = socket.socket.connect


def _guarded_connect(self, address):
    host = address[0] if isinstance(address, tuple) else None
    if host is not None:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError as e:
            raise RuntimeError(f"tests must not resolve/contact external hosts: {host!r}") from e
        if not ip.is_loopback:
            raise RuntimeError(f"tests must not contact non-loopback address {host}")
    return _real_connect(self, address)


_real_getaddrinfo = socket.getaddrinfo
_LOCAL_NAMES = {"localhost", "testserver", "127.0.0.1", "::1"}


def _guarded_getaddrinfo(host, *args, **kwargs):
    if host is not None and str(host) not in _LOCAL_NAMES:
        raise RuntimeError(f"tests must not resolve hostnames: {host!r}")
    return _real_getaddrinfo(host, *args, **kwargs)


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)
    yield
