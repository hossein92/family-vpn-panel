# Development

## Layout

```
app/            FastAPI application (routes, policy engine, monitor, templates, static files)
helper/         vpnpanel-helper — the only privileged component (stdlib-only Python)
deploy/         installer, systemd/nginx/OpenVPN templates, backup script, admin CLI wrapper
tools/          demo data seeder, vpn-nstest (namespace test clients for the integration test)
tests/          unit + HTTP flow tests (fake backend); tests/integration/ = opt-in server test
docs/           documentation and demo screenshots
```

Stack: Python 3.12, FastAPI, Jinja2 server-rendered pages, a little vanilla JS (no build step),
SQLite, nginx, OpenVPN 2.6, Easy-RSA 3, AdGuard Home.

## Demo mode

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
VPNPANEL_FAKE=1 .venv/bin/python tools/demo_seed.py
VPNPANEL_FAKE=1 .venv/bin/uvicorn app.main:app --port 8765 --reload
```

`VPNPANEL_FAKE=1` swaps the root helper and AdGuard client for in-memory fakes, stores data in
`.devdata/`, and uses non-secure cookies for plain HTTP. Sign in with `demo` / `demo-password-123`.
Demo identities are fictional; addresses come from documentation ranges.

## Tests

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check . && .venv/bin/ruff check helper/vpnpanel-helper
shellcheck -S warning deploy/*.sh deploy/vpnpanel-backup deploy/vpnpanel-admin tools/vpn-nstest
```

The test suite runs entirely against the fake backend. A guard in `tests/conftest.py` fails any test
that tries to resolve a hostname or connect to a non-loopback address, so tests can never reach a
real server.

### Integration test (your own server only)

`tests/integration/e2e_server.py` exercises a real installation: it signs in to the panel over
verified HTTPS, creates `E2E …` members and devices, connects real OpenVPN clients from network
namespaces and checks filtering, schedules, revocation, isolation and audit logging.

```bash
sudo vpnpanel-admin create-admin e2e-test        # temporary admin; disable it afterwards
sudo python3 tests/integration/e2e_server.py --i-am-on-the-vpn-server e2e-test /root/e2e-password.txt
sudo python3 tests/integration/e2e_server.py --cleanup
```

Targets come from `/etc/vpnpanel/panel.env`. External checks can be redirected with
`EGRESS_CHECK_URL`, `WEB_CHECK_URL`, `DOT_TEST_HOST` and `EXPECTED_EGRESS_IP` (useful in isolated
labs). It is never run in CI.

A disposable lab works well with a privileged systemd container (`ubuntu:24.04` + `systemd`,
`--privileged --cgroupns=host --device /dev/net/tun`). Note that Docker Desktop's userspace network
delivers packets with invalid TCP checksums, which tunnelled clients drop; attach the container to a
plain bridge network (e.g. `203.0.113.0/24`), use that as `PUBLIC_INTERFACE` and point the egress
checks at a container on it.

## Conventions

* Every state change goes through `engine.apply()`; never write OpenVPN/AdGuard/nftables state from
  routes directly.
* Every sensitive action calls `audit.log()`; never pass key material or passwords to it.
* New privileged operations need a helper verb with strict argument validation.
* Keep pages working without JavaScript; no inline scripts/styles (CSP).

## Contributing

Issues and pull requests are welcome. Please run the tests and linters, keep changes focused, and
never include real server addresses, names, keys or logs in issues, fixtures or screenshots — use
`example.com` and RFC 5737 addresses. Security issues: see [SECURITY.md](SECURITY.md).
