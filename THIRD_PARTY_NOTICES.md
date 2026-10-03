# Third-party components

Family VPN Panel is licensed under the Apache License 2.0. **No third-party source code is vendored
in this repository.** The components below are installed or downloaded at install/run time from
their official sources and remain under their own licenses.

## Python packages (installed from PyPI via `requirements.txt`)

| Package | License |
|---|---|
| FastAPI | MIT |
| Starlette | BSD-3-Clause |
| Pydantic, pydantic-core | MIT |
| Uvicorn | BSD-3-Clause |
| Jinja2, MarkupSafe | BSD-3-Clause |
| argon2-cffi, argon2-cffi-bindings | MIT |
| python-multipart | Apache-2.0 |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| Transitive: anyio, h11, idna, click, cffi (MIT-0), pycparser, typing-extensions (PSF-2.0), annotated-types, typing-inspection, annotated-doc, opentelemetry-api (Apache-2.0) | permissive |

Development only (`requirements-dev.txt`): pytest (MIT), httpx (BSD-3-Clause), ruff (MIT).

## System software (used, not distributed)

| Software | License | Use |
|---|---|---|
| OpenVPN | GPL-2.0 | VPN server, invoked as a separate program |
| Easy-RSA | GPL-2.0 | PKI tool, invoked as a separate program |
| AdGuard Home | GPL-3.0 | DNS filter, official release binary downloaded by the installer; controlled via its HTTP API |
| nginx | BSD-2-Clause | reverse proxy |
| nftables / UFW / iptables | GPL-2.0 / GPL-3.0 | firewall tools, invoked as separate programs |

## Block lists (data fetched at run time, not distributed)

HaGeZi DNS Blocklists (GPL-3.0), URLHaus (CC0), Phishing URL Blocklist (see upstream), AdGuard
HostlistsRegistry entries (see each list). Their licenses apply to the list data.

## Artwork

All icons and styles in `app/static` and `app/templates` were created for this project.
