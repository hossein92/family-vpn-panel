# Security audit report — `security-hardening` branch

Scope: the complete repository at release `1985b66`: the root helper and sudoers rule, FastAPI routes and authentication, every privileged operation and its call site, OpenVPN configuration generation, the nftables table and UFW integration, the AdGuard Home integration, IPv4/IPv6 routing, the installer, the backup and restore procedure, and the tests and CI.

Method:

- Read the code.
- For each suspected defect, write a regression test that fails on the old code, then fix it.
- Verify behaviour in a disposable Docker lab: a real installer run, real OpenVPN clients in network namespaces, real AdGuard Home and nftables.
- Never touch a production system.

A finding is marked **resolved** only when a test that failed before the fix passes after it. Fixing the code or the documentation alone does not count.

## 1. Findings matrix

| ID | Severity | Status | Finding | Affected files | Fix |
|---|---|---|---|---|---|
| F-01 | **Medium** (availability, root) | Confirmed · resolved | The root helper busy-loops forever when the OpenVPN management socket closes before its banner. | `helper/vpnpanel-helper` (`_mgmt`) | `2302b20` |
| F-02 | **Medium** (data integrity) | Confirmed · resolved | The documented restore replays the old database's write-ahead log onto the restored file. | `docs/OPERATIONS.md` | `b37afbd` |
| F-03 | Low | Confirmed · resolved | The root backup job opens the database inside the panel-owned directory. | `deploy/vpnpanel-backup` | `a195f30` |
| F-04 | Low (protection gap) | Confirmed · resolved | "Prevent filter bypass" promised to block encrypted-DNS resolvers but enforced it by DNS name only. | `helper/vpnpanel-helper`, `app/engine.py` | `b8b6b8c`, `974d70f` |
| F-05 | Low | Confirmed · resolved | `nft-apply` leaves rendered temporary rulesets in `/etc/vpnpanel` after a failure. | `helper/vpnpanel-helper` | `2302b20` |
| F-06 | Low | Confirmed · resolved (defence in depth) | The installer stages the sudoers rule at the fixed path `/tmp/vpnpanel.sudoers`. | `deploy/install.sh` | `1b7b555` |
| F-07 | Low | Hardening · resolved | The root helper passes its inherited environment to Easy-RSA, OpenSSL, nft and systemctl. | `helper/vpnpanel-helper` (`run`) | `f666d5e` |
| F-08 | Info | Not exploitable · hardened | The post-login `next` check relied on Starlette's Location encoding. | `app/main.py` | `8715ac6` |
| F-09 | Info | Not reachable from browsers · hardened | `back()` accepted any `Referer` that contained `//<host>/`. | `app/main.py` | `fee92fe` |
| R-01 | **Medium** (availability of revocation) | Found in final review · resolved | An invalid optional `EXTRA_BLOCKED_RESOLVERS` value made the helper fail at startup, which disabled every verb including `revoke`. | `helper/vpnpanel-helper` | `b9cdabf` |
| R-02 | Low | Found in final review · resolved | A management-socket failure while killing sessions after the CRL update turned a completed revocation into an error, leaving the database and the PKI inconsistent until a retry. | `helper/vpnpanel-helper` | `b9cdabf` |
| R-03 | Low | Found in final review · resolved | Two processes starting together (panel and `vpnpanel-admin`) could race on the additive migration; the second crashed with "duplicate column". | `app/db.py` | `943c27b` |

### F-01 — Root helper spins forever on a closed management socket

- **Before:** `_mgmt()` read the banner with `while b"\n" not in buf: buf += s.recv(4096)`. On EOF, `recv` returns `b""`, so the loop never ends and never blocks.
- **Preconditions:** OpenVPN closes the management connection before sending its banner, for example while it restarts. The panel polls the helper every 15 seconds, so this is a realistic timing.
- **Impact:** a root process at 100% CPU that never exits. The unprivileged panel cannot signal a root process, so every occurrence accumulates another one.
- **Fix:** EOF raises `ConnectionError`, which callers already treat as "management interface unavailable".
- **Test:** `test_helper_mgmt_eof_during_banner_does_not_hang`. A Unix socket that accepts and immediately closes the connection hangs the old code; the test's 5-second guard trips. The fixed code returns at once.

### F-02 — Restore replays a stale write-ahead log

- **Before:** the documented restore installed the backed-up `vpnpanel.db` over the live one and left `vpnpanel.db-wal`/`-shm` in place. The panel never checkpoints on shutdown, so the log still holds recent committed changes.
- **Lab evidence:** a backup with 3 members was restored with the documented steps and the database came back with 6. The rows written after the backup were replayed onto the restored file.
  - Here the integrity check still passed because the two files share a history.
  - With unrelated histories, the same mechanism can corrupt the database or bring back deleted records, for example a revoked device's row.
- **Fix:** the restore procedure now:
  1. verifies the archive checksum;
  2. stops the panel;
  3. removes the old `-wal`/`-shm`;
  4. installs the restored file;
  5. restores the database and `etc.tgz` together from the same archive, so the database and the PKI describe the same certificates.
- **Tests:**
  - `test_restore_procedure_discards_stale_wal_before_installing_database` checks the documented order; it fails on the old document.
  - The lab drill reproduces the stale-log state and verifies the documented steps.

### F-03 — Backup opened a panel-controlled path as root

- **Before:** `vpnpanel-backup`, which runs as root, ran `sqlite3 /var/lib/vpnpanel/vpnpanel.db ".backup …"`. The directory and the file belong to the unprivileged `vpnpanel` user.
- **Preconditions:** an attacker controls the `vpnpanel` account, for example through code execution in the web app.
- **Impact:**
  - Root follows a symlink placed there; the target only ever lands in a root-only archive, so this is not a disclosure.
  - Root parses database content shaped by the attacker.
  - When the panel is stopped, root can create root-owned `-wal`/`-shm` files that keep the panel from opening its database (denial of service).
- **Fix:** the snapshot is taken **as `vpnpanel`**:
  - Python's SQLite backup API, opened `mode=rw` so a missing database is never created;
  - an integrity check inside that process;
  - the result streamed over a pipe into root's private work directory.

  Root never opens a path under `/var/lib/vpnpanel`. The archive layout is unchanged.
- **Tests:**
  - Unit: `test_backup_never_opens_panel_database_as_root` (static), and functional tests of the snapshot code for consistency with rows still in the WAL, refusal of a non-database file, and refusal of a missing database.
  - Lab drills:
    - the backup leaves no root-owned files;
    - the archive is 0600 inside a 0700 directory and its checksum verifies;
    - a database path symlinked to `/etc/shadow` makes the backup fail with nothing captured;
    - the restore round-trip works.

### F-04 — "Prevent filter bypass" was DNS-only

- **Before:** the policy option said it *"Blocks encrypted-DNS resolvers, public VPN/proxy services and iCloud Private Relay"*, but it acted only through AdGuard lists, which match names. Encrypted DNS sent directly to a well-known resolver *address* involves no name lookup, so it was not covered.
- **Fix:** devices whose effective policy has the option join a new nftables set, `bypass_protected`, which rejects:
  - TCP/UDP 853;
  - all traffic to a curated set of public resolver addresses that serve only DNS.

  Plain DNS to those addresses still works, because port 53 is redirected to the filtering resolver before forwarding. No ordinary HTTPS or CDN address is affected. `EXTRA_BLOCKED_RESOLVERS` adds addresses; it accepts only public IPv4 addresses or networks of /16 or smaller.
- **Tests:**
  - Unit tests check rule scoping, input validation and that the old rules render unchanged.
  - Flow tests check set membership by policy and that turning the option off removes the device.
  - Lab results:
    - the child device is blocked from the resolver address;
    - the adult and guest devices can still reach it;
    - plain DNS to that address is still answered and filtered;
    - the child keeps ordinary web access.

### F-05 — Temporary ruleset left behind

When `nft -c` or `nft -f` failed, the temporary file created with `mkstemp` stayed in `/etc/vpnpanel`. It is now always removed.

- **Unit test:** `test_helper_nft_apply_cleans_temp_file_on_failure`.
- **Lab:** after a refused apply, no `.nft-*` file is left.

### F-06 — Predictable temporary file in the installer

The sudoers draft was written to `/tmp/vpnpanel.sudoers`, checked with `visudo`, then installed. That is a classic temp-file race. Ubuntu's `protected_symlinks`/`protected_regular` mitigate it but don't remove it.

- **Fix:** the draft is now staged with `mktemp` inside `/etc/sudoers.d` under a dot-name, which sudo ignores. A failed `visudo` check aborts the install.
- **Tests:** `test_scripts_do_not_use_fixed_paths_in_tmp`. In the lab, `visudo -c` passes after a full install.

### F-07 — Inherited environment in root subprocesses

`run()` copied `os.environ` into every root subprocess. sudo's default `env_reset` makes this safe today. A future sudoers change (`env_keep`, `SETENV`, `!env_reset`) would have let variables such as `OPENSSL_CONF`, `EASYRSA_*` or `LD_*` reach root processes.

- **Fix:** subprocesses now get a fixed allow-list environment.
- **Test:** `test_helper_subprocesses_get_a_fixed_minimal_environment`.
- **Lab:** issuing, revoking, regenerating the CRL and applying the firewall all work with the minimal environment.

### R-01 to R-03 — Final independent review

A fresh review of the complete diff, after merging the latest `main`, found three more issues. None was Critical or High.

- **R-01 (Medium):** the new optional setting was validated while the helper module loaded, so a typo made *every* verb fail, revocation included.
  - **Fix:** the value is recorded at load time. Only `nft-apply` refuses, with a clear error, and the live table stays as it is.
  - **Unit test:** `test_invalid_extra_resolvers_only_block_the_firewall_apply`.
  - **Lab drill:** with an invalid value, `ccd-list` and `health` still work; `nft-apply` refuses and the table is byte-identical; after the value is corrected, apply works again.
- **R-02 (Low):** session kills that run after the CRL update now tolerate socket errors.
  - **Test:** `test_revoke_session_kill_tolerates_management_socket_failure`.
- **R-03 (Low):** the migration ignores a "duplicate column" error caused by a concurrent process.
  - **Test:** `test_migration_tolerates_a_concurrent_process`.

The review also made the integration checks compare the live table without packet counters (`nft -s`), so a busy table can't cause false results.

### F-08 / F-09 — Redirect handling (not exploitable)

- **F-08:** values such as `/\evil.example`, `/<TAB>/evil.example` and `/%2F/evil.example` passed the old `next` check. Starlette percent-encodes backslashes and control characters in `Location`, so browsers stayed on the same origin; no open redirect was found. `safe_next()` now accepts only same-origin absolute paths and is applied both when rendering and when processing the login form.
- **F-09:** `back()` matched the `Referer` by substring. Exploiting it would require a victim's browser to send a forged same-origin `Referer` on a CSRF-protected POST, while the panel sends `Referrer-Policy: no-referrer`. It now compares scheme and host exactly and uses only the path.
- **Tests:** 23 parameterised flow tests.

## 2. Reviewed with no defect found

- **Sudoers:** a single rule for the helper; read-only polling verbs are excluded from logging.
- **Root helper:**
  - accepts a fixed set of verbs and at most 4 arguments of at most 200 characters;
  - validates Common Names with a strict regex and refuses `server`/`ca`;
  - checks client IPs against the client range and revocation reasons against a list;
  - always runs subprocesses from argument lists, never a shell;
  - writes CCD and CRL files atomically in root-only directories;
  - uses a management socket in a root-only directory;
  - shreds client keys after the profile is built.
- **Web application:**
  - Argon2id passwords with a constant-time login path;
  - per-user and per-IP lockout plus an nginx rate limit;
  - server-side sessions storing only the SHA-256 of the token;
  - `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict` cookies;
  - 30-minute idle and 12-hour absolute timeouts, and session rotation at login;
  - sessions destroyed on password change and on admin disable;
  - CSRF token plus Origin check on every POST;
  - Jinja autoescaping, with `|safe` only on constant strings;
  - bound SQL parameters (f-strings only build fixed identifiers);
  - strict CSP and security headers;
  - the AdGuard list feed is loopback-only, refuses proxied requests, and nginx returns 404 for `/internal/`.
- **AdGuard integration:**
  - loopback API with credentials in a 0640 root:vpnpanel file;
  - downloaded lists are reduced to validated domain names, so no rule injection is possible;
  - custom rules use the same validator.
- **Installer:**
  - parses `panel.env` as data;
  - verifies the AdGuard release checksum;
  - detects and allows the SSH port(s) before enabling UFW;
  - never overwrites an existing `server.conf` or PKI.
- **nftables:**
  - the table only restricts traffic (UFW stays authoritative);
  - it is replaced atomically with one `delete` + `create` in a single `nft -f`;
  - rules are evaluated per packet, so policy changes also affect existing connections;
  - all IPv6 forwarded from the tunnel is rejected.

## 3. Policy-aware firewall: how it works

- **Storage:** `policies` table. A device's effective policy is its own policy, falling back to its owner's.
- **Apply and remove:**
  1. `engine.apply()` computes IP sets from the database.
  2. The helper validates them, renders the whole table and replaces it in one transaction.
  3. A device is removed by dropping out of a set on the next apply.
  4. Applies are idempotent; they are skipped when the content hash hasn't changed.
- **Sets:**
  - `no_internet`, `children` (DoT/DoQ), `panel_admins`: as before.
  - `bypass_protected`: devices with *Prevent filter bypass*.
  - `tunnel_blocked`: devices with the new opt-in policy flag *Block VPN and proxy protocols*, off for every policy including existing ones. It rejects the standard ports of OpenVPN, WireGuard, IPsec/IKE (with ESP/AH), L2TP, PPTP (with GRE) and SOCKS. It can affect Wi-Fi Calling on some phones (IKE/IPsec), which is why it is opt-in.
- **Adult, Child, Guest:**
  - Built-in Child policies have *Prevent filter bypass* on.
  - Adult and Guest policies have neither flag.
  - Devices without the flags keep exactly their previous rules.
- **IPv4/IPv6:** the sets are IPv4. All IPv6 from the tunnel is rejected.
- **Disconnects and reconnects:** addresses are static (via CCD), so set membership is independent of connection state. Lab result: the restriction holds across a client reconnect and across restarts of `vpnpanel-nft`, the panel (which re-applies with force) and OpenVPN.
- **Compatibility:**
  - States without the new keys render the previous rules unchanged (unit test).
  - The previous release's helper accepts the new panel's state (lab).
  - The previous release's app runs against the migrated database (lab).
  - The schema change is one additive column.

## 4. IPv6 and leak behaviour

**Enforced on the server:**
- `server-ipv6` with a unique-local /64;
- pushed `redirect-gateway def1 ipv6`;
- `block-ipv6` on the server and pushed to clients;
- nftables rejects all IPv6 forwarded from the tunnel.

**Observed on a Linux client (OpenVPN 2.6, lab):**
- `::/3`, `2000::/4`, `3000::/4` and `fc00::/7` are routed into the tunnel.
- IPv6 to the internet is refused.
- DNS to an IPv6 resolver gets no answer.

**Depends on the client operating system (not verifiable in this environment):**
- **Outside the tunnel:** link-local and on-link LAN prefixes stay outside the tunnel on every platform.
- **Windows:** `block-outside-dns` is honoured by OpenVPN GUI 2.4 and later; other clients may still use LAN DNS.
- **iOS, Android and macOS:** support for pushed `block-ipv6` and IPv6 redirection varies by client app and version.
- **Disconnected:** traffic flows outside the VPN unless the OS enforces always-on behaviour, such as Android "Always-on VPN" with "Block connections without VPN", or MDM / Screen Time controls on iOS and macOS.

**What the server cannot see:** it never sees traffic that does not enter the tunnel.

## 5. Residual risks and unsupported guarantees

**Unsupported guarantees.** The project does not claim, and cannot provide at the network layer:
- Detection of encrypted DNS, proxies or VPNs carried over ordinary HTTPS to endpoints that are not on the lists. That would require TLS interception, which is deliberately not done.
- Blocking VPNs on non-standard ports, or new services before the lists include them.
- Detection of data carried inside DNS queries through the filtering resolver.
- Filtering while a device is disconnected, or for traffic to the device's own local network.
- Stopping a phone user from replacing the family VPN with another VPN app. Phones generally run one VPN at a time; preventing the switch needs OS or MDM controls.

**Accepted architectural risks:**
- **Panel account compromise:** whoever controls the `vpnpanel` account controls VPN access and filtering through the helper's verbs (issue, revoke, CCD, firewall sets), but gets no root shell. That is the panel's job, so it is by design.
- **Single admin role:** all admins have equal rights.
- **Limited service sandboxing:** `vpnpanel.service` can't use `NoNewPrivileges` or `ProtectSystem`, because the helper is invoked through sudo and inherits the unit's namespace.
- **SSH via the tunnel address:** VPN clients can reach the server's SSH port on its tunnel address. That's the same exposure as the public address.

**Theoretical:**
- `vpnpanel-admin` runs the CLI as `vpnpanel` on the administrator's terminal. No practical way to inject terminal input was found: Yama blocks attaching, the terminal's permissions block opening it, and there is no code-injection path.

**Operational:**
- After restoring a database that is older than the PKI, issuing a new certificate for a name that exists only in the PKI fails with a clear error. Restoring both from the same archive avoids this.

## 6. Test evidence

| Suite | Command | Result |
|---|---|---|
| Unit | `python -m pytest -q tests/test_units.py` | 35 passed |
| HTTP flows (fake backend, network-guarded) | `python -m pytest -q tests/test_flows.py` | 31 passed |
| Lint | `ruff check . && ruff check helper/vpnpanel-helper` (ruff 0.16.10) | clean |
| Python 3.12 (CI version) | full pytest + ruff in a `python:3.12-slim` container | 66 passed, clean |
| Shell | `shellcheck -S warning deploy/*.sh deploy/vpnpanel-backup deploy/vpnpanel-admin tools/vpn-nstest tests/integration/lab/*.sh` | clean |
| Secret scan | `gitleaks git` (16 commits), `trufflehog git --since-commit 1985b66` | no findings |
| Lab integration | `tests/integration/lab/run-lab.sh e2e` | **79/79** |
| Lab drills | `tests/integration/lab/run-lab.sh drills` | **32/32** |

Each regression test listed under F-01 to F-09 and R-01 to R-03 was run against the previous code and failed before it was committed with its fix.

**Lab environment:**
- Ubuntu 24.04 in privileged systemd containers on Docker Desktop (arm64);
- OpenVPN 2.6, Easy-RSA 3, AdGuard Home v0.107.79, nftables, UFW;
- a `203.0.113.0/24` network;
- a stand-in "internet" host, which also answers for one public-resolver address inside the lab only;
- all resources named `fvpsec-*`, created and removed by the script.

One e2e run failed 11 checks because the host machine slept for 42 minutes in the middle of the run. The panel then enforced its 30-minute idle timeout, which was correct behaviour. A rerun passed 79/79, and the CRL check now counts from the reconnect attempt instead of "the last minute" (`58df074`).

During the final review, one lab rebuild stopped while downloading AdGuard Home because of a transient network timeout. The drills that ran against that half-installed server failed and were discarded. A full rebuild then passed e2e 79/79 and drills 32/32.

**Not validated here (needs manual checks):**
- client behaviour on real iOS, Android, Windows and macOS devices (IPv6, DNS, behaviour while disconnected);
- the Wi-Fi Calling impact of the VPN-protocol flag;
- reachability of the real public resolvers from a production network;
- x86-64 hosts;
- an upgrade of a real installation.

## 7. Deployment

Applies to an installation running `1985b66` or later.

1. **Back up:**

   ```bash
   sudo vpnpanel-backup
   ```

   Also copy the current code and units:

   ```bash
   sudo tar -czpf /root/pre-hardening.tgz /opt/vpnpanel/app /usr/local/sbin/vpnpanel-helper /usr/local/sbin/vpnpanel-backup /etc/systemd/system/vpnpanel.service /etc/sudoers.d/50-vpnpanel
   ```

2. **Stage** the reviewed commit on the server, for example with `git archive`, and check its hash.
3. **Install**, with either option:
   - **Full update:** `sudo deploy/install.sh`, with no flags. It keeps the data, keys and existing firewall rules.
   - **Targeted update:** stop `vpnpanel`, then install the helper, `app/` and the backup script **together**. Start `vpnpanel`. On start it adds the new database column and re-applies the firewall table.
4. **Verify:**
   - `nft list table inet vpnpanel` shows the `bypass_protected`, `tunnel_blocked` and `dns_resolvers` sets;
   - *Server health* is all green;
   - connected devices stay connected; only the panel restarts;
   - one device per policy type can browse;
   - `sudo vpnpanel-backup` succeeds.
5. **Know the behaviour change:** devices whose policy has *Prevent filter bypass* can no longer contact the listed public resolvers directly, or port 853. The VPN-protocol block stays off until enabled per policy.

## 8. Rollback

1. Stop the panel:

   ```bash
   sudo systemctl stop vpnpanel
   ```

2. Restore the previous code:

   ```bash
   sudo tar -xzpf /root/pre-hardening.tgz -C /
   ```

3. Reload and restart, then re-apply. The previous helper renders the previous table:

   ```bash
   sudo systemctl daemon-reload && sudo systemctl start vpnpanel
   sudo vpnpanel-admin apply
   ```

**No database rollback is needed.** The previous app ignores the added column (verified in the lab). OpenVPN, AdGuard Home, the PKI and existing client profiles are untouched by both deployment and rollback.
