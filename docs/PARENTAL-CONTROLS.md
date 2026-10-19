# Parental controls

Family VPN Panel offers **network-level** controls that respect privacy: DNS filtering, service
blocking, SafeSearch, firewall schedules. It does **not** do TLS interception or HTTPS MITM, does not
require a root certificate on children's devices, and cannot read messages or page contents.

## Policies

A policy is a reusable template, assigned to a family member (all their devices) or overridden per
device. Built-in templates:

| Template | Contents |
|---|---|
| **Adult — unrestricted** | Malware & phishing protection only |
| **Child — standard** | Adult content, gambling, dating and malware blocked; bypass prevention; SafeSearch; YouTube Restricted Mode |
| **Child — strict** | Standard + social media, gaming and trackers blocked; access schedule enforced |
| **Guest** | Malware protection; no access to private networks; profiles expire (default 7 days) |

Create your own by cloning (*New policy*), e.g. "Child A" (social media allowed) and "Child B"
(social media blocked, gaming blocked after 21:00).

Each **service group** — social media, gaming, video & music streaming, messaging, dating, gambling,
AI chatbots, shopping — can be *Allowed*, *Always blocked* or *Blocked during* a daily window.
Individual apps can be blocked too. Custom block and allow lists take plain domains (subdomains
included).

Changes apply within seconds without reconnecting.

## Schedules

*Access schedules* define **allowed** internet hours per person:

* any number of windows, each with weekdays and start/end time;
* windows ending "before" they start run past midnight (e.g. 20:00–01:00);
* every schedule has its own IANA timezone; DST is handled; the server runs on UTC;
* presets (school days, daily, strict);
* outside the allowed hours the device stays connected to the VPN (DNS works, the panel shows the
  state) but has no internet access — enforced in the firewall, so it applies to every app.

Policies with *Enforce an access schedule* use a default (weekdays 06:30–21:30, weekends
07:30–22:30) until you set one.

## Temporary overrides

On *Access schedules* or a member's schedule page: **+30 / +60 / +120 min** extra time or **Pause
1 h**, or any duration from 5 minutes to 24 hours, with an optional note. Overrides end
automatically, can be cancelled, and are recorded in the audit log.

## Per-device switches

* **Turn internet off** — VPN-only access (DNS and panel still work).
* **Disable** — the device cannot connect at all (reversible).
* **Revoke** — permanent; see [OPENVPN.md](OPENVPN.md#revocation-workflow).

## What is recorded

| Recorded | Not recorded |
|---|---|
| Connect / disconnect times, duration | Passwords |
| Assigned VPN IP, public source IP | HTTPS contents, URLs or page contents |
| Byte counters (hourly) | Messages, calls, photos |
| DNS domain names (7 days, AdGuard) | Banking or form data |
| Admin actions (audit log) | Decrypted TLS traffic |

## Honest limitations

* DNS filtering blocks domains, not individual pages or videos.
* Apps that use hard-coded IPs, their own VPN, or encrypted-DNS endpoints unknown to the lists can
  evade DNS filtering. The bypass list, the resolver-address and port-853 firewall rules, the optional
  VPN-protocol block and service blocking reduce this; they don't eliminate it. Tunnels that look like
  ordinary HTTPS cannot be detected without TLS interception, which this project does not do.
* On phones a second VPN app usually *replaces* the family VPN rather than running inside it — the
  server cannot prevent that. Use the platform's controls: Android "Always-on VPN" + "Block
  connections without VPN", or Screen Time / MDM restrictions on installing VPN profiles and apps.
* Controls apply only while the device is connected to the VPN. Use the device's own settings
  (Screen Time, Family Link, always-on VPN / "Connect On Demand") to keep the VPN on.
* SafeSearch / YouTube Restricted Mode depend on those services honouring the DNS-based mechanism.
* Talk with your children about what is filtered and why — this tool is not meant for covert monitoring.
