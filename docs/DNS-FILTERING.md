# DNS filtering

DNS filtering is done by [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome). The panel
configures it through its local REST API instead of duplicating a filtering engine.

## Exposure

* DNS listens on `VPN_SERVER_ADDRESS:53` and `127.0.0.1:53` only; UFW allows port 53 only on the
  VPN interface. It is not an open resolver.
* The web UI/API listens on `127.0.0.1:3080`; the panel's nftables table also drops VPN traffic to it.
* systemd-resolved keeps `127.0.0.53` for the host itself; there is no port conflict.
* Upstreams: Quad9 and Cloudflare over DNS-over-HTTPS, DNSSEC validation on.

## Per-device clients

Every device is an AdGuard *persistent client* named after its CN and identified by its static VPN
IP, with settings derived from its effective policy:

| Policy option | AdGuard setting |
|---|---|
| Malware & phishing | Safe Browsing |
| Adult content | Parental Control + the NSFW category list |
| SafeSearch | Safe search for Google, Bing, DuckDuckGo, Yandex, Ecosia, Pixabay |
| YouTube Restricted Mode | Safe search for YouTube (`restrictmoderate.youtube.com`) |
| Service groups / individual apps | Blocked services (time windows evaluated by the panel) |
| Prevent filter bypass | Encrypted-DNS/VPN/proxy list + iCloud Private Relay & proxy services |

## Lists

| Scope | List (default) |
|---|---|
| Everyone | HaGeZi Threat Intelligence Feeds (medium), URLHaus, Phishing URL Blocklist |
| Per category | HaGeZi NSFW · HaGeZi Gambling (medium) · HaGeZi Light (ads/trackers) · HaGeZi DoH/VPN/Proxy bypass |

Category lists are downloaded by the panel (domains only), and served to AdGuard from loopback as
rules restricted to the devices that need them, e.g. `||example.com^$client=10.8.0.50|10.8.0.51`.
When membership changes, the list URL gets a new version parameter so AdGuard reloads exactly that
list. Lists are refreshed daily. The lists are third-party data fetched at runtime (licensing of the
upstream lists applies to the data; nothing is redistributed in this repository).

Custom rules: per-policy block/allow lists become `$client` rules (allow rules use `$important` so
they win over lists); the global blocklist on the *DNS filtering* page applies to all devices.

## Leak and bypass protection

* nftables redirects **all** DNS (UDP/TCP 53) from the tunnel to AdGuard, so `8.8.8.8` configured on a
  device still ends up at the filter.
* Child devices cannot reach port 853 (DNS-over-TLS / DNS-over-QUIC).
* DNS-over-HTTPS cannot be distinguished from normal HTTPS without interception; child policies block
  known DoH endpoints by name instead.

## Privacy

* The query log (domain names, client IP, result) is kept for **7 days**; statistics for 7 days.
* WHOIS / reverse DNS / ARP client lookups are disabled.
* Safe Browsing and Parental Control use AdGuard's hash-prefix lookups: only a short prefix of a
  domain's hash is sent to AdGuard's servers. Disable them per policy if you prefer local lists only.
* The panel shows recent lookups per device to admins. Nothing beyond domain names is visible —
  no URLs, page contents or HTTPS data.

To change retention, edit `querylog.interval` in `/var/lib/adguardhome/AdGuardHome.yaml` (stop
`adguardhome` first) or use the AdGuard UI through an SSH tunnel to `127.0.0.1:3080`.
