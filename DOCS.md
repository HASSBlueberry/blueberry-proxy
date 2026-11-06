# BlueberryProxy

A DNS proxy for Home Assistant: intercept, redirect or blackhole DNS queries on
your LAN, with DoH, an admin API and network scanning for device discovery.

## Installation

1. Add the BlueberryFaygo repository in **Settings → Add-ons → Add-on Store → ⋮ → Repositories**.
2. Install **BlueberryProxy** and start it.
3. The add-on binds the host network, so DNS, proxy, and WebSocket ports are
   served directly on the Home Assistant host.

> If `systemd-resolved` (or another local DNS) already owns port 53 on your
> host, change `dns_port` in the add-on configuration (e.g. `5353`) and point
> clients at `homeassistant:5353`, or free port 53 first.

## Configuration

Example `options`:

```yaml
dns_port: 53
bind: 0.0.0.0
doh_port: 8053
admin_port: 8054
admin_bind: 127.0.0.1
proxy_port: 8080
websocket_port: 8055
dns_cache_enabled: true
dns_cache_max_entries: 10000
dns_cache_max_ttl: 86400
blocklist_refresh_hours: 24
blocklist_action: blackhole
data_dir: /data
log: true
log_queries: true
upstreams:
  - name: cloudflare
    protocol: udp
    host: 1.1.1.1
    port: 53
  - name: cloudflare-doh
    protocol: https
    host: https://cloudflare-dns.com/dns-query
    port: 443
rules:
  - id: myts-cloud
    match_type: suffix
    match: yunext.com
    action: static
    value: 192.168.1.10
  - id: block-ads
    match_type: suffix
    match: ads.example.com
    action: blackhole
proxy_maps: []
blocklists: []
ptr_records: []
transformers: []
```

### Rule actions

| Action | Effect |
|---|---|
| `static` | answer with `value` (IPv4/IPv6/TXT, comma-separated for several) |
| `blackhole` | answer `0.0.0.0` / `::` |
| `redirect` | answer a CNAME pointing at `value` |
| `upstream` | force `value` to be an upstream name (e.g. `cloudflare-doh`) |
| `passthrough` | forward normally (default) |

`match_type` is `exact`, `suffix` (longest wins) or `regex`.

## DoH

```
https://<homeassistant>:8053/dns-query   (GET ?dns=base64url or POST body)
```

## Admin API

Bound to `127.0.0.1:8054` by default — reach it via the Home Assistant terminal
or an SSH add-on:

```sh
curl http://127.0.0.1:8054/status
curl http://127.0.0.1:8054/queries?n=50      # which device asked what
curl "http://127.0.0.1:8054/scan?cidr=192.168.1.0/24"   # ARP + ping sweep
curl -X POST http://127.0.0.1:8054/rules -d \
  '{"id":"myts","match_type":"suffix","match":"yunext.com","action":"static","value":"192.168.1.10"}'
```

Rules are persisted to `/data/rules.edn` and survive restarts; `options.rules`
only seeds the file the first time it is empty.

The admin service has no authentication. Keep its default loopback bind unless
you need LAN access, and only open it on a trusted home network when you do.
The shared proxy listener defaults to port 8080, while `ws://<host>:8055/`
streams inspection events. Enable `proxy_tls_enabled` for HTTPS on the shared
listener. Set `proxy_tls_self_signed` to create a PKCS12 certificate under
`/data`, or provide a PKCS12 keystore and password. Set `proxy_tls_sans` to the
LAN names and IP addresses used by clients. Clients need to trust a
self-signed certificate. TLS terminates at BlueberryProxy, and does not decrypt
connections a device makes directly to a remote server.

Dedicated listeners are stored at `POST /proxy/listeners`, each with `map-id`,
`port`, optional `bind`, `enabled`, and `tls`. They select only their assigned
map and start after a proxy restart. `POST /proxymount` stores a path mount with
`proxy-map-id`, `path`, and `target`. Mounts also take effect after restart.
The add-on uses host networking so listeners bind directly on the host.

PTR records and blocklists are managed through the admin API. For example:

```sh
curl -X POST http://127.0.0.1:8054/ptr -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.1.25","hostname":"plug.local"}'
curl -X POST http://127.0.0.1:8054/blocklists -H 'Content-Type: application/json' \
  -d '{"id":"ads","url":"https://example.net/domains.txt"}'
curl -X POST http://127.0.0.1:8054/blocklists/refresh
```

Blocklists accept domain-per-line, hosts file, and common AdBlock formats. They
refresh every 24 hours by default. Blocklisted A, AAAA and ANY lookups return
zero addresses. Use `blocklist_action: nxdomain` to reply with NXDOMAIN.

Upstream DNS responses are cached in memory by question, relevant query flags
and EDNS settings. Positive TTLs are aged on hits and capped by
`dns_cache_max_ttl`. NXDOMAIN and NODATA are cached only when an SOA record
provides a negative TTL. Truncated and error responses are not cached. The
`/status` endpoint reports cache hits, misses, evictions and entry count.

GraalJS scripts can edit HTTP requests and responses. Register a script at
`POST /proxy/transformers` with `id`, `type: "javascript"` and `script`. The
script declares `function transform(req) { ...; return req; }`. Attach its ID
to a map as `request_script_transformer` or `response_script_transformer` in
add-on options, or as the hyphenated JSON field in admin API calls. Request
objects contain `method`, `uri`, `headers`, and `body`. Response objects contain
`status`, `headers`, and `body`. Java 25 is used in the add-on container for the
GraalJS 25 runtime.

## Device discovery workflow

1. Point DHCP DNS at Home Assistant.
2. Wait for IoT devices to phone home; check `GET /queries` — each entry has
   the client IP and qname.
3. `GET /scan?cidr=...` merges the ARP table (MAC addresses) with a ping sweep.
4. Add `static` rules to pin cloud endpoints at a local mock, or `blackhole`
   rules to force devices into local-only mode.

## Dashboard and Home Assistant card

Version 0.2 serves a statistics dashboard at `http://HOST:8055/`, using the
configured `websocket_port` when changed. It includes a same-origin WebSocket
at `/events`, DNS allowed/blocked/error totals, domain/client rankings, cache
statistics, a bounded live-flow table, domain rules, blocking controls, and
proxy map switches. The HA app's Open Web UI button uses Ingress on a separate
port 8056, restricted to the Supervisor gateway IP `172.30.32.2`.

The local dashboard port also forwards management API calls to the configured
admin listener. It is an unauthenticated LAN management surface and belongs on
a trusted network. The existing port 8054 admin API continues to work. The new
HTTP facade limits uploads to 1 MiB and uses one request per connection.

`GET /stats` returns totals, top domains, top blocked domains, top clients,
tracking limits, blocking state, and DNS cache counters. Counters reset on
restart. DNS statistics respect `log_queries`. Rank storage admits at most
10,000 distinct domains and 4,096 clients while global totals keep counting.
Allowed means a locally permitted DNS request, including static answers and
redirects, and is not a promise of successful HTTP traffic. Upstream DNS
resolution failures are counted separately.

`GET /settings` reads `blocking-enabled`. `POST /settings` accepts a JSON boolean
for that field and persists it. Disabled blocking skips blocklists and
blackhole rules, leaving other DNS answers and proxy routing active. An exact
`passthrough` rule overrides a blocklist for its domain. The dashboard and card
use `dashboard-DOMAIN` IDs for editable exact allow/block rules. Remove a rule
through the web UI to restore ordinary policy. `POST /cache/clear` empties the
upstream answer cache, without resetting cache hit/miss counters.

The `/events` feed emits sanitized DNS, proxy request, and proxy response
summaries. Headers, bodies, URL credentials, and URL query strings are omitted.
The legacy root WebSocket and listener-specific routes retain inspection data.
Connections have bounded queues, ping/pong handling, and slow clients are
disconnected to keep publishers from waiting on network writes.

Install `sre/BlueberryProxy/custom_components/blueberry_proxy` for the HA card.
Add the BlueberryProxy Dashboard integration using its local port 8055 URL.
Then add `type: custom:blueberry-proxy-card` to a dashboard. Its module is
registered automatically. HA relays reads and writes over authenticated
WebSockets and permits these operations only for administrators. No direct
browser-to-proxy access or CORS configuration is required for the card.

Dashboard domain rules use priority 100 to resolve ties with existing exact
rules for the same domain. Match type and suffix length retain precedence.

## UScan discovery

UScan runs bounded background discovery jobs using native mDNS/DNS-SD, WSD, ONVIF, ARP and TCP probes. The Avahi scanner uses `avahi-browse` if available and otherwise reports a native DNS-SD fallback. It does not require an Avahi daemon for the other scanners. Select persistent profiles and override CIDRs, ports, interfaces, duration, timeout and probe budgets from the dashboard. Scope defaults use physical LAN interfaces and their actual prefixes. Large scans exceeding configured budgets fail explicitly. IPv6 scanning is not implemented.

`GET /uscan` returns interfaces, profiles, recent jobs and discovered devices. `POST /uscan/scanners` registers a profile with `id`, `kind`, `enabled`, `parameters`, and optional `script` for kind `graaljs`. `POST /uscan/jobs` accepts `scanner_ids` and `parameters`. Poll or cancel with `/uscan/jobs?id=JOB_ID` using GET or DELETE. `GET /uscan/devices` returns the full inventory. Administrators can import inventory through POST to that path with `source`, explicit `cidrs`, and up to 4096 `devices` carrying observed `ip`, `mac` and `hostname`. Every IP must fall inside the advertised CIDRs. Imported evidence remains distinct from active probe evidence.

A GraalJS scanner implements `function scan(ctx)`. It can iterate `ctx.targets`, read `ctx.parameters`, use `ctx.tcp(ip, port)` and `ctx.udp(ip, port, hexPayload)`, and publish `ctx.emit({ip, mac, hostname, ports, evidence})`. Hosts and ports are constrained by the profile. Scripts have no Java, filesystem or native-thread access. Context cancellation enforces the job deadline. These are administrative APIs on the same trusted-LAN and Ingress management boundary as the proxy's other configuration APIs.

The dashboard displays scan jobs, per-scanner failures and discovered devices. Discovery and scan events stream over `/events`. The Home Assistant integration maintains that connection while loaded and fires `blueberry_proxy_discovery` and `blueberry_proxy_scan` events, even when its card is closed. The card can start discovery. The legacy `/scan` response includes UScan evidence and fresh ARP records for existing integrations. Multicast discovery remains local to selected interfaces; explicit routed CIDRs do not create multicast forwarding.
