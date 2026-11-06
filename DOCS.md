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
