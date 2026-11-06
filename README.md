# BlueberryProxy

BlueberryProxy is a home network DNS and HTTP proxy for local device discovery, reverse-engineering, and control. It supports configurable upstreams, DNS overrides, PTR records, refreshable blocklists, persistent HTTP proxy maps, and GraalJS request and response transformers.

## Features

- **DNS listeners**: UDP + TCP on one port (default 53), pure Clojure wire codec (RFC 1035 + EDNS(0))
- **DoH endpoint**: RFC 8484 `GET ?dns=` and `POST application/dns-message` on `/dns-query`
- **Rules**: exact / suffix / regex matching with `static`, `blackhole`, `redirect`, `upstream` and `passthrough` actions, persisted as EDN
- **Upstreams**: weighted UDP/TCP/DoH resolvers with failover, health tracking and exponential-backoff cooldown
- **Admin API**: status, rule CRUD, upstream management, query log and **LAN scanning** (ARP table + ping sweep) for device discovery
- **Query log**: every client IP + qname recorded (capped ring), so devices on the network identify themselves by what they resolve
- **HTTP transform proxy** (`xform.proxy`, default :8080): reverse proxy with declarative request/response header and body transforms, driven by maps stored via the admin API (`/proxy/maps`)
- **WebSocket event feed** (`xform.websocket`, default :8055): RFC 6455 text feed of proxy/DNS events for local inspection clients
- **Reverse DNS**: IPv4 and IPv6 PTR records can be created through the admin API
- **Refreshable DNS blocklists**: hosts files, domain lists and common AdBlock lines refresh on a schedule
- **DNS answer cache**: bounded in-memory cache ages positive TTLs, respects SOA negative TTLs, and reports hit, miss and eviction counts at `/status`
- **GraalJS transforms**: request and response scripts can edit HTTP methods, URIs, headers, bodies and status codes
- **TLS proxy listeners**: optional PKCS12 certificates, with locally generated self-signed certificates or a supplied keystore
- **Per-device listeners and mounts**: dedicated proxy interfaces select a persistent map, while `/proxymount` adds path routes to a map
- **Home Assistant research integrations**: Separate device integrations under `sre/` consume the generic proxy API

## Run locally

```sh
lein run                                  # needs port 53, or set env vars:
BLUEBERRY_DNS_PORT=5399 \
BLUEBERRY_DOH_PORT=8053 \
BLUEBERRY_ADMIN_PORT=8054 \
BLUEBERRY_ADMIN_BIND=127.0.0.1 \
BLUEBERRY_DATA_DIR=/tmp/bpdata lein run

dig @127.0.0.1 -p 5399 example.com
curl http://127.0.0.1:8054/status
```

Config precedence (low → high): defaults → `config.edn` → env vars → Home Assistant `/data/options.json`.

Env vars: `BLUEBERRY_DNS_PORT`, `BLUEBERRY_BIND`, `BLUEBERRY_DOH_PORT`, `BLUEBERRY_ADMIN_PORT`, `BLUEBERRY_ADMIN_BIND`, `BLUEBERRY_PROXY_PORT`, `BLUEBERRY_WEBSOCKET_PORT`, `BLUEBERRY_BLOCKLIST_REFRESH_HOURS`, `BLUEBERRY_DATA_DIR`, `BLUEBERRY_LOG_QUERIES`.

## Admin API

| Method | Path | Purpose |
|---|---|---|
| GET | `/status` | uptime, stats, upstream health, interfaces |
| GET/POST/DELETE | `/rules` | list / add / remove rules (`?id=` for DELETE) |
| GET/POST/DELETE | `/upstreams` | list / add / remove upstreams |
| GET | `/queries?n=100` | recent query log + top clients |
| GET | `/scan?cidr=192.168.1.0/24&timeout=250` | ARP table + ping sweep |
| GET | `/health` | liveness |
| GET/POST/DELETE | `/ptr` | inspect or edit IPv4 and IPv6 reverse DNS records |
| GET/POST/DELETE | `/blocklists` | inspect or edit blocklist sources |
| POST | `/blocklists/refresh` | refresh enabled sources now |
| GET/POST/DELETE | `/proxy/maps` | inspect or edit persistent HTTP reverse proxy maps |
| GET/POST/DELETE | `/proxy/transformers` | inspect or edit declarative and GraalJS transforms |
| GET/POST/DELETE | `/proxy/listeners` | persistent per-map listeners, applied at process start |
| GET/POST/DELETE | `/proxy/mounts` or `/proxymount` | path mounts attached to a persistent proxy map |

Bodies accept JSON or EDN.

## Reverse DNS and blocklists

Create PTR records with `POST /ptr` using `{"ip":"192.168.1.25","hostname":"plug.local"}`. For blocklists, post `{"id":"ads","url":"https://example.net/domains.txt"}` to `/blocklists`. Sources refresh every 24 hours by default. The parser accepts domains, hosts files, and `||domain^` filter rules. `POST /blocklists/refresh` starts an immediate update. Blocked A, AAAA, and ANY queries return `0.0.0.0` or `::`. Set `blocklist_action: nxdomain` to return NXDOMAIN.

## HTTP scripts

Register a JavaScript transformer by posting an ID, type and source to `/proxy/transformers`:

```json
{"id":"localize","type":"javascript","script":"function transform(req) { req.headers['X-Lab'] = 'blueberry'; req.body = req.body.replace('cloud', 'local'); return req; }"}
```

Attach the transformer ID to a map as `request-script-transformer` or `response-script-transformer`. Request input has `method`, `uri`, `headers` and `body`. Response input has `status`, `headers` and `body`. Scripts return the updated object. GraalJS receives no Java host access, file access, native access or thread creation. It is intended for trusted local scripts. The container uses Java 25 to match the GraalJS 25.3 runtime.

HTTP reverse proxying works on the shared listener and on isolated listeners assigned to a map. Set `proxy_tls_enabled` to serve the shared listener over HTTPS. To enable TLS on isolated listeners, set `tls: true` on each listener. The default certificate path is `/data/blueberry-proxy.p12`. Set `proxy_tls_self_signed` to generate a local PKCS12 certificate on first start, and set `proxy_tls_sans` to the DNS names and IP addresses clients use. A client must explicitly trust a self-signed certificate. TLS is terminated at the proxy, so this does not decrypt a device's direct connection to a remote server. CONNECT tunneling and WebSocket application-frame forwarding are not implemented. The WebSocket event listener streams inspected request and response events.

Listeners and mounts can be managed through the admin API. Listener changes take effect after a BlueberryProxy restart. The add-on uses host networking so configured LAN-facing ports bind directly on the Home Assistant host. Keep the admin API on its loopback default unless the home LAN needs access.

The Home Assistant integrations are separate packages in `sre/BlueberryJasco` and `sre/BlueberryVelux`. Copy the matching `custom_components` directory into Home Assistant and add the integration through the UI with the BlueberryProxy admin API URL. They register their own JS transformer IDs and expose proxy health, discovered LAN hosts and configured maps. The scripts stay under each device's `sre` directory. HTTPS certificate verification is enabled by default in both integrations, with an explicit option to disable it for a self-signed local certificate.

Map records can set `websocket-listener` to a route name. Connect to `ws://<host>:8055/<route>` to receive events assigned to that map. Connecting to `/` receives all proxy events.

### Rule examples

```json
{"id":"myts-cloud","match_type":"suffix","match":"yunext.com","action":"static","value":"192.168.1.10"}
{"id":"block-telemetry","match_type":"suffix","match":"telemetry.example.com","action":"blackhole"}
{"id":"local-api","match_type":"exact","match":"api.device.local","action":"redirect","value":"ha.local"}
```

## Home Assistant add-on

This directory is a Home Assistant add-on (see `config.yaml`, `Dockerfile`, `DOCS.md`).
Add this repository in **Settings → Add-ons → Add-on Store → Repositories** and install
**BlueberryProxy**. It runs with `host_network` so it can serve LAN DNS on port 53;
point your router or DHCP clients at the Home Assistant host.

## License

EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0 (see `LICENSE`).
