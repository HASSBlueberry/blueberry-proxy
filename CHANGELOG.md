# Change Log
All notable changes to this project will be documented in this file. This change log follows the conventions of [keepachangelog.com](https://keepachangelog.com/).

## [0.0.1]
### Added
- IPv4 and IPv6 reverse DNS PTR record management through `/ptr`.
- Scheduled and on-demand DNS blocklist updates with hosts, domain-per-line,
  and common AdBlock source parsing.
- GraalJS request and response transformer scripts using restricted polyglot
  contexts, with scripts attached to persistent proxy maps.
- Admin API management for PTR records and blocklist sources, plus status
  summaries for maps, transformers, and reverse records.
- Real DNS wire codec in `dns.dnsPrims` (RFC 1035 messages, name compression, EDNS(0) OPT).
- UDP and TCP listeners (`dns.over.udp`, `dns.over.tcp`) with length-prefix framing.
- DoH server endpoint (`dns.over.https`, RFC 8484 GET/POST on `/dns-query`).
- Upstream clients over UDP/TCP/DoH with weighted failover, health tracking
  and exponential-backoff cooldown (`dns.upstream.*`).
- EDN-backed rule store with exact/suffix/regex matching, static/blackhole/
  redirect/upstream/passthrough actions and a capped query log
  (`storage.storage`).
- Admin HTTP API: status, rule CRUD, upstreams, query log, LAN scan
  (ARP + ping sweep) (`admin.api`).
- HTTP transform reverse proxy (`xform.proxy`, port 8080) with declarative
  header/body transforms managed through `/proxy/maps` on the admin API.
- RFC 6455 WebSocket event feed (`xform.websocket`, port 8055) for local
  inspection clients.
- Home Assistant add-on packaging: `Dockerfile`, `config.yaml`, `DOCS.md`,
  repository `repository.json`.
- Local Jasco/myTouchSmart device frame codec (`local.jascoFrame`): `0xA1`
  16-byte header encode/parse with MAC conversion, validation, and
  login/countdown/command payload builders reverse-engineered from the app.
- Default add-on rules pinning Jasco cloud hosts (`yunext.com`,
  `iotworkshop.com` static → local mock; firmware host blackholed) so devices
  can be kept off the cloud from first boot.

### Changed
- `blueberryProxy/-main` now loads config (defaults → config.edn → env →
  `/data/options.json`), wires all listeners and shuts down cleanly on SIGTERM.

## [0.1.0] - 2026-11-05
### Added
- Files from the new template.

[Unreleased]: https://git.crit.rip/BlueberryFaygo/blueberryfaygo/compare/0.1.0...HEAD
[0.1.0]: https://git.crit.rip/BlueberryFaygo/blueberryfaygo/releases/tag/0.1.0

## 0.2.0

Added the local and HA Ingress statistics dashboard, sanitized live WebSocket
flow, bounded DNS domain/client rankings, persisted blocking controls, exact
domain allow/block rules, and DNS cache clearing. Added the independent HA
frontend integration and automatically registered management card. Query
history now returns the latest retained entries first, and runtime statistics
are excluded from saved configuration. WebSocket delivery uses bounded queues,
control frames, and shared HTTP access for the dashboard.

### App repository validation fix

Removed the invalid fixed-port `webui` field. The dashboard remains available through Ingress. Generated app packages are validated before deployment, and repository metadata points to the published apps repository.
