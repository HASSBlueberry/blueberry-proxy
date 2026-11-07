# BlueberryProxy Dashboard for Home Assistant

This custom integration adds a locally hosted dashboard card for BlueberryProxy
0.2 or later. It serves the card JavaScript automatically and uses Home
Assistant's authenticated WebSocket connection for statistics, live traffic,
and management. The browser never needs direct access to the proxy. The
integration and its commands require an HA administrator account.

## Install

Copy `custom_components/blueberry_proxy` into Home Assistant's
`custom_components` directory and restart Home Assistant. Add **BlueberryProxy
Dashboard** through Settings, Devices & services. Enter the proxy's dashboard
URL, normally `http://YOUR_PROXY_HOST:8055`. With HA Core and the proxy using
host networking on the same machine, `http://127.0.0.1:8055` is suitable. Setup
checks the proxy identity, statistics endpoint, and WebSocket handshake.

Reload the browser after installing the integration. In your HA dashboard,
choose Add card and select BlueberryProxy, or use this YAML.

```yaml
type: custom:blueberry-proxy-card
title: Home network
```

The card selects the configured proxy automatically. If you have multiple
instances, it offers a selector. Set `entry_id` in the card configuration to
pin a card to one instance. No separate Lovelace resource registration is
required, because the integration registers its own module URL.

## Controls and live data

The card shows requested, allowed, and blocked DNS totals, resolution failures,
cache size, top requested and blocked domains, and the latest ten DNS or HTTP
summary events. It can pause or resume blocking, refresh blocklists, clear the
DNS cache, add exact domain allow/block rules, and enable or disable existing
reverse proxy maps. Domain buttons use the same deterministic rule IDs as the
full dashboard so a later decision replaces the earlier one. The full web UI
also lets you remove those rules.

Statistics are sampled every five seconds. Live events share one upstream
WebSocket connection per configured proxy and are batched for card clients.
Subscriptions, timers, and connections are cancelled when the card disconnects
or the integration unloads. Request headers, bodies, URL credentials, and URL
query parameters are excluded from dashboard event summaries.

The full web dashboard is available through the BlueberryProxy app's Open Web
UI button using Ingress, or locally at port 8055. The separate Ingress listener
uses port 8056 and only accepts the Supervisor gateway at `172.30.32.2`.
The local dashboard on 8055 exposes the local management API and should be
reachable only on your trusted LAN. The HA card grants access only to admins.

## Statistics scope

DNS totals and rankings reset on proxy restart and require query logging.
Rankings retain counters for at most 10,000 domain names and 4,096 clients;
existing names continue accumulating after the limit, and total request counts
continue for all requests. Failures are counted separately from allowed and
blocked requests. The browser's live table and HA card are bounded views, not
permanent traffic archives. Pausing a view does not affect DNS. Pausing
blocking persists until resumed and skips blocklists and blackhole rules;
local answers, redirects, and proxy routes continue operating.

## Validation

Offline tests cover statistics, DNS policy changes, event redaction, WebSocket
framing, HTTP header/body preservation, and management command validation.
A separate socket integration test exercises the HTTP facade and live events.
Run it in the `blueberryProxy` project with `lein test :integration` in an
environment that permits local sockets. Live HA/Ingress behavior requires a
running Home Assistant installation.

Dashboard domain rules use priority 100 to resolve ties with existing exact
rules for the same domain. Match type and suffix length retain precedence.

The integration now keeps its event connection active while loaded and publishes `blueberry_proxy_discovery` and `blueberry_proxy_scan` Home Assistant events. The frontend card can start UScan discovery and show discoveries in the live feed. Configure scanner profiles, scope and advanced GraalJS parameters through the proxy dashboard. BlueberryQuantum can import a gateway's observed device inventory into the same generic discovery API.
