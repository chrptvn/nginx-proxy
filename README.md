# HeaderProxy

A Dockerized HTTP proxy for **injecting and removing HTTP headers on the fly**, driven by a
dynamic REST API and an **MCP server** (every endpoint is also an MCP tool). Header rules are
organized into **sessions** you can save, switch and delete, persisted in **SQLite**.

It was built to sit in front of automated browsers (e.g. the Playwright MCP server) and make
their traffic look like it comes from a regular browser — see [Stealth](#stealth-what-the-proxy-does-and-what-it-cannot).

```
                     ┌────────────────────────── header-proxy ──────────────────────────┐
                     │                                                                  │
 browser / MCP ────► │  data plane :8088        control plane :8080                     │
 curl / playwright   │  ┌──────────────────┐     ┌───────────────────────────┐          │
                     │  │ forward proxy    │     │ REST API  (/api/...)      │          │
                     │  │  plain HTTP      │     │ MCP tools (/mcp)          │          │
                     │  │  CONNECT + MITM  │     │        │                  │          │
                     │  │  WebSocket relay │     │  ┌──────▼───────┐          │          │
                     │  └───────┬──────────┘     │  │ SQLite (WAL) │ /data    │          │
                     │          │                │  └──────────────┘          │          │
                     │  ┌───────▼──────────┐     └───────────────────────────┘          │
                     │  │ curl-impersonate │                                            │
                     │  │ (Chrome TLS/JA4) │                                            │
                     │  └───────┬──────────┘                                            │
                     └──────────┼───────────────────────────────────────────────────────┘
                                ▼
                             origins
```

## Features

- **Header overrides** — `set` or `remove` any header on the *request* or the *response*,
  with priorities and enable flags.
- **Filters** — scope any override to matching traffic with `host` / `path` globs
  (`*.example.com`, `/api/*`).
- **Sessions** — named rule sets; exactly one session is active and its rules apply to all
  proxied traffic. Save snapshots, switch atomically, delete with their config.
- **HTTPS support (MITM)** — `CONNECT` tunnels are terminated with per-host leaf certificates
  signed by an auto-generated local CA (persisted under `/data/ca/`).
- **Chrome-grade TLS fingerprint** — upstream requests are sent through
  [curl-impersonate](https://github.com/lwthiker/curl-impersonate), so origins observe an
  authentic Chrome TLS (JA3/JA4) and HTTP/2 handshake even though the proxy rewrote the
  headers. Verified: JA4 seen by origins through the proxy is byte-identical to a direct
  Chrome-impersonated connection.
- **WebSocket relay** — `ws://` and `wss://` upgrades are tunneled raw (rules still apply to
  the upgrade request).
- **Streaming** — responses are relayed chunk-by-chunk (SSE and large downloads work).
- **MCP server** — streamable HTTP at `/mcp`, stateless JSON mode; all 18 control operations
  available as tools.
- **Persistence** — SQLite in WAL mode; survives restarts.
- **Optional API key** — protect `/api` + `/mcp` with a bearer token.

## Quickstart

```bash
git clone https://github.com/chrptvn/nginx-proxy.git header-proxy
cd header-proxy
docker compose up -d --build

# proxy is on :8088, control plane on :8080
curl -s http://127.0.0.1:8080/api/status
```

Inject a header and watch it reach the origin:

```bash
curl -X POST http://127.0.0.1:8080/api/sessions/default/overrides \
  -H 'Content-Type: application/json' \
  -d '{"action": "set", "header": "X-Env", "value": "staging"}'

curl -x http://127.0.0.1:8088 http://httpbin.org/headers    # → X-Env: staging arrives
```

HTTPS (MITM) — trust the proxy CA so curl verifies the generated certificates:

```bash
docker exec header-proxy cat /data/ca/ca.crt > hp-ca.crt
curl --cacert hp-ca.crt -x http://127.0.0.1:8088 https://httpbin.org/headers
```

> The ports above are published to **127.0.0.1 only** by default. Other containers on the same
> Docker network reach it as `header-proxy:8088` (data) and `header-proxy:8080` (control).
> To expose it on your LAN, change the port mappings in `docker-compose.yml` and set
> `HP_API_KEY`.

## Sessions

A **session** is a named set of overrides + filters with a stealth flag. Exactly one session
is active; the proxy applies its rules to every request.

| Operation | REST | MCP tool |
|---|---|---|
| create | `POST /api/sessions` `{"name": "scraping"}` | `create_session` |
| save active config as | `POST /api/sessions/{name}/save` | `save_session` |
| switch active | `POST /api/sessions/{name}/activate` | `switch_session` |
| toggle stealth | `PATCH /api/sessions/{name}` `{"stealth": false}` | — |
| delete (with config) | `DELETE /api/sessions/{name}` | `delete_session` |
| list | `GET /api/sessions` | `list_sessions` |

- Saving under the active session's own name is an explicit checkpoint.
- Saving under a different name **copies** the active session's config there (replacing it).
- Deleting the active session is refused — switch first.
- `default` exists from first start and cannot be deleted while active.

## REST API

All endpoints are under `/api` on port **8080**. Interactive docs at `/docs`.

### Overrides (header rules)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/sessions/{name}/overrides` | inject / remove a header |
| `GET` | `/api/sessions/{name}/overrides` | list overrides |
| `DELETE` | `/api/sessions/{name}/overrides/{id}` | remove one override |
| `DELETE` | `/api/sessions/{name}/overrides` | **clean all** overrides (filters kept) |

Body:

```jsonc
{
  "direction": "request",       // or "response"
  "action": "set",              // or "remove"
  "header": "X-Custom-Header",
  "value": "injected",          // required for action "set"
  "filter_id": null,            // optional Filter.id to scope the rule
  "priority": 0,                // higher priority applied later (wins)
  "comment": "why this rule exists",
  "enabled": true
}
```

### Filters

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/sessions/{name}/filters` | add a filter |
| `GET` | `/api/sessions/{name}/filters` | list filters |
| `DELETE` | `/api/sessions/{name}/filters/{id}` | remove filter (overrides become unscoped) |

Body: `{"host": "*.example.com", "path": "/api/*", "comment": "..."}`.
Patterns are globs (`*`, `?`, `[seq]`); `host` matches the hostname (or `host:port` if the
pattern contains a port), `path` matches the URL path without the query string.

### Meta

- `GET /api/health` — liveness (never requires auth).
- `GET /api/status` — active session, rule counts, version.

A full annotated walkthrough: `tests/test_api.py` and `tests/test_mcp.py` double as
executable documentation.

## MCP

Streamable HTTP transport at **`http://header-proxy:8080/mcp`** (stateless JSON mode).
Tools operate on the **active session** (VPN tools are session-independent — see
[VPN egress](#vpn-egress-optional)):

`proxy_status` · `create_session` · `list_sessions` · `save_session` · `switch_session` ·
`delete_session` · `inject_header` · `remove_header` · `list_overrides` · `remove_override` ·
`clean_overrides` · `add_filter` · `list_filters` · `remove_filter` · `activate_vpn` ·
`deactivate_vpn` · `vpn_status` · `list_vpn_profiles`

### n8n (MCP Client Tool node)

Endpoint: `http://header-proxy:8080/mcp` (same Docker network), Server Transport:
*Streamable HTTP*. If `HP_API_KEY` is set, add the header
`Authorization: Bearer <key>`.

### Claude Code / generic clients

```bash
claude mcp add --transport http header-proxy http://127.0.0.1:8080/mcp
```

## Using with Playwright (MCP)

Point the browser at the proxy and let it accept the MITM certificates:

```jsonc
// playwright-mcp config.json
{
  "browser": {
    "launchOptions": {
      "headless": false,
      "proxy": { "server": "http://header-proxy:8088" }
    },
    "contextOptions": {
      "ignoreHTTPSErrors": true
    }
  }
}
```

(For headless launches, keep `headless: false` under Xvfb or add stealth browser patches —
see below.) Restart the MCP server afterwards. Every page request now passes through
HeaderProxy: session rules apply, and the origin sees a Chrome-grade TLS handshake.

Alternatively, install the CA into the browser/OS trust store instead of
`ignoreHTTPSErrors`:

```bash
docker exec header-proxy cat /data/ca/ca.crt   # install this cert
```

## Stealth: what the proxy does — and what it cannot

A proxy sits at the network layer, so it controls **exactly** the network-level signals:

| Signal | Handled by HeaderProxy |
|---|---|
| TLS fingerprint (JA3/JA4), HTTP/2 SETTINGS, header order | ✅ curl-impersonate upstream (Chrome-grade) |
| `HeadlessChrome` marker in `User-Agent` | ✅ rewritten to `Chrome` (stealth mode) |
| Proxy-leak headers (`Via`, `X-Forwarded-*`, `Forwarded`, `X-Real-IP`) | ✅ stripped (stealth mode) |
| Removed `User-Agent` | falls back to the impersonated Chrome UA |
| `navigator.webdriver`, CDP leaks, canvas/WebGL, font entropy | ❌ inside the browser — pair with a stealth-patched Playwright build (e.g. rebrowser-patched driver, `--disable-blink-features=AutomationControlled`, headed mode under Xvfb) |

Stealth is on by default (`HP_STEALTH_DEFAULT=1`) and can be toggled per session
(`PATCH /api/sessions/{name}`).

## VPN egress (optional)

The image ships [wireproxy](https://github.com/pufferffish/wireproxy), a userspace
WireGuard client that exposes a tunnel as a local SOCKS5 proxy. Drop standard
wg-quick profile `.conf` files into `./data/vpn/` on the host (bind-mounted
read-only at `/data/vpn`), then activate one — every upstream request the proxy
makes leaves through the VPN until you deactivate it:

```
proxy → curl-impersonate ──► socks5h://127.0.0.1:40001 (wireproxy) ──► WireGuard ──► origins
```

Example with ProtonVPN: dashboard → *Downloads* → *WireGuard configuration* →
save the file as `data/vpn/proton-nl.conf` → activate it. The directory is
created on first use and is gitignored.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/vpn/activate` | route egress through a profile: `{"profile": "proton-nl.conf"}` |
| `POST` | `/api/vpn/deactivate` | stop the tunnel, egress goes direct |
| `GET` | `/api/vpn/status` | active profile, pid, uptime, handshake state |
| `GET` | `/api/vpn/profiles` | available profiles + which is active |

MCP tools: `activate_vpn` · `deactivate_vpn` · `vpn_status` · `list_vpn_profiles`.

Security notes:

- Private keys stay in your mounted `data/vpn/` folder — profiles are passed to
  wireproxy in place and are never copied, parsed or returned by the API.
- Fail-closed: if the wireproxy process dies, egress is switched back to direct
  immediately and the status endpoint reflects it.
- VPN state is runtime-only — it deactivates on container restart.
- Activating takes up to a few seconds (the API waits for the tunnel handshake
  before answering, and reports `handshake_ready`).

## Configuration

| Env var | Default | Description |
|---|---|---|
| `HP_PROXY_HOST` / `HP_PROXY_PORT` | `0.0.0.0` / `8088` | data-plane bind address |
| `HP_API_HOST` / `HP_API_PORT` | `0.0.0.0` / `8080` | control-plane bind address |
| `HP_DATA_DIR` | `/data` | SQLite DB + CA storage |
| `HP_API_KEY` | *(empty)* | require `Authorization: Bearer <key>` on `/api` + `/mcp` |
| `HP_LOG_LEVEL` | `INFO` | `DEBUG` logs every applied rule |
| `HP_IMPERSONATE` | `chrome` | curl-impersonate target for upstream requests |
| `HP_STEALTH_DEFAULT` | `1` | stealth flag for newly created sessions |
| `HP_MAX_BODY_BYTES` | `67108864` | buffered request-body cap (413 beyond) |
| `HP_CLIENT_IDLE_TIMEOUT` | `300` | seconds before idle client connections close |
| `HP_UPSTREAM_TIMEOUT` | `180` | upstream request timeout (seconds) |
| `HP_UPSTREAM_VERIFY` | `system` | upstream TLS: `system`, `none`, or CA bundle path |
| `HP_CERT_CACHE_SIZE` | `2048` | MITM leaf-certificate LRU size |
| `HP_VPN` | `1` | enable the VPN egress feature (needs wireproxy in `PATH`) |
| `HP_VPN_BINARY` | `wireproxy` | wireproxy executable used for VPN egress |
| `HP_WS_RELAY` | `1` | tunnel WebSocket upgrades |

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest                    # 75 tests: unit + REST + MCP + end-to-end data plane
```

The end-to-end suite spins up real origins (HTTP, HTTPS and a minimal RFC6455 WebSocket echo
server) and drives the actual proxy through curl-impersonate clients and raw sockets.

## Known limitations

- Request bodies are buffered in memory (capped by `HP_MAX_BODY_BYTES`); responses stream.
- HTTP/2 to the *client* is not spoken (proxy connections are HTTP/1.1 — as mitmproxy's
  default); upstream connections use HTTP/2 with Chrome fingerprinting.
- WebSocket tunnels relay raw bytes upstream over a Python TLS session (WS connections are
  rarely JA3-fingerprinted; regular requests always use the impersonated client).

## License

[MIT](LICENSE)
