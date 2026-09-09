# astrolabe

astrolabe maps the private API behind a website you're authorized to test — the
GraphQL and REST calls a page makes once you're logged in — and turns what it
observes into a typed, versioned contract instead of a one-off scrape. Point it
at a domain with a browser session, and it gives you back an executable
inventory of every operation it saw, with proof of what actually worked.

> **Alpha safety boundary:** default generation and execution expose only
> operations classified as queries from trusted evidence. Persisted/unknown
> operations are inventory-only; recipes are executable code and require
> explicit trust acknowledgement. Historical example artifacts are
> documentation, not fresh executable contracts.

## What it does

A capture host drives a real, logged-in browser session against the target
site (via a Playwright-style browser automation layer, proxied through Burp
with a Cloudflare-challenge fallback), records every GraphQL/REST/WebSocket
call it makes, and hands the traffic to a local analysis pipeline:

- **capture** — record real traffic from a real session (GraphQL, REST,
  WebSocket/socket.io), shape-only by default (no payload values persisted)
- **analyze** — turn a capture into a human-readable map (`map.md`) and a
  machine-readable endpoint inventory (`endpoints.json`)
- **contract** — build a durable, versioned, typed contract of every
  operation observed, merged across runs so completeness and drift are
  tracked over time, with optional active re-verification
- **mcp-gen** — generate a typed [MCP](https://modelcontextprotocol.io)
  toolpack from a capture, so an agent can call the site's own API directly
  instead of scraping HTML
- **scan** — a deterministic, evidence-grounded source scan (sitemap, DOM,
  service worker, bundle/chunk-manifest mining) that scaffolds a per-site
  recipe from what it actually found, not from guesses
- **replay** — browserless, TLS-fingerprint-matched, high-frequency
  re-execution of a single operation, for monitoring or parameter
  enumeration without a browser per request

## Authentication

Supply an exported session with `--cookies-file`, or explicitly select a local
Linux Chromium browser with `--browser vivaldi --profile Default`. Browser import
requires `astrolabe[browser-auth]` and reads only cookies for the requested domain
and its subdomains. It decrypts v10/v11 cookies using the browser's Safe Storage
key, validates padding and modern cookie domain binding, and never returns cookie
values through MCP. Native import is local-only, disables HAR and TLS interception,
and stages temporary credentials in private tmpfs files removed after capture.

For MCP, the operator must first configure `ASTROLABE_BROWSER_AUTH_DOMAINS=x.com`
on the server process (comma-separated exact domains; empty by default). Then call
`map_site(domain="x.com", browser="vivaldi", seeds=["https://x.com/home"])`.
Tool arguments cannot enable or widen this operator allowlist. Browser import is explicit; omitting both `browser`
and `cookies_file` remains anonymous. Windows/macOS native browser decryption is
not implemented; exported cookie files remain portable across platforms.

Persisted recovery is separately opt-in: `--recover-persisted` or
`map_site(..., recover_persisted=True)`. This matches APQ documents by SHA-256 and
Meta Relay compiler metadata by exact persisted ID and operation name. Metadata
recovery does not imply recovery of original GraphQL source. See
[recovery and browser-auth security](docs/relay-and-browser-auth.md).

## Install

```
uv sync --extra dev
uv run playwright install chromium
```

Requires Python 3.11+. Plain [Playwright](https://playwright.dev) is a core
dependency, so `astrolabe map --local example.com` works clone-and-go on any
machine right after the two commands above — no separate capture host and no
stealth engine required. The capture tier can also run against a remote
"capture host" (`--host`, or bare `astrolabe map` when the profile resolves to
one) through the same browser layer; the analysis/contract/mcp-gen/replay
tiers are pure Python and run anywhere.

### Browser backend

astrolabe drives the browser through a small pluggable layer
(`astrolabe/browser.py`) with two backends:

- **playwright** (default, always available) — plain Chromium via Playwright.
  This is what makes the local demo clone-and-go.
- **cloakbrowser** (optional) — a stealth, Cloudflare-hardened
  Playwright-compatible driver for bot-protected targets. Install it with:

  ```
  pip install astrolabe[stealth]
  ```

Selection is automatic: `ASTROLABE_BROWSER=auto` (the default) uses
cloakbrowser when it's installed, otherwise falls back to plain Playwright.
Set `ASTROLABE_BROWSER=playwright` or `ASTROLABE_BROWSER=cloakbrowser` to pin
one explicitly; pinning to `cloakbrowser` without the extra installed fails
fast with an install hint rather than silently falling back.

## Usage

The native mapping MCP entry point is `astrolabe-mapping-mcp` (or
`python -m astrolabe.mapping_mcp`). Set `ASTROLABE_WORKSPACE` to the local
capture workspace. Its `map_site` accepts a private exported `cookies_file`,
optional seed URLs, and enables exact persisted-query recovery by default.
It uses this installation's browser/Byparr pipeline and generates a read-only
Chart. Serve that Chart with `astrolabe-mcp`.

See [persisted-query recovery and payload decoding](docs/persisted-recovery.md)
for supported packaging, evidence requirements, and limitations.

```
astrolabe preflight                          # health + egress-safety check

astrolabe scan https://example.com/catalog \
    [--operator-seed https://example.com/search] \
    [--max-total-requests 100 --max-static-resources 25] \
    [--account-risk sensitive --delay-ms 750] \
    [--working-hours-utc 9-17] \
    [--authorized-path /catalog --prohibited-path /account]
    # -> scan.json + scan.md + an evidence-grounded recipe scaffold

astrolabe map example.com \
    --cookies-file cookies.json \            # bring-your-own Playwright cookie export
    --recover-persisted \                    # match browser SHA-256 inputs to observed APQ requests
    --recipe surfaces/example.com.recipe.py \  # per-site interactions (optional)
    [--schema]     # recover GraphQL schema if introspection is off + suggestions leak
    [--openapi]    # first-party REST OpenAPI (host-side; HAR never leaves the host)
    [--no-auth]    # anonymous target (skip cookies entirely)
    [--seeds URL,URL] [--crawl N] [--out DIR]
    # -> contract.md (contract of record) + map.md + endpoints.json

astrolabe contract <capture-dir> \        # versioned typed inventory + observation/proof history
    [--merge prior/contract.json]           # union across runs (completeness) + drift
    [--execute --cookies-file cookies.json --domain example.com]  # actively re-verify
    # -> contract.json (contract of record) + contract.md (coverage scorecard)

astrolabe mcp-gen <capture-dir> \         # generate a typed MCP toolpack from a capture
    --overrides surfaces                    # use curated minimal queries where available
    # -> toolpack.json: typed tools only for safely classified, runtime-compatible ops.
    # Serve with `astrolabe-mcp` (FastMCP; env: ASTROLABE_TOOLPACK/COOKIES/AUTH).

astrolabe replay example.com --op op.json \   # browserless, TLS-matched, high-frequency replay
    --cookies-file cookies.json --auth-file auth.map.json \  # both bring-your-own
    [--vary 'dotpath=a,b,c'] [--repeat N] [--interval S]
```

`astrolabe scan` fuses sitemap, DOM/navigation, service-worker, operator-seed,
bundle, chunk manifest, dynamic-import, and source-map evidence without
flattening provenance or confidence. It never invents an executable operation
from a static candidate — it hands you evidence to review, not a guess.

## Status

Alpha. This is the reusable core of a larger internal tool, extracted and
made target-neutral for public reference; the remote orchestration pieces
(SSH to a capture host, Burp/CF-challenge-fallback wiring) assume you already
have that infrastructure or run everything with `--local`.

## License

MIT — see [LICENSE](LICENSE).
