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
  instead of scraping HTML. An operation astrolabe re-executed and failed is
  withdrawn rather than shipped as a working tool; `--require-active-proof`
  exposes only what it re-executed successfully, reading the
  `active-verification.json` that `astrolabe contract --execute` writes beside
  the capture, and refuses to generate at all when no such artifact is present
  rather than emitting an empty pack that looks like a successful run
- **inventory** — catalogue every operation the client's own compiler output
  declares, not only the ones a walk happened to trigger. A read-only walk
  never fires a delete, so the writes a site supports stay visible without
  becoming callable: declared operations carry no request and the validator
  refuses them if they ever do
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
`python -m astrolabe.mapping_mcp`). Charts, run logs, and staged credentials
live in `ASTROLABE_WORKSPACE`, defaulting to `$XDG_DATA_HOME/astrolabe`
(`~/.local/share/astrolabe`). Serve a generated Chart with `astrolabe-mcp`.

`astrolabe-mapping-mcp` exposes exactly these twelve tools:

| tool | what it does |
|---|---|
| `map_site` | capture a site and generate a read-only Chart |
| `scan_site` | source-scan a site from a seed URL and scaffold a recipe, without logging in |
| `scan_to_recipe` | turn a scan's evidence into candidate `actions` for `map_site` |
| `solve_challenge` | solve a Cloudflare-style challenge with Byparr into a private cookie file |
| `verify_chart` | re-execute a Chart's reads in a warm browser to earn `verified-active` proof |
| `import_har` | chart a HAR recorded elsewhere; proof is labelled `imported` |
| `generate_chart` | regenerate a Chart (optionally with `read_pattern` for POST-based searches) |
| `chart_status` | report which Charts are mounted, which were skipped and why |
| `preflight` | check local capture services and the active egress policy |
| `list_charts` | list generated Chart paths without reading credentials or captures |
| `register_session` | store a session you already hold and get back an opaque handle |
| `revoke_session` | revoke a registered session so its handle stops working |

`astrolabe-unified-mcp` serves those same twelve plus the discovery pair that
replaced per-Chart tool mounting. Mounted Charts are no longer flattened into one
tool list; an agent finds the operation, then calls it:

| tool | what it does |
|---|---|
| `search_tools` | find callable operations across every mounted Chart, by name or description |
| `call_tool` | invoke one operation by the `operation_id` `search_tools` returned |

### Registering a session the agent already holds

`register_session(domain=..., cookies=[...], headers={...})` stores a session you
already have and returns an opaque handle; spend it with
`map_site(domain=..., session=<handle>)` or `verify_chart`. The response echoes
cookie and header *names* only, never values, and the handle is a bearer token:
it is never written to a run log and never appears in `revoke_session`'s reply.
Lifetimes are bounded rather than inherited, one hour by default and never more
than 24, and expiry is re-checked on every use, so a leaked handle dies without
the server restarting.

This is a different trust relationship from an operator-staged cookie file,
because the agent decides when a secret enters the system. The operator must
therefore list exact domains in `ASTROLABE_SESSION_DOMAINS` (empty by default),
exactly as for `ASTROLABE_BROWSER_AUTH_DOMAINS`; no tool argument can widen it.
See [agent-held sessions](docs/relay-and-browser-auth.md#agent-held-sessions) for
what this puts in scope, including the agent's own transcript.

Many APIs only fire after someone types, submits, dismisses a modal, or pages
through results. Pass those steps as `actions`; each runs on the last seed page
and waits for the API traffic it caused to settle before the next:

```json
{"domain": "example.com", "seeds": ["https://example.com/search"],
 "actions": [
   {"action": "search", "selector": "role=textbox[name=\"Name\"]", "value": "smith",
    "submit": true, "safe_annotation": "read-only name search"},
   {"action": "click", "selector": "role=button[name=\"Acknowledge\"]", "optional": true,
    "safe_annotation": "dismiss disclaimer"},
   {"action": "wait_for", "selector": ".result"},
   {"action": "click", "selector": "text=Load More", "safe_annotation": "next page"}],
 "read_pattern": "/api/search$"}
```

Actions are `search`, `click`, `press` (Enter/Tab/Escape/arrows/Space),
`select`, `wait_for`, `wait`, and `scroll`. State-changing steps require a
`safe_annotation`; selector steps accept `optional` and `timeout_ms` (≤15s).

You do not have to invent that vocabulary blind. `scan_site` reads a site
without logging in and writes `scan.json` plus a recipe scaffold, and
`scan_to_recipe` turns what it actually observed into candidate `actions` for
`map_site`, each already carrying a `safe_annotation` explaining why the step is
read-only. A scan observes a site and never replays a request, so it cannot know
which interactions are safe; the proposals are evidence to review, not a
decision. Selectors are built from structural attributes and ARIA roles only,
never from a target's own text.

Session sources are mutually exclusive: a workspace `cookies_file` (for
example from `solve_challenge`, together with its `user_agent`, because
clearance is bound to the agent that solved it), a decrypted local `browser`
profile, or a running browser via `cdp_endpoint`. Omit all three for anonymous
capture. Validation refusals and CLI failures come back with their reason and
the path of the run's private log.

### Attaching to a running browser

`astrolabe map --cdp-endpoint http://127.0.0.1:9222` (or `map_site(...,
cdp_endpoint=...)`) captures inside a Chromium you already have open, started
with `--remote-debugging-port=9222`, reusing its logins and challenge
clearance. astrolabe opens its own tab, scopes routing, budgets, and listeners
to that tab, and on exit closes only that tab and disconnects. Only loopback
endpoints are accepted, and the MCP server additionally requires the operator
to list the exact endpoint in `ASTROLABE_CDP_ENDPOINTS`. Attached capture
cannot combine with cookie files, native browser import, proxies, or HAR export.

See [persisted-query recovery and payload decoding](docs/persisted-recovery.md)
for supported packaging, evidence requirements, and limitations.

### Operator configuration

None of these is settable from a tool argument; each is read from the server
process, so an agent cannot widen its own authorization envelope.

| variable | default | what it controls |
|---|---|---|
| `ASTROLABE_WORKSPACE` | `$XDG_DATA_HOME/astrolabe` | where Charts, run logs and staged credentials live |
| `ASTROLABE_BROWSER_AUTH_DOMAINS` | empty | exact domains native browser import may decrypt cookies for |
| `ASTROLABE_SESSION_DOMAINS` | empty | exact domains `register_session` may store a credential for |
| `ASTROLABE_CDP_ENDPOINTS` | empty | exact loopback `cdp_endpoint` values `map_site` may attach to |
| `ASTROLABE_BROWSER_EGRESS` | `allow-third-party` | `first-party-only` aborts and records every non-first-party request |
| `ASTROLABE_MCP_SPAWN` | unset | `1` puts every dispatched command back on one-subprocess-per-call |
| `ASTROLABE_TOOLPACK`, `ASTROLABE_COOKIES`, `ASTROLABE_AUTH` | unset | what `astrolabe-mcp` serves for a generated Chart |
| `FASTMCP_TELEMETRY_MODE` | `native` | FastMCP's OpenTelemetry instrumentation, see below |

The last row is the vendor's own setting, deliberately not aliased. FastMCP 4
turned its OTel instrumentation on by default, and its `native` mode calls only
the OpenTelemetry API, so span creation is a no-op with negligible overhead
unless an SDK and exporter are configured. astrolabe adopts no OTel SDK and no
exporter of its own, so nothing is exported anywhere as installed; an operator
who configures a collector inherits FastMCP's MCP spans and can select
`propagation_only` (carry trace context, create no spans) or `off` (FastMCP
touches no OTel context at all). A second astrolabe-prefixed name would
duplicate a supported control and could not express a future mode value, so the
vendor knob is the documented one.

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
    [--cdp-endpoint http://127.0.0.1:9222]  # capture inside a running browser session
    [--user-agent UA]                       # pair with `challenge` cookies
    # -> contract.md (contract of record) + map.md + endpoints.json

astrolabe challenge https://example.com/ --domain example.com \
    --out cookies.json --local            # Byparr solve -> 0600 cookie file + solving agent

astrolabe import-har capture.har \        # convert a HAR recorded elsewhere into chartable evidence
    --domain example.com \                  # first-party host to keep traffic for
    [--out DIR] [--no-contract-store]
    # -> contract.md (contract of record) + map.md + endpoints.json, same as `map`

astrolabe contract <capture-dir> \        # versioned typed inventory + observation/proof history
    [--merge prior/contract.json]           # union across runs (completeness) + drift
    [--execute --cookies-file cookies.json --domain example.com]  # actively re-verify
    [--execute --no-auth --seeds URL,URL [--recipe actions.json]]  # anonymous public site
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

### Import a HAR

`astrolabe map` charts traffic astrolabe's own headless browser observed. If
you already have traffic recorded elsewhere — Chrome DevTools' Network tab
via "Save all as HAR", any other browser's HAR export, a proxy dump — `import-har`
converts it into the same capture-dir shape astrolabe's own capture engine
produces, so `analyze`/`contract`/`mcp-gen` consume it without caring where
the evidence came from. It keeps only first-party XHR/fetch traffic, and
only ever persists structural shapes and header/query *presence*, never
values: a HAR routinely carries live session cookies, bearer tokens, and PII
in exactly the fields that never make it into `capture.jsonl`. Every record
and the run's `meta.json` is stamped `evidence_source: "har-import"`, and the
resulting `contract.md` marks those operations `imported` rather than
`observed` — imported evidence is never presented as something astrolabe
itself watched happen.

```
astrolabe import-har capture.har --domain example.com --out ./astrolabe-example.com
astrolabe mcp-gen ./astrolabe-example.com   # same as after a live `astrolabe map`
```

## Status

Alpha. This is the reusable core of a larger internal tool, extracted and
made target-neutral for public reference; the remote orchestration pieces
(SSH to a capture host, Burp/CF-challenge-fallback wiring) assume you already
have that infrastructure or run everything with `--local`.

## License

MIT — see [LICENSE](LICENSE).
