# Relay recovery and native browser authentication

Both capabilities are opt-in. Anonymous mapping does not open a browser cookie
database or access the keyring. Install the optional `browser-auth` extra to use
local Linux Chromium v10/v11 import. Other encryption formats fail closed.

## Operator boundary

CLI: explicitly pass `--browser vivaldi --local`. MCP: configure the server's
`ASTROLABE_BROWSER_AUTH_DOMAINS` with exact domains, then explicitly pass `browser`
to `map_site`. The default allowlist is empty. A tool call cannot edit it. Domain
authorization includes cookie subdomains within that domain; it does not permit
another top-level map call for a subdomain absent from the exact allowlist.

The same shape gates the two other operator-owned ingresses. `map_site` and
`verify_chart` accept a `cdp_endpoint` only if the exact loopback endpoint is
listed in `ASTROLABE_CDP_ENDPOINTS`, and `register_session` may store a credential
for a domain only if that exact domain is listed in `ASTROLABE_SESSION_DOMAINS`.
Both allowlists are empty by default and no tool argument can widen either one.

`ASTROLABE_SESSION_DOMAINS` exists because the agent is now a credential
*origin*, not only a credential consumer. Every other path here starts with
something the operator already staged; this one lets the caller decide when a
secret enters the system, which puts the agent's own process, its memory, and its
transcript in scope, and those are exactly the surfaces the concessions below
already say we cannot defend. The delta is spelled out, once, in
[Agent-held sessions](#agent-held-sessions); the rest of this document's
limitations apply to it unchanged.

Import reads only the selected current-user profile and registrable domain using
read-only SQLite. Public suffixes, symlinked paths, wrong owners, unsupported
encryption, invalid padding and failed modern host binding are rejected. Only
matching unlocked browser Safe Storage secrets are read. No keyring unlocking,
password guessing, arbitrary database path, all-domain export, or credential
return tool is provided. Import is capped at 512 cookies and 64 KiB per cookie.

Native imports cannot use remote capture, recipes, or HAR/OpenAPI export. They
use strict TLS without Burp, one browser, and at most 100 total/100 per-origin/20
per-operation budgeted requests. The CLI disables core dumps and stages cookies
directly in a mode-0700 local tmpfs capture directory with mode-0600 files. Normal
completion and handled failures remove those files; credentials never enter the
generated chart. Capture outputs remain sensitive metadata, even without values.

These controls reduce accidental disclosure and agent-driven credential access;
they do not make a general-purpose tool impossible to misuse. The operator, OS
account, browser, keyring, dependencies, and configured server process are trusted.
Same-user code/root can modify software or inspect process memory. Python cannot
guarantee zeroization; tmpfs may swap; SIGKILL/power loss can bypass cleanup.
Use a dedicated OS user/browser profile, encrypted swap or disabled swap, and
short-lived sessions when stronger isolation is needed. A writable source checkout
is not a security boundary against an agent that can modify it.

## Browser egress policy

A capture browser loads real pages, and real pages pull third-party subresources:
CDN bundles, analytics beacons, auth widgets, font hosts. Blocking those outright
breaks many sites, so the default policy `allow-third-party` lets the browser fetch
them while still never recording their requests — `capture.jsonl` and the contract
only ever contain first-party traffic. Note the asymmetry, because it is the whole
point of naming the policy: *allowed* and *recorded* are deliberately different
things, and "allowed" does not mean "audited".

Set `ASTROLABE_BROWSER_EGRESS=first-party-only` to abort every non-first-party
request instead, recording each as a truncation with reason `egress-policy`. An
unrecognized value fails the run before a browser opens, rather than silently
falling back to the permissive default and reporting a control the run does not
have. This is operator config only: no tool argument can select or widen the
policy, mirroring the allowlists above.

Recipe drives are always strict regardless of the operator default, recorded as
`recipe-egress-policy`, because a driven step is the point at which target-supplied
content most directly shapes what the browser requests.

`preflight` reports the active policy as `browser_egress_policy`, and each run
records the value it actually enforced in `meta.json`, so an agent can see the
control before a capture rather than infer it from a truncation list afterwards.

Attaching to a running browser with `cdp_endpoint` is the sharpest edge of this:
the capture reuses the operator's live authenticated session, so target-served
content can steer a browser that already holds real credentials, and the operator's
own cookies travel with any subresource the page pulls. Use `cookies_file` when the
capture does not need the live session.

## Dispatch isolation

`map_site`, `verify_chart` and `import_har` shell out to `python -m
astrolabe.cli` for the capture itself, because a browser must not share the
server's process. `preflight` and `mcp-gen` are short, browserless and read
from disk, so they run on the server's own interpreter instead of paying for a
fresh interpreter per call. That trade is deliberate and it has two costs: an
in-process run holds the event loop for its duration, and it cannot be timed
out, so a hung command is no longer interrupted at the tool boundary.

Set `ASTROLABE_MCP_SPAWN=1` to put every command back on the subprocess path,
one interpreter per call, which restores both the per-call timeout and the
isolation. It is operator config in the same sense as the allowlists above: no
tool argument can set it, and the server reads it once at startup. Either way
`sys.argv`, the working directory and stdout/stderr are restored around an
in-process call, and each call's stderr is written to the same mode-0600 log
file the response's `log` key points at, so the two dispatch paths return the
same envelope.

## Instrumentation

Both MCP servers run on FastMCP 4, whose OpenTelemetry instrumentation is on by
default. astrolabe did not add OTel and does not want it: the SDK migration
deliberately took no OTel dependency, so as installed nothing is exported, and a
span that exists only when an operator has separately configured an SDK and
exporter is not a control this tool can make a claim about.

The vendor setting is the documented one, because adding an astrolabe-prefixed
alias would duplicate a supported control and could not express a future mode
value. `FASTMCP_TELEMETRY_MODE` takes `native` (the default; FastMCP calls the OTel
API, so span creation is a no-op unless an SDK and exporter are configured),
`propagation_only` (extract and inject trace context, create no spans of its own),
or `off` (FastMCP touches no OTel context at all, inbound or outbound). An
operator who configures a collector inherits FastMCP's MCP spans; an operator who
wants none sets `off`. No tool argument selects or widens this, in the same sense
as the allowlists above.

What that means for a reader of this document: the controls described here are
about what the process does with credentials and evidence, and none of them
depends on a span being emitted. Setting the mode to `off` removes
instrumentation without removing a control, and nothing in this document should
be read as a claim about telemetry.

## Agent-held sessions

`register_session` lets an agent store a session it already holds and spend it
via `map_site(domain=..., session=<handle>)` or `verify_chart`. This is a
different trust relationship from an operator-staged cookie file, because the
*agent* decides when a secret enters the system. It is gated accordingly.

The gate mirrors the browser-auth boundary above: `ASTROLABE_SESSION_DOMAINS`
lists exact domains, the default allowlist is empty, and no tool argument can
widen it. A registration or a use for an unlisted domain is refused by exact
normalised match, so `sub.example.com` does not permit `example.com`.

A handle is 256 bits of `secrets` output. It is never used as a filename and
never passed on a command line: the resolved path is derived from a SHA-256 of
the handle, because argv is world-readable through `ps` and a path containing
the handle would be a bearer token for the life of the run. The handle is not
echoed by `revoke_session`, and it is not written to any run log.

Lifetimes are bounded rather than inherited: one hour by default and never more
than 24 hours, even when a cookie claims a longer life. Expiry is re-checked on
every resolve, not only at registration, so a leaked handle dies on its own
without the server restarting. `revoke_session` removes it immediately.

Newly in scope, beyond the concessions already recorded above: the agent's own
transcript. The handle is returned to the agent, so wherever that transcript is
retained, a bearer token is retained with it. The same-user-code, process-memory
and SIGKILL caveats above apply unchanged; what is new is that the caller of
this tool may itself be the thing holding the secret.

## Recovery evidence

The capture inspects HTTPS JavaScript responses already loaded by an authorized
page, including CDN scripts. It does not crawl additional bundles, execute
downloaded source, or export source bodies. Tree-sitter parses literal `params`
on Relay `Request` and `PreloadableConcreteRequest` objects. It resolves static
references only to already-loaded Meta ID modules containing a single literal
export, with declared dependency and unshadowed loader checks. Arbitrary computed
IDs, spreads, duplicate fields, malformed syntax and name-only guesses do not
establish evidence.

Each artifact records ID, name, kind, sanitized source URL and source SHA-256.
Joining happens after capture, requiring exact ID/name agreement and no conflicting
kind/name for that ID. Budget exhaustion prevents the catalog from authorizing
operations. A script with none of the recovery markers (`operationKind`,
`RelayOperation`, `queryId`) can yield no artifact, so it is skipped before it
counts against any budget; framework and vendor bundles therefore do not starve
the recovery of large sites. Limits, applied to candidate scripts only: 8 MiB per
script, 64 MiB total, 512 scripts, 4096 artifacts, 2,000,000 AST nodes per script.
Browser response retrieval can temporarily allocate the entire already-loaded
response before its decoded size is checked.

A successful observed GraphQL response is required before exposure. Mutations
remain gated. Runtime validates the recovered evidence against the generated
operation, and `verify_operation` records active response/schema proof separately.
The ID is a server lookup key, not ciphertext; compiler metadata is not original
GraphQL query text and source digests are provenance, not a vendor signature.

Meta session form fields belong in a private version-2 credential record's
`form_fields`, scoped to the operation, origin, expiry and cookie generation.
Only `fb_dtsg`, `jazoest`, `lsd`, `__a`, `__user`, `__comet_req`, and `av` are
accepted (strings, at most 16 KiB each). They are injected only into the Meta POST
adapter and cannot replace `doc_id`, variables, or URLs. They are never tool
arguments, headers, generated-chart values, or verification-journal values.

## Prior art and dependency provenance

PAPER standard tier, narrowed to the protocol interface and normal dependencies.
Adopt Tree-sitter instead of extending heuristic regexes into an authorizer.
No Instagram application source is copied into production code or test fixtures.
Tests use independently authored synthetic artifacts. Exact package versions and
hashes are in `uv.lock`.

| Material | Use | License / disposition |
|---|---|---|
| [Relay persisted-query interface](https://relay.dev/docs/guides/persisted-queries/) | Protocol behavior reference | Interface-only; no implementation copied |
| [py-tree-sitter](https://github.com/tree-sitter/py-tree-sitter) | AST parser dependency | MIT, normal adoption; retain packaged notices |
| [tree-sitter-javascript](https://github.com/tree-sitter/tree-sitter-javascript) | JavaScript grammar dependency | MIT, normal adoption; retain packaged notices |
| [publicsuffixlist](https://pypi.org/project/publicsuffixlist/) | Offline domain boundary validation | Module and bundled PSL MPL-2.0, separate unmodified dependency with notices/source retained (mode B) |

The public-suffix package uses its bundled snapshot; import makes no update request.
Distribution must retain dependency notices and the publicsuffixlist module and
bundled PSL's MPL notice/source. No MPL implementation is copied into Astrolabe files.

## Native Instagram dogfood, 2026-09-09 UTC

Final capture: `chart-instagram.com-d83fdf7f13a6/` (private, gitignored).
24 API observations; 44 loaded scripts inspected; 452 compiler/ID-export artifacts;
no recovery budget exhaustion. All five observed persisted operations matched
compiler metadata and successful GraphQL responses. Original query text remains
absent. This is coverage of this page load, not Instagram's whole backend.

| Operation | Exact compiler binding + observed success | Active MCP proof |
|---|---|---|
| IGDBadgeCountOffMsysQuery | Yes | HTTP 200, schema validated |
| IGDChatTabsJewelOffMsysQuery | Yes | HTTP 200, schema validated |
| IGDOmniPickerNullStateListQuery | Yes | Not attempted |
| QuickPromotionSupportIGSchemaBatchFetchQuery | Yes | Not attempted |
| PolarisStoriesV3AdsPoolQuery | Yes | Not attempted |

Proof is recorded by `astrolabe contract --execute` in the artifacts below,
beside the chart. None of them contains arguments, credentials or response data.
Three observed REST writes remain gated.

| artifact | written by | shape |
|---|---|---|
| `verify.json` | `astrolabe contract --execute` | the per-operation verification record, keyed by operation |
| `active-verification.json` | `astrolabe contract --execute` | the same records as a list, each with the derived `ok` flag `mcp-gen --require-active-proof` reads |
| `verification.jsonl` | the Chart MCP server (`astrolabe-mcp`) | one appended value-free proof record per verified call, beside the toolpack |

The two writers are different processes and the three names are not
interchangeable. The Chart MCP server's journal is a durability log for calls
made through a served Chart, not an input to `mcp-gen`; `mcp-gen --require-active-proof`
reads `active-verification.json` and refuses rather than falling back to either of
the other two.
The artifact manifest validates with no checksum failures. Strict TLS was used;
no cookie/auth/HAR file remains in the chart, and no Instagram capture/verification
tmpfs directory remained after completion. Decryption was authorized for this
run through an in-process exact-domain operator allowlist; persistent MCP
configuration was not broadened.

Validation: 782 tests passed, 1 skipped; 72.18% package coverage. Ruff, mypy,
test formatting and `git diff --check` passed. Tests cover explicit/default
authorization, domain and profile boundaries, keyring filtering, cipher binding,
static-parser conflicts and decoys, mutation gating, unknown-kind gating,
cross-protocol evidence isolation, credential-field isolation, and runtime
evidence revalidation.
