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

Proof is recorded in `verification.jsonl` and summarized in
`active-verification.json` beside the chart. Neither contains arguments,
credentials or response data. Three observed REST writes remain gated.
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
