# Native persisted-query recovery

Astrolabe can recover the full document behind a captured Apollo APQ request
when the application hashes that document through Web Crypto. A persisted hash
is an identifier, not encrypted query text: recovery observes the application's
plaintext hash input and binds it to the request with an independently computed
SHA-256 digest.

## Run through MCP

Start `python -m astrolabe.mapping_mcp` with `ASTROLABE_WORKSPACE` pointing at
the capture workspace. The native facade exposes `preflight`, `map_site`,
`generate_chart`, and `list_charts`. For example:

```json
{
  "domain": "example.com",
  "cookies_file": "cookies.json",
  "seeds": ["https://example.com/feed"],
  "recover_persisted": true
}
```

Cookie files must be private regular JSON exports within the configured
workspace. Omitting the file requests anonymous capture. The mapper bounds the run
to five same-site seeds, 100 requests, and one browser. It does not accept executable
recipes. It generates a validated Chart
and returns paths, never credential values or captured response bodies.
Playwright arrays, storage-state objects, and common extension exports (including
`expirationDate` and extension `sameSite` values) are normalized natively.
Alternatively, explicitly pass `browser="vivaldi"` (and optionally `profile`) to
import domain-scoped Linux Chromium cookies through the native Safe Storage
decryptor. Install the `browser-auth` extra for this path. No all-host export is
available; browser databases are read-only and temporary cookies are cleaned up.

The same pipeline is available through the CLI:

```sh
astrolabe map example.com --local --no-burp \
  --cookies-file cookies.json --recover-persisted \
  --seeds https://example.com/feed --max-total-requests 100
```

Use the generated Chart server (`astrolabe-mcp`, `ASTROLABE_TOOLPACK`,
`ASTROLABE_COOKIES`, and an exact per-operation `ASTROLABE_AUTH` header map)
for `verify_operation` and `invoke_query`. Verification reports schema validation,
success, timestamp, and the persisted document hash. Discovery and HTTP success
are distinct from successful active verification.
It appends value-free proof records to a private `verification.jsonl` beside the
toolpack. `proof_recorded` distinguishes successful verification from successful
local evidence persistence; the journal contains no arguments or returned data.

## Evidence and gating

1. Install a browser initialization observer before application scripts run.
   Observe SHA-256 inputs without altering the digest result or returned promise.
2. Keep at most 128 candidate documents / 2 MiB in the page, with a 256 KiB
   per-document limit. Export only documents whose hashes occur in captured
   first-party APQ requests. No non-GraphQL hash inputs or keys are exported.
3. Recompute SHA-256 over the exact UTF-8 document in Python. Parse strictly and
   require one operation matching the request's operation name. Mismatches,
   malformed documents, and multi-operation documents remain inventory-only.
4. Preserve document provenance, exact endpoint, variable declarations, response
   shapes, and whether the observed GraphQL response succeeded. Recovered tools
   require successful observed data with no GraphQL errors. Normal mutation and
   telemetry gates still apply.
5. Recheck the document/hash binding when the generated MCP server loads. A changed
   hash cannot inherit the old document's classification. APQ fallback is not
   enabled by recovery.

The native mapper uses Astrolabe's configured browser and existing Byparr fallback.
After clearance transfer, it rechecks for a challenge; unresolved challenges mark
the capture partial. It does not silently change the configured egress route.
The local `cffetch` / Copernicus workflow is a reference for challenge handoff and
reverification, not a dependency or an implicit switch into a machine-specific VPN.

Recovery observes Web Crypto in browser frames. Precomputed IDs are never hashed
in the page, so they are resolved from compiler output instead: `doc_id` through
the Relay catalog and X `queryId` through its persisted registry, both described
below. JavaScript-only hashing implementations and worker-only hashing still need
another evidence source and remain inventory-only. This feature does not evaluate bundles
or register guessed documents with the upstream server.

## Payload packaging

Capture and MCP replay share a bounded decoder. Capture retains structural shapes
and decoder layer names, not response values. Supported packaging can be nested:

| Packaging | Handling |
|---|---|
| JSON under incorrect MIME types | Parse bounded bytes, including GraphQL `text/plain` |
| JSON encoded as a JSON string | Unwrap only when it yields an object or array |
| Base64 / URL-safe base64, hex, percent encoding | Decode complete payloads without interpreting code |
| gzip, zlib/deflate, raw deflate | Bounded decompression; raw deflate requires an explicit encoding |
| bzip2, XZ | Bounded output and XZ decoder memory |
| ZIP | One unencrypted entry, in memory, no filesystem extraction |
| Known anti-XSSI guards | Remove recognized guards only |
| JSONP | Parse the callback argument; never execute the callback |
| NDJSON | Preserve bounded records as an array |
| GraphQL multipart JSON | Preserve complete parts; no inferred incremental-result merging |
| HTTP Brotli / Zstd | Browser/libcurl transport decoding; not guessed from arbitrary bytes |

Limits apply to input bytes, decoded bytes, cumulative expansion, nesting layers,
and multipart/NDJSON record counts. Unknown packaging, ciphertext without an
available key/plaintext boundary, executable obfuscators, truncated compression,
and incomplete multipart streams are not decoded into fabricated successes.
Packaged request bodies are useful inventory evidence, but remain non-executable
until an exact request replay adapter exists.

Shape truncation markers are evidence metadata, not JSON response properties.
The schema merger preserves observed nullability and leaves truncated values
unconstrained; it does not assert that a partial shape is a complete GraphQL schema.

## Nextdoor dogfood, 2026-09-08

Native MCP mapping recovered all 16 observed GraphQL documents, including
`getMe` and `PersonalizedFeed`. The generated Chart exposed 12 GraphQL reads and
two REST reads. The timestamp update and exposure logging operations were parsed
as mutations and stayed disabled. Both `getMe` and a one-item `PersonalizedFeed`
request succeeded through the generated MCP verification tool with schema
validation. No Nextdoor documents, credentials, or feed bodies are checked into
this repository; live evidence stays in the operator's private capture workspace.

The run also found and fixed native-null/truncation schema handling and a verification
reporting bug that treated successful GraphQL envelopes without an `ok` field as
failures. Verification now requires actual schema validation and no operation errors.

## X dogfood, 2026-09-09

X serves persisted queries as `/i/api/graphql/<queryId>/<OperationName>`, captured
under the `graphql-x-persisted` protocol. Web Crypto recovery does not apply: the
client never hashes the document, so there is no plaintext hash input to observe.

That is the same precomputed-ID condition as Meta `doc_id`, and it has the same
answer: resolve the ID from the application's own compiler output rather than
from the request. X ships one webpack module per operation whose entire body is a
literal export binding the ID to its name and kind:

```js
123456(e){e.exports={queryId:"...",operationName:"...",operationType:"query",...}}
```

`_x_registry` recovers these under the evidence rules the Relay path already uses:
tree-sitter only, literal fields only, exactly one exported statement assigning to
the module's own parameter. A computed ID, a rebound export target, a second
statement, a computed key or a malformed module is rejected rather than
interpreted. Joining still requires exact ID and operation-name agreement with no
conflicting kind for that ID, and an exhausted budget authorizes nothing.
Evidence is not interchangeable between protocols: `graphql-meta-doc-id` accepts
only `relay-compiler-ast` and `graphql-x-persisted` only `x-persisted-registry`,
so a Relay artifact cannot classify an X operation or the reverse.

Verified against X's live `responsive-web` bundle: `main.js` alone yields 104
registry artifacts (67 queries, 37 mutations) and binds four of the fifteen
operations this capture observed, including `DataSaverMode`, with an exact name
match. The remaining eleven live in other chunks that a logged-in page load
fetches. No X bundle content is copied into this repository; the tests use
independently authored synthetic modules.

Two budgets bound this end to end, and the fix for each is now in place. The
script cap was one: the first observed page loaded 294 scripts against
`MAX_SCRIPTS = 256`, so the catalog was marked exhausted and bound nothing. The
cap is now 512. The second was the 64 MiB cumulative byte budget: a broad
authenticated walk loads X's large marker-less framework bundles, which counted
against recovery without ever producing an artifact and exhausted it. Scripts with
none of the recovery markers are now skipped before they count, so the byte and
script budgets are spent on candidate bundles. An exhausted catalog still
authorizes nothing; the per-script (8 MiB) and total (64 MiB) byte guards are
unchanged.

Authenticated dogfood, 2026-09-09: native `--browser vivaldi` import of a live
x.com session, local strict-TLS capture (no Burp, no VPN re-routing of the
session), `--recover-persisted --block-assets --max-operation-requests 2` across
ten authenticated surfaces. `--block-assets` blocks only image/media/font; X's
request-eaters are first-party telemetry XHR (`flow/timeline.json`,
`viewer_context`, `app_context`, CSP and measurement beacons), which the low
per-operation cap throttles by capping repeat calls to each endpoint. The walk
completed within the 100-request native cap (81 used, not partial), loaded 260
candidate scripts / 3079 artifacts without exhausting recovery, and classified
19 of 21 observed persisted operations from compiler metadata: 14 exposed reads
(`HomeTimeline`, `NotificationsTimeline`, `ExploreSidebar`, `PinnedTimelines`,
`SidebarUserRecommendations`, `DataSaverMode`, `CreatorStudioTabBarItemQuery`,
`NflScoresSidebarFollow`, `useStoryTopicQuery`, `useDirectCallSetupQuery`,
`xChatDmSettingsQuery`, `PremiumContentQuery`, `useFetchProductSubscriptionsQuery`,
`CarouselQuery`, `TopicCarouselQuery`, `CommunitiesCreateButtonQuery`) plus two
gated mutations (`CreateWebSessionBind`, `usePremiumPaywallOnLoadMutation`). Two
operations (`GenerateXChatTokenMutation`, `GetPublicKeysQuery`) stayed `unknown`
because their defining chunks were not among those loaded -- the correct
fail-closed state, not a finished result. The REST surface adds six exposed reads
and five gated writes. No X query documents, credentials, or response bodies are
checked into this repository.

Capture referenced: `chart-x.com-cc488f7e1895/` (private, gitignored). 84 records,
strict TLS, no failures, not partial. No X query documents, credentials, or
response bodies are checked into this repository.

## Prior effort

This extends Astrolabe's existing APQ runtime and uses its existing MIT-licensed
[graphql-core parser](https://github.com/graphql-python/graphql-core); no external
source implementation was copied. Exact-document SHA-256 matching follows the
[Apollo persisted-query protocol](https://www.apollographql.com/docs/react/api/link/persisted-queries).
The implementation adds a browser evidence join, rather than another GraphQL parser.
