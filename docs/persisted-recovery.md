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

Use the generated Chart server (`sextant-mcp`, `ASTROLABE_TOOLPACK`,
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

## Prior effort

This extends Astrolabe's existing APQ runtime and uses its existing MIT-licensed
[graphql-core parser](https://github.com/graphql-python/graphql-core); no external
source implementation was copied. Exact-document SHA-256 matching follows the
[Apollo persisted-query protocol](https://www.apollographql.com/docs/react/api/link/persisted-queries).
The implementation adds a browser evidence join, rather than another GraphQL parser.
