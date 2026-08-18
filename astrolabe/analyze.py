#!/usr/bin/env python3
"""astrolabe analyzer — turn a capture dir into map.md + endpoints.json.

Generic across sites. Reads: capture.jsonl, meta.json, and (optional) schema.json
(clairvoyance) + openapi.yaml/json (har-to-openapi). Emits a human map and a
machine-readable inventory. Records shapes only — no PII.
"""

from __future__ import annotations
import argparse, json, os, re, collections, urllib.parse as up

from .gqlvars import merge_declared_with_observed, parse_variable_definitions
from .shapemerge import merge_shapes
from .operation import graphql_protocol, semantic_kind
from .media import MediaKind, classify_media
from .artifact import (
    atomic_write_json,
    atomic_write_text,
    build_manifest,
    utc_now,
    write_manifest,
)
from .ir import graph_from_inventory, load_graph, merge_graphs, write_graph
from .discovery import DiscoverySource, completeness_metrics, pipeline_discovery_corpus
from .schema import validate_artifact

OP = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)")

# Site-agnostic default categorization for GraphQL operations. Domain-neutral
# buckets matched on API vocabulary common across arbitrary targets — no
# vendor/product names, so this works the same on an e-commerce site, a social
# app, or anything else. A per-site capture dir may prepend its own buckets
# via categories.json (see load_categories()) without needing to edit this
# module — that's how a site with a genuinely distinct vocabulary (e.g. a
# ticketing platform's "box office" terms) extends the defaults.
CATS_DEFAULT = [
    (
        "Search & discovery",
        r"(search|query|suggest|discover|recommend|related|browse|explore|typeahead|autocomplete|facet)",
    ),
    (
        "Commerce & payments",
        r"(cart|checkout|order|payment|billing|invoice|price|product|purchase|subscription|wallet|balance|\bfee\b|discount|coupon)",
    ),
    ("Users & profiles", r"(user|profile|identity|account|avatar|member|author)"),
    ("Social graph", r"(follow|friend|connection|\bblock\b|\bmute\b|network)"),
    (
        "Messaging & notifications",
        r"(message|inbox|\bchat\b|conversation|notification|unread|announcement|alert)",
    ),
    (
        "Content & media",
        r"(post|article|comment|review|rating|media|image|video|upload|\bfeed\b|content|blog)",
    ),
    ("Account & settings", r"(setting|preferenc|permission|security|privacy|consent|config)"),
]


def load_categories(outdir):
    """Return the categorization buckets to use for one capture dir: any
    site-specific override declared in <outdir>/categories.json — a JSON list
    of [name, regex] pairs — prepended ahead of the generic, site-agnostic
    defaults (so the site's own vocabulary wins first). Falls back to defaults
    only if categories.json is absent, unreadable, or malformed."""
    overrides = []
    p = os.path.join(outdir, "categories.json")
    if os.path.exists(p):
        try:
            data = json.load(open(p))
            if isinstance(data, list):
                for item in data:
                    if (
                        isinstance(item, (list, tuple))
                        and len(item) == 2
                        and isinstance(item[0], str)
                        and isinstance(item[1], str)
                    ):
                        overrides.append((item[0], item[1]))
        except Exception:
            overrides = []
    return overrides + CATS_DEFAULT


def load(outdir):
    recs = []
    p = os.path.join(outdir, "capture.jsonl")
    if os.path.exists(p):
        recs = [json.loads(l) for l in open(p)]
    meta = {}
    mp = os.path.join(outdir, "meta.json")
    if os.path.exists(mp):
        meta = json.load(open(mp))
    return recs, meta


def _depth_keys(v, d=0):
    """Count nested dict keys (used to pick the richest input shape)."""
    if not isinstance(v, dict) or d > 5:
        return 0
    return len(v) + sum(_depth_keys(x, d + 1) for x in v.values())


def op_id(rec, gqlop):
    """Best human id for an operation across aliasing conventions."""
    qs = dict(up.parse_qsl(up.urlparse(rec["url"]).query))
    if qs.get("alias"):
        return qs["alias"]
    if qs.get("operationName"):
        return qs["operationName"]
    if gqlop.get("operationName"):
        return gqlop["operationName"]
    m = OP.search(gqlop.get("query") or "")
    if m:
        return m.group(2)
    if gqlop.get("persistedHash"):
        return "persisted:" + gqlop["persistedHash"][:12]
    return "(anonymous)"


def _categorize(text, cats):
    t = text.lower()
    for name, pat in cats:
        if re.search(pat, t):
            return name
    return "Other"


def category(text):
    """Categorize `text` using the generic, site-agnostic default buckets.
    render() uses _categorize() directly with the per-capture-dir categories
    (defaults + any categories.json override) instead of this convenience
    wrapper, so a site override is honored during actual map.md generation."""
    return _categorize(text, CATS_DEFAULT)


def path_tmpl(url):
    """Single-URL lexical guess at a REST path template: does a segment merely
    *look* parameter-shaped (a 3+ digit run, a 24+ char lowercase-hex run, or a
    `~uid`-style tilde segment)? This has no evidence beyond one URL, so it can
    both miss real parameters (`/api/user/42` — only 2 digits) and wrongly
    templatize a genuine literal segment that happens to look numeric.

    Kept intact, verbatim, for two reasons: (1) it is the fallback
    PathTemplater below uses whenever a specific path position has too little
    cross-request evidence to say anything better, and (2) astrolabe/mcpgen.py
    (owned by a concurrent workstream) has its own frozen mirror,
    `_template_path`, that keys captured REST response shapes to these exact
    templates — changing this function's substitution rules would silently
    break that join. See PathTemplater for the evidence-based replacement
    used by build() to key the REST inventory.
    """
    p = up.urlparse(url).path
    p = re.sub(r"/\d{3,}", "/{id}", p)
    p = re.sub(r"/[0-9a-f]{24,}", "/{hash}", p)
    p = re.sub(r"~[0-9a-z]+", "~{uid}", p)
    return p


# ---- evidence-based REST path templating -----------------------------------
# path_tmpl() above answers "does this one URL look parameter-shaped?" with no
# cross-request context. PathTemplater answers the better question: "did this
# *position*, across every request sharing the same literal prefix, actually
# vary?" That is real evidence a segment is a parameter rather than a guess
# about what its value looks like.
#
# Implementation: build a trie over the '/'-delimited segments of every
# observed REST path, counting occurrences at each edge. At any node in that
# trie -- i.e. for one exact literal prefix -- two numbers describe the next
# position: N, the total requests observed passing through that prefix, and
# D, the number of *distinct* next-segment values among them.
#
#   - D == 1 (always the same next segment) -> literal, unconditionally: zero
#     observed variation is definitive regardless of sample size.
#   - N < MIN_SAMPLES (default 4) -> THIN EVIDENCE. 1-3 total observations is
#     too little to trust a cardinality signal either way (the spec this
#     implements explicitly calls out 2-3 observations as weak evidence) --
#     fall back to path_tmpl()'s lexical heuristic for that one segment. This
#     also keeps the common single/low-observation case byte-identical to
#     path_tmpl()/mcpgen._template_path.
#   - D >= 2 and N >= MIN_SAMPLES -> look at the *uniqueness ratio* D/N rather
#     than raw distinctness alone. Pure "D >= 2 => parameter" over-fires on a
#     real, common shape: a capture naturally visits many *different REST
#     resources* under a shared prefix (`/api/cart`, `/api/checkout`,
#     `/api/user`, `/api/orders`, ...), and that position necessarily has many
#     distinct values too -- but each is a genuinely different endpoint
#     literal, repeated across many requests to that same endpoint, not an
#     id space. An id/slug/hash/uuid position looks different: almost every
#     request through it carries a *different* value, so D approaches N. A
#     small closed set of literal siblings (a handful of resource names, or a
#     version fork like v1/v2) instead has D held down by repeat traffic to
#     each literal, so D/N stays low even as N grows. Parameterize only when
#     D/N >= PARAM_UNIQUE_RATIO (default 0.6): most of the traffic through
#     this node used a distinct value.
#
# This ratio check is also what keeps small enumerations (api versions,
# environment names, a 2-3-way literal fork) from collapsing into a bogus
# parameter purely because they technically have D >= 2 -- the same mechanism
# that fixes `/api/user/42` (D/N -> 1.0 once a few different ids are seen)
# naturally protects the low-cardinality literal-fork case too, without a
# special exemption list.
#
# Naming: once a position is templated, every value observed there is
# inspected together: all UUID-shaped -> {uuid}; all-numeric -> {id}; all
# long lowercase/uppercase hex -> {hash}; otherwise -> {slug}.
#
# Residual limitation: a route that forks into exactly two (or a few) literal
# branches that *also* each see only light, roughly-even traffic can still
# land above the ratio threshold and get merged -- e.g. `/user/{id}` vs.
# `/user/settings` observed once each (D=2, N=2) is thin evidence (N <
# MIN_SAMPLES) and falls back to the lexical guess per segment instead, but
# the same fork observed 3-4 times apiece could cross PARAM_UNIQUE_RATIO. This
# is an accepted tradeoff of cardinality-only clustering (no semantic
# awareness of "is this a resource name or a value"), not fixed here.

MIN_SAMPLES = 4  # fewer total requests through a trie position than
# this is thin evidence; fall back to the lexical
# guess for that segment regardless of distinctness.
PARAM_UNIQUE_RATIO = 0.6  # >= this fraction of requests through a position
# using a distinct value is treated as an id/slug/
# hash/uuid space rather than a small literal fork.

_SEG_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_SEG_DIGITS = re.compile(r"^\d+$")
_SEG_HEX = re.compile(r"^[0-9a-f]+$", re.I)


def _param_name_for_values(values):
    """Name a templated position by inspecting every raw value observed
    there, so generated REST tools get readable input names instead of a
    generic placeholder."""
    vals = list(values)
    if vals and all(_SEG_UUID.match(v) for v in vals):
        return "uuid"
    if vals and all(_SEG_DIGITS.match(v) for v in vals):
        return "id"
    if vals and all(len(v) >= 24 and _SEG_HEX.match(v) for v in vals):
        return "hash"
    return "slug"


class _TrieNode:
    __slots__ = ("children", "counts")

    def __init__(self):
        self.children: dict[str, _TrieNode] = {}
        self.counts: dict[str, int] = {}  # next-segment value -> occurrence count


class PathTemplater:
    """Evidence-based REST path templater built from every path observed in
    one capture. Construct once with `build()`'s full record set, then call
    `.apply(url)` per record -- this is inherently a two-pass operation
    (learn cardinality across all requests, then template each one), unlike
    path_tmpl()'s single-URL pure function.
    """

    def __init__(self, urls):
        self._root = _TrieNode()
        for u in urls:
            segs = up.urlparse(u).path.split("/")
            node = self._root
            for s in segs:
                node.counts[s] = node.counts.get(s, 0) + 1
                node = node.children.setdefault(s, _TrieNode())

    def apply(self, url):
        path = up.urlparse(url).path
        raw = path.split("/")
        baseline = path_tmpl(url).split("/")
        out = []
        node: _TrieNode | None = self._root
        for i, s in enumerate(raw):
            counts = node.counts if node is not None else {}
            n = sum(counts.values())
            d = len(counts)
            if d >= 2 and n >= MIN_SAMPLES and (d / n) >= PARAM_UNIQUE_RATIO:
                out.append("{" + _param_name_for_values(counts.keys()) + "}")
            else:
                out.append(baseline[i] if i < len(baseline) else s)
            node = node.children.get(s) if node is not None else None
        return "/".join(out)


def input_schema(op):
    """Typed input schema for one operation, from two complementary sources.

    The captured query text declares every variable with its exact type and
    requiredness — including variables this capture never exercised. Observed
    variable values supply the internal structure of custom input objects, which
    the declaration only names. Declaration wins on types; observations fill in
    structure. Falls back to observations alone for persisted operations, which
    carry a hash instead of query text.
    """
    declared = parse_variable_definitions(op.get("query") or "")
    observed = merge_observed_variables(op.get("input_shapes") or [])
    if declared:
        return merge_declared_with_observed(declared, observed)
    return observed or {"type": "object", "properties": {}}


def merge_observed_variables(shapes):
    """Union every observed variable shape rather than picking one sample."""
    return merge_shapes(shapes) if shapes else {}


def build(recs, meta):
    base = meta.get("base_domain", "")
    gql_paths = set(meta.get("graphql_endpoints", {}).keys())

    ops = {}
    for r in recs:
        if "graphql" not in r:
            continue
        for o in r["graphql"]:
            # A multi-operation document executes only the envelope-selected member.
            # Inventorying its siblings as observed would manufacture proof.
            if o.get("selected") is False:
                continue
            oid = op_id(r, o)
            kind = o.get("semantic_kind") or semantic_kind(o.get("query")).value
            protocol = (
                o.get("protocol")
                or graphql_protocol(
                    query=o.get("query"),
                    persisted_id=o.get("persistedHash"),
                    url=r.get("url", ""),
                    media_type=r.get("request_media_type", ""),
                ).value
            )
            d = ops.setdefault(
                oid,
                {
                    "type": kind,
                    "semantic_kind": kind,
                    "protocol": protocol,
                    "op": o.get("operationName"),
                    "vars": set(),
                    "returns": set(),
                    "hash": o.get("persistedHash"),
                    "count": 0,
                    "status": set(),
                    "input_shape": None,
                    "input_shapes": [],
                    "query": "",
                    "http_method": r.get("method"),
                    "request_media_type": r.get("request_media_type"),
                    "request_url": r.get("url", "").split("#", 1)[0],
                },
            )
            d["parse_confidence"] = o.get("parse_confidence") or "legacy"
            d["directives"] = sorted(
                set(d.get("directives") or []) | set(o.get("directives") or [])
            )
            d["root_fields"] = sorted(
                set(d.get("root_fields") or []) | set(o.get("root_fields") or [])
            )
            if o.get("request_template"):
                d["request_template"] = o["request_template"]
            d["count"] += 1
            d["status"].add(r["status"])
            d["vars"].update(o.get("variables_keys") or [])
            # Keep the longest query text seen: its variable declaration list is the
            # authoritative source for input types and requiredness (see gqlvars).
            q = o.get("query") or ""
            if len(q) > len(d["query"]):
                d["query"] = q
            vs = o.get("variables_shape")
            if isinstance(vs, dict):
                d["input_shapes"].append(vs)
            # keep the richest input shape seen (most nested keys)
            if isinstance(vs, dict) and _depth_keys(vs) > _depth_keys(d["input_shape"]):
                d["input_shape"] = vs
            rs = r.get("resp_shape")
            if isinstance(rs, dict) and isinstance(rs.get("data"), dict):
                d["returns"].update(rs["data"].keys())

    def eligible_rest(record):
        kind = (
            record.get("response_kind")
            or classify_media(record.get("resp_ct"), record.get("rtype")).value
        )
        return kind not in {
            MediaKind.HTML.value,
            MediaKind.JAVASCRIPT.value,
        }

    rest_urls = [
        r["url"]
        for r in recs
        if "graphql" not in r and up.urlparse(r["url"]).path not in gql_paths and eligible_rest(r)
    ]
    templater = PathTemplater(rest_urls)

    rest = collections.OrderedDict()
    for r in recs:
        if "graphql" in r or up.urlparse(r["url"]).path in gql_paths or not eligible_rest(r):
            continue
        key = (r["method"], templater.apply(r["url"]))
        e = rest.setdefault(
            key,
            {"n": 0, "hdr": {}, "status": set(), "response_kinds": set(), "media_types": set()},
        )
        e["n"] += 1
        e["status"].add(r["status"])
        e["response_kinds"].add(
            r.get("response_kind") or classify_media(r.get("resp_ct"), r.get("rtype")).value
        )
        if r.get("resp_ct"):
            e["media_types"].add(str(r["resp_ct"]).split(";", 1)[0].lower())
        if r.get("req_headers"):
            e["hdr"] = r["req_headers"]
    return ops, rest


def websocket_operations(meta):
    """Normalize meta.json's `websockets` catalog (capture.py's shape-only
    socket.io/WS event inventory) into the same {key: operation} shape the
    GraphQL/REST inventories use, so downstream tooling (mcp-gen and anything
    that walks endpoints.json) can consume all three transports uniformly.

    `direction` matters: "sent" events are things a client can emit
    (candidate operations); "received" events are server pushes (candidate
    subscriptions). Inventory + typing only -- there is no socket transport in
    the MCP server, so nothing here is made executable.
    """
    ops = {}
    for url, entry in (meta.get("websockets") or {}).items():
        if not isinstance(entry, dict):
            continue
        eio = entry.get("engineio")
        for direction, evs in (
            ("sent", entry.get("events_sent") or {}),
            ("received", entry.get("events_received") or {}),
        ):
            for name, d in evs.items():
                key = f"{url}::{direction}::{name}"
                ops[key] = {
                    "url": url,
                    "event": name,
                    "direction": direction,
                    "namespace": d.get("ns"),
                    "calls": d.get("count", 0),
                    "input_schema": merge_shapes([d.get("arg_shape")]),
                    "engineio": eio,
                }
        non_socketio = entry.get("non_socketio") or {}
        if not eio:
            for direction in ("sent", "received"):
                calls = int(non_socketio.get(direction) or 0)
                if not calls:
                    continue
                event_name = "raw-message"
                key = f"{url}::{direction}::{event_name}"
                ops[key] = {
                    "url": url,
                    "event": event_name,
                    "direction": direction,
                    "namespace": None,
                    "calls": calls,
                    "input_schema": {},
                    "engineio": None,
                }
    return ops


def miscellaneous_operations(recs, meta):
    """Inventory unsupported backend protocols without making any executable."""
    operations = {}
    for record in recs:
        url = str(record.get("url") or "")
        path = up.urlparse(url).path.lower()
        request_media = str(record.get("request_media_type") or "").lower()
        response_media = str(record.get("resp_ct") or "").lower()
        request_shape = record.get("request_shape") or {}
        protocol = None
        if "grpc-web" in request_media or "grpc-web" in response_media:
            protocol = "grpc-web"
        elif "protobuf" in request_media or "protobuf" in response_media:
            protocol = "protobuf"
        elif "/trpc/" in path or path.startswith("/trpc"):
            protocol = "trpc"
        elif isinstance(request_shape, dict) and {"jsonrpc", "method"}.issubset(request_shape):
            protocol = "json-rpc"
        if protocol:
            key = f"{protocol}:{record.get('method', 'POST')}:{url}"
            entry = operations.setdefault(
                key,
                {
                    "id": key,
                    "protocol": protocol,
                    "url": url,
                    "method": record.get("method") or "POST",
                    "calls": 0,
                    "request_shape": request_shape,
                    "response_shape": record.get("resp_shape"),
                    "executable": False,
                    "disabled_reason": ("inventory-only protocol; no reviewed execution adapter"),
                },
            )
            entry["calls"] += 1
    for url in meta.get("service_workers") or []:
        key = f"service-worker:{url}"
        operations[key] = {
            "id": key,
            "protocol": "service-worker",
            "url": url,
            "method": "REGISTER",
            "calls": 1,
            "executable": False,
            "disabled_reason": "inventory-only browser worker channel",
        }
    for item in meta.get("offline_queues") or []:
        kind = (
            str(item.get("kind") or "browser-storage")
            if isinstance(item, dict)
            else "browser-storage"
        )
        key = f"offline-queue:{kind}"
        operations[key] = {
            "id": key,
            "protocol": "offline-queue",
            "url": f"browser-storage://{kind}",
            "method": "QUEUE",
            "calls": int(item.get("count") or 1) if isinstance(item, dict) else 1,
            "executable": False,
            "disabled_reason": "inventory-only offline queue",
        }
    return operations


def render(outdir, recs, meta, *, prior_graph=None):
    cats = load_categories(outdir)
    ops, rest = build(recs, meta)
    base = meta.get("base_domain", "?")
    ev = meta.get("events", {})
    schema_path = os.path.join(outdir, "schema.json")
    openapi_path = next(
        (
            os.path.join(outdir, f)
            for f in ("openapi.yaml", "openapi.json")
            if os.path.exists(os.path.join(outdir, f))
        ),
        None,
    )

    # endpoints.json
    inv = {
        "base_domain": base,
        "graphql_endpoints": list(meta.get("graphql_endpoints", {})),
        "auth_headers": meta.get("auth_headers", {}),
        "introspection": ev.get("introspection"),
        "graphql_operations": {
            k: {
                "type": v["semantic_kind"],
                "semantic_kind": v["semantic_kind"],
                "protocol": v["protocol"],
                "http_method": v["http_method"],
                "request_media_type": v.get("request_media_type"),
                "request_url": v["request_url"],
                "request_template": v.get("request_template") or {},
                "parse_confidence": v.get("parse_confidence"),
                "directives": v.get("directives") or [],
                "root_fields": v.get("root_fields") or [],
                "query": v.get("query") or None,
                "operation": v["op"],
                "variables": sorted(v["vars"]),
                "returns": sorted(v["returns"]),
                "input_shape": v["input_shape"],
                "input_schema": input_schema(v),
                "persistedHash": v["hash"],
                "calls": v["count"],
            }
            for k, v in ops.items()
        },
        "rest_endpoints": [
            {
                "method": m,
                "path": p,
                "auth_headers": list(e["hdr"]),
                "calls": e["n"],
                "status": sorted(e["status"]),
                "response_kinds": sorted(e["response_kinds"]),
                "response_media_types": sorted(e["media_types"]),
            }
            for (m, p), e in rest.items()
        ],
        "websockets": meta.get("websockets", {}),
        "websocket_operations": websocket_operations(meta),
        "misc_operations": miscellaneous_operations(recs, meta),
    }
    atomic_write_json(os.path.join(outdir, "endpoints.json"), inv)
    graph = graph_from_inventory(inv, recs, meta)
    if prior_graph and os.path.exists(prior_graph):
        graph_value = merge_graphs(load_graph(prior_graph), graph.to_dict())
        atomic_write_json(os.path.join(outdir, "graph.json"), graph_value)
    else:
        write_graph(os.path.join(outdir, "graph.json"), graph)

    def optional_json(path):
        if not path or not os.path.exists(path) or not path.endswith(".json"):
            return None
        try:
            with open(path, encoding="utf-8") as handle:
                value = json.load(handle)
            return value if isinstance(value, dict) else None
        except (OSError, ValueError):
            return None

    scan_report = optional_json(os.path.join(outdir, "scan.json"))
    openapi_doc = optional_json(openapi_path)
    schema_doc = optional_json(schema_path)
    corpus = pipeline_discovery_corpus(
        recs,
        meta,
        scan_report=scan_report,
        openapi=openapi_doc,
        schema=schema_doc,
    )
    corpus_value = corpus.to_dict()
    candidates = corpus.candidates
    traffic_sources = {DiscoverySource.TRAFFIC}
    static_sources = {
        DiscoverySource.BUNDLE,
        DiscoverySource.SOURCE_MAP,
        DiscoverySource.MANIFEST,
    }

    def has_source(candidate, sources):
        return bool({item.source for item in candidate.evidence} & sources)

    def endpoint_token(value):
        parsed_value = up.urlparse(value)
        return parsed_value.path if parsed_value.scheme else value

    observed = {
        endpoint_token(item.value)
        for item in candidates
        if item.kind == "endpoint" and has_source(item, traffic_sources)
    }
    observed.update(
        item.value
        for item in candidates
        if item.kind in {"graphql-operation-name", "persisted-identifier"}
        and has_source(item, traffic_sources)
    )
    static_candidates = {
        endpoint_token(item.value)
        for item in candidates
        if item.kind == "endpoint" and has_source(item, static_sources)
    }
    static_candidates.update(
        item.value
        for item in candidates
        if item.kind in {"graphql-operation-name", "persisted-identifier"}
        and has_source(item, static_sources)
    )
    navigation_routes = {
        item.value for item in candidates if item.kind == "navigation-route"
    }
    observed_routes = set(meta.get("surfaces") or [])
    observed_spec_ops = {
        f"{str(record.get('method') or 'GET').upper()} {up.urlparse(str(record.get('url') or '')).path}"
        for record in recs
        if record.get("url")
    }
    spec_operations = {item.value for item in candidates if item.kind == "spec-operation"}
    schema_fields = {
        item.value.rsplit(".", 1)[-1] for item in candidates if item.kind == "schema-field"
    }
    observed_fields = {field for operation in ops.values() for field in operation["returns"]}
    recipe_actions = {item.key for item in candidates if item.kind == "recipe-action"}
    completed_actions = {
        item.key
        for item in candidates
        if item.kind == "recipe-action" and item.metadata.get("completed")
    }
    run_sets = []
    if prior_graph and os.path.exists(prior_graph):
        prior_value = load_graph(prior_graph)
        run_sets.append(
            {
                str(item.get("id"))
                for item in prior_value.get("operations", [])
                if isinstance(item, dict) and item.get("id")
            }
        )
    run_sets.append(
        {
            str(item.get("id"))
            for item in graph.to_dict().get("operations", [])
            if isinstance(item, dict) and item.get("id")
        }
    )
    coverage_value = completeness_metrics(
        observed=observed,
        static_candidates=static_candidates,
        navigation_routes=navigation_routes,
        spec_operations=spec_operations,
        schema_fields=schema_fields,
        recipe_actions=recipe_actions,
        completed_actions=completed_actions,
        run_operation_sets=run_sets,
    )
    # Denominators live in different namespaces; supply their matching observations.
    coverage_value["navigation_coverage"] = {
        "covered": len(observed_routes & navigation_routes),
        "total": len(navigation_routes),
        "ratio": round(len(observed_routes & navigation_routes) / len(navigation_routes), 6)
        if navigation_routes
        else None,
    }
    coverage_value["spec_coverage"] = {
        "covered": len(observed_spec_ops & spec_operations),
        "total": len(spec_operations),
        "ratio": round(len(observed_spec_ops & spec_operations) / len(spec_operations), 6)
        if spec_operations
        else None,
    }
    coverage_value["schema_field_coverage"] = {
        "covered": len(observed_fields & schema_fields),
        "total": len(schema_fields),
        "ratio": round(len(observed_fields & schema_fields) / len(schema_fields), 6)
        if schema_fields
        else None,
    }
    corpus_value["coverage"] = coverage_value
    validate_artifact(corpus_value, "discovery-v1.schema.json")
    atomic_write_json(os.path.join(outdir, "discovery.json"), corpus_value)

    # map.md
    L = []
    W = L.append
    W(f"# {base} — API / GraphQL map\n")
    W(f"_Generated by astrolabe. Surface only (no response values / token values persisted)._\n")
    W("## Summary\n")
    W(f"- First-party API calls captured: **{len(recs)}**")
    W(
        f"- GraphQL endpoint(s): {', '.join('`' + p + '`' for p in meta.get('graphql_endpoints', {})) or '—'}"
    )
    W(f"- Distinct GraphQL operations: **{len(ops)}**  |  REST endpoints: **{len(rest)}**")
    wsk = meta.get("websockets", {})
    if wsk:
        ws_ev = sum(
            len(s.get("events_sent", {})) + len(s.get("events_received", {})) for s in wsk.values()
        )
        W(f"- WebSocket(s): **{len(wsk)}**  |  socket.io events: **{ws_ev}**")
    ah = meta.get("auth_headers", {})
    W(f"- Auth/client headers: {', '.join('`' + h + '`' for h in ah) or '—'}")
    intro = ev.get("introspection")
    if intro:
        W(
            f"- GraphQL introspection: **{'ENABLED' if intro.get('enabled') else 'disabled'}**"
            + (f" ({intro.get('types')} types)" if intro.get("enabled") else "")
            + (f" — schema recovered → `schema.json`" if os.path.exists(schema_path) else "")
        )
    if os.path.exists(schema_path):
        try:
            sch = json.load(open(schema_path))
            n = len(
                (sch.get("data", {}).get("__schema", {}) or sch.get("__schema", {})).get(
                    "types", []
                )
            )
            W(f"- Recovered schema (clairvoyance): **{n} types** in `schema.json`")
        except Exception:
            W("- Recovered schema (clairvoyance): `schema.json`")
    if openapi_path:
        W(f"- REST OpenAPI spec: `{os.path.basename(openapi_path)}`")
    if ev.get("cf"):
        W(
            f"- Cloudflare challenges hit: {len(ev['cf'])} (byparr fallback used {len(ev.get('byparr', []))}×)"
        )
    W("")

    # GraphQL operations by category
    W("## GraphQL operations\n")
    buckets = collections.defaultdict(list)
    for oid, d in ops.items():
        buckets[_categorize(oid + " " + " ".join(d["returns"]) + " " + str(d["op"]), cats)].append(
            (oid, d)
        )
    for name, _ in cats + [("Other", None)]:
        rows = sorted(buckets.get(name, []))
        if not rows:
            continue
        W(f"### {name} ({len(rows)})\n")
        W("| operation / alias | type | variables | returns |")
        W("|---|---|---|---|")
        for oid, d in rows:
            op = f"`{d['op']}`" if d["op"] else "_persisted_"
            v = ", ".join(f"`{x}`" for x in sorted(d["vars"])) or "—"
            ret = ", ".join(f"`{x}`" for x in sorted(d["returns"])) or "—"
            W(f"| `{oid}` | {op} {d['type']} | {v} | {ret} |")
        W("")

    # Notable input schemas (nested GraphQL inputs — e.g. search filter params)
    rich = [
        (oid, d)
        for oid, d in ops.items()
        if isinstance(d["input_shape"], dict) and _depth_keys(d["input_shape"]) >= 3
    ]
    if rich:
        W("## Notable input schemas (request variable structure)\n")
        for oid, d in sorted(rich, key=lambda x: -_depth_keys(x[1]["input_shape"]))[:12]:
            W(f"**`{oid}`**")
            W("```json")
            W(json.dumps(d["input_shape"], indent=2))
            W("```\n")

    # REST
    if rest:
        W("## REST / non-GraphQL endpoints\n")
        W("| method | path | auth | calls | status |")
        W("|---|---|---|---|---|")
        for (m, p), e in sorted(rest.items(), key=lambda x: -x[1]["n"]):
            W(f"| {m} | `{p}` | {', '.join(e['hdr']) or '—'} | {e['n']} | {sorted(e['status'])} |")
        W("")

    # WebSocket / socket.io surface
    wsk = meta.get("websockets", {})
    if wsk:
        W("## WebSocket / socket.io surface\n")
        W("_Frames cataloged shape-only — event names + argument structure, no payload values._\n")
        for url, s in sorted(wsk.items()):
            eio = s.get("engineio")
            hs = f" (Engine.IO v{eio})" if eio else ""
            frames = s.get("frames", 0)
            W(f"### `{url}`{hs}\n")
            meta_bits = [f"{frames} frames"]
            if s.get("binary_frames"):
                meta_bits.append(f"{s['binary_frames']} binary")
            nonsio = s.get("non_socketio", {})
            if nonsio.get("sent") or nonsio.get("received"):
                meta_bits.append(
                    f"{nonsio.get('sent', 0)}↑/{nonsio.get('received', 0)}↓ non-socket.io"
                )
            W(f"_{', '.join(meta_bits)}._\n")
            for label, evs in (
                ("received (server → client)", s.get("events_received", {})),
                ("sent (client → server)", s.get("events_sent", {})),
            ):
                if not evs:
                    continue
                W(f"**Events {label}** ({len(evs)})\n")
                W("| event | ns | count | arg shape |")
                W("|---|---|---|---|")
                for name, d in sorted(evs.items()):
                    ns = f"`{d['ns']}`" if d.get("ns") else "—"
                    argsh = d.get("arg_shape")
                    argstr = "`" + json.dumps(argsh) + "`" if argsh not in (None, [], {}) else "—"
                    if len(argstr) > 120:
                        argstr = argstr[:117] + "…`"
                    W(f"| `{name}` | {ns} | {d.get('count', 0)} | {argstr} |")
                W("")

    atomic_write_text(os.path.join(outdir, "map.md"), "\n".join(L))
    now = utc_now()
    manifest = build_manifest(
        outdir,
        artifact_type="backend-map",
        artifact_schema_version=1,
        run_id=str(meta.get("run_id") or f"capture-{base}"),
        target=base,
        completeness="partial" if meta.get("partial") else "complete",
        started_at=str(meta.get("started_at") or meta.get("captured_at") or now),
        completed_at=str(meta.get("completed_at") or meta.get("captured_at") or now),
        artifact_names=["graph.json", "endpoints.json", "discovery.json", "map.md"],
        profile=meta.get("profile"),
        failures=list(meta.get("failures") or []),
        truncations=dict(meta.get("truncations") or {}),
        safety_mode=str(meta.get("safety_mode") or "read-only"),
    )
    write_manifest(os.path.join(outdir, "artifact-manifest.json"), manifest)
    return len(ops), len(rest)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    a = ap.parse_args()
    recs, meta = load(a.outdir)
    nops, nrest = render(a.outdir, recs, meta)
    print(f"[analyze] {nops} gql ops, {nrest} rest endpoints -> {a.outdir}/map.md, endpoints.json")


if __name__ == "__main__":
    main()
