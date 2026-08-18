#!/usr/bin/env python3
"""astrolabe mcp-gen — turn a capture dir into a typed MCP toolpack.

Joins endpoints.json (typed inventory: input shapes + returns) with capture.jsonl
(full query text) and, when present, contract.json (the durable contract of record,
ADR-0003) -> toolpack.json: one typed tool per safe, executable operation.

Covers both transports the capture layer can observe:
  * graphql — inline query text (or a curated --overrides query) posted to the
              GraphQL endpoint.
  * rest    — method + path template, called directly. Path placeholders emitted by
              analyze.path_tmpl ({id}, {hash}, {uid}) become required typed inputs.

Curation: exposes read-only operations; writes, persisted (no-query) ops and telemetry
are recorded but marked exposed=false with a reason. Return schemas are carried through
from the contract (preferred) or the raw capture, so tools are typed on both sides.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse as up
from typing import Any

from .gqlschema import SchemaIndex
from .artifact import atomic_write_json
from .ir import evidence_records_from_graph, inventory_from_graph, load_graph, stable_id
from .media import is_api_media
from .operation import Protocol, SemanticKind, graphql_protocol, semantic_kind
from .graphql_doc import parse_graphql_document
from .shapemerge import coerce_to_schema, merge_json_schemas, merge_shapes

TOOLPACK_VERSION = 2

OP = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)")

# Generic, vendor-neutral telemetry / UI-chrome patterns. These are operations that
# exist on most sites and are never data ops worth handing an agent. Deliberately
# contains NO site-specific product names — a target whose telemetry uses its own
# vocabulary supplies it via --noise-pattern (see main()).
DEFAULT_NOISE = re.compile(
    r"(telemetry|analytics|metrics?\b|beacon|tracking|tracker|logger|logging|"
    r"heartbeat|keepalive|ping\b|pageview|impression|clickstream|"
    r"consent|cookie-?banner|announcement|advertisement|\bads?-|ad-status|"
    r"experiment|feature-?flag|abtest|ab-test|"
    r"footer|banner|nav-?chrome|displayed)",
    re.I,
)

# Path placeholders analyze.path_tmpl emits when it templatises a REST path.
PATH_PARAM = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

TYPEMAP = {"str": "string", "int": "integer", "bool": "boolean", "float": "number"}

READ_METHODS = {"GET", "HEAD", "OPTIONS"}

# HTTP method is an unreliable read/write signal on real REST APIs: .NET buyer
# backends expose GET operations that mutate (Favorite/AddToFavorite) and POST
# operations that only read (Search/ItemListing, a search with a filter body).
# So classify by the operation's own verb vocabulary and fall back to the method,
# resolving a conflict conservatively toward "write" — auto-exposing a mutation is
# worse than gating a read.
WRITE_VERBS = re.compile(
    r"(add|remove|delete|create|update|save|change|cancel|place|pay|process|submit|"
    r"send|combine|choose|revoke|deactivate|edit|\bset\b|buynow|checkout|logout|"
    r"signout|reset|confirm|apply|redeem|upload|import|merge|move|assign|approve|reject)",
    re.I,
)
READ_VERBS = re.compile(
    r"(get|search|list|show|view|find|lookup|browse|detail|count|check|display|"
    r"query|fetch|read|load|preview|status|info|all\b|model|active|current|history)",
    re.I,
)


def classify_rest(method: str, path: str, read_pattern: re.Pattern | None = None) -> str:
    """Return 'query' (read) or 'mutation' (write) for a REST operation.

    An explicit read_pattern (operator-supplied, --read-pattern) forces a read.
    Otherwise a write verb in the path wins over everything (so a mutating GET is
    still gated), then a read verb, then the HTTP method, then a conservative
    'mutation' default for any non-idempotent method with no signal either way.
    """
    tail = path.rsplit("/", 1)[-1] if "/" in path else path
    if read_pattern and read_pattern.search(path):
        return "query"
    if WRITE_VERBS.search(tail):
        return "mutation"
    if method.upper() in READ_METHODS:
        return "query"
    return "mutation"


class GenerationError(RuntimeError):
    """Raised when a capture cannot yield a usable toolpack."""


def shape_to_schema(v: Any) -> dict[str, Any]:
    if isinstance(v, dict):
        props = {k: shape_to_schema(x) for k, x in v.items()}
        return {"type": "object", "properties": props}
    if isinstance(v, list):
        return {"type": "array", "items": shape_to_schema(v[0])} if v else {"type": "array"}
    if isinstance(v, str) and v in TYPEMAP:
        return {"type": TYPEMAP[v]}
    return {}  # unknown / any


def tool_name(alias: str | None, op: str | None) -> str:
    base = alias if alias and alias != "(none)" else (op or "op")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", base)[:60]


def rest_tool_name(method: str, path: str) -> str:
    """Stable, readable name for a REST operation: getApiV2Products_id."""
    segs = [s for s in PATH_PARAM.sub(lambda m: m.group(1), path).split("/") if s]
    camel = "".join(s[:1].upper() + s[1:] for s in (re.sub(r"[^A-Za-z0-9]", "_", s) for s in segs))
    return re.sub(r"[^a-zA-Z0-9_-]", "_", f"{method.lower()}{camel}")[:60]


def _dedupe(name: str, taken: set[str]) -> str:
    """Deterministically resolve a name collision rather than letting the server reject
    the whole pack at startup."""
    if name not in taken:
        taken.add(name)
        return name
    for i in range(2, 1000):
        candidate = f"{name[: 60 - len(str(i)) - 1]}_{i}"
        if candidate not in taken:
            taken.add(candidate)
            return candidate
    raise GenerationError(f"cannot disambiguate tool name {name!r}")


def envelope_schema(return_schema: Any) -> dict[str, Any]:
    """Describe what a tool actually returns to the agent.

    The runtime hands back the upstream payload plus a `_astrolabe` provenance block, or a
    failure envelope. Describing `data` precisely is the useful part; the rest of the
    envelope is declared so structured output validates in both the success and failure
    case.

    Accepts either a merged JSON Schema or a legacy raw capture shape.
    """
    data_schema = coerce_to_schema(return_schema) if return_schema else {}
    schema: dict[str, Any] = {
        "type": "object",
        "additionalProperties": True,
        "properties": {
            "errors": {"type": "array", "description": "upstream GraphQL/API errors, if any"},
            "ok": {"type": "boolean", "description": "false on a astrolabe-level failure"},
            "error_code": {"type": "string"},
            "error_detail": {"type": "string"},
            "retryable": {"type": "boolean"},
            "_astrolabe": {
                "type": "object",
                "description": "provenance: http_status, duration_ms, attempts",
                "additionalProperties": True,
            },
        },
    }
    if data_schema:
        schema["properties"]["data"] = data_schema
    return schema


def load_overrides(path: str | None) -> dict[str, str]:
    """Curated minimal queries: <alias>.op.json files whose proven query text replaces
    the captured verbose one."""
    overrides: dict[str, str] = {}
    if not path or not os.path.isdir(path):
        return overrides
    for fn in sorted(os.listdir(path)):
        if not fn.endswith(".op.json"):
            continue
        full = os.path.join(path, fn)
        try:
            with open(full, encoding="utf-8") as fh:
                o = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[mcp-gen] WARN: unreadable override {fn}: {exc}", file=sys.stderr)
            continue
        if o.get("alias") and o.get("query"):
            overrides[o["alias"]] = o["query"]
    return overrides


def load_capture(capture_dir: str) -> tuple[dict[str, str], dict[str, Any], dict[tuple, Any]]:
    """Read capture.jsonl once: longest query text per alias, plus merged response
    schemas for GraphQL aliases and REST (method, path) keys.

    Every observation is collected and unioned rather than keeping a single
    representative sample, so nullability and always-present fields survive.
    """
    qtext: dict[str, str] = {}
    gql_shapes: dict[str, list[Any]] = {}
    rest_shapes: dict[tuple, list[Any]] = {}
    graph_path = os.path.join(capture_dir, "graph.json")
    if os.path.exists(graph_path):
        records = evidence_records_from_graph(load_graph(graph_path))
    else:
        path = os.path.join(capture_dir, "capture.jsonl")
        if not os.path.exists(path):
            return qtext, {}, {}
        records = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    for r in records:
        resp_shape = r.get("resp_shape")
        status = r.get("status")
        if "graphql" in r:
            alias = r.get("operation_alias") or dict(up.parse_qsl(up.urlparse(r["url"]).query)).get(
                "alias", "(none)"
            )
            for o in r["graphql"]:
                q = o.get("query") or ""
                if q and (alias not in qtext or len(q) > len(qtext[alias])):
                    qtext[alias] = q
            if isinstance(resp_shape, dict) and isinstance(status, int) and status < 400:
                data = resp_shape.get("data", resp_shape)
                if data:
                    gql_shapes.setdefault(alias, []).append(data)
        elif isinstance(resp_shape, (dict, list)) and isinstance(status, int) and status < 400:
            key = (r.get("method", "GET"), _template_path(r.get("url", "")))
            rest_shapes.setdefault(key, []).append(resp_shape)
    gql_returns = {k: merge_shapes(v) for k, v in gql_shapes.items()}
    rest_returns = {k: merge_shapes(v) for k, v in rest_shapes.items()}
    return qtext, gql_returns, rest_returns


def _template_path(url: str) -> str:
    """Mirror analyze.path_tmpl so capture records key to the same path templates the
    inventory uses."""
    p = up.urlparse(url).path
    p = re.sub(r"/\d{3,}", "/{id}", p)
    p = re.sub(r"/[0-9a-f]{24,}", "/{hash}", p)
    p = re.sub(r"~[0-9a-z]+", "~{uid}", p)
    return p


def load_contract_returns(capture_dir: str) -> dict[str, Any]:
    """Return schemas from the contract of record. The contract merges across runs, so
    it holds return schemas for operations this run did not re-observe — strictly better
    coverage than the raw capture alone. Legacy (schema_version 1) contracts stored raw
    capture shapes here, so values are coerced on read."""
    ops = _read_contract(capture_dir).get("operations")
    if not isinstance(ops, dict):
        return {}
    return {
        k: coerce_to_schema(v.get("return_schema"))
        for k, v in ops.items()
        if isinstance(v, dict) and v.get("return_schema")
    }


def load_contract_proof(capture_dir: str) -> dict[str, str]:
    """Per-operation proof status from the contract of record.

    The contract already tracks whether astrolabe re-executed each operation itself
    (`verified-active`) or merely observed it (`verified-observed`). Carrying that
    into the toolpack lets an agent tell a proven tool from an inferred one
    instead of treating every generated tool as equally trustworthy.
    """
    contract = _read_contract(capture_dir)
    ops = contract.get("operations") if isinstance(contract, dict) else None
    if not isinstance(ops, dict):
        return {}
    return {
        k: v["status"]
        for k, v in ops.items()
        if isinstance(v, dict) and isinstance(v.get("status"), str)
    }


def _read_contract(capture_dir: str) -> dict[str, Any]:
    path = os.path.join(capture_dir, "contract.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[mcp-gen] WARN: unreadable contract.json: {exc}", file=sys.stderr)
        return {}
    return loaded if isinstance(loaded, dict) else {}


def apply_protocol_overrides(capture_dir: str, inv: dict[str, Any]) -> None:
    """Join reviewed exact protocol contracts maintained downstream of capture.

    Some sites mint an opaque persisted-query ID (query ID / doc ID) client-side
    rather than sending inline query text, alongside vendor-specific request
    metadata (feature flags, field toggles) that generic capture heuristics
    cannot infer. A reviewer can record those contracts per-alias in an optional
    `protocol-overrides.json` sitting next to the capture, keyed by operation
    alias; this joins them into the inventory before the toolpack is generated,
    so a reviewed exact contract is never overwritten by a heuristic guess.

    File shape: {"<alias>": {"queryId": str, "method"?: str, "features"?: dict,
    "fieldToggles"?: dict}, ...}. Absent file: a no-op.
    """
    path = os.path.join(capture_dir, "protocol-overrides.json")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as handle:
        reviewed = json.load(handle)
    operations = inv.get("graphql_operations") or {}
    for alias, contract in reviewed.items():
        meta = operations.get(alias)
        if not isinstance(meta, dict) or not isinstance(contract, dict):
            continue
        query_id = contract.get("queryId")
        if not isinstance(query_id, str) or not query_id:
            continue
        meta.update(
            {
                "semantic_kind": SemanticKind.QUERY.value,
                "type": SemanticKind.QUERY.value,
                "protocol": Protocol.GRAPHQL_X_PERSISTED.value,
                "persistedHash": query_id,
                "http_method": str(contract.get("method") or "GET").upper(),
                "request_url": (f"https://{inv['base_domain']}/graphql/{query_id}/{alias}"),
                "request_template": {
                    "features": contract.get("features") or {},
                    "fieldToggles": contract.get("fieldToggles") or {},
                },
                "protocol_source": "reviewed-protocol-overrides",
            }
        )


def graphql_endpoint(inv: dict[str, Any]) -> str | None:
    """Resolve the GraphQL endpoint from the inventory. Returns None when the capture
    saw no GraphQL endpoint — callers must NOT invent one."""
    eps = inv.get("graphql_endpoints") or []
    if isinstance(eps, dict):
        eps = list(eps)
    if not eps:
        return None
    first = eps[0]
    if isinstance(first, str) and first.startswith(("http://", "https://")):
        return first
    return f"https://{inv['base_domain']}{first}"


def build_graphql_tools(
    inv: dict[str, Any],
    qtext: dict[str, str],
    overrides: dict[str, str],
    returns: dict[str, Any],
    noise: re.Pattern,
    include_mutations: bool,
    taken: set[str],
    schema_index: SchemaIndex | None = None,
    proof: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    tools = []
    proof = proof or {}
    for alias, meta in (inv.get("graphql_operations") or {}).items():
        q = overrides.get(alias) or qtext.get(alias, "")
        op = meta.get("operation")
        parsed_document = parse_graphql_document(q, op) if q else []
        if q and not any(item.selected for item in parsed_document) and len(parsed_document) == 1:
            # A reviewed override may deliberately rename the operation while retaining
            # the capture alias. The executable envelope must name the override document,
            # not the stale captured operation name.
            op = parsed_document[0].name
        typ = semantic_kind(q, meta.get("semantic_kind") or meta.get("type")).value
        apq_hash = meta.get("persistedHash")
        protocol = (
            meta.get("protocol")
            or graphql_protocol(
                query=q,
                persisted_id=apq_hash,
                url=meta.get("request_url", ""),
            ).value
        )
        # analyze.py emits a typed input_schema built from the operation's own
        # variable declarations plus merged observations. Older inventories only
        # carry a single observed shape, so fall back to converting that.
        in_schema = meta.get("input_schema")
        if not in_schema:
            input_shape = meta.get("input_shape") or {}
            in_schema = (
                shape_to_schema(input_shape)
                if input_shape
                else {"type": "object", "properties": {}}
            )
        in_schema = dict(in_schema)
        in_schema.setdefault("type", "object")
        # The recovered schema knows every field of a custom input object,
        # including ones no capture ever exercised.
        if schema_index:
            in_schema = schema_index.enrich(in_schema)

        reason = None
        lifecycle_status = meta.get("lifecycle_status")
        if lifecycle_status and lifecycle_status != "current":
            reason = f"operation lifecycle is {lifecycle_status}; inventoried but not current"
        elif q and meta.get("parse_confidence") not in {None, "legacy", "parsed"}:
            reason = "GraphQL document required tolerant parsing; inventoried at low confidence"
        elif typ == SemanticKind.UNKNOWN.value:
            reason = "unknown semantic kind — inventoried only until trusted evidence classifies it"
        elif typ == SemanticKind.SUBSCRIPTION.value:
            reason = "subscription is not supported by the request runtime"
        elif typ == SemanticKind.MUTATION.value and not include_mutations:
            reason = "mutation — gated (write op); expose with --include-mutations + review"
        elif not q and not apq_hash:
            reason = "no inline query and no persisted hash; nothing to execute"
        elif not q and protocol not in {
            Protocol.GRAPHQL_APQ.value,
            Protocol.GRAPHQL_X_PERSISTED.value,
            Protocol.GRAPHQL_META_DOC_ID.value,
        }:
            reason = f"{protocol} has no reviewed exact execution adapter"
        elif noise.search(alias):
            reason = "telemetry / UI-chrome (not a data op)"

        status = None if meta.get("protocol_source") else proof.get(alias)
        proof_note = f" Proof: {status}." if status else ""
        if not q and apq_hash and protocol == Protocol.GRAPHQL_APQ.value:
            apq_note = " Executes via Apollo APQ with a captured SHA-256 hash."
        elif not q and apq_hash:
            apq_note = f" Executes via reviewed {protocol} request template."
        else:
            apq_note = ""
        tools.append(
            {
                "name": _dedupe(tool_name(alias, op), taken),
                "transport": "graphql",
                "alias": alias,
                "operation": op,
                "type": typ,
                "semantic_kind": typ,
                "protocol": protocol,
                "http_method": meta.get("http_method") or "POST",
                "request_media_type": meta.get("request_media_type") or "application/json",
                "request_url": meta.get("request_url"),
                "request_template": meta.get("request_template") or {},
                "protocol_source": meta.get("protocol_source"),
                "parse_confidence": meta.get("parse_confidence"),
                "description": (
                    f"GraphQL {typ} '{op or alias}' on {inv['base_domain']}. "
                    f"Returns: {', '.join(meta.get('returns') or []) or 'n/a'}."
                    f"{apq_note}{proof_note}"
                ),
                "input_schema": in_schema,
                "output_schema": envelope_schema(returns.get(alias)),
                "query": q,
                "apq_hash": apq_hash,
                "apq_fallback_allowed": bool(meta.get("apq_fallback_allowed")),
                "proof_status": status,
                "curated": alias in overrides,
                "returns": meta.get("returns"),
                "exposed": reason is None,
                "reason": reason,
            }
        )
    return tools


def build_rest_tools(
    inv: dict[str, Any],
    returns: dict[tuple, Any],
    noise: re.Pattern,
    include_mutations: bool,
    taken: set[str],
    read_pattern: re.Pattern | None = None,
) -> list[dict[str, Any]]:
    """Turn evidenced REST endpoints into typed tools.

    Only endpoints the capture actually observed succeeding become exposed: a path that
    only ever returned >=400 is recorded but gated, because we have no evidence an agent
    could drive it. Read vs write is classified by verb vocabulary, not HTTP method, so a
    POST search is not gated and a mutating GET is (see classify_rest).
    """
    tools = []
    for ep in inv.get("rest_endpoints") or []:
        method = str(ep.get("method") or "GET").upper()
        path = ep.get("path") or "/"
        statuses = [s for s in (ep.get("status") or []) if isinstance(s, int)]
        # An imported OpenAPI/Swagger inventory already carries a full input schema
        # (path + query + body params, real types); prefer it over deriving
        # path-params-only from the URL.
        schema = ep.get("input_schema")
        if not isinstance(schema, dict) or "properties" not in schema:
            params = PATH_PARAM.findall(path)
            schema = {
                "type": "object",
                "properties": {
                    p: {"type": "string", "description": f"path parameter {{{p}}}"} for p in params
                },
            }
            if params:
                schema["required"] = params

        attested_read = bool(ep.get("read_only_attested"))
        op_type = "query" if attested_read else classify_rest(method, path, read_pattern)
        # A doc-sourced endpoint was never observed as traffic, so a documented 2xx
        # schema is its evidence of being drivable; do not gate it for lack of a
        # captured success it could not have.
        documented = ep.get("source") == "openapi"
        response_variants = ep.get("response_variants") or []
        success_media = {
            item.get("media_type")
            for item in response_variants
            if item.get("success") and item.get("media_type")
        }
        reason = None
        lifecycle_status = ep.get("lifecycle_status")
        if lifecycle_status and lifecycle_status != "current":
            reason = f"operation lifecycle is {lifecycle_status}; inventoried but not current"
        elif op_type == "mutation" and not include_mutations:
            reason = f"{method} write op — gated; expose with --include-mutations + review"
        elif noise.search(path):
            reason = "telemetry / UI-chrome (not a data op)"
        elif statuses and not any(s < 400 for s in statuses) and not documented:
            reason = f"never observed succeeding (statuses: {sorted(set(statuses))})"
        elif ep.get("response_kinds") and not any(
            is_api_media(kind) for kind in ep["response_kinds"]
        ):
            reason = (
                "response media is not JSON/GraphQL; inventoried only until a matching "
                "MCP content/resource adapter is selected"
            )
        elif success_media and not any(
            "json" in str(media).lower() or "graphql" in str(media).lower()
            for media in success_media
        ):
            reason = (
                "documented success media is not JSON; inventoried until a matching "
                "MCP content/resource adapter is selected"
            )

        tools.append(
            {
                "name": _dedupe(rest_tool_name(method, path), taken),
                "transport": "rest",
                "alias": ep.get("alias") or path,
                "operation": f"{method} {path}",
                "type": op_type,
                "semantic_kind": op_type,
                "protocol": "rest",
                "classification_evidence": (
                    "trusted read-only attestation"
                    if attested_read
                    else "operator read pattern"
                    if read_pattern and read_pattern.search(path)
                    else "safe method and no write indicator"
                    if op_type == "query"
                    else "write indicator or unsafe method"
                ),
                "method": method,
                "path": path,
                "request_url": ep.get("request_url"),
                "servers": ep.get("servers") or [],
                "parameters": ep.get("parameters") or [],
                "body_media_type": ep.get("body_media_type"),
                "response_variants": response_variants,
                "description": (
                    f"REST {method} {path} on {inv['base_domain']}. "
                    f"Observed {ep.get('calls', 0)} call(s), status {sorted(set(statuses)) or 'n/a'}."
                ),
                "input_schema": schema,
                # A documented return schema (from an imported spec) is the return
                # contract when no live response was captured for this endpoint.
                "output_schema": envelope_schema(
                    returns.get((method, path)) or ep.get("return_schema")
                ),
                "query": "",
                "curated": False,
                "returns": None,
                "auth_headers": ep.get("auth_headers") or [],
                "exposed": reason is None,
                "reason": reason,
            }
        )
    return tools


def build_event_channels(inv: dict[str, Any]) -> list[dict[str, Any]]:
    channels: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for operation in (inv.get("websocket_operations") or {}).values():
        if not isinstance(operation, dict) or operation.get("direction") != "received":
            continue
        url = operation.get("url")
        if not isinstance(url, str):
            continue
        protocol = "socketio" if operation.get("engineio") else "websocket"
        key = (protocol, url, operation.get("namespace"))
        channel = channels.setdefault(
            key,
            {
                "id": stable_id("event-channel", *key),
                "alias": stable_id("event-alias", *key),
                "protocol": protocol,
                "url": url,
                "namespace": operation.get("namespace"),
                "engineio": operation.get("engineio"),
                "received_events": [],
                "read_only_setup_attested": bool(operation.get("read_only_setup_attested")),
                "resume_understood": False,
            },
        )
        event = operation.get("event")
        if isinstance(event, str) and event not in channel["received_events"]:
            channel["received_events"].append(event)
    for endpoint in inv.get("rest_endpoints") or []:
        if not isinstance(endpoint, dict):
            continue
        media = {
            str(item).split(";", 1)[0].lower()
            for item in endpoint.get("response_media_types") or []
        }
        media.update(
            str(item.get("media_type")).lower()
            for item in endpoint.get("response_variants") or []
            if isinstance(item, dict) and item.get("success") and item.get("media_type")
        )
        if "text/event-stream" not in media:
            continue
        url = endpoint.get("request_url") or (
            f"https://{inv['base_domain']}{endpoint.get('path') or '/'}"
        )
        key = ("sse", str(url), None)
        channels[key] = {
            "id": stable_id("event-channel", *key),
            "alias": endpoint.get("alias") or endpoint.get("path") or key[1],
            "protocol": "sse",
            "url": url,
            "received_events": endpoint.get("event_names") or [],
            "read_only_setup_attested": str(endpoint.get("method") or "GET").upper() == "GET",
            "resume_understood": bool(endpoint.get("resume_understood")),
        }
    return sorted(channels.values(), key=lambda item: item["id"])


def build_pack(
    capture_dir: str,
    *,
    overrides_dir: str | None = None,
    include_mutations: bool = False,
    noise_pattern: str | None = None,
    read_pattern: str | None = None,
) -> dict[str, Any]:
    graph_path = os.path.join(capture_dir, "graph.json")
    inv_path = os.path.join(capture_dir, "endpoints.json")
    if not os.path.exists(graph_path) and not os.path.exists(inv_path):
        raise GenerationError(
            f"no endpoints.json in {capture_dir} — run `astrolabe map` (or `astrolabe analyze`) first"
        )
    if os.path.exists(graph_path):
        inv = inventory_from_graph(load_graph(graph_path))
    else:
        with open(inv_path, encoding="utf-8") as fh:
            inv = json.load(fh)
    if not inv.get("base_domain"):
        raise GenerationError("endpoints.json has no base_domain")
    apply_protocol_overrides(capture_dir, inv)

    noise = DEFAULT_NOISE
    if noise_pattern:
        noise = re.compile(f"(?:{DEFAULT_NOISE.pattern})|(?:{noise_pattern})", re.I)
    read_re = re.compile(read_pattern, re.I) if read_pattern else None

    gql_ops = inv.get("graphql_operations") or {}
    rest_eps = inv.get("rest_endpoints") or []
    if not gql_ops and not rest_eps:
        raise GenerationError(
            f"{capture_dir} has no GraphQL operations and no REST endpoints — nothing to "
            "generate. The capture recorded no first-party API calls; check the recipe "
            "drove the surfaces that fire them."
        )

    endpoint = graphql_endpoint(inv)
    if gql_ops and not endpoint:
        raise GenerationError(
            f"{len(gql_ops)} GraphQL operation(s) were captured but endpoints.json declares no "
            "graphql_endpoints. Refusing to guess an endpoint path — re-run the capture so the "
            "endpoint is recorded, or add it to endpoints.json."
        )

    overrides = load_overrides(overrides_dir)
    qtext, gql_returns, rest_returns = load_capture(capture_dir)
    contract_returns = load_contract_returns(capture_dir)
    # The contract accumulates across runs and this run's capture may show fields it
    # has never seen, so union the two rather than letting either win outright.
    merged_returns = dict(gql_returns)
    for k, v in contract_returns.items():
        if v:
            merged_returns[k] = merge_json_schemas(merged_returns.get(k) or {}, v)

    taken: set[str] = set()
    tools = build_graphql_tools(
        inv,
        qtext,
        overrides,
        merged_returns,
        noise,
        include_mutations,
        taken,
        schema_index=SchemaIndex.load(capture_dir),
        proof=load_contract_proof(capture_dir),
    )
    tools += build_rest_tools(inv, rest_returns, noise, include_mutations, taken, read_re)

    pack: dict[str, Any] = {
        "version": TOOLPACK_VERSION,
        "schema_version": TOOLPACK_VERSION,
        "historical": False,
        "executable": True,
        "base_domain": inv["base_domain"],
        "auth_headers": list(inv.get("auth_headers", {})),
        "tools": tools,
        "event_channels": build_event_channels(inv),
        "misc_operations": inv.get("misc_operations") or {},
    }
    if endpoint:
        pack["endpoint"] = endpoint
    return pack


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mcpgen")
    ap.add_argument("capture_dir")
    ap.add_argument("--out", help="toolpack.json (default: <capture_dir>/toolpack.json)")
    ap.add_argument(
        "--include-mutations",
        action="store_true",
        help="expose write ops too (default: recorded but exposed=false)",
    )
    ap.add_argument(
        "--overrides",
        help="dir of <alias>.op.json files whose (minimal, proven) query replaces the "
        "captured verbose one — more reliable to execute",
    )
    ap.add_argument(
        "--noise-pattern",
        help="extra regex of site-specific telemetry/UI-chrome aliases to gate, applied "
        "in addition to the generic defaults",
    )
    ap.add_argument(
        "--read-pattern",
        help="regex of REST paths to force-classify as reads, overriding the verb "
        "heuristic (e.g. a POST-based search endpoint that would otherwise be gated)",
    )
    a = ap.parse_args(argv)

    try:
        pack = build_pack(
            a.capture_dir,
            overrides_dir=a.overrides,
            include_mutations=a.include_mutations,
            noise_pattern=a.noise_pattern,
            read_pattern=a.read_pattern,
        )
    except GenerationError as exc:
        raise SystemExit(f"[mcp-gen] {exc}") from exc

    # Generation and serving share one compatibility gate. Validate before the
    # artifact is written so a successful mcp-gen can never emit a pack that the
    # installed runtime rejects at startup.
    from pathlib import Path

    from .mcp_server import Settings, _validate_pack

    try:
        _validate_pack(pack, Settings(Path(a.out or "toolpack.json")))
    except Exception as exc:
        raise SystemExit(f"[mcp-gen] generated toolpack failed runtime validation: {exc}") from exc

    out = a.out or os.path.join(a.capture_dir, "toolpack.json")
    atomic_write_json(out, pack)

    tools = pack["tools"]
    exposed = [t for t in tools if t["exposed"]]
    typed_returns = sum(1 for t in exposed if "data" in t["output_schema"].get("properties", {}))
    by_transport = {t: sum(1 for x in exposed if x["transport"] == t) for t in ("graphql", "rest")}
    print(
        f"[mcp-gen] {len(exposed)} exposed / {len(tools)} total ops "
        f"(graphql {by_transport['graphql']}, rest {by_transport['rest']}) | "
        f"typed returns {typed_returns}/{len(exposed)} -> {out}"
    )
    print("  exposed:", ", ".join(t["name"] for t in exposed)[:400])


if __name__ == "__main__":
    main()
