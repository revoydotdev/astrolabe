#!/usr/bin/env python3
"""astrolabe contract — turn a map into a durable, executable, TYPED CONTRACT.

The lodestar: a map is only useful to downstream active tooling if every operation is
(1) typed (input + return JSON Schema), (2) proven executable, and (3) durable (mergeable
across runs → completeness; diffable over time → drift). This module makes that a
first-class artifact.

Two proof tiers per op:
  * observed  — the capture holds a real HTTP-200 response; its shape IS the return
                contract. Proves the op exists and its typed return is accurate.
  * active    — astrolabe re-executed the op itself (warm-browser, `--execute`) and got a
                200 conforming to the contract. Proves *our tooling* can drive it — the
                bar for active tooling.

Outputs: contract.json (machine, the contract of record) + contract.md (scorecard).
Merges a prior contract (`--merge`) for completeness + drift.
"""

from __future__ import annotations
import argparse, json, os, re, urllib.parse as up, datetime
from .artifact import atomic_write_json, atomic_write_text
from .ir import evidence_records_from_graph, inventory_from_graph, load_graph
from .mcpgen import apply_protocol_overrides, classify_rest, shape_to_schema, tool_name
from .shapemerge import coerce_to_schema, merge_json_schemas, merge_shapes, schema_properties

OP = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)")

# schema_version 1 stored `input_schema`/`return_schema` as raw capture shapes
# (trees of type-name strings). Version 2 stores real JSON Schema, merged across
# every observation. Readers coerce v1 values so old contracts keep merging.
SCHEMA_VERSION = 2

# REST path placeholders, e.g. `/api/order/{id}`. Mirrors mcpgen.PATH_PARAM.
PATH_PARAM = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

READ_METHODS = {"GET", "HEAD", "OPTIONS"}


def _op_key(url, gqlop, alias=None):
    if alias:
        return alias
    qs = dict(up.parse_qsl(up.urlparse(url).query))
    if qs.get("alias"):
        return qs["alias"]
    if gqlop.get("operationName"):
        return gqlop["operationName"]
    m = OP.search(gqlop.get("query") or "")
    return m.group(2) if m else "(anon)"


def _template_path(url):
    """Mirror mcpgen._template_path (itself a frozen mirror of analyze.path_tmpl):
    the lexical-only path template capture.jsonl REST responses must be keyed by
    for this module's return-shape recovery to agree with what mcp-gen shows an
    agent. Duplicated rather than imported so this module has no live coupling to
    mcpgen.py while a concurrent workstream is editing it; keep this byte-identical
    to its sibling if that function ever changes."""
    p = up.urlparse(url).path
    p = re.sub(r"/\d{3,}", "/{id}", p)
    p = re.sub(r"/[0-9a-f]{24,}", "/{hash}", p)
    p = re.sub(r"~[0-9a-z]+", "~{uid}", p)
    return p


def _rest_op_key(method, path):
    """Stable REST op key, prefixed with the method so it cannot collide with a
    GraphQL alias/operationName key: those come from `_op_key` and are bare
    identifiers (an alias, an operationName, or a regex-matched op name) with no
    spaces, while this is always `"METHOD /path"`."""
    return f"{method} {path}"


def build_from_capture(capture_dir):
    graph_path = os.path.join(capture_dir, "graph.json")
    graph = load_graph(graph_path) if os.path.exists(graph_path) else None
    inv = (
        inventory_from_graph(graph)
        if graph is not None
        else json.load(open(os.path.join(capture_dir, "endpoints.json")))
    )
    apply_protocol_overrides(capture_dir, inv)
    base = inv["base_domain"]
    meta_path = os.path.join(capture_dir, "meta.json")
    run_meta = json.load(open(meta_path)) if os.path.exists(meta_path) else {}
    run_id = run_meta.get("run_id") or os.path.basename(os.path.abspath(capture_dir))
    # Evidence provenance: a normal capture is astrolabe's own headless browser
    # observing live traffic; an imported HAR is evidence recorded elsewhere and
    # merely converted here. The distinction MUST survive into the contract so a
    # reader (human or agent) never mistakes imported evidence for something
    # astrolabe itself watched happen.
    observed_source = run_meta.get("evidence_source") or "astrolabe-capture"
    # Every observed return shape per op, plus statuses. Collecting all of them
    # (rather than keeping whichever serialised longest) is what lets the merge
    # recover nullability and which fields are actually always present.
    ret, seen = {}, {}
    # REST return shapes, keyed exactly like mcpgen.load_capture keys them --
    # (method, _template_path(url)) -- so the shapes recovered here agree with
    # what mcp-gen shows an agent for the same endpoint.
    rest_ret = {}
    # An imported OpenAPI inventory (astrolabe import-openapi) has no capture.jsonl:
    # its schemas come from the document, not observed traffic. Absence is normal.
    cap_path = os.path.join(capture_dir, "capture.jsonl")
    if graph is not None:
        evidence_records = evidence_records_from_graph(graph)
    else:
        cap_lines = open(cap_path) if os.path.exists(cap_path) else []
        evidence_records = (json.loads(line) for line in cap_lines)
    for r in evidence_records:
        if "graphql" in r:
            for o in r["graphql"]:
                k = _op_key(r["url"], o, r.get("operation_alias"))
                seen.setdefault(k, {"status": set(), "n": 0})
                seen[k]["status"].add(r["status"])
                seen[k]["n"] += 1
                rs = r.get("resp_shape")
                # Graph-derived evidence carries `status: None` for anything that never
                # produced an HTTP response (a WebSocket frame, an aborted navigation).
                # The REST branch below already guards this; the GraphQL branch did not,
                # and one such record aborted the whole contract build — which is the
                # last step of `astrolabe map`, so it took the entire run down with it.
                if isinstance(rs, dict) and isinstance(r.get("status"), int) and r["status"] < 400:
                    data = rs.get("data", rs)
                    if data:
                        ret.setdefault(k, []).append(data)
            continue
        # A REST record: no "graphql" key, but method/url/status/resp_shape.
        rs = r.get("resp_shape")
        status = r.get("status")
        if isinstance(rs, (dict, list)) and isinstance(status, int) and status < 400:
            rk = ((r.get("method") or "GET").upper(), _template_path(r.get("url") or ""))
            rest_ret.setdefault(rk, []).append(rs)

    ops = {}
    for k, meta in inv["graphql_operations"].items():
        # analyze.py now emits a typed input_schema joining the operation's own
        # variable declarations with merged observations; fall back to the legacy
        # single-shape field for inventories written before that.
        input_schema = meta.get("input_schema")
        if not input_schema:
            in_shape = meta.get("input_shape") or {}
            input_schema = (
                shape_to_schema(in_shape) if in_shape else {"type": "object", "properties": {}}
            )
        input_schema = dict(input_schema)
        input_schema.setdefault("type", "object")
        return_schema = merge_shapes(ret.get(k, [])) or None
        s = seen.get(k, {"status": set(), "n": 0})
        observed = bool(return_schema) and any(st == 200 for st in s["status"])
        ops[k] = {
            "operation": meta.get("operation"),
            "type": meta.get("semantic_kind") or meta.get("type") or "unknown",
            "semantic_kind": meta.get("semantic_kind") or meta.get("type") or "unknown",
            "protocol": meta.get("protocol"),
            "http_method": meta.get("http_method"),
            "request_url": meta.get("request_url"),
            "request_template": meta.get("request_template") or {},
            "request_template_history": [],
            "lifecycle_status": meta.get("lifecycle_status") or "current",
            "response_kinds": meta.get("response_kinds") or [],
            "response_media_types": meta.get("response_media_types") or [],
            "queryId_or_hash": meta.get("persistedHash"),
            "identifier_history": [],
            "transport": "graphql",
            "input_schema": input_schema,
            "return_schema": return_schema,
            "proof": {
                "observed": {
                    "ok": observed,
                    "status": sorted(s["status"]),
                    "samples": s["n"],
                    "run_id": run_id,
                    "observed_at": run_meta.get("completed_at") or run_meta.get("captured_at"),
                    "source": observed_source,
                },
                "active": None,
                "active_history": [],
            },
        }
        ops[k]["status"] = classify(ops[k])

    for ep in inv.get("rest_endpoints") or []:
        method = str(ep.get("method") or "GET").upper()
        path = ep.get("path") or "/"
        k = _rest_op_key(method, path)
        # An imported OpenAPI inventory already carries a full input schema (path +
        # query + body params); prefer it. Otherwise path params are the only input
        # contract capture can honestly claim — mirrors mcpgen.build_rest_tools.
        input_schema = ep.get("input_schema")
        if not isinstance(input_schema, dict) or "properties" not in input_schema:
            params = PATH_PARAM.findall(path)
            input_schema = {
                "type": "object",
                "properties": {
                    p: {"type": "string", "description": f"path parameter {{{p}}}"} for p in params
                },
            }
            if params:
                input_schema["required"] = params
        # Observed capture wins (it is ground truth); fall back to a documented
        # return schema from an imported spec.
        return_schema = merge_shapes(rest_ret.get((method, path), [])) or ep.get("return_schema")
        statuses = sorted({s for s in (ep.get("status") or []) if isinstance(s, int)})
        observed = bool(merge_shapes(rest_ret.get((method, path), []))) and any(
            st == 200 for st in statuses
        )
        ops[k] = {
            "operation": ep.get("operationId"),
            "type": classify_rest(method, path),
            "queryId_or_hash": None,
            "transport": "rest",
            "method": method,
            "path": path,
            "lifecycle_status": ep.get("lifecycle_status") or "current",
            "response_kinds": ep.get("response_kinds") or [],
            "response_media_types": ep.get("response_media_types") or [],
            "input_schema": input_schema,
            "return_schema": return_schema,
            "proof": {
                "observed": {
                    "ok": observed,
                    "status": statuses,
                    "samples": ep.get("calls", 0),
                    "source": observed_source,
                },
                "active": None,
            },
        }
        ops[k]["status"] = classify(ops[k])

    for wk, meta in (inv.get("websocket_operations") or {}).items():
        # Inventory only -- there is no socket transport in the MCP server, so
        # this is never executable and proof.active stays null forever. Proof
        # is simply "did we ever see this event fire" (calls > 0); there is no
        # return shape (server pushes and client emits are not request/response
        # pairs), so return_schema is always None for this transport.
        k = f"WS {wk}"
        input_schema = meta.get("input_schema") or {"type": "object", "properties": {}}
        input_schema = dict(input_schema)
        input_schema.setdefault("type", "object")
        calls = meta.get("calls", 0) or 0
        ops[k] = {
            "operation": meta.get("event"),
            "type": "subscription" if meta.get("direction") == "received" else "mutation",
            "queryId_or_hash": None,
            "transport": "websocket",
            "method": None,
            "path": meta.get("url"),
            "input_schema": input_schema,
            "return_schema": None,
            "proof": {
                "observed": {
                    "ok": calls > 0,
                    "status": [],
                    "samples": calls,
                    "source": observed_source,
                },
                "active": None,
            },
        }
        ops[k]["status"] = classify(ops[k])

    return {
        "schema_version": SCHEMA_VERSION,
        "base_domain": base,
        "endpoints": inv.get("graphql_endpoints", []),
        "auth_headers": list(inv.get("auth_headers", {})),
        "operations": ops,
    }


def upgrade(contract):
    """Normalise a contract read from disk to the current schema_version.

    v1 stored raw capture shapes where v2 stores JSON Schema. Coercing on read
    means an accumulated contract from earlier runs keeps merging instead of
    being silently compared against values of a different kind.
    """
    if not isinstance(contract, dict):
        return contract
    if contract.get("schema_version") == SCHEMA_VERSION:
        return contract
    ops = contract.get("operations")
    if isinstance(ops, dict):
        for op in ops.values():
            if not isinstance(op, dict):
                continue
            for field in ("input_schema", "return_schema"):
                if op.get(field):
                    op[field] = coerce_to_schema(op[field])
    contract["schema_version"] = SCHEMA_VERSION
    return contract


# Consecutive merges that must miss an operation before its active proof is dropped.
# One miss is weak evidence -- a capture may simply not have visited that surface -- while
# two in a row means nothing observed supports the claim any more.
UNOBSERVED_RUNS_BEFORE_ACTIVE_DECAY = 2


def classify(op):
    if op.get("lifecycle_status") not in (None, "current"):
        return "historical"
    proof = op.get("proof") or {}
    a = proof.get("active")
    if a and a.get("ok"):
        return "verified-active"
    if (proof.get("observed") or {}).get("ok"):
        return "verified-observed"
    if op.get("input_schema") or op.get("return_schema"):
        return "typed-unproven"
    return "listed"


def merge(prior, cur):
    """Union of operations (completeness), unioning schemas; preserve any active proof.

    Schemas are merged rather than "richest wins": a run that happened to see
    fewer fields must not erase what an earlier run proved exists. Drift on the
    return schema is classified rather than flagged as a single bit, so an added
    optional field reads differently from a removed or retyped one."""
    if not prior:
        return cur, {"added": list(cur["operations"]), "removed": [], "changed": [], "breaking": []}
    prior = upgrade(prior)
    out = {**cur, "operations": dict(prior["operations"])}
    # Operations were unioned but the rest of the record was last-writer-wins, so an
    # endpoint or auth header seen only in an earlier run vanished the moment the run
    # that had it stopped seeing it -- while its operations survived. Union them too.
    for fld in ("endpoints", "auth_headers"):
        seen = list(cur.get(fld) or [])
        out[fld] = list(dict.fromkeys([*seen, *(prior.get(fld) or [])]))
    added, changed, breaking = [], [], []
    pri, curr = prior["operations"], cur["operations"]
    for k, co in curr.items():
        if k not in pri:
            out["operations"][k] = co
            added.append(k)
            continue
        po = pri[k]
        merged = dict(po)
        for fld in ("input_schema", "return_schema"):
            merged[fld] = merge_json_schemas(po.get(fld) or {}, co.get(fld) or {}) or None
        identifier_changed = (
            co.get("queryId_or_hash") is not None
            and po.get("queryId_or_hash") is not None
            and co.get("queryId_or_hash") != po.get("queryId_or_hash")
        )
        history = list(po.get("identifier_history") or [])
        if identifier_changed and po.get("queryId_or_hash") not in history:
            history.append(po["queryId_or_hash"])
            changed.append(k)
        merged["identifier_history"] = history
        template_changed = (
            bool(co.get("request_template"))
            and bool(po.get("request_template"))
            and co.get("request_template") != po.get("request_template")
        )
        template_history = list(po.get("request_template_history") or [])
        if template_changed and po.get("request_template") not in template_history:
            template_history.append(po["request_template"])
            changed.append(k)
        merged["request_template_history"] = template_history
        # Current observations win for every executable request field. The old
        # identifier remains historical; it must never stay current through a
        # union merely because it was seen first.
        for fld in (
            "operation",
            "type",
            "semantic_kind",
            "protocol",
            "http_method",
            "request_url",
            "request_template",
            "queryId_or_hash",
            "transport",
            "method",
            "path",
            "lifecycle_status",
        ):
            if co.get(fld) is not None:
                merged[fld] = co[fld]
        if po.get("return_schema") and co.get("return_schema"):
            kind = classify_drift(po["return_schema"], co["return_schema"])
            if kind == "breaking":
                changed.append(k)
                breaking.append(k)
            elif kind == "additive":
                changed.append(k)
        # merge proof: freshest observed, keep active from whichever has it
        merged["proof"] = {
            "observed": co["proof"]["observed"]
            if co["proof"]["observed"]["ok"]
            else po["proof"]["observed"],
            # Active proof applies to the exact executable identifier. Rotation
            # invalidates the old proof until the new identifier is executed.
            "active": co["proof"].get("active")
            or (None if identifier_changed else po["proof"].get("active")),
            "active_history": list(po["proof"].get("active_history") or [])
            + list(co["proof"].get("active_history") or []),
        }
        merged["status"] = classify(merged)
        out["operations"][k] = merged

    # A prior-only operation keeps its operations entry but was never re-classified, so
    # `verified-active` survived indefinitely with nothing observed behind it. Count the
    # runs that have missed it and drop the active proof once that exceeds
    # UNOBSERVED_RUNS_BEFORE_ACTIVE_DECAY.
    for key in [k for k in pri if k not in curr]:
        merged = dict(out["operations"][key])
        proof = dict(merged.get("proof") or {})
        misses = int(proof.get("runs_unobserved") or 0) + 1
        proof["runs_unobserved"] = misses
        if misses >= UNOBSERVED_RUNS_BEFORE_ACTIVE_DECAY and (proof.get("active") or {}).get("ok"):
            # Kept in active_history so the proof of what did happen is not lost; only
            # the current claim stops being made.
            proof["active"] = None
            proof["active_decayed"] = True
        merged["proof"] = proof
        merged["status"] = classify(merged)
        out["operations"][key] = merged

    removed = [k for k in pri if k not in curr]  # present before, not seen now (possible drift)
    return out, {
        "added": added,
        "removed": removed,
        "changed": list(dict.fromkeys(changed)),
        "breaking": breaking,
    }


def classify_drift(before, after):
    """Classify a return-schema change: none | additive | breaking.

    Additive means fields appeared and nothing an agent relied on went away.
    Breaking means a top-level field disappeared or a field's type changed --
    those are the changes that actually invalidate downstream tooling, and
    equality alone could not tell them apart from a harmless new field.
    """
    before_props, after_props = schema_properties(before), schema_properties(after)
    if before_props - after_props:
        return "breaking"
    if _retyped(before, after):
        return "breaking"
    if after_props - before_props:
        return "additive"
    return "none" if before == after else "additive"


def _retyped(before, after):
    """True if any shared property's declared type changed incompatibly."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    b_props = before.get("properties") if isinstance(before.get("properties"), dict) else {}
    a_props = after.get("properties") if isinstance(after.get("properties"), dict) else {}
    for name, b_sub in b_props.items():
        a_sub = a_props.get(name)
        if not isinstance(a_sub, dict) or not isinstance(b_sub, dict):
            continue
        b_type, a_type = b_sub.get("type"), a_sub.get("type")
        if b_type and a_type:
            b_set = {b_type} if isinstance(b_type, str) else set(b_type)
            a_set = {a_type} if isinstance(a_type, str) else set(a_type)
            # Widening (a new nullable, say) is fine; losing a type an agent
            # may already handle is not.
            if b_set - a_set:
                return True
        if _retyped(b_sub, a_sub):
            return True
    return False


def apply_active(contract, verify):
    """Fold active-verification results (op -> {status, conforms}) into the contract."""
    for k, v in (verify or {}).items():
        if k in contract["operations"]:
            executed = bool(v.get("actively_executed", v.get("status") is not None))
            schema_validated = bool(v.get("schema_validated", False))
            ok = executed and v.get("status") == 200 and schema_validated
            contract["operations"][k]["proof"]["active"] = {
                "ok": ok,
                "actively_executed": executed,
                "status": v.get("status"),
                "schema_validated": schema_validated,
                "request_validation": v.get("request_validation"),
                "response_validation": v.get("response_validation"),
                "side_effect_reviewed": bool(v.get("side_effect_reviewed", False)),
                "semantic_kind": v.get("semantic_kind"),
                "indeterminate": bool(v.get("indeterminate", False)),
                "refused": v.get("refused"),
                "method": v.get("method"),
                "verified_at": v.get("verified_at"),
            }
            contract["operations"][k]["proof"].setdefault("active_history", []).append(
                dict(contract["operations"][k]["proof"]["active"])
            )
            contract["operations"][k]["status"] = classify(contract["operations"][k])
    return contract


def _coverage_of(ops):
    n = len(ops)
    return {
        "total": n,
        "typed_input": sum(1 for o in ops if (o.get("input_schema") or {}).get("properties")),
        "typed_return": sum(1 for o in ops if o.get("return_schema")),
        "verified_observed": sum(
            1 for o in ops if ((o.get("proof") or {}).get("observed") or {}).get("ok")
        ),
        "verified_active": sum(
            1 for o in ops if ((o.get("proof") or {}).get("active") or {}).get("ok")
        ),
    }


def coverage(contract):
    ops = list(contract["operations"].values())
    cov = _coverage_of(ops)
    # Contracts predating the transport field (or merged from one) default to
    # graphql -- that was the only transport before this module covered REST.
    by_transport = {}
    for o in ops:
        by_transport.setdefault(o.get("transport") or "graphql", []).append(o)
    cov["by_transport"] = {t: _coverage_of(v) for t, v in sorted(by_transport.items())}
    return cov


def render_md(contract, drift=None):
    cov = coverage(contract)
    n = cov["total"] or 1
    L = [
        f"# {contract['base_domain']} — executable typed contract\n",
        f"_Durable contract of record. Endpoints: {', '.join('`' + e + '`' for e in contract['endpoints'])}._\n",
        "## Coverage scorecard\n",
        f"| metric | count | % |",
        "|---|---|---|",
        f"| operations | {cov['total']} | 100% |",
        f"| typed input schema | {cov['typed_input']} | {cov['typed_input'] * 100 // n}% |",
        f"| typed return schema | {cov['typed_return']} | {cov['typed_return'] * 100 // n}% |",
        f"| **verified — observed** (real 200 captured) | {cov['verified_observed']} | {cov['verified_observed'] * 100 // n}% |",
        f"| **verified — active** (re-executed by astrolabe) | {cov['verified_active']} | {cov['verified_active'] * 100 // n}% |",
        "",
    ]
    by_transport = cov.get("by_transport") or {}
    if len(by_transport) > 1:
        L += [
            "## Coverage by transport\n",
            "| transport | ops | typed return | verified observed | verified active |",
            "|---|---|---|---|---|",
        ]
        for t, tc in by_transport.items():
            L.append(
                f"| {t} | {tc['total']} | {tc['typed_return']} | {tc['verified_observed']} "
                f"| {tc['verified_active']} |"
            )
        L.append("")
    if drift and (drift["added"] or drift["removed"] or drift["changed"]):
        L += [
            "## Drift since last contract\n",
            f"- added: {', '.join('`' + x + '`' for x in drift['added']) or '—'}",
            f"- removed (not seen this run): {', '.join('`' + x + '`' for x in drift['removed']) or '—'}",
            f"- return-schema changed: {', '.join('`' + x + '`' for x in drift['changed']) or '—'}",
            # The union deliberately keeps a field a prior run saw even when this run
            # did not, so "breaking" describes the schema CHANGE, not the field's absence
            # from the table above. Saying so prevents the two reading as a contradiction.
            f"- **breaking** (field removed or retyped last run; the tables above keep the "
            f"union of both schemas, so the field is still typed): "
            f"{', '.join('`' + x + '`' for x in drift.get('breaking') or []) or '—'}",
            "",
        ]
    L += [
        "## Operations\n",
        "| op | type | transport | status | in | return |",
        "|---|---|---|---|---|---|",
    ]
    for k, o in sorted(contract["operations"].items()):
        imported = (((o.get("proof") or {}).get("observed") or {}).get("source") == "har-import")
        st = {
            "verified-active": "✅ active",
            "verified-observed": "🟢 imported" if imported else "🟢 observed",
            "typed-unproven": "🟡 typed",
            "listed": "⚪ listed",
            "historical": "◌ historical",
        }.get(o["status"], o["status"])
        ins = "✓" if (o.get("input_schema") or {}).get("properties") else "—"
        rets = "✓" if o.get("return_schema") else "—"
        transport = o.get("transport") or "graphql"
        L.append(f"| `{k}` | {o['type']} | {transport} | {st} | {ins} | {rets} |")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture_dir")
    ap.add_argument("--merge", help="prior contract.json to union with (completeness + drift)")
    ap.add_argument("--active", help="verify.json (op->{status,conforms}) from active execution")
    ap.add_argument("--out", help="contract.json (default: <capture_dir>/contract.json)")
    a = ap.parse_args()
    cur = build_from_capture(a.capture_dir)
    prior = json.load(open(a.merge)) if a.merge and os.path.exists(a.merge) else None
    contract, drift = merge(prior, cur)
    if a.active and os.path.exists(a.active):
        contract = apply_active(contract, json.load(open(a.active)))
    contract["generated_at"] = datetime.datetime.now().isoformat(timespec="seconds")
    out = a.out or os.path.join(a.capture_dir, "contract.json")
    atomic_write_json(out, contract)
    atomic_write_text(
        os.path.join(os.path.dirname(out) or ".", "contract.md"), render_md(contract, drift)
    )
    cov = coverage(contract)
    print(
        f"[contract] {cov['total']} ops | typed-in {cov['typed_input']} | typed-ret {cov['typed_return']} "
        f"| observed {cov['verified_observed']} | active {cov['verified_active']} -> {out}"
    )
    if drift and (drift["added"] or drift["removed"] or drift["changed"]):
        breaking = drift.get("breaking") or []
        print(
            f"[drift] +{len(drift['added'])} -{len(drift['removed'])} ~{len(drift['changed'])}"
            + (f"  ⚠ {len(breaking)} BREAKING: {', '.join(breaking[:6])}" if breaking else "")
        )


if __name__ == "__main__":
    main()
