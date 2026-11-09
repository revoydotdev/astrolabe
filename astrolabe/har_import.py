"""HAR importer — convert traffic recorded elsewhere into chartable evidence.

Turns a HAR 1.2 document (Chrome DevTools "Save all as HAR", or any other
HAR-emitting tool) into the same capture.jsonl / meta.json shape astrolabe's
own headless capture (astrolabe/capture.py, see `on_response`) produces, so
the existing analyze -> contract -> mcp-gen pipeline can chart it without
caring where the evidence came from.

Security invariant (hard, mirrors on_response exactly): only structural
shapes and header/query *presence* survive into capture.jsonl. HAR files
routinely carry live session cookies, bearer tokens, and PII in exactly the
fields this module must never persist -- header VALUES, cookie VALUES,
query-string VALUES beyond what `safe_url` keeps, and response VALUES are
never written, only their shapes.

Every record and the meta.json this writes is stamped
`evidence_source: "har-import"` so downstream tooling (mcp-gen, contract.py)
and a human reading contract.md can never mistake imported evidence for
something astrolabe's own browser watched happen.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import urllib.parse as up
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .artifact import sha256_file
from .capture import (
    API_HINT,
    GQL_NAME,
    SHAPE_LIMITS,
    SHAPE_TRUNCATIONS,
    failure_evidence,
    graphql_entries,
    is_auth_header,
    persisted_path,
    shape,
    summarize_failures,
)
from .media import classify_media
from .payloads import PackagingError, decode_payload
from .persisted import graphql_response_success
from .security import (
    atomic_write_json,
    atomic_write_text,
    is_first_party,
    request_metadata,
    safe_url,
)

MAX_BODY_BYTES = 2_000_000

# Chrome DevTools' `_resourceType` extension field is the strongest signal a HAR
# entry is API traffic. Only these two values are ever charted; everything else
# (document/script/stylesheet/image/font/media/...) is UI plumbing that
# capture.py's on_response() also never records. A HAR from a non-Chrome
# exporter that omits `_resourceType` falls back to API_HINT on the URL alone --
# the same fallback on_response() uses.
_API_RESOURCE_TYPES = {"xhr", "fetch"}


def _header_value(headers: list[dict[str, Any]] | None, name: str) -> str | None:
    lname = name.lower()
    for header in headers or []:
        if str(header.get("name", "")).lower() == lname:
            return header.get("value")
    return None


def _decode_har_body(content: dict[str, Any] | None) -> bytes | None:
    """Return the raw bytes of a HAR request/response body, or None."""
    if not isinstance(content, dict):
        return None
    text = content.get("text")
    if text is None:
        return None
    if str(content.get("encoding") or "").lower() == "base64":
        try:
            return base64.b64decode(text, validate=False)
        except (binascii.Error, ValueError):
            return None
    return str(text).encode("utf-8", "replace")


def _entry_url(entry: dict[str, Any]) -> str:
    return str((entry.get("request") or {}).get("url") or "")


def _entry_time_range(entries: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    starts, ends = [], []
    for entry in entries:
        started = entry.get("startedDateTime")
        if not started:
            continue
        try:
            ts = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
        except ValueError:
            continue
        starts.append(ts)
        try:
            duration_ms = max(float(entry.get("time") or 0), 0.0)
        except (TypeError, ValueError):
            duration_ms = 0.0
        ends.append(ts + timedelta(milliseconds=duration_ms))
    if not starts:
        return None, None
    return min(starts).isoformat(), max(ends).isoformat()


def _entry_to_record(
    entry: dict[str, Any],
    domain: str,
    names: set[str],
    gql_endpoints: dict[str, dict[str, int]],
    auth_seen: dict[str, int],
) -> dict[str, Any] | None:
    request = entry.get("request") or {}
    response = entry.get("response") or {}
    live_url = _entry_url(entry).split("#")[0]
    if not live_url:
        raise ValueError("HAR entry has no request URL")
    resource_type = str(entry.get("_resourceType") or "").lower()
    if resource_type:
        if resource_type not in _API_RESOURCE_TYPES:
            return None
    elif not API_HINT.search(live_url):
        return None
    if not is_first_party(live_url, domain):
        return None

    method = str(request.get("method") or "GET").upper()
    status = response.get("status")
    if not isinstance(status, int):
        raise ValueError("HAR entry response has no numeric status")

    resp_ct = _header_value(response.get("headers"), "content-type") or ""
    rec: dict[str, Any] = {
        "method": method,
        "url": safe_url(live_url),
        "status": status,
        "rtype": resource_type or "xhr",
        "resp_ct": resp_ct,
        "evidence_source": "har-import",
    }

    hdrs: dict[str, str] = {}
    for header in request.get("headers") or []:
        name = header.get("name")
        if name and is_auth_header(name):
            hdrs[name] = "<present>"
            auth_seen[name] = auth_seen.get(name, 0) + 1
    if hdrs:
        rec["req_headers"] = hdrs

    post_data = request.get("postData")
    body_media_type = str((post_data or {}).get("mimeType") or "")
    body_bytes = _decode_har_body(post_data)

    if body_bytes:
        rec.update(
            request_metadata(
                body_bytes,
                body_media_type,
                shape_counters=SHAPE_TRUNCATIONS,
                shape_limits=SHAPE_LIMITS,
                max_body_bytes=MAX_BODY_BYTES,
            )
        )
        try:
            decoded_request = decode_payload(
                body_bytes, media_type=body_media_type, max_bytes=MAX_BODY_BYTES
            )
            payload_value = decoded_request.value
            rec["request_packaging"] = list(decoded_request.layers)
            payloads = payload_value if isinstance(payload_value, list) else [payload_value]
            ops = []
            for candidate in payloads:
                if not isinstance(candidate, dict):
                    continue
                if (
                    "query" in candidate
                    or "operationName" in candidate
                    or "extensions" in candidate
                ):
                    query_text = candidate.get("query") or ""
                    names.update(GQL_NAME.findall(query_text))
                    if candidate.get("operationName"):
                        names.add(candidate["operationName"])
                    ops.extend(graphql_entries(candidate, live_url, body_media_type))
            if ops:
                rec["graphql"] = ops
                path = up.urlparse(live_url).path
                gql_endpoints.setdefault(path, {"count": 0})["count"] += 1
        except (PackagingError, ValueError, TypeError, UnicodeDecodeError):
            pass

    if "graphql" not in rec and method == "GET":
        query_fields = up.parse_qs(up.urlparse(live_url).query)
        query_text = query_fields.get("query", [None])[0]
        if query_text:
            envelope: dict[str, Any] = {
                "query": query_text,
                "operationName": query_fields.get("operationName", [None])[0],
            }
            for key in ("variables", "extensions"):
                raw_value = query_fields.get(key, [None])[0]
                if raw_value:
                    try:
                        envelope[key] = json.loads(raw_value)
                    except (ValueError, TypeError):
                        pass
            names.update(GQL_NAME.findall(query_text))
            rec["graphql"] = graphql_entries(
                envelope, live_url, body_media_type.split(";", 1)[0].lower()
            )
            path = up.urlparse(live_url).path
            gql_endpoints.setdefault(path, {"count": 0})["count"] += 1

    if "graphql" not in rec:
        path_operation = persisted_path(live_url)
        if path_operation:
            qid, opname = path_operation
            variables = None
            if body_bytes:
                try:
                    body_json = json.loads(body_bytes.decode("utf-8", "replace"))
                    if isinstance(body_json, dict):
                        variables = body_json.get("variables")
                        qid = body_json.get("queryId") or qid
                except (ValueError, TypeError):
                    pass
            if opname:
                names.add(opname)
                rec["graphql"] = [
                    {
                        "operationName": opname,
                        "variables_keys": sorted(variables)
                        if isinstance(variables, dict)
                        else None,
                        "variables_shape": shape(variables) if variables else None,
                        "persistedHash": qid,
                        "semantic_kind": "unknown",
                        "protocol": "graphql-x-persisted",
                        "request_template": {},
                        "query": "",
                    }
                ]
                segments = [s for s in up.urlparse(live_url).path.split("/") if s]
                norm = (
                    "/" + "/".join(segments[:-2])
                    if len(segments) >= 2
                    else up.urlparse(live_url).path
                )
                gql_endpoints.setdefault(norm, {"count": 0})["count"] += 1

    if status < 400 and status != 204:
        content = response.get("content") or {}
        resp_media_type = str(content.get("mimeType") or resp_ct or "")
        kind_hint = resp_media_type.split(";", 1)[0].lower()
        skip_body = kind_hint in {"text/event-stream", "text/html"} or (
            not rec.get("graphql") and kind_hint in {"application/javascript", "text/javascript"}
        )
        if not skip_body:
            raw = _decode_har_body(content)
            if raw and raw.strip():
                try:
                    decoded = decode_payload(
                        raw, media_type=resp_media_type, max_bytes=MAX_BODY_BYTES
                    )
                    response_value = decoded.value
                    rec["response_packaging"] = list(decoded.layers)
                    rec["resp_shape"] = shape(response_value)
                    if rec.get("graphql"):
                        rec["graphql_response_success"] = graphql_response_success(
                            response_value, rec["graphql"]
                        )
                except (PackagingError, ValueError, TypeError, UnicodeDecodeError):
                    pass

    rec["response_kind"] = classify_media(
        rec.get("resp_ct"), rec.get("rtype"), graphql="graphql" in rec
    ).value
    return rec


def import_har(har_path: str, domain: str, outdir: str) -> dict[str, Any]:
    """Convert a HAR file's first-party API traffic into an astrolabe capture dir.

    Writes capture.jsonl, meta.json, graphql-names.txt, transfer-manifest.json --
    the same artifacts capture.py's flush_meta() writes -- so `astrolabe analyze`,
    `astrolabe contract`, and `astrolabe mcp-gen` consume this directory exactly
    as they would a live capture. Returns a summary of what was kept.
    """
    with open(har_path, encoding="utf-8-sig") as handle:
        har = json.load(handle)
    log = har.get("log") or {}
    entries = log.get("entries") or []
    if not isinstance(entries, list):
        raise ValueError("HAR log.entries must be a list")
    creator = log.get("creator") or {}

    os.makedirs(outdir, exist_ok=True)
    cap_path = os.path.join(outdir, "capture.jsonl")

    names: set[str] = set()
    gql_endpoints: dict[str, dict[str, int]] = {}
    auth_seen: dict[str, int] = {}
    failures: list[dict[str, Any]] = []
    kept = 0

    with open(cap_path, "w", encoding="utf-8") as jf:
        for entry in entries:
            try:
                if not isinstance(entry, dict):
                    raise ValueError("HAR entry is not an object")
                rec = _entry_to_record(entry, domain, names, gql_endpoints, auth_seen)
            except Exception as exc:  # malformed entry -> typed failure, never a crash
                failures.append(
                    failure_evidence(
                        "har-entry",
                        "parse",
                        exc,
                        context=safe_url(_entry_url(entry)) if isinstance(entry, dict) else None,
                    )
                )
                continue
            if rec is None:
                continue
            jf.write(json.dumps(rec) + "\n")
            kept += 1

    started_at, completed_at = _entry_time_range(entries)
    now = datetime.now(UTC).isoformat()
    run_id = f"har-import-{uuid.uuid4().hex}"
    creator_name = creator.get("name") if isinstance(creator, dict) else None
    creator_version = creator.get("version") if isinstance(creator, dict) else None
    meta = {
        "base_domain": domain,
        "graphql_endpoints": gql_endpoints,
        "auth_headers": auth_seen,
        "events": {},
        "websockets": {},
        "declared_operations": [],
        "client_credentials": [],
        "truncations": dict(SHAPE_TRUNCATIONS),
        "failures": failures,
        "failure_summary": summarize_failures(failures),
        "interactions": [
            {
                "kind": "import",
                "url": None,
                "started_at": started_at or now,
                "completed_at": completed_at or now,
            }
        ],
        "run_id": run_id,
        "started_at": started_at or now,
        "completed_at": completed_at or now,
        "captured_at": completed_at or now,
        "partial": False,
        "records": kept,
        "evidence_source": "har-import",
        "import": {
            "format": "har",
            "entries_total": len(entries),
            "entries_kept": kept,
            "creator": (
                f"{creator_name}/{creator_version}" if creator_name or creator_version else None
            ),
        },
    }
    atomic_write_json(os.path.join(outdir, "meta.json"), meta)
    atomic_write_text(os.path.join(outdir, "graphql-names.txt"), "\n".join(sorted(names)))

    checksums = {
        name: sha256_file(os.path.join(outdir, name))
        for name in ("capture.jsonl", "meta.json", "graphql-names.txt")
    }
    atomic_write_json(
        os.path.join(outdir, "transfer-manifest.json"),
        {"run_id": run_id, "sha256": checksums},
    )

    return {
        "run_id": run_id,
        "entries_total": len(entries),
        "entries_kept": kept,
        "failures": len(failures),
        "graphql_endpoints": len(gql_endpoints),
        "records": kept,
    }
