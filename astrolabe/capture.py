#!/usr/bin/env python3
"""astrolabe capture engine — drive CloakBrowser (stealth Chromium) to map a site's
API surface. Standalone: runs on the pipeline host in the cloakbrowser venv.
Stdlib + cloakbrowser only.

Emits into --outdir:
  capture.jsonl     request/response *shapes* (PII-safe: no response values, no token values)
  capture.har       full HAR (feeds har-to-openapi)  [--har]
  graphql-names.txt GraphQL operation/field/type names (clairvoyance -w wordlist)
  meta.json         graphql endpoints, auth-header model, CF/byparr events, introspection result

Per-site recipe (--recipe file.py) may define:
  SURFACES = ["https://…", …]           # URLs to visit
  def drive(page, log): ...             # custom interaction (drive search filters, pagers, …)
"""

from __future__ import annotations
import argparse
import atexit
import hashlib
import json
import os
import re
import signal
import time
import importlib.util
import urllib.request
import urllib.parse as up
from datetime import UTC, datetime
from functools import lru_cache

try:
    from astrolabe.browser import connect_context, launch_context
    from astrolabe.graphql_doc import parse_graphql_document
    from astrolabe.media import classify_media
    from astrolabe.operation import graphql_protocol
    from astrolabe.persisted import (
        RECOVERY_INIT_SCRIPT,
        RECOVERY_READ_SCRIPT,
        bind_document,
        graphql_response_success,
    )
    from astrolabe.relay import RelayCatalog, MAX_SCRIPT_BYTES, MAX_SCRIPTS
    from astrolabe.client_credentials import MAX_SITES_PER_CAPTURE as MAX_CREDENTIAL_SITES
    from astrolabe.client_credentials import discover as discover_client_credentials
    from astrolabe.payloads import PackagingError, decode_payload
    from astrolabe.security import (
        atomic_write_json,
        atomic_write_text,
        egress_policy,
        host_matches,
        is_first_party as _shared_is_first_party,
        request_metadata,
        safe_text,
        safe_url,
        structural_shape,
        third_party_egress,
        validate_url,
    )
except ImportError:  # standalone deployment on the capture host
    from browser import connect_context, launch_context  # type: ignore[import-not-found,no-redef]
    from graphql_doc import parse_graphql_document  # type: ignore[import-not-found,no-redef]
    from media import classify_media  # type: ignore[import-not-found,no-redef]
    from operation import graphql_protocol  # type: ignore[import-not-found,no-redef]
    from persisted import (  # type: ignore[import-not-found,no-redef]
        RECOVERY_INIT_SCRIPT,
        RECOVERY_READ_SCRIPT,
        bind_document,
        graphql_response_success,
    )
    from relay import RelayCatalog, MAX_SCRIPT_BYTES, MAX_SCRIPTS  # type: ignore[import-not-found,no-redef]
    from client_credentials import (  # type: ignore[import-not-found,no-redef]
        MAX_SITES_PER_CAPTURE as MAX_CREDENTIAL_SITES,
        discover as discover_client_credentials,
    )
    from payloads import PackagingError, decode_payload  # type: ignore[import-not-found,no-redef]
    from security import (  # type: ignore[import-not-found,no-redef]
        atomic_write_json,
        atomic_write_text,
        egress_policy,
        host_matches,
        is_first_party as _shared_is_first_party,
        request_metadata,
        safe_text,
        safe_url,
        structural_shape,
        third_party_egress,
        validate_url,
    )

API_HINT = re.compile(r"(graphql|/api/|/ab/|gql|\.json(\?|$)|/o/|/v\d/)", re.I)
GQL_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
PERSISTED_PATH = re.compile(r"/graphql/([^/]+)/([_A-Za-z][_0-9A-Za-z]*)$")
CF_MARKERS = re.compile(
    r"(just a moment|verifying you are human|cf-chl|challenge-platform|attention required)", re.I
)

# ---- generic auth/client-header detection (site-agnostic) ------------------
# A small set of genuinely universal header names, PLUS a name-pattern match so
# arbitrary sites' auth models (x-api-key, x-shopify-storefront-access-token,
# apikey, x-auth-token, x-session-id, vendor-prefixed tenant/client headers, …)
# are captured without hardcoding any vendor's header names in this module.
# Deliberately generous on detection — a false positive just adds a harmless
# extra column to capture.jsonl; a false negative makes a site's auth model
# invisible on the passive-capture path.
AUTH_HEADER_NAMES_DEFAULT = frozenset(
    {
        "authorization",
        "x-requested-with",
        "x-csrf-token",
        "x-api-key",
    }
)
AUTH_HEADER_PATTERN_DEFAULT = re.compile(
    r"auth|token|csrf|api[-_]?key|session"  # generic auth/secret vocabulary
    r"|client-(?:name|version)"  # e.g. apollographql-client-name
    r"|accept-language$"  # e.g. x-vendor-accept-language
    r"|^x-.*(?:key|secret|tenant|client)",  # x-<vendor>-tenant/key/secret/client
    re.I,
)

# Redaction (security-critical — do not weaken): any DETECTED header whose name
# matches this is secret-bearing and MUST be recorded as "<present>", never its
# real value. Only headers detected-but-not-secret (client-identification
# headers like x-requested-with, *-client-name, *-client-version,
# *-accept-language) may keep their real value. When in doubt, redact.
SECRET_HEADER_PATTERN = re.compile(r"authorization|token|key|secret|csrf|session", re.I)


def is_auth_header(name, extra_names=(), pattern=AUTH_HEADER_PATTERN_DEFAULT):
    """Is `name` part of the auth/client-identification header surface?"""
    n = name.lower()
    if n in AUTH_HEADER_NAMES_DEFAULT or n in extra_names:
        return True
    return bool(pattern.search(n))


def is_secret_header(name):
    """Is `name` secret-bearing (must never have its real value persisted)?"""
    return bool(SECRET_HEADER_PATTERN.search(name.lower()))


def is_first_party(url, base):
    """Is `url`'s host `base` itself, or a subdomain of it?

    Uses `hostname` (not `netloc`) so a port survives on the URL but not on
    the comparison -- `netloc` carries the port (e.g. "example.com:8443"),
    which used to make first-party traffic on a non-default port silently
    fail to match and drop out of the capture entirely. `hostname` also
    lowercases, so casing differences never cause a false negative.

    Domain-boundary semantics are unchanged: matching is host-equality or a
    "." + base suffix, so "notexample.com" never matches base "example.com".
    """
    return _shared_is_first_party(url, base)


def build_auth_matcher(recipe):
    """Combine the generic defaults with an optional per-site recipe extension.

    A recipe may define AUTH_HEADERS (iterable of extra exact header names,
    always treated as auth) and/or AUTH_HEADER_PATTERN (a regex string, OR'd
    into the default pattern). Both EXTEND the generic defaults; neither can
    disable them. Returns (extra_names: frozenset, pattern: re.Pattern).
    """
    extra_names = frozenset()
    pattern = AUTH_HEADER_PATTERN_DEFAULT
    if recipe is not None:
        raw_extra = getattr(recipe, "AUTH_HEADERS", None) or ()
        extra_names = frozenset(h.lower() for h in raw_extra)
        extra_pattern_src = getattr(recipe, "AUTH_HEADER_PATTERN", None)
        if extra_pattern_src:
            pattern = re.compile(
                f"(?:{AUTH_HEADER_PATTERN_DEFAULT.pattern})|(?:{extra_pattern_src})",
                re.I,
            )
    return extra_names, pattern


SHAPE_LIMITS = {
    "max_depth": 8,
    "max_nodes": 1000,
    "max_keys": 200,
    "max_array_samples": 8,
}
SHAPE_TRUNCATIONS: dict[str, int] = {}


def shape(v, d=0):
    limits = dict(SHAPE_LIMITS)
    limits["max_depth"] = max(0, limits["max_depth"] - d)
    return structural_shape(v, counters=SHAPE_TRUNCATIONS, **limits)


def graphql_entries(payload, live_url, media_type):
    """Turn one GraphQL transport envelope into parser-backed operation evidence."""
    if not isinstance(payload, dict):
        return []
    query = payload.get("query") or ""
    selected_name = payload.get("operationName")
    variables = payload.get("variables")
    persisted_id = (
        ((payload.get("extensions") or {}).get("persistedQuery") or {}).get("sha256Hash")
        if isinstance(payload.get("extensions"), dict)
        else None
    )
    template = {
        key: payload[key]
        for key in ("features", "fieldToggles")
        if isinstance(payload.get(key), dict)
    }
    common = {
        "variables_keys": sorted(variables) if isinstance(variables, dict) else None,
        "variables_shape": shape(variables) if variables else None,
        "persistedHash": persisted_id,
        "protocol": graphql_protocol(
            query=query,
            persisted_id=persisted_id,
            url=live_url,
            media_type=media_type,
        ).value,
        "request_template": template,
        "query": query[:20000],
    }
    if not query:
        return [
            {
                **common,
                "operationName": selected_name,
                "semantic_kind": "unknown",
                "parse_confidence": "transport-only",
                "selected": True,
            }
        ]
    return [
        {
            **common,
            "operationName": item.name,
            "semantic_kind": item.semantic_kind,
            "declared_variables": item.variable_names,
            "response_keys": item.response_keys,
            "root_fields": item.root_fields,
            "directives": item.directives,
            "selected": item.selected,
            "parse_confidence": item.parse_confidence,
            **({"parse_error": item.parse_error} if item.parse_error else {}),
        }
        for item in parse_graphql_document(query, selected_name)
    ]


def persisted_path(url):
    """Recognize exactly /graphql/<identifier>/<operation>, not legacy REST paths."""
    match = PERSISTED_PATH.search(up.urlparse(url).path)
    return (match.group(1), match.group(2)) if match else None


@lru_cache(maxsize=1024)
def gql_names(query):
    """Tokenise one query document into candidate names.

    A page fires the same query text on every navigation, and a run re-tokenises it
    once per response; the result is a pure function of the text, so it is cached
    rather than recomputed. Capped, so an unbounded stream of distinct documents
    cannot grow this without limit.
    """
    return tuple(GQL_NAME.findall(query))


def response_payload(response, max_bytes, *, graphql=False):
    """Never wait for an unbounded stream or parse document/static responses as APIs."""
    media_type = response.headers.get("content-type", "")
    kind = media_type.split(";", 1)[0].lower()
    if kind in {"text/event-stream", "text/html"} or (
        not graphql and kind in {"application/javascript", "text/javascript"}
    ):
        return None
    request = getattr(response, "request", None)
    if str(getattr(request, "method", "")).upper() == "HEAD":
        return None  # HEAD responses carry no body to decode.
    raw = response.body()
    if not raw.strip():
        return None
    try:
        return decode_payload(raw, media_type=media_type, max_bytes=max_bytes)
    except PackagingError:
        # Plain or unlabeled text (properties files, CSV, prose) is a legitimate non-API
        # body, not a decode failure. A body labeled GraphQL or structured still fails.
        if not graphql and (not kind or kind.startswith("text/")) and kind != "text/json":
            return None
        raise


def admit_request(
    state,
    origin,
    operation,
    *,
    total_limit,
    origin_limit,
    operation_limit,
):
    """Atomically account for one request and return a pre-request rejection reason."""
    if origin in state["blocked_origins"]:
        reason = "rate-limit-reserve"
    elif state["total"] >= max(1, total_limit):
        reason = "total-request-budget"
    elif state["origins"].get(origin, 0) >= max(1, origin_limit):
        reason = "origin-request-budget"
    elif state["operations"].get(operation, 0) >= max(1, operation_limit):
        reason = "operation-request-budget"
    else:
        state["total"] += 1
        state["origins"][origin] = state["origins"].get(origin, 0) + 1
        state["operations"][operation] = state["operations"].get(operation, 0) + 1
        return None
    state["truncation_count"] += 1
    if len(state["truncations"]) < 1000:
        state["truncations"].append({"reason": reason, "origin": origin, "operation": operation})
    return reason


_VOLATILE_PATH_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{24,}|[A-Za-z0-9_-]{40,})$",
    re.I,
)


def request_budget_operation(method, url, body=None):
    """Derive a stable pre-request budget key without retaining argument values."""
    parsed = up.urlparse(url)
    if body:
        try:
            payload = json.loads(body)
            members = payload if isinstance(payload, list) else [payload]
            names = sorted(
                {
                    str(member.get("operationName"))
                    for member in members
                    if isinstance(member, dict) and member.get("operationName")
                }
            )
            if names:
                return f"GRAPHQL {','.join(names)}"
        except (TypeError, json.JSONDecodeError):
            pass
    segments = [
        "{id}" if _VOLATILE_PATH_SEGMENT.fullmatch(segment) else segment
        for segment in parsed.path.split("/")
    ]
    return f"{str(method).upper()} {'/'.join(segments) or '/'}"


def rate_stop_path(directory, origin):
    return os.path.join(directory, hashlib.sha256(origin.encode()).hexdigest())


def publish_rate_stop(directory, origin):
    os.makedirs(directory, exist_ok=True)
    atomic_write_text(rate_stop_path(directory, origin), origin)


def rate_stopped(directory, origin):
    return bool(directory and os.path.exists(rate_stop_path(directory, origin)))


def browser_context_options(proxy, outdir, *, record_har=False, user_agent=None):
    options = {
        "headless": True,
        "stealth_args": True,
        "geoip": not bool(proxy),
        "locale": "en-US",
        "viewport": {"width": 1920, "height": 1080},
        # Direct capture must use normal certificate validation. Ignoring TLS
        # errors is limited to the explicit interception-proxy mode.
        "ignore_https_errors": bool(proxy),
    }
    if proxy:
        options["proxy"] = proxy
    if user_agent:
        options["user_agent"] = user_agent
    if record_har:
        options["record_har_path"] = os.path.join(outdir, "capture.har")
        options["record_har_mode"] = "full"
    return options


def _shape_weight(s):
    """Rough structural richness of a shape() result — used to keep the most
    informative arg shape seen for a given websocket event."""
    if isinstance(s, dict):
        return 2 + sum(_shape_weight(v) for v in s.values())
    if isinstance(s, list):
        return 1 + sum(_shape_weight(v) for v in s)
    return 0


def parse_socketio(payload):
    """Parse a socket.io-over-Engine.IO v3/v4 text frame.

    Engine.IO wraps socket.io: a text data packet is '4' (Engine.IO MESSAGE)
    followed by a socket.io packet '<type>[/ns,][ackid]<json>'. socket.io packet
    types: 0 CONNECT, 1 DISCONNECT, 2 EVENT, 3 ACK, 4 CONNECT_ERROR, 5 BINARY_EVENT.
    Returns {sio_type, ns, event, args, data} for a socket.io packet, or None for
    Engine.IO control frames (ping/pong/open/upgrade) and non-socket.io text."""
    if not isinstance(payload, str) or not payload:
        return None
    if payload[0] != "4":  # not an Engine.IO MESSAGE (2=ping,3=pong,0=open,…)
        return None
    sio = payload[1:]
    if not sio or not sio[0].isdigit():
        return None
    sio_type, rest = sio[0], sio[1:]
    ns = None
    if rest.startswith("/"):  # explicit namespace, terminated by ','
        comma = rest.find(",")
        if comma == -1:
            ns, rest = rest, ""
        else:
            ns, rest = rest[:comma], rest[comma + 1 :]
    i = 0
    while i < len(rest) and rest[i].isdigit():  # optional ack id
        i += 1
    body = rest[i:]
    data = None
    if body:
        try:
            data = json.loads(body)
        except Exception:
            data = None
    event, args = None, None
    if sio_type in ("2", "5") and isinstance(data, list) and data:
        event = data[0] if isinstance(data[0], str) else None
        args = data[1:]
    return {"sio_type": sio_type, "ns": ns, "event": event, "args": args, "data": data}


def failure_evidence(stage, category, error, *, context=None, interaction_id=None):
    """Build a value-safe typed failure record suitable for persisted run metadata."""
    return {
        "stage": str(stage),
        "category": str(category),
        "error_type": type(error).__name__,
        "message": safe_text(error),
        "context": safe_text(context) if context is not None else None,
        "interaction_id": interaction_id,
        "observed_at": datetime.now(UTC).isoformat(),
    }


def browser_failure_category(error):
    message = str(error).lower()
    if any(
        marker in message
        for marker in (
            "err_cert_",
            "certificate verify failed",
            "certificate has expired",
            "self signed certificate",
            "tls handshake",
        )
    ):
        return "tls"
    if "timeout" in message:
        return "timeout"
    if any(marker in message for marker in ("captcha", "challenge", "access denied")):
        return "challenge"
    return "browser"


def summarize_failures(failures):
    summary = {"total": len(failures), "by_stage": {}, "by_category": {}, "by_surface": {}}
    for failure in failures:
        for output, field in (("by_stage", "stage"), ("by_category", "category")):
            key = str(failure.get(field) or "unknown")
            summary[output][key] = summary[output].get(key, 0) + 1
        if failure.get("context"):
            surface = safe_url(str(failure["context"]))
            parsed_surface = up.urlsplit(surface)
            if parsed_surface.scheme and parsed_surface.netloc:
                surface = up.urlunsplit(
                    (parsed_surface.scheme, parsed_surface.netloc, parsed_surface.path, "", "")
                )
            summary["by_surface"][surface] = summary["by_surface"].get(surface, 0) + 1
    return summary


def load_recipe(path, *, allow_inprocess=False):
    if not path:
        return None
    if path.lower().endswith(".json"):
        try:
            from astrolabe.recipe import load_declarative_recipe
        except ImportError:
            from recipe import load_declarative_recipe  # type: ignore[import-not-found,no-redef]
        return load_declarative_recipe(path)
    try:
        from astrolabe.recipe import recipe_safety_findings
    except ImportError:
        from recipe import recipe_safety_findings  # type: ignore[import-not-found,no-redef]
    unsafe = recipe_safety_findings(path)
    if unsafe:
        summary = "; ".join(str(item) for item in unsafe[:5])
        raise ValueError(f"Python recipe requires explicit safety annotations: {summary}")
    if not allow_inprocess:
        try:
            from astrolabe.recipe_runtime import SandboxedRecipe
        except ImportError:
            from recipe_runtime import SandboxedRecipe  # type: ignore[import-not-found,no-redef]
        worker_path = os.path.join(os.path.dirname(__file__), "recipe_worker.py")
        return SandboxedRecipe(path, worker_path=worker_path)
    spec = importlib.util.spec_from_file_location("recipe", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def byparr_solve(endpoint, url, timeout_s=60):
    """Solve a challenge with Byparr's /v1 LinkRequest contract.

    Byparr takes `max_timeout` in seconds; FlareSolverr's millisecond `maxTimeout`
    is not part of its schema and was silently ignored.
    """
    body = json.dumps({"cmd": "request.get", "url": url, "max_timeout": int(timeout_s)}).encode()
    req = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout_s + 30) as r:
        result = json.loads(r.read())
    if not isinstance(result, dict) or result.get("status") != "ok":
        message = result.get("message") if isinstance(result, dict) else None
        raise RuntimeError(f"byparr did not solve the challenge: {safe_text(message)[:200]}")
    return result


def challenge_cookies(solution, base):
    """Playwright cookies from a Byparr Solution, limited to the target's own domain."""
    cookies = []
    for cookie in solution.get("cookies") or []:
        if not isinstance(cookie, dict) or not cookie.get("name"):
            continue
        domain = str(cookie.get("domain") or "." + base)
        cookie_host = domain.lstrip(".").lower()
        # Browser domain-matching: the target must be the cookie domain or beneath it
        # (a parent-domain __cf_bm is sent to the target). Single-label domains are
        # never valid cookie scopes.
        if "." not in cookie_host or not host_matches(base, cookie_host):
            continue
        entry = {
            "name": cookie["name"],
            "value": str(cookie.get("value") or ""),
            "domain": domain,
            "path": cookie.get("path") or "/",
        }
        if isinstance(cookie.get("expires"), (int, float)) and cookie["expires"] > 0:
            entry["expires"] = cookie["expires"]
        for flag in ("httpOnly", "secure"):
            if isinstance(cookie.get(flag), bool):
                entry[flag] = cookie[flag]
        if cookie.get("sameSite") in {"Lax", "None", "Strict"}:
            entry["sameSite"] = cookie["sameSite"]
        cookies.append(entry)
    return cookies


# ---- adaptive settle detection ---------------------------------------------
# A flat post-navigation sleep is wrong in both directions: it wastes seconds
# on pages that finish fast, and it silently TRUNCATES slow pages, dropping
# API operations from capture.jsonl — an accuracy bug, not just a speed one.
# on_response (below) already fires for every first-party XHR/fetch/API
# response; settle detection reuses that exact signal instead of a fixed
# duration.
SETTLE_MIN_MS_DEFAULT = 800  # an SPA typically fires nothing for the first
# several hundred ms; returning before this
# races the page's initial XHR burst and
# yields a false "quiet" reading of zero calls.
SETTLE_MS_DEFAULT = 1500  # quiet-period threshold: no first-party API
# response for this long => considered settled.
# Settle detection trades deadline-truncation
# for GAP-truncation: any inter-burst gap longer
# than this ends the visit early. Measured
# against the old flat 4.0s sleep, an 800ms
# threshold newly truncated pages whose second
# wave (lazy loads, deferred fetches, a slow
# backend) landed 0.8-4.0s in — a regression on
# the accuracy this feature exists to protect.
# 1500ms still returns in ~2.1s on a fast page
# (vs 4.0s before) while covering the common
# gap. Raise it, or use --no-settle, on a target
# that loads in widely spaced waves.
SETTLE_POLL_MS = 150  # polling slice, within the requested 100-200ms
# band — fine enough not to overshoot the
# settle/ceiling deadlines by more than ~150ms.
# ceiling = wait_s * 1000 * this factor. The legacy flat sleep was `wait`
# seconds (4.0s for surfaces, 3.0s for crawl); settle detection normally
# returns much sooner than that, so the ceiling only needs to fire for
# genuinely slow/chatty pages. 1.5x turns the old 4.0s default into a 6.0s
# ceiling and the old 3.0s crawl default into a 4.5s ceiling -- a safety net
# above the old behavior's upper bound, not a tighter one.
SETTLE_CEILING_FACTOR = 1.5


def wait_for_settle(
    page,
    stats,
    *,
    min_ms=SETTLE_MIN_MS_DEFAULT,
    settle_ms=SETTLE_MS_DEFAULT,
    ceiling_ms=6000,
    poll_ms=SETTLE_POLL_MS,
    now=time.monotonic,
):
    """Poll `page` until the first-party API response stream tracked in
    `stats` has been quiet for `settle_ms`, subject to `min_ms` and
    `ceiling_ms`. `stats` is the dict on_response mutates: stats["n"] is a
    running total call count, stats["last_ts"] is time.monotonic() of the
    most recently recorded first-party API response.

    Returns (elapsed_seconds, calls_seen_this_visit, settled). `settled` is
    False only when the ceiling fired while the response stream was still
    active (i.e. real truncation, worth logging distinctly from a clean quiet
    exit).
    """
    start = now()
    n0 = stats["n"]
    deadline = start + ceiling_ms / 1000.0

    def sleep_slice(remaining_ms):
        page.wait_for_timeout(int(max(1, min(poll_ms, remaining_ms))))

    # 1) minimum wait -- always honored, regardless of activity.
    while (now() - start) * 1000.0 < min_ms:
        sleep_slice(min_ms - (now() - start) * 1000.0)

    # 2) zero-activity short-circuit: a static page that has fired nothing at
    #    all gets a short grace beyond min_ms, then returns rather than
    #    burning the full ceiling.
    if stats["n"] == n0:
        grace_deadline = min(start + (min_ms + min(300, settle_ms)) / 1000.0, deadline)
        while stats["n"] == n0 and now() < grace_deadline:
            sleep_slice((grace_deadline - now()) * 1000.0)
        if stats["n"] == n0:
            return now() - start, 0, True

    # 3) settle-quiet loop, bounded by the ceiling.
    while True:
        gaps = sorted(float(value) for value in stats.get("burst_gaps_ms", [])[-100:])
        adaptive_settle_ms = settle_ms
        if gaps:
            p90 = gaps[min(len(gaps) - 1, int((len(gaps) - 1) * 0.9))]
            adaptive_settle_ms = min(max(settle_ms, int(p90 * 1.5)), 5000)
        stats["effective_settle_ms"] = adaptive_settle_ms
        last_ts = stats.get("last_ts", start)
        quiet_ms = (now() - last_ts) * 1000.0
        if quiet_ms >= adaptive_settle_ms:
            return now() - start, stats["n"] - n0, True
        t = now()
        if t >= deadline:
            return t - start, stats["n"] - n0, False
        sleep_slice(min(adaptive_settle_ms - quiet_ms, (deadline - t) * 1000.0))


def settle_or_wait(
    page,
    stats,
    wait_s,
    *,
    no_settle=False,
    min_ms=SETTLE_MIN_MS_DEFAULT,
    settle_ms=SETTLE_MS_DEFAULT,
    ceiling_ms=None,
    ceiling_factor=SETTLE_CEILING_FACTOR,
    poll_ms=SETTLE_POLL_MS,
    now=time.monotonic,
    log=None,
    label="visit",
    url="",
):
    """Navigation-settle entry point used by visit(). With `no_settle` (the
    --no-settle escape hatch) this is exactly the old flat `page.wait_for_timeout(wait_s
    * 1000)` behavior, for debugging a target where settle detection misbehaves.
    Otherwise it delegates to wait_for_settle() with a ceiling derived from
    `wait_s` (unless the caller passes an explicit `ceiling_ms` override, e.g.
    from --settle-timeout-ms), and logs the outcome so runtime is observable."""
    if no_settle:
        page.wait_for_timeout(int(wait_s * 1000))
        return None
    ceiling = ceiling_ms if ceiling_ms is not None else int(wait_s * 1000 * ceiling_factor)
    elapsed, n_calls, settled = wait_for_settle(
        page,
        stats,
        min_ms=min_ms,
        settle_ms=settle_ms,
        ceiling_ms=ceiling,
        poll_ms=poll_ms,
        now=now,
    )
    if log:
        if settled:
            log(f"[{label}] {url} -> settled in {elapsed:.1f}s ({n_calls} calls)")
        else:
            log(f"[{label}] {url} -> ceiling {elapsed:.1f}s ({n_calls} calls, still active)")
    return elapsed, n_calls, settled


def build_parser():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cookies")
    ap.add_argument("--recipe")
    ap.add_argument(
        "--trusted-recipe",
        action="store_true",
        help="acknowledge that a Python recipe is executable trusted code",
    )
    ap.add_argument(
        "--allow-inprocess-python-recipe",
        action="store_true",
        help="second acknowledgement for the unconstrained Python drive() escape hatch",
    )
    ap.add_argument("--seeds", default="")
    ap.add_argument("--seed", action="append", default=[], help=argparse.SUPPRESS)
    ap.add_argument("--skip-recipe-surfaces", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--rate-stop-dir", help=argparse.SUPPRESS)
    ap.add_argument("--crawl", type=int, default=0, help="follow N same-origin nav links")
    ap.add_argument(
        "--block-assets",
        action="store_true",
        help="skip images, media, and fonts to preserve the API request budget",
    )
    ap.add_argument("--base-domain", required=True)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--byparr", default=None, help="byparr /v1 endpoint for CF fallback")
    ap.add_argument(
        "--user-agent",
        default=None,
        help="browser user agent; pair with challenge cookies minted under that agent",
    )
    ap.add_argument(
        "--cdp-endpoint",
        default=None,
        help="attach to a running loopback Chromium (http://127.0.0.1:PORT) and reuse "
        "its session instead of launching a browser",
    )
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--run-id", help="caller-generated identity used to reject stale transfers")
    ap.add_argument("--har", action="store_true")
    ap.add_argument("--introspect", action="store_true")
    ap.add_argument(
        "--recover-persisted",
        action="store_true",
        help="recover exact APQ documents from browser Web Crypto hash inputs",
    )
    ap.add_argument("--shape-max-depth", type=int, default=8)
    ap.add_argument("--shape-max-nodes", type=int, default=1000)
    ap.add_argument("--shape-max-keys", type=int, default=200)
    ap.add_argument("--shape-array-samples", type=int, default=8)
    ap.add_argument("--body-max-bytes", type=int, default=2_000_000)
    ap.add_argument("--max-total-requests", type=int, default=10_000)
    ap.add_argument("--max-origin-requests", type=int, default=5_000)
    ap.add_argument("--max-operation-requests", type=int, default=500)
    ap.add_argument("--rate-limit-reserve", type=int, default=1)
    ap.add_argument(
        "--settle-ms",
        type=int,
        default=SETTLE_MS_DEFAULT,
        help="quiet period (ms) with no first-party API response "
        "before a page is considered settled",
    )
    ap.add_argument(
        "--settle-min-ms",
        type=int,
        default=SETTLE_MIN_MS_DEFAULT,
        help="minimum wait (ms) before settle-checking begins "
        "(avoids racing an SPA's first XHR burst)",
    )
    ap.add_argument(
        "--settle-timeout-ms",
        type=int,
        default=None,
        help="hard ceiling (ms) for settle detection; default is "
        "derived per-visit from the legacy wait value (~1.5x)",
    )
    ap.add_argument(
        "--no-settle",
        action="store_true",
        help="disable settle detection; restore the old flat "
        "sleep(wait) behavior (debugging escape hatch)",
    )
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)
    if a.cdp_endpoint and (a.cookies or a.proxy or a.har or a.user_agent):
        raise SystemExit(
            "--cdp-endpoint reuses the attached browser's own session; it cannot combine "
            "with --cookies, --proxy, --har, or --user-agent"
        )
    for option, value in (
        ("--max-total-requests", a.max_total_requests),
        ("--max-origin-requests", a.max_origin_requests),
        ("--max-operation-requests", a.max_operation_requests),
    ):
        if value < 1:
            raise SystemExit(f"{option} must be at least 1")
    if a.rate_limit_reserve < 0:
        raise SystemExit("--rate-limit-reserve must be non-negative")
    SHAPE_LIMITS.update(
        {
            "max_depth": max(1, a.shape_max_depth),
            "max_nodes": max(1, a.shape_max_nodes),
            "max_keys": max(1, a.shape_max_keys),
            "max_array_samples": max(1, a.shape_array_samples),
        }
    )
    SHAPE_TRUNCATIONS.clear()
    os.makedirs(a.outdir, exist_ok=True)
    if a.rate_stop_dir:
        os.makedirs(a.rate_stop_dir, exist_ok=True)
    base = a.base_domain

    # recipe is loaded up-front (instead of later, before drive()) so the
    # generic auth-header matcher below can be extended by a per-site recipe
    # before the response/request listeners that reference it are ever fired.
    if a.recipe and not a.recipe.lower().endswith(".json") and not a.trusted_recipe:
        raise SystemExit(
            "Python recipes require --trusted-recipe and run in an isolated worker by default; "
            "prefer declarative JSON"
        )
    recipe = load_recipe(
        a.recipe,
        allow_inprocess=bool(a.allow_inprocess_python_recipe),
    )
    auth_extra_headers, auth_header_pattern = build_auth_matcher(recipe)

    def is_auth(h):
        return is_auth_header(h, auth_extra_headers, auth_header_pattern)

    def _first_party(u):
        return is_first_party(u, base)

    names, gql_endpoints, auth_seen = set(), {}, {}
    ws_catalog = {}  # ws_url(path-normalized) -> event catalog (shapes only)
    events = {"cf": [], "byparr": [], "introspection": None}
    surfaces = []  # populated after recipe load; referenced by flush_meta()
    stats = {"n": 0, "interaction_id": None}
    failures = []
    interactions = []
    interaction_started: dict[str, float] = {}
    credential_observations = []
    credential_fingerprints: dict[str, str] = {}
    service_workers = set()
    offline_queues = []
    budget_state = {
        "total": 0,
        "origins": {},
        "operations": {},
        "blocked_origins": set(),
        "truncations": [],
        "truncation_count": 0,
        "rate_limits": {},
    }
    strict_recipe_egress = [False]
    # Resolved once, up front: a bad operator value must fail the run before a browser
    # opens, and the run's reported policy must be the one actually enforced.
    try:
        egress = egress_policy()
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if a.run_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", a.run_id):
        raise SystemExit("--run-id contains unsupported characters")
    run_state = {
        "run_id": a.run_id or f"{int(time.time())}-{os.getpid()}",
        "started_at": datetime.now(UTC).isoformat(),
        "completed_at": None,
        "partial": False,
    }

    def begin_interaction(kind: str, surface: str, annotation: str | None = None) -> dict:
        interaction_id = f"interaction-{len(interactions) + 1}"
        interaction = {
            "id": interaction_id,
            "kind": kind,
            "surface": safe_url(surface),
            "started_at": datetime.now(UTC).isoformat(),
            "calls_before": stats["n"],
        }
        if annotation:
            interaction["safe_annotation"] = annotation
        interactions.append(interaction)
        interaction_started[interaction_id] = time.monotonic()
        stats["interaction_id"] = interaction_id
        stats["burst_gaps_ms"] = []
        stats.pop("last_ts", None)
        stats.pop("effective_settle_ms", None)
        return interaction

    def mark_api_response() -> None:
        now_monotonic = time.monotonic()
        previous = stats.get("last_ts")
        if previous is not None:
            stats.setdefault("burst_gaps_ms", []).append((now_monotonic - previous) * 1000.0)
        stats["last_ts"] = now_monotonic
        interaction_id = stats.get("interaction_id")
        if not interaction_id:
            return
        interaction = next(
            (item for item in reversed(interactions) if item["id"] == interaction_id), None
        )
        if interaction is not None and "first_api_at" not in interaction:
            interaction["first_api_at"] = datetime.now(UTC).isoformat()
            interaction["first_api_latency_ms"] = round(
                (now_monotonic - interaction_started[interaction_id]) * 1000.0, 3
            )

    def record_failure(stage, category, error, *, context=None, partial=False):
        failures.append(
            failure_evidence(
                stage,
                category,
                error,
                context=context,
                interaction_id=stats.get("interaction_id"),
            )
        )
        if partial:
            run_state["partial"] = True

    # capture.jsonl is written incrementally (append per response + flush) so a
    # terminated run always leaves the full request stream on disk — the capture is
    # no longer all-or-nothing.
    jf = open(os.path.join(a.outdir, "capture.jsonl"), "w")
    relay_catalog = RelayCatalog()
    credential_sites: list[dict] = []

    if a.cdp_endpoint:
        # Attached mode shares the operator's browser. Everything astrolabe installs
        # (routing, listeners, init scripts) is scoped to its own page so the
        # operator's other tabs are neither budgeted, blocked, nor recorded.
        ctx = connect_context(a.cdp_endpoint)
        page = ctx.new_page()
        traffic = page
    else:
        kw = browser_context_options(a.proxy, a.outdir, record_har=a.har, user_agent=a.user_agent)
        ctx = launch_context(**kw)
        traffic = ctx
    if a.recover_persisted:
        traffic.add_init_script(RECOVERY_INIT_SCRIPT)
    traffic.set_default_navigation_timeout(45000)

    def enforce_request_budget(route):
        request = route.request
        if a.block_assets and request.resource_type in {"image", "media", "font"}:
            route.abort("blockedbyclient")
            return
        parsed = up.urlparse(request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        try:
            request_body = request.post_data
        except Exception:
            request_body = None
        operation = request_budget_operation(request.method, request.url, request_body)
        if rate_stopped(a.rate_stop_dir, origin):
            budget_state["blocked_origins"].add(origin)
        if not _first_party(request.url):
            abort, truncation = third_party_egress(
                policy=egress,
                recipe_active=strict_recipe_egress[0],
            )
            if abort:
                budget_state["truncation_count"] += 1
                if len(budget_state["truncations"]) < 1000:
                    budget_state["truncations"].append(
                        {
                            "reason": truncation,
                            "origin": origin,
                            "operation": operation,
                        }
                    )
                route.abort("blockedbyclient")
                return
            route.continue_()
            return
        reason = admit_request(
            budget_state,
            origin,
            operation,
            total_limit=a.max_total_requests,
            origin_limit=a.max_origin_requests,
            operation_limit=a.max_operation_requests,
        )
        if reason:
            route.abort("blockedbyclient")
            return
        route.continue_()

    traffic.route("**/*", enforce_request_budget)
    try:
        ctx.on(
            "serviceworker",
            lambda worker: service_workers.add(safe_url(getattr(worker, "url", ""))),
        )
    except Exception as exc:
        record_failure("service-worker", "browser", exc)
    if a.cookies:
        ctx.add_cookies(json.load(open(a.cookies)))

    def on_response(resp):
        if jf.closed:
            return
        try:
            req = resp.request
            live_url = req.url.split("#")[0]
            url = safe_url(live_url)
            if a.recover_persisted and req.resource_type == "script":
                # Inspect only scripts already loaded by an authorized HTTPS page.
                # CDN origins are allowed here; no credential forwarding or extra fetch.
                try:
                    frame_url = req.frame.url
                except Exception:
                    return  # Service-worker scripts have no authorized page frame.
                if (
                    live_url.startswith("https://")
                    and _first_party(frame_url)
                    and resp.status == 200
                    and not relay_catalog.exhausted
                ):
                    length = resp.headers.get("content-length")
                    if relay_catalog.scripts >= MAX_SCRIPTS or (
                        length and int(length) > MAX_SCRIPT_BYTES
                    ):
                        relay_catalog.exhausted = True
                    else:
                        try:
                            script_body = resp.body()
                        except Exception:
                            return  # A navigated-away CDN body supplies no usable evidence.
                        relay_catalog.add(script_body, live_url)
                        # Same already-loaded script, so no extra fetch: note where the
                        # application keeps its static client credential. Provenance and
                        # digest only — the value itself is never recorded.
                        if len(credential_sites) < MAX_CREDENTIAL_SITES:
                            for site in discover_client_credentials(script_body, live_url):
                                if site.to_dict() not in credential_sites:
                                    credential_sites.append(site.to_dict())
                return
            if req.resource_type not in ("xhr", "fetch") and not API_HINT.search(live_url):
                return
            if not _first_party(live_url):
                return
            rec = {
                "method": req.method,
                "url": url,
                "status": resp.status,
                "rtype": req.resource_type,
                "resp_ct": resp.headers.get("content-type", ""),
            }
            remaining_header = resp.headers.get("x-ratelimit-remaining") or resp.headers.get(
                "ratelimit-remaining"
            )
            limit_header = resp.headers.get("x-ratelimit-limit") or resp.headers.get(
                "ratelimit-limit"
            )
            reset_header = resp.headers.get("x-ratelimit-reset") or resp.headers.get(
                "ratelimit-reset"
            )
            if remaining_header is not None:
                try:
                    remaining = int(float(remaining_header))
                    parsed_live = up.urlparse(live_url)
                    origin = f"{parsed_live.scheme}://{parsed_live.netloc}"
                    budget_state["rate_limits"][origin] = {
                        "limit": int(float(limit_header)) if limit_header is not None else None,
                        "remaining": remaining,
                        "reset": reset_header,
                    }
                    if remaining <= max(0, a.rate_limit_reserve):
                        budget_state["blocked_origins"].add(origin)
                        if a.rate_stop_dir:
                            publish_rate_stop(a.rate_stop_dir, origin)
                except (TypeError, ValueError):
                    pass
            if stats.get("interaction_id"):
                rec["interaction_id"] = stats["interaction_id"]
            hdrs = {}
            for h in req.headers:
                if is_auth(h):
                    hdrs[h] = "<present>"
                    auth_seen[h] = auth_seen.get(h, 0) + 1
            if hdrs:
                rec["req_headers"] = hdrs
            body = None
            try:
                body = req.post_data
            except Exception as exc:
                # post_data base64→utf-8 decodes internally and throws on
                # gzip/binary bodies (e.g. 0x8b gzip magic). Skip the body
                # but keep recording the rest of the request instead of
                # letting the exception drop the whole record.
                body = getattr(req, "post_data_buffer", None)
                record_failure("request-body", "body-decode", exc, context=url)
            if body:
                decoded_request = None
                try:
                    raw_request = body if isinstance(body, bytes) else body.encode("utf-8")
                    decoded_request = decode_payload(
                        raw_request,
                        media_type=req.headers.get("content-type", ""),
                        content_encoding=req.headers.get("content-encoding", ""),
                        max_bytes=a.body_max_bytes,
                    )
                except Exception:
                    pass
                rec.update(
                    request_metadata(
                        body,
                        req.headers.get("content-type", ""),
                        content_encoding=req.headers.get("content-encoding", ""),
                        max_body_bytes=a.body_max_bytes,
                        shape_counters=SHAPE_TRUNCATIONS,
                        shape_limits=SHAPE_LIMITS,
                        decoded_payload=decoded_request,
                    )
                )
                try:
                    if decoded_request is None:
                        raise PackagingError("request body is not decodable")
                    j = decoded_request.value
                    payloads = j if isinstance(j, list) else [j]
                    ops = []
                    for p in payloads:
                        if not isinstance(p, dict):
                            continue
                        if "query" in p or "operationName" in p or "extensions" in p:
                            q = p.get("query") or ""
                            names.update(gql_names(q))
                            if p.get("operationName"):
                                names.add(p["operationName"])
                            ops.extend(
                                graphql_entries(
                                    p,
                                    live_url,
                                    req.headers.get("content-type", ""),
                                )
                            )
                    if ops:
                        if list(decoded_request.layers) != ["json"]:
                            for operation in ops:
                                operation.setdefault("request_template", {})[
                                    "payload_packaging"
                                ] = list(decoded_request.layers)
                        rec["graphql"] = ops
                        path = up.urlparse(url).path
                        ge = gql_endpoints.setdefault(path, {"count": 0})
                        ge["count"] += 1
                except Exception:
                    # Form-encoded GraphQL fallback: some sites send
                    # application/x-www-form-urlencoded with doc_id + variables
                    # fields instead of a JSON body. json.loads fails on these;
                    # parse the form fields to extract the persisted doc_id and
                    # the variable shape so the GraphQL surface isn't invisible.
                    if isinstance(body, bytes):
                        body = body.decode("utf-8", "replace")
                    if (
                        "doc_id=" in body
                        or "query_hash=" in body
                        or ("variables=" in body and "graphql" in live_url.lower())
                    ):
                        try:
                            form = dict(up.parse_qsl(body))
                            doc_id = form.get("doc_id") or form.get("query_hash")
                            variables_raw = form.get("variables")
                            vobj = json.loads(variables_raw) if variables_raw else None
                            op_name = form.get("operationName") or form.get(
                                "fb_api_req_friendly_name"
                            )
                            request_template = {
                                key: form[key]
                                for key in ("fb_api_req_friendly_name", "operationName")
                                if form.get(key)
                            }
                            if doc_id:
                                names.add(doc_id)
                            ops = [
                                {
                                    "operationName": op_name,
                                    "variables_keys": sorted(vobj.keys())
                                    if isinstance(vobj, dict)
                                    else None,
                                    "variables_shape": shape(vobj) if vobj else None,
                                    "persistedHash": doc_id,
                                    "semantic_kind": "unknown",
                                    "protocol": "graphql-meta-doc-id",
                                    "request_template": request_template,
                                    "query": "",
                                }
                            ]
                            rec["graphql"] = ops
                            path = up.urlparse(url).path
                            gql_endpoints.setdefault(path, {"count": 0})["count"] += 1
                        except Exception as exc:
                            record_failure("graphql-form", "parse", exc, context=url)
            # GraphQL-over-HTTP also permits a raw document body and GET query-string
            # envelopes. Preserve those transports instead of treating JSON POST as the
            # only valid shape.
            content_type = req.headers.get("content-type", "").split(";", 1)[0].lower()
            if "graphql" not in rec and body and content_type == "application/graphql":
                names.update(gql_names(body))
                rec["graphql"] = graphql_entries({"query": body}, live_url, content_type)
                path = up.urlparse(url).path
                gql_endpoints.setdefault(path, {"count": 0})["count"] += 1
            if "graphql" not in rec and req.method.upper() == "GET":
                query_fields = up.parse_qs(up.urlparse(live_url).query)
                query_text = query_fields.get("query", [None])[0]
                if query_text:
                    envelope = {
                        "query": query_text,
                        "operationName": query_fields.get("operationName", [None])[0],
                    }
                    for key in ("variables", "extensions"):
                        raw_value = query_fields.get(key, [None])[0]
                        if raw_value:
                            try:
                                envelope[key] = json.loads(raw_value)
                            except Exception as exc:
                                record_failure("graphql-get-envelope", "parse", exc, context=url)
                    names.update(gql_names(query_text))
                    rec["graphql"] = graphql_entries(envelope, live_url, content_type)
                    path = up.urlparse(url).path
                    gql_endpoints.setdefault(path, {"count": 0})["count"] += 1
            # Path-style GraphQL (e.g. X: GET /i/api/graphql/<queryId>/<OpName>?variables=..;
            # POST bodies with {queryId,variables} but no "query"/"operationName" key).
            path_operation = persisted_path(url)
            if "graphql" not in rec and path_operation:
                segs = [s for s in up.urlparse(url).path.split("/") if s]
                qid, opname = path_operation
                vobj = None
                request_template = {}
                if body:
                    try:
                        jb = json.loads(body)
                        vobj = jb.get("variables")
                        qid = jb.get("queryId") or qid
                        request_template.update(
                            {
                                key: jb[key]
                                for key in ("features", "fieldToggles")
                                if isinstance(jb.get(key), dict)
                            }
                        )
                    except Exception as exc:
                        record_failure("graphql-path-body", "parse", exc, context=url)
                if vobj is None:
                    query_fields = up.parse_qs(up.urlparse(live_url).query)
                    qv = query_fields.get("variables", [None])[0]
                    if qv:
                        try:
                            vobj = json.loads(qv)
                        except Exception as exc:
                            record_failure("graphql-query-variables", "parse", exc, context=url)
                    for key in ("features", "fieldToggles"):
                        raw_template = query_fields.get(key, [None])[0]
                        if raw_template:
                            try:
                                parsed_template = json.loads(raw_template)
                                if isinstance(parsed_template, dict):
                                    request_template[key] = parsed_template
                            except Exception as exc:
                                record_failure(
                                    "graphql-request-template", "parse", exc, context=url
                                )
                if opname:
                    names.add(opname)
                    rec["graphql"] = [
                        {
                            "operationName": opname,
                            "variables_keys": sorted(vobj.keys())
                            if isinstance(vobj, dict)
                            else None,
                            "variables_shape": shape(vobj) if vobj else None,
                            "persistedHash": qid,
                            "semantic_kind": "unknown",
                            "protocol": "graphql-x-persisted",
                            "request_template": request_template,
                            "query": "",
                        }
                    ]
                    norm = "/" + "/".join(segs[:-2]) if len(segs) >= 2 else up.urlparse(url).path
                    gql_endpoints.setdefault(norm, {"count": 0})["count"] += 1
            if a.recover_persisted and rec.get("graphql"):
                try:
                    hashes = [
                        o["persistedHash"]
                        for o in rec["graphql"]
                        if o.get("protocol") == "graphql-apq" and o.get("persistedHash")
                    ]
                    candidates = req.frame.evaluate(RECOVERY_READ_SCRIPT, hashes)
                    documents = {c["hash"]: c.get("document") for c in candidates}
                    rec["graphql"] = [
                        bind_document(
                            o,
                            documents.get(o.get("persistedHash")),
                            source_url=req.frame.url,
                            observed_at=datetime.now(UTC).isoformat(),
                        )
                        for o in rec["graphql"]
                    ]
                except Exception as exc:
                    record_failure("persisted-recovery", "browser", exc, context=url)
            if resp.status < 400 and resp.status != 204:
                try:
                    # GraphQL is sometimes JSON served as text/plain. Transport evidence,
                    # not MIME alone, authorizes parsing; keep only bounded structural data.
                    decoded = response_payload(
                        resp, a.body_max_bytes, graphql=bool(rec.get("graphql"))
                    )
                    response_value = decoded.value if decoded is not None else None
                    if decoded is not None:
                        rec["response_packaging"] = list(decoded.layers)
                        rec["resp_shape"] = shape(response_value)
                    if rec.get("graphql"):
                        rec["graphql_response_success"] = graphql_response_success(
                            response_value, rec["graphql"]
                        )
                        for operation in rec["graphql"]:
                            evidence = (operation.get("request_template") or {}).get(
                                "document_evidence"
                            )
                            if evidence:
                                evidence["observed_response_success"] = rec[
                                    "graphql_response_success"
                                ]
                except Exception as exc:
                    record_failure("response-body", "body-decode", exc, context=url)
            rec["response_kind"] = classify_media(
                rec.get("resp_ct"),
                rec.get("rtype"),
                graphql="graphql" in rec,
            ).value
            if jf.closed:
                return  # A browser callback may have been pending when shutdown began.
            jf.write(json.dumps(rec) + "\n")
            jf.flush()
            stats["n"] += 1
            mark_api_response()
        except Exception as exc:
            record_failure(
                "response-handler",
                "browser",
                exc,
                context=safe_url(getattr(resp, "url", "")),
                partial=True,
            )

    traffic.on("response", on_response)
    if not a.cdp_endpoint:
        page = ctx.new_page()
    last_auth = {}  # keep live auth header VALUES in memory for introspection (never persisted)

    def track_auth(req):
        if _first_party(req.url):
            found = False
            for h in req.headers:
                if is_auth(h):
                    found = True
                    fingerprint = hashlib.sha256(str(req.headers[h]).encode()).hexdigest()
                    if credential_fingerprints.get(h) != fingerprint:
                        credential_observations.append(
                            {
                                "credential_name": h,
                                "interaction_id": stats.get("interaction_id"),
                                "surface": safe_url(getattr(page, "url", "")),
                                "event": (
                                    "observed" if h not in credential_fingerprints else "rotated"
                                ),
                            }
                        )
                        credential_fingerprints[h] = fingerprint
                    last_auth[h] = req.headers[h]
            if found:
                last_auth["_endpoint"] = req.url.split("?")[0]

    page.on("request", track_auth)

    # ---- WebSocket capture (socket.io / raw ws) --------------------------------
    # capture.py's on_response records XHR/fetch only; socket.io apps (chat/
    # realtime products) put most of their surface on the websocket. We catalog frames
    # SHAPE-ONLY, exactly like the REST/GraphQL path: event names + arg *shapes*,
    # never payload values — so chat/message content is never persisted. Engine.IO
    # ping/pong heartbeats are dropped as noise; the OPEN handshake yields the
    # protocol version. Event names are the key prize: socket.io event names are
    # often computed at runtime and can't be mined statically from bundles.
    def _ws_key(u):
        pr = up.urlparse(u)
        # Engine.IO version and transport are protocol identity. Session IDs and
        # application query values are volatile/secret-bearing and never persist.
        safe_protocol_query = [
            (key, value)
            for key, value in up.parse_qsl(pr.query)
            if key.lower() in {"eio", "transport", "b64"}
        ]
        query = up.urlencode(safe_protocol_query)
        return f"{pr.scheme}://{pr.netloc}{pr.path}{'?' + query if query else ''}"

    def _ws_entry(key):
        return ws_catalog.setdefault(
            key,
            {
                "engineio": None,
                "frames": 0,
                "binary_frames": 0,
                "events_sent": {},
                "events_received": {},
                "non_socketio": {"sent": 0, "received": 0},
            },
        )

    MAX_WS_EVENTS = 300

    def on_ws_frame(url, direction, payload):
        try:
            entry = _ws_entry(_ws_key(url))
            entry["frames"] += 1
            if isinstance(payload, bytes):
                entry["binary_frames"] += 1
                return
            if not isinstance(payload, str) or not payload:
                return
            c0 = payload[0]
            if c0 in ("2", "3"):  # Engine.IO ping / pong heartbeats — noise
                return
            if c0 == "0":  # Engine.IO OPEN handshake ({sid,pingInterval,…})
                try:
                    h = json.loads(payload[1:])
                    if isinstance(h, dict) and "sid" in h:
                        entry["engineio"] = "4" if "maxPayload" in h else "3"
                except Exception:
                    pass
                return
            pkt = parse_socketio(payload)
            if not pkt:  # raw (non-socket.io) ws text frame
                entry["non_socketio"]["sent" if direction == "sent" else "received"] += 1
                return
            if pkt["event"]:
                evmap = entry["events_sent"] if direction == "sent" else entry["events_received"]
                if pkt["event"] not in evmap and len(evmap) >= MAX_WS_EVENTS:
                    return
                ev = evmap.setdefault(
                    pkt["event"], {"count": 0, "arg_shape": None, "ns": pkt["ns"]}
                )
                ev["count"] += 1
                sh = shape(pkt["args"])  # types/keys only — no values
                if _shape_weight(sh) > _shape_weight(ev["arg_shape"]):
                    ev["arg_shape"] = sh
        except Exception as exc:
            record_failure("websocket-frame", "parse", exc, context=safe_url(url))

    def on_websocket(ws):
        try:
            if not _first_party(ws.url):
                return
            _ws_entry(_ws_key(ws.url))  # register even if no frames observed
            ws.on("framesent", lambda p: on_ws_frame(ws.url, "sent", p))
            ws.on("framereceived", lambda p: on_ws_frame(ws.url, "received", p))
            print(f"[ws] open {_ws_key(ws.url)}", flush=True)
        except Exception as exc:
            record_failure(
                "websocket-open", "browser", exc, context=safe_url(getattr(ws, "url", ""))
            )

    page.on("websocket", on_websocket)

    def log(msg):
        print(safe_text(msg), flush=True)

    def cf_blocked():
        try:
            t = page.title() or ""
            return bool(CF_MARKERS.search(t)) or bool(CF_MARKERS.search(page.content()[:4000]))
        except Exception:
            return False

    def visit(url, wait=3.5):
        interaction = begin_interaction("navigation", url)

        def _settle(label):
            outcome = settle_or_wait(
                page,
                stats,
                wait,
                no_settle=a.no_settle,
                min_ms=a.settle_min_ms,
                settle_ms=a.settle_ms,
                ceiling_ms=a.settle_timeout_ms,
                log=log,
                label=label,
                url=url,
            )
            if outcome:
                elapsed, calls, settled = outcome
                interaction.update(
                    {
                        "settle_seconds": elapsed,
                        "calls": calls,
                        "settled": settled,
                        "settle_ceiling_ms": a.settle_timeout_ms
                        or int(wait * 1000 * SETTLE_CEILING_FACTOR),
                        "quiet_threshold_ms": stats.get("effective_settle_ms", a.settle_ms),
                        "burst_gaps_ms": [
                            round(value, 3) for value in stats.get("burst_gaps_ms", [])
                        ],
                        "truncation_reason": None if settled else "settle_ceiling",
                    }
                )
                if not settled:
                    SHAPE_TRUNCATIONS["settle_ceiling"] = (
                        SHAPE_TRUNCATIONS.get("settle_ceiling", 0) + 1
                    )

        try:
            url = validate_url(url, {base}, schemes=("https", "http"), resolve=True)
            page.goto(url, wait_until="domcontentloaded")
            _settle("visit")
            if cf_blocked() and a.byparr and not a.cdp_endpoint:
                log(f"[cf] challenge on {url} -> byparr")
                events["cf"].append(url)
                try:
                    sol = byparr_solve(a.byparr, url).get("solution") or {}
                    cks = [
                        c
                        for c in challenge_cookies(sol, base)
                        if c["name"] in ("cf_clearance", "__cf_bm")
                    ]
                    if cks:
                        ctx.add_cookies(cks)
                        solver_agent = str(sol.get("userAgent") or "")
                        if solver_agent:
                            # Clearance is bound to the agent that solved it.
                            page.set_extra_http_headers({"User-Agent": solver_agent})
                        events["byparr"].append(
                            {
                                "url": url,
                                "injected": [c["name"] for c in cks],
                                "user_agent_aligned": bool(solver_agent),
                            }
                        )
                        page.goto(url, wait_until="domcontentloaded")
                        _settle("byparr-retry")
                        log(f"[byparr] injected {[c['name'] for c in cks]}, retried")
                except Exception as e:
                    record_failure("challenge", "challenge", e, context=url, partial=True)
                    log(f"[byparr-ERR] {safe_text(e)}")
            if cf_blocked():
                raise RuntimeError("challenge_unresolved after browser/Byparr flow")
            if page.url and not _first_party(page.url):
                raise ValueError("navigation redirected outside the allowed origin set")
            log(f"[visit] {url} -> {page.url.split('?')[0]} | {(page.title() or '')[:60]}")
            interaction["completed_at"] = datetime.now(UTC).isoformat()
            return page.url
        except Exception as e:
            record_failure(
                "navigation",
                browser_failure_category(e),
                e,
                context=safe_url(url),
                partial=True,
            )
            interaction["completed_at"] = datetime.now(UTC).isoformat()
            interaction["failure"] = failure_evidence("navigation", "browser", e)
            log(f"[visit-ERR] {url.split('?')[0]} :: {safe_text(e)}")
            return None
        finally:
            stats["interaction_id"] = None

    # ---- run surfaces (recipe or seeds) ----
    # recipe was already loaded up-front (see auth-matcher setup above).
    surfaces = (
        list(getattr(recipe, "SURFACES", [])) if recipe and not a.skip_recipe_surfaces else []
    )
    surfaces += [s for s in a.seeds.split(",") if s.strip()]
    surfaces += list(a.seed)

    def flush_meta():
        """Persist meta/names/auth from current in-memory state. Idempotent; runs at
        normal end, on SIGTERM/SIGINT, and via atexit — so a killed run is salvageable
        (capture.jsonl is already flushed incrementally)."""
        try:
            jf.flush()
        except Exception:
            pass
        atomic_write_text(os.path.join(a.outdir, "graphql-names.txt"), "\n".join(sorted(names)))
        atomic_write_json(
            os.path.join(a.outdir, "meta.json"),
            {
                "base_domain": base,
                "egress_policy": egress,
                "graphql_endpoints": gql_endpoints,
                "auth_headers": auth_seen,
                "events": events,
                "websockets": ws_catalog,
                "service_workers": sorted(url for url in service_workers if url),
                "offline_queues": offline_queues,
                "request_budgets": {
                    "limits": {
                        "total": a.max_total_requests,
                        "per_origin": a.max_origin_requests,
                        "per_operation": a.max_operation_requests,
                        "rate_limit_reserve": a.rate_limit_reserve,
                    },
                    "used": {
                        "total": budget_state["total"],
                        "origins": budget_state["origins"],
                        "operations": budget_state["operations"],
                    },
                    "truncations": budget_state["truncations"][:1000],
                    "truncation_count": budget_state["truncation_count"],
                    "rate_limits": budget_state["rate_limits"],
                },
                "surfaces": surfaces,
                "records": stats["n"],
                "persisted_recovery": {
                    "enabled": a.recover_persisted,
                    "method": "browser-webcrypto-sha256",
                    "relay_scripts": relay_catalog.scripts,
                    "relay_artifacts": relay_catalog.count,
                    "relay_budget_exhausted": relay_catalog.exhausted,
                },
                # Inventory of what the client declares, which is a superset of what a
                # read-only walk can trigger. Never an authorization to execute.
                "declared_operations": relay_catalog.declared_operations(),
                "client_credentials": credential_sites,
                "truncations": dict(SHAPE_TRUNCATIONS),
                "failures": failures,
                "failure_summary": summarize_failures(failures),
                "interactions": interactions,
                "authentication": {
                    "public_identifier_names": sorted(
                        name
                        for name in auth_seen
                        if re.search(
                            r"client-(?:name|version)|accept-language|app[-_]?id", name, re.I
                        )
                    ),
                    "secret_credential_names": sorted(
                        name
                        for name in auth_seen
                        if not re.search(
                            r"client-(?:name|version)|accept-language|app[-_]?id", name, re.I
                        )
                    ),
                    "observations": credential_observations,
                },
                "run_id": run_state["run_id"],
                "started_at": run_state["started_at"],
                "completed_at": run_state["completed_at"],
                "captured_at": run_state["completed_at"],
                "partial": run_state["partial"],
                "proxy_interception": bool(a.proxy),
                "tls_verification": "intercepted" if a.proxy else "strict",
            },
        )
        # live auth header VALUES for the on-host schema-recovery step ONLY.
        # Stays on the (tmpfs) capture host; the orchestrator never pulls this file.
        if last_auth:
            ap_ = os.path.join(a.outdir, "auth.headers.json")
            atomic_write_json(ap_, {k: v for k, v in last_auth.items()}, mode=0o600)
        # ponytail: a normal run hashes capture.jsonl twice — once here, once when
        # atexit re-runs this function with nothing left to change. Measured on this
        # box: 0.02 ms for a 34 KiB capture, 3.3 ms for a full-budget 5.7 MiB one
        # (4000 records), 16.5 ms at a 28 MiB pathological size, against a browser
        # session measured in tens of seconds. Skipping the second pass needs a
        # "nothing changed" flag, and that flag can only be wrong in the direction
        # that ships a stale checksum after an unclean exit -- so the cost stays.
        # Ceiling: it stays linear in capture size. Upgrade path: hash the writes as
        # they happen (a running digest per artifact) if that ever costs real time.
        checksums = {}
        for artifact_name in ("capture.jsonl", "meta.json", "graphql-names.txt"):
            artifact_path = os.path.join(a.outdir, artifact_name)
            digest = hashlib.sha256()
            with open(artifact_path, "rb") as artifact_handle:
                for chunk in iter(lambda: artifact_handle.read(65_536), b""):
                    digest.update(chunk)
            checksums[artifact_name] = digest.hexdigest()
        atomic_write_json(
            os.path.join(a.outdir, "transfer-manifest.json"),
            {"run_id": run_state["run_id"], "sha256": checksums},
        )

    def _on_term(signum, _frame):
        # Parent sends SIGTERM on timeout; flush everything then exit before SIGKILL.
        log(f"[signal] {signum} received — flushing artifacts and exiting")
        run_state["partial"] = True
        run_state["completed_at"] = datetime.now(UTC).isoformat()
        record_failure("capture", "cancellation", RuntimeError(f"signal {signum}"), partial=True)
        try:
            traffic.remove_listener("response", on_response)
        except Exception:
            pass  # A closing browser must not prevent partial-artifact flushing.
        flush_meta()
        try:
            jf.close()
        except Exception:
            pass
        try:
            ctx.close()  # best-effort HAR flush so --openapi still works
        except Exception:
            pass
        os._exit(0)

    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    atexit.register(flush_meta)

    # Links are harvested from every surface, not only whichever page happened to be
    # current after the last seed, so each seed contributes crawl candidates.
    crawl_candidates: list[str] = []
    for u in surfaces:
        landed = visit(u, 4.0)
        if a.crawl and landed:
            try:
                crawl_candidates += page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)"
                )
            except Exception as e:
                record_failure("crawl", "browser", e, context=safe_url(u))

    # recipe custom driving (search filters, pagers, settings nav)
    if recipe and hasattr(recipe, "drive"):
        active_action: list[dict | None] = [None]

        def finish_action() -> None:
            interaction = active_action[0]
            if interaction is not None:
                settled = interaction.get("settled", True)
                interaction.update(
                    {
                        "calls": stats["n"] - interaction["calls_before"],
                        "settled": settled,
                        "completed_at": datetime.now(UTC).isoformat(),
                        "truncation_reason": None if settled else "settle_ceiling",
                    }
                )

        def start_action(kind, annotation) -> None:
            finish_action()
            active_action[0] = begin_interaction(kind, getattr(page, "url", ""), str(annotation))

        try:
            strict_recipe_egress[0] = True
            if getattr(recipe, "declarative", False):

                def settle_action(kind: str) -> None:
                    outcome = settle_or_wait(
                        page,
                        stats,
                        3.0,
                        no_settle=a.no_settle,
                        min_ms=a.settle_min_ms,
                        settle_ms=a.settle_ms,
                        ceiling_ms=a.settle_timeout_ms,
                        log=log,
                        label=f"action:{kind}",
                        url=safe_url(getattr(page, "url", "")),
                    )
                    interaction = active_action[0]
                    if outcome and interaction is not None:
                        interaction["settle_seconds"] = outcome[0]
                        interaction["settled"] = outcome[2]

                recipe.drive(page, log, start_action, settle=settle_action)
            elif getattr(recipe, "sandboxed", False):
                recipe.drive(
                    page,
                    log,
                    validate_navigation=lambda url: validate_url(
                        url,
                        {base},
                        schemes=("https", "http", "wss", "ws"),
                        resolve=True,
                    ),
                    interaction=start_action,
                )
            else:
                recipe.drive(page, log)
            if page.url and not _first_party(page.url):
                raise ValueError("recipe action navigated outside the allowed origin set")
        except Exception as e:
            record_failure("recipe-drive", "recipe", e, partial=True)
            log(f"[drive-ERR] {safe_text(e)}")
        finally:
            strict_recipe_egress[0] = False
            finish_action()
            stats["interaction_id"] = None

    # optional shallow same-origin crawl — after drive(), so recipe actions start on
    # the seed page instead of whichever link the crawl happened to visit last
    if a.crawl and crawl_candidates:
        seen = set(surfaces)
        crawled = 0
        for h in crawl_candidates:
            if crawled >= a.crawl:
                break
            h = h.split("#", 1)[0]
            if _first_party(h) and h not in seen and up.urlparse(h).path not in ("", "/"):
                seen.add(h)
                crawled += 1
                visit(h, 3.0)

    # ---- active probing: fire recipe-declared endpoints through the page's own
    #      fetch() context, using session headers harvested from the SPA's XHRs.
    #      This is the atomic mint-and-fire pattern for targets where the SPA
    #      mints its own session token client-side (x-api-key, anonymous bearer,
    #      CSRF token, etc.) that curl_cffi/ctx.request can't reproduce. The
    #      page's fetch inherits the SPA's cookies, sensor state, and Akamai/
    #      CF validation — so our probes look identical to the SPA's own XHRs.
    #      E.g. a site whose SPA mints x-api-key on load: passive capture caught
    #      0 endpoints (the CDN walled the SPA's XHRs after the first run), but
    #      active probing through page.evaluate(fetch) got 9/9 at 200.
    probes = list(getattr(recipe, "ACTIVE_PROBES", [])) if recipe else []
    if probes:
        log(f"[active] firing {len(probes)} recipe-declared probes via page.evaluate(fetch)…")
        # harvest session headers from auth_seen (populated by on_response)
        # + any the SPA put on its requests that we captured
        sess_hdrs = {}
        for h in auth_seen:
            sess_hdrs[h] = "<present>"  # we don't have values (shapes-only capture)
        # the recipe can also declare SESS_HEADERS with literal values, or a
        # SESS_HEADER_HARVEST regex to extract them from the page's JS state
        if hasattr(recipe, "SESS_HEADERS"):
            for k, v in (recipe.SESS_HEADERS or {}).items():
                sess_hdrs[k] = v
        # harvest from the page's runtime: if the recipe declares
        # SESS_HEADER_HARVEST = {"x-api-key": "localStorage.getItem('apiKey')"}
        # we evaluate each expression in the page context to get the live value
        harvest = getattr(recipe, "SESS_HEADER_HARVEST", None) or {}
        for hdr, js_expr in harvest.items():
            try:
                val = page.evaluate(f"() => {js_expr}")
                if val:
                    sess_hdrs[hdr] = val
                    log(f"[active] harvested {hdr} from page runtime (present=true)")
            except Exception as exc:
                record_failure("auth-harvest", "auth", exc, context=hdr)
        # also harvest from captured request headers (track_auth stores values)
        for h, v in last_auth.items():
            if not h.startswith("_") and h not in sess_hdrs:
                sess_hdrs[h] = v
        # Page-context headers some APIs validate (x-referer, x-page-unique-id) are
        # only added when the recipe asks for them; sending them unconditionally made
        # every probe distinguishable from the SPA's own traffic on most sites.
        if getattr(recipe, "PAGE_CONTEXT_HEADERS", False):
            import base64 as _b64

            try:
                cur_url = page.url
                sess_hdrs.setdefault("x-referer", cur_url)
                sess_hdrs.setdefault("x-page-unique-id", _b64.b64encode(cur_url.encode()).decode())
            except Exception:
                pass

        for probe in probes:
            method = probe.get("method", "GET")
            url = validate_url(probe["url"], {base}, schemes=("https", "http"), resolve=True)
            body = probe.get("body")
            interaction = begin_interaction(
                "probe",
                url,
                str(probe.get("safe_annotation") or "recipe-declared read-only probe"),
            )
            hdrs = dict(sess_hdrs)
            hdrs["accept"] = "application/json, text/plain, */*"
            if getattr(recipe, "PAGE_CONTEXT_HEADERS", False):
                hdrs["x-api-correlation-id"] = __import__("uuid").uuid4().hex
            if method == "POST" and body:
                hdrs["content-type"] = "application/json"
            fetch_opts = {"method": method, "headers": hdrs}
            fetch_opts["redirect"] = "manual"
            if body:
                fetch_opts["body"] = json.dumps(body)
            try:
                result = page.evaluate(
                    """async (args) => {
                    const r = await fetch(args.url, args.opts);
                    const ct = r.headers.get('content-type') || '';
                    let body; try { body = ct.includes('json') ? await r.json() : await r.text(); } catch { body = null; }
                    return { status: r.status, ct: ct, body: body };
                }""",
                    {"url": url, "opts": fetch_opts},
                )
                status = result["status"]
                # record as a synthetic capture record (same shape as on_response)
                rec = {
                    "method": method,
                    "url": url,
                    "status": status,
                    "rtype": "fetch",
                    "resp_ct": result.get("ct", ""),
                    "_active_probe": True,
                    "interaction_id": interaction["id"],
                }
                hdrs_redacted = {}
                for h in hdrs:
                    if is_auth(h):
                        hdrs_redacted[h] = "<present>"
                if hdrs_redacted:
                    rec["req_headers"] = hdrs_redacted
                if body is not None:
                    rec.update(
                        request_metadata(
                            json.dumps(body),
                            "application/json",
                            max_body_bytes=a.body_max_bytes,
                            shape_counters=SHAPE_TRUNCATIONS,
                            shape_limits=SHAPE_LIMITS,
                        )
                    )
                rs = result.get("body")
                if isinstance(rs, (dict, list)):
                    rec["resp_shape"] = shape(rs)
                rec["response_kind"] = classify_media(
                    rec.get("resp_ct"), rec.get("rtype"), graphql="graphql" in rec
                ).value
                jf.write(json.dumps(rec) + "\n")
                jf.flush()
                stats["n"] += 1
                mark_api_response()
                interaction.update(
                    {
                        "calls": stats["n"] - interaction["calls_before"],
                        "settled": True,
                        "truncation_reason": None,
                    }
                )
                ok = "✓" if status == 200 else "✗"
                p = up.urlparse(url).path
                log(f"  {ok} {status} {method:4} {p[:55]}")
            except Exception as e:
                record_failure("active-probe", "transport", e, context=safe_url(url), partial=True)
                log(
                    f"  ✗ active-probe ERR {method} {up.urlparse(url).path[:55]}: {safe_text(e)[:60]}"
                )
            finally:
                interaction["completed_at"] = datetime.now(UTC).isoformat()
                stats["interaction_id"] = None

    # ---- GraphQL introspection attempt (read-only), reusing captured auth ----
    if a.introspect and last_auth.get("_endpoint"):
        endpoint = last_auth["_endpoint"]
        hdrs = {k: v for k, v in last_auth.items() if not k.startswith("_")}
        hdrs["content-type"] = "application/json"
        iq = {
            "query": "query IntrospectionQuery { __schema { queryType { name } types { name kind } } }"
        }
        try:
            r = ctx.request.post(
                endpoint + "?alias=introspection",
                headers=hdrs,
                data=json.dumps(iq),
                max_redirects=0,
            )
            status = r.status
            try:
                j = r.json()
            except Exception:
                j = None
            if isinstance(j, dict):
                enabled = bool((j.get("data") or {}).get("__schema"))
                ntypes = len(((j.get("data") or {}).get("__schema") or {}).get("types", []))
                err = (j.get("errors") or [{}])[0].get("message") if j.get("errors") else None
            else:
                enabled, ntypes, err = False, 0, (r.text() or "")[:160]
            events["introspection"] = {
                "endpoint": endpoint,
                "status": status,
                "enabled": enabled,
                "types": ntypes,
                "error": err,
            }
            log(
                f"[introspect] {up.urlparse(endpoint).path} status={status} enabled={enabled} types={ntypes} err={safe_text(err)[:80]}"
            )
        except Exception as e:
            record_failure("introspection", "schema", e, context=safe_url(endpoint))
            events["introspection"] = {
                "endpoint": endpoint,
                "enabled": False,
                "error": safe_text(e),
            }
            log(f"[introspect-ERR] {safe_text(e)}")

    # ---- write artifacts (final; flush_meta also runs on signal/atexit) ----
    try:
        queue_counts = page.evaluate(
            """async () => {
              const queueLike = /queue|outbox|offline|pending|sync/i;
              const local = Object.keys(localStorage).filter(k => queueLike.test(k)).length;
              const session = Object.keys(sessionStorage).filter(k => queueLike.test(k)).length;
              let indexed = 0;
              if (indexedDB.databases) {
                indexed = (await indexedDB.databases()).filter(d => queueLike.test(d.name || '')).length;
              }
              return {localStorage: local, sessionStorage: session, indexedDB: indexed};
            }"""
        )
        if isinstance(queue_counts, dict):
            offline_queues.extend(
                {"kind": kind, "count": int(count)}
                for kind, count in queue_counts.items()
                if isinstance(count, (int, float)) and count > 0
            )
    except Exception as exc:
        record_failure("offline-queue", "browser", exc)
    run_state["completed_at"] = datetime.now(UTC).isoformat()
    try:
        traffic.remove_listener("response", on_response)
    except Exception:
        pass
    flush_meta()
    try:
        jf.close()
    except Exception:
        pass
    ws_events = sum(len(e["events_sent"]) + len(e["events_received"]) for e in ws_catalog.values())
    log(
        f"[done] {stats['n']} calls, {len(names)} gql names, endpoints={list(gql_endpoints)}, "
        f"ws={len(ws_catalog)} socket(s)/{ws_events} events"
    )
    ctx.close()
    if a.recover_persisted:
        relay_catalog.enrich_capture(os.path.join(a.outdir, "capture.jsonl"))
        flush_meta()  # Recompute transfer checksums after metadata enrichment.


if __name__ == "__main__":
    main()
