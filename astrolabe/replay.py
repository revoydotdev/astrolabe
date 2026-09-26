#!/usr/bin/env python3
"""astrolabe replay tier — browserless, TLS-matched high-frequency op replay.

Replays a GraphQL/REST operation with curl_cffi impersonating a real Chrome
(JA3/HTTP2 match → Cloudflare accepts it, unlike Burp/Java), reusing session
cookies plus a pre-made, scoped auth-header credential bundle (see
astrolabe.credentials for the schema). For param enumeration and high-frequency
monitoring without a browser per request.

Runs on the capture host (residential egress, curl_cffi present). Stdlib + curl_cffi.
Site-agnostic: every request-shaping detail (endpoint, auth headers, whether the URL
carries an alias query param) comes from the op-file / auth map, not a hardcoded site.

op-file JSON:
  { "alias": "userJobSearch",
    "endpoint": "https://www.example.com/api/graphql/v1",
    "query": "query ...",
    "variables": { ...template... },
    "extract": "data.search.field.total",
    "alias_param": true }

  `endpoint` is required — there is no default, since defaulting to any one site's
  API would make this a single-site tool. `alias_param` is optional (default false);
  when true AND the endpoint doesn't already carry a query string, `?alias=<alias>`
  is appended — some sites use the alias to route/log the op server-side; most
  don't need it.
"""

from __future__ import annotations
import argparse
import json
import os
import time
import urllib.parse as up
from curl_cffi import requests

try:
    from astrolabe.credentials import generations_match, unwrap_cookies, unwrap_credentials
    from astrolabe.security import atomic_write_json, safe_text, validate_url
except ImportError:
    from credentials import (  # type: ignore[import-not-found,no-redef]
        generations_match,
        unwrap_cookies,
        unwrap_credentials,
    )
    from security import (  # type: ignore[import-not-found,no-redef]
        atomic_write_json,
        safe_text,
        validate_url,
    )

# Hop-by-hop / connection-management header names (RFC 7230 §6.1, plus a couple
# curl_cffi/requests manage themselves) that must never be forwarded verbatim from
# a harvested auth map — the auth map is a dict of real request headers as recorded
# in the credential bundle, and forwarding these would either be ignored, wrong
# (stale content-length), or fought over with the HTTP client itself.
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "host",
    }
)


def dget(obj, path):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except Exception:
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def dset(obj, path, val):
    parts = path.split(".")
    cur = obj
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = val


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cookies", required=True)
    ap.add_argument(
        "--auth",
        required=True,
        help="auth.map.json credential bundle (pre-made; see astrolabe.credentials)",
    )
    ap.add_argument("--op-file", required=True)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--vary", default="", help="dotpath=v1,v2,... sweep over a variable")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument(
        "--interval", type=float, default=0.0, help="seconds between calls (rate limit)"
    )
    ap.add_argument("--impersonate", default="chrome")
    a = ap.parse_args()

    op = json.load(open(a.op_file))
    auth_generation, auth_map = unwrap_credentials(json.load(open(a.auth)))
    auth = auth_map.get(op["alias"])
    if not auth:
        raise SystemExit("no scoped bearer; NO_CREDENTIAL_FOR_OPERATION: " + op["alias"])
    endpoint = op.get("endpoint")
    if not endpoint:
        raise SystemExit(
            "op-file missing required 'endpoint' — astrolabe is site-agnostic, so there is "
            "no default GraphQL endpoint to fall back to"
        )
    endpoint_host = op.get("base_domain") or up.urlparse(endpoint).hostname
    if not isinstance(endpoint_host, str):
        raise SystemExit("op-file endpoint has no valid host")
    endpoint = validate_url(endpoint, {endpoint_host})
    url = endpoint
    if op.get("alias_param") and "?" not in endpoint:
        url = f"{endpoint}?alias={op['alias']}"

    cookie_generation, cookies = unwrap_cookies(json.load(open(a.cookies)))
    if not generations_match(auth_generation, cookie_generation):
        raise SystemExit("AUTH_GENERATION_MISMATCH: credentials and cookies are not coherent")
    s = requests.Session(impersonate=a.impersonate)
    for c in cookies:
        try:
            s.cookies.set(c["name"], c["value"], domain=c["domain"], path=c.get("path", "/"))
        except Exception:
            pass
    # Forward whatever real headers the credential bundle records for this alias
    # (already a dict of real header:value pairs — site-specific names and all),
    # minus hop-by-hop headers. Generic client-identification defaults fill in only
    # when the harvested set didn't already supply them.
    headers = {k: v for k, v in auth.items() if k.lower() not in HOP_BY_HOP}
    headers.setdefault("x-requested-with", "XMLHttpRequest")
    headers.setdefault("content-type", "application/json")

    # build the value matrix
    if a.vary:
        vpath, vals = a.vary.split("=", 1)
        matrix = [(vpath, v) for v in vals.split(",")]
    else:
        matrix = [(None, None)] * a.repeat

    results, t0 = [], time.time()
    for i, (vpath, v) in enumerate(matrix):
        variables = json.loads(json.dumps(op.get("variables", {})))  # deep copy
        if vpath:
            dset(variables, vpath, v)
        t = time.time()
        try:
            r = s.post(
                url,
                headers=headers,
                data=json.dumps({"query": op["query"], "variables": variables}),
                timeout=30,
            )
            dt = round((time.time() - t) * 1000)
            try:
                j = r.json()
            except Exception:
                j = None
            extracted = dget(j, op["extract"]) if (j and "extract" in op) else None
            err = (
                (j.get("errors") or [{}])[0].get("message")
                if isinstance(j, dict) and j.get("errors")
                else None
            )
            err = safe_text(err) if err else None
            rec = {
                "i": i,
                "vary": v,
                "status": r.status_code,
                "ms": dt,
                "extracted": extracted,
                "error": err,
            }
        except Exception as e:
            rec = {"i": i, "vary": v, "status": None, "error": safe_text(e)}
        results.append(rec)
        print(
            f"  [{i:>3}] {str(v):>16}  HTTP {rec.get('status')}  {rec.get('ms', '')}ms  "
            f"{op.get('extract', '').split('.')[-1]}={rec.get('extracted')}"
            + (f"  ERR {rec['error'][:60]}" if rec.get("error") else ""),
            flush=True,
        )
        if a.interval:
            time.sleep(a.interval)

    elapsed = round(time.time() - t0, 2)
    ok = sum(1 for r in results if r.get("status") == 200 and not r.get("error"))
    out = {
        "op": op["alias"],
        "count": len(results),
        "ok": ok,
        "elapsed_s": elapsed,
        "rate_per_s": round(len(results) / elapsed, 1) if elapsed else None,
        "results": results,
    }
    p = os.path.join(a.outdir, "replay.json")
    atomic_write_json(p, out)
    print(
        f"[replay] {ok}/{len(results)} ok in {elapsed}s ({out['rate_per_s']}/s) -> {p}", flush=True
    )


if __name__ == "__main__":
    main()
