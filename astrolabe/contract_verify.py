#!/usr/bin/env python3
"""Active contract verification — prove astrolabe can EXECUTE each op itself.

Warm a persistent logged-in CloakBrowser context, capture each op's real request,
then RE-EXECUTE it in-context (page.evaluate fetch — validated across multiple
authenticated GraphQL sites) and record status + conformance. Writes verify.json
for `astrolabe contract --active`. Runs in the cloakbrowser venv on the capture host.
"""

from __future__ import annotations
import argparse, datetime, json, importlib.util, os, re, urllib.parse as up

try:
    from astrolabe.browser import launch_context
    from astrolabe.operation import SemanticKind, semantic_kind, verification_allowed
    from astrolabe.validation import validate_json_schema, validate_response
    from astrolabe.security import atomic_write_json, safe_text, validate_url
    from astrolabe.recipe import load_declarative_recipe, recipe_safety_findings
    from astrolabe.recipe_runtime import SandboxedRecipe
except ImportError:
    from browser import launch_context  # type: ignore[import-not-found,no-redef]
    from operation import (  # type: ignore[import-not-found,no-redef]
        SemanticKind,
        semantic_kind,
        verification_allowed,
    )
    from validation import validate_json_schema, validate_response  # type: ignore[import-not-found,no-redef]
    from security import (  # type: ignore[import-not-found,no-redef]
        atomic_write_json,
        safe_text,
        validate_url,
    )
    from recipe import load_declarative_recipe, recipe_safety_findings  # type: ignore[import-not-found,no-redef]
    from recipe_runtime import SandboxedRecipe  # type: ignore[import-not-found,no-redef]

# fetch() silently drops these; don't forward them
FORBIDDEN = {
    "cookie",
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "transfer-encoding",
    "user-agent",
    "accept-charset",
    "keep-alive",
}


REST_READ_METHODS = frozenset({"GET", "HEAD"})
_PATH_PARAMETER = re.compile(r"\\\{[^/]+?\\\}")


def rest_read_matchers(contract):
    """(method, compiled path pattern, op key) for each contract REST op typed a read.

    The contract is the source of truth for both the templated key and the read
    classification, so the verifier never re-derives either independently.
    """
    matchers = []
    for key, operation in (contract.get("operations") or {}).items():
        method = str(operation.get("method") or "").upper()
        if (
            operation.get("transport") != "rest"
            or operation.get("type") != "query"
            or method not in REST_READ_METHODS
        ):
            continue
        pattern = _PATH_PARAMETER.sub("[^/]+", re.escape(str(operation.get("path") or "/")))
        matchers.append((method, re.compile(pattern + "/?"), key))
    # Literal paths outrank templates when both match the same URL.
    matchers.sort(key=lambda item: item[1].pattern.count("[^/]+"))
    return matchers


def rest_op_key(matchers, method, url):
    path = up.urlparse(url).path or "/"
    for candidate_method, pattern, key in matchers:
        if candidate_method == method.upper() and pattern.fullmatch(path):
            return key
    return None


def op_key(url):
    qs = dict(up.parse_qsl(up.urlparse(url).query))
    if qs.get("alias"):
        return qs["alias"]
    return up.urlparse(url).path.rstrip("/").split("/")[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cookies", help="Playwright cookie JSON; omit to verify anonymously")
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--gql-marker", default="/graphql")
    ap.add_argument("--recipe")
    ap.add_argument("--trusted-recipe", action="store_true")
    ap.add_argument("--allow-inprocess-python-recipe", action="store_true")
    ap.add_argument("--urls", default="")
    ap.add_argument("--drive-search", default="")
    ap.add_argument("--base-domain", required=True)
    ap.add_argument("--contract", help="current contract.json for Draft 2020-12 validation")
    ap.add_argument(
        "--allow-mutation",
        action="append",
        default=[],
        metavar="EXACT_OPERATION_ID",
        help="allow one exact mutation identifier (repeatable)",
    )
    ap.add_argument(
        "--enable-mutation-execution",
        action="store_true",
        help="second runtime opt-in required before an allowlisted mutation can execute",
    )
    ap.add_argument("--warm-ms", type=int, default=4500, help="settle wait per warm-up URL")
    ap.add_argument(
        "--delay",
        type=float,
        default=0.4,
        help="seconds between re-executions (avoid bursting a live account)",
    )
    a = ap.parse_args()
    contract = json.load(open(a.contract)) if a.contract else {"operations": {}}

    recipe = None
    if a.recipe and not a.recipe.lower().endswith(".json") and not a.trusted_recipe:
        raise SystemExit(
            "Python recipes require --trusted-recipe and run in an isolated worker by default"
        )
    if a.recipe:
        if a.recipe.lower().endswith(".json"):
            recipe = load_declarative_recipe(a.recipe)
        else:
            unsafe = recipe_safety_findings(a.recipe)
            if unsafe:
                raise SystemExit(
                    "Python recipe requires explicit safety annotations: "
                    + "; ".join(str(item) for item in unsafe[:5])
                )
            if a.allow_inprocess_python_recipe:
                spec = importlib.util.spec_from_file_location("recipe", a.recipe)
                recipe = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(recipe)
            else:
                recipe = SandboxedRecipe(
                    a.recipe,
                    worker_path=os.path.join(os.path.dirname(__file__), "recipe_worker.py"),
                )

    ctx = launch_context(
        headless=True,
        stealth_args=True,
        geoip=True,
        locale="en-US",
        viewport={"width": 1600, "height": 900},
    )
    ctx.set_default_navigation_timeout(45000)
    if a.cookies:
        ctx.add_cookies(json.load(open(a.cookies)))
    page = ctx.new_page()

    catalog = {}
    rest_matchers = rest_read_matchers(contract)

    def first_party(url):
        try:
            validate_url(url, {a.base_domain}, schemes=("https", "http"))
        except ValueError:
            return False
        return True

    def on_req(r):
        if r.resource_type in {"xhr", "fetch"} and a.gql_marker not in r.url:
            k = rest_op_key(rest_matchers, r.method, r.url)
            if k and first_party(r.url):
                catalog.setdefault(
                    k,
                    {
                        "method": r.method,
                        "url": r.url.split("#")[0],
                        "headers": {
                            h: v
                            for h, v in r.headers.items()
                            if h.lower() not in FORBIDDEN and h.lower() != "accept-encoding"
                        },
                        "body": None,
                        "semantic_kind": SemanticKind.QUERY.value,
                        "mixed_or_unsafe_batch": False,
                        "transport": "rest",
                    },
                )
            return
        if a.gql_marker in r.url:
            k = op_key(r.url)
            if not first_party(r.url):
                return
            try:
                payload = json.loads(r.post_data or "{}")
            except Exception:
                payload = None
            members = payload if isinstance(payload, list) else [payload]
            kinds = [
                semantic_kind(member.get("query") if isinstance(member, dict) else None)
                for member in members
            ]
            kind = kinds[0] if len(kinds) == 1 else SemanticKind.UNKNOWN
            mixed_or_unsafe_batch = len(set(kinds)) > 1 or any(
                item != SemanticKind.QUERY for item in kinds
            )
            catalog.setdefault(
                k,
                {
                    "method": r.method,
                    "url": r.url.split("#")[0],
                    "headers": {
                        h: v
                        for h, v in r.headers.items()
                        if h.lower() not in FORBIDDEN and h.lower() != "accept-encoding"
                    },
                    "body": r.post_data,
                    "semantic_kind": kind.value,
                    "mixed_or_unsafe_batch": mixed_or_unsafe_batch,
                },
            )

    page.on("request", on_req)
    strict_recipe_egress = [False]

    def route_request(route):
        if strict_recipe_egress[0]:
            try:
                validate_url(
                    route.request.url,
                    {a.base_domain},
                    schemes=("https", "http"),
                    resolve=True,
                )
            except ValueError:
                route.abort("blockedbyclient")
                return
        route.continue_()

    ctx.route("**/*", route_request)

    def log(m):
        print(m, flush=True)

    urls = list(getattr(recipe, "SURFACES", [])) if recipe else []
    urls += [u for u in a.urls.split(",") if u.strip()]
    for u in urls:
        try:
            u = validate_url(u, {a.base_domain}, schemes=("https", "http"))
            page.goto(u, wait_until="domcontentloaded")
            page.wait_for_timeout(a.warm_ms)
        except Exception as e:
            log(f"[warm-err] navigation: {safe_text(e)[:50]}")
    if recipe and hasattr(recipe, "drive"):
        try:
            strict_recipe_egress[0] = True
            if getattr(recipe, "sandboxed", False):
                recipe.drive(
                    page,
                    log,
                    validate_navigation=lambda url: validate_url(
                        url,
                        {a.base_domain},
                        schemes=("https", "http", "wss", "ws"),
                        resolve=True,
                    ),
                )
            elif getattr(recipe, "declarative", False):
                recipe.drive(page, log, settle=lambda _kind: page.wait_for_timeout(2500))
            else:
                recipe.drive(page, log)
        except Exception as e:
            log(f"[drive-err] {safe_text(e)}")
        finally:
            strict_recipe_egress[0] = False

    log(f"[verify] captured {len(catalog)} ops; re-executing in-context…")
    js = """async (c) => {
      try {
        const opt={method:c.method, headers:c.headers, credentials:'include', redirect:'manual'};
        if (c.body!=null) opt.body=c.body;
        const r=await fetch(c.url, opt); const t=await r.text();
        let payload=null; try { payload=JSON.parse(t); } catch(e){}
        return {status:r.status, media_type:r.headers.get('content-type')||'', payload:payload, len:t.length};
      } catch(e){ return {status:null, payload:null, err:String(e)}; }
    }"""
    verify = {}
    for k, c in catalog.items():
        kind = c["semantic_kind"]
        allowed, _ = verification_allowed(
            k,
            [SemanticKind(kind)]
            if not c["mixed_or_unsafe_batch"]
            else [SemanticKind.QUERY, SemanticKind.UNKNOWN],
            set(a.allow_mutation),
            a.enable_mutation_execution,
        )
        if not allowed:
            verify[k] = {
                "status": None,
                "schema_validated": False,
                "actively_executed": False,
                "semantic_kind": kind,
                "refused": "operation is not a query proven by query text",
            }
            log(f"  {k:34} REFUSED semantic_kind={kind}")
            continue
        try:
            res = page.evaluate(js, c)
        except Exception as e:
            res = {
                "status": None,
                "conforms": False,
                "err": safe_text(e)[:80],
                "indeterminate": kind == SemanticKind.MUTATION.value,
            }
        operation_contract = (contract.get("operations") or {}).get(k) or {}
        rest = c.get("transport") == "rest"
        request_payload = {} if rest else None
        try:
            decoded_request = json.loads(c.get("body") or "{}")
            if isinstance(decoded_request, dict) and not rest:
                request_payload = decoded_request.get("variables", {})
        except (TypeError, json.JSONDecodeError):
            request_payload = None
        request_validation = validate_json_schema(
            request_payload,
            operation_contract.get("input_schema") or {"type": "object", "properties": {}},
        )
        response_validation = validate_response(
            res.pop("payload", None),
            operation_contract.get("return_schema"),
            status=res.get("status"),
            media_type=str(res.get("media_type") or ""),
            graphql=not rest,
        )
        res["request_validation"] = request_validation
        res["response_validation"] = response_validation
        res["conforms"] = response_validation["valid"]
        res["method"] = c["method"]
        res["semantic_kind"] = kind
        res["actively_executed"] = True
        res["verified_at"] = datetime.datetime.now(datetime.UTC).isoformat()
        # The old `conforms` flag only checked for data/no-errors. Keep it for
        # compatibility but do not misrepresent it as schema validation.
        res["schema_validated"] = bool(request_validation["valid"] and response_validation["valid"])
        verify[k] = res
        log(f"  {k:34} HTTP {res.get('status')} conforms={res.get('conforms')}")
        if a.delay:
            page.wait_for_timeout(int(a.delay * 1000))

    atomic_write_json(f"{a.outdir}/verify.json", verify)
    ok = sum(1 for v in verify.values() if v.get("status") == 200 and v.get("conforms"))
    log(f"[verify] {ok}/{len(verify)} ops actively verified -> {a.outdir}/verify.json")
    ctx.close()


if __name__ == "__main__":
    main()
