#!/usr/bin/env python3
"""astrolabe scan — deterministic source-scan → recipe scaffold.

Given a raw URL, this tool pulls the site's sitemap, visits each surface in a
stealth headless browser (CloakBrowser), and mines the live DOM + JS bundles for
the evidence a hand-written recipe currently guesses at:

  * anchors, classified by path shape (/product/*, /event/*, /post/*, …)
  * the site's own interactive vocabulary ([data-hook], [data-testid])
  * click-target inventory (role=listitem, role=button, [onclick], forms)
  * inline JSON blobs (Next.js __NEXT_DATA__, Wix wix-essential-viewer-model)
  * JS-bundle endpoint paths (LinkFinder-style regex → latent API surface)

It then scaffolds a recipe (surfaces/<domain>.recipe.py) whose SURFACES come
from the sitemap and whose drive() selectors are COMMENTED WITH EVIDENCE — the
actual attributes/values observed on the page — rather than guessed. The human
(or agent) editing the recipe works from evidence, not from sitemap assumptions.

This is the "evidence layer" under recipes' "intent layer" (see the postmortem
on an earlier map: a hand-written recipe guessed product selectors that didn't
exist because the shop grid rendered empty; a scan would have flagged that in
seconds).

Outputs into <outdir>/ (default ./scan-<domain>/):
  scan.json           full evidence report (machine-readable)
  scan.md             human-readable summary
  recipe.py           scaffolded recipe (copy to surfaces/<domain>.recipe.py)

Standalone: runs on the pipeline host in the cloakbrowser venv. Stdlib +
cloakbrowser + urllib only. Read-only — never clicks, submits, or mutates.
"""

from __future__ import annotations
import argparse
import os
import re
import sys
import time
import urllib.parse as up
import urllib.request
from concurrent.futures import ThreadPoolExecutor

try:
    from astrolabe.discovery import (
        ActionLedger,
        Candidate,
        DiscoveryCorpus,
        DiscoverySource,
        Evidence,
        StaticBundleMiner,
        StaticMiningResult,
        StaticResource,
        TargetPolicy,
        completeness_metrics,
        derive_interactions,
        plan_interactions,
    )
    from astrolabe.security import atomic_write_json, atomic_write_text, validate_url
except ImportError:
    from discovery import (  # type: ignore[import-not-found,no-redef]
        ActionLedger,
        Candidate,
        DiscoveryCorpus,
        DiscoverySource,
        Evidence,
        StaticBundleMiner,
        StaticMiningResult,
        StaticResource,
        TargetPolicy,
        completeness_metrics,
        derive_interactions,
        plan_interactions,
    )
    from security import (  # type: ignore[import-not-found,no-redef]
        atomic_write_json,
        atomic_write_text,
        validate_url,
    )

# Endpoint-path miner (LinkFinder-style, conservative — host-first-party paths only).
# Matches /api/..., /_api/..., /graphql, /oauth/... as literals in JS bundles.
# Deliberately narrow: a bare /v1/ branch would catch CDN/asset paths (e.g. Wix
# image-transform /v1/fill/w_...), so versioned APIs are matched only under an
# explicit /api/ or /_api/ prefix where real API versioning lives.
# Quote classes include the backtick: Vite/Rollup minified output uses template
# literals (backtick-delimited strings) heavily, so ['"] alone misses most paths.
EP_RE = re.compile(
    r'["\'`]((?:/_api/|/api/|/_serverless/|/graphql\b|/oauth/|/rest/)'
    r'[A-Za-z0-9_][A-Za-z0-9_\-/]*[A-Za-z0-9_])["\'`]'
)
# Lazy-imported route chunks (Vite/Rollup): import(`./<name>-<hash>.js`). These
# hold the per-route API code the main bundle only references, not executes.
CHUNK_RE = re.compile(
    r'["\'`](\./?(?:js-direct-|assets/|chunks/)?[A-Za-z0-9_./-]+-[A-Za-z0-9_-]+\.js)["\'`]'
)
# Sitemap <loc> is wrapped in namespace; match loosely.
LOC_RE = re.compile(r"<loc>([^<]+)</loc>")
# Wix metaSiteId (the key for Wix's API gateway) leaks in the viewer-model JSON.
WIX_META_RE = re.compile(r'"metaSiteId"\s*:\s*"([0-9a-f\-]+)"')
WIX_TPL_RE = re.compile(r'"appDefinitionIdToSiteRevision"\s*:\s*(\{[^}]+\})')


# ---------------------------------------------------------------------------
# 1. sitemap discovery (deterministic — no link-guessing)
# ---------------------------------------------------------------------------


def fetch(url, timeout=15, ua="Mozilla/5.0 (compatible; astrolabe-scan/1.0)"):
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def _robots_sitemaps(root, log=print, audit_decision=None):
    """Parse robots.txt Sitemap: directives. Many enterprise sites host sitemap
    indexes on a separate CDN (files.<cdn>.com/...xml) and never expose them at
    the conventional /sitemap.xml path — they're only discoverable via robots.txt.
    E.g. a site with several sitemaps hosted on a CDN subdomain, where /sitemap.xml
    itself just returns the SPA shell."""
    sm = []
    robots_url = f"{root}/robots.txt"
    if audit_decision:
        audit_decision(robots_url, True, "first-party-robots")
    try:
        body = fetch(robots_url, timeout=15)
    except Exception:
        return sm
    for line in body.splitlines():
        line = line.strip()
        if line.lower().startswith("sitemap:"):
            url = line.split(":", 1)[1].strip()
            if url:
                sm.append(url)
    if sm:
        log(f"[sitemap] robots.txt declares {len(sm)} sitemap(s)")
    return sm


def sitemap_urls(
    base_url,
    log=print,
    *,
    concurrency=4,
    max_requests=50,
    max_origin_requests=25,
    allowed_hosts=(),
    delay_ms=0,
    audit_decision=None,
):
    """Return all <loc> URLs from sitemap.xml + nested sitemap indexes.
    Falls back to [] if none found (caller can still scan the seed URL).

    Discovery order: (1) robots.txt Sitemap: directives (enterprise sites with
    CDN-hosted sitemaps), (2) the conventional /sitemap.xml. Both are followed
    recursively through nested index sitemaps."""
    origin = up.urlparse(base_url)
    root = f"{origin.scheme}://{origin.netloc}"
    validate_url(
        base_url,
        {origin.hostname},
        schemes=("https", "http"),
        resolve=True,
    )
    urls, seen = [], set()
    authorized_hosts = {origin.hostname, *(host.lower() for host in allowed_hosts)}
    queue = _robots_sitemaps(root, log=log, audit_decision=audit_decision) + [f"{root}/sitemap.xml"]
    visited_idx = set()
    origin_counts = {root: 1}
    sitemap_budget = max(0, max_requests - 1)  # robots.txt consumed the first request

    def bounded_fetch(sx):
        parsed_sitemap = up.urlparse(sx)
        sitemap_origin = f"{parsed_sitemap.scheme}://{parsed_sitemap.netloc}"
        validate_url(
            sx,
            authorized_hosts,
            schemes=("https", "http"),
            resolve=True,
        )
        return sx, sitemap_origin, fetch(sx, timeout=20)

    try:
        while queue and len(visited_idx) < sitemap_budget:
            batch = []
            while queue and len(batch) < max(1, concurrency):
                if len(visited_idx) >= sitemap_budget:
                    break
                sx = queue.pop(0)
                if sx in visited_idx:
                    continue
                sitemap_origin = f"{up.urlparse(sx).scheme}://{up.urlparse(sx).netloc}"
                sitemap_host = (up.urlparse(sx).hostname or "").lower()
                if sitemap_host not in authorized_hosts:
                    if audit_decision:
                        audit_decision(sx, False, "third-party-sitemap-denied")
                    log(f"[sitemap] {sx} :: third-party host not authorized")
                    continue
                if origin_counts.get(sitemap_origin, 0) >= max(1, max_origin_requests):
                    log(f"[sitemap] {sx} :: origin request budget exhausted")
                    continue
                visited_idx.add(sx)
                origin_counts[sitemap_origin] = origin_counts.get(sitemap_origin, 0) + 1
                if audit_decision:
                    audit_decision(sx, True, "first-party-or-explicit-sitemap-host")
                batch.append(sx)
            if not batch:
                continue
            if delay_ms:
                time.sleep(delay_ms / 1000)
            with ThreadPoolExecutor(max_workers=min(max(1, concurrency), len(batch))) as pool:
                futures = [pool.submit(bounded_fetch, sx) for sx in batch]
            for sx, future in zip(batch, futures, strict=True):
                try:
                    _, _, body = future.result()
                except Exception as e:
                    log(f"[sitemap] {sx} :: {str(e)[:60]}")
                    continue
                locs = LOC_RE.findall(body)
                if not locs:
                    continue
                # Distinguish index sitemaps (point to .xml) from URL sitemaps.
                for u in locs:
                    if u.endswith(".xml"):
                        queue.append(u)
                    elif u not in seen:
                        seen.add(u)
                        urls.append(u)
                log(f"[sitemap] {sx} → {len(locs)} locs (urls so far: {len(seen)})")
    except Exception as e:
        log(f"[sitemap] discovery aborted: {e}")
    return urls


def classify_surfaces(urls, base_host):
    """Bucket sitemap URLs by path shape so the scaffolded SURFACES list reads
    naturally and the agent can spot the interesting surfaces at a glance."""
    buckets = {
        "root": [],
        "product": [],
        "event": [],
        "post": [],
        "category": [],
        "profile": [],
        "other": [],
    }
    for u in urls:
        p = up.urlparse(u)
        if p.netloc and p.netloc != base_host and not p.netloc.endswith("." + base_host):
            continue
        path = p.path or "/"
        if path in ("", "/"):
            buckets["root"].append(u)
        elif re.search(r"/(product|store|item|shop)/", path):
            buckets["product"].append(u)
        elif re.search(r"/(event|course|service|booking|schedule|calendar)/", path):
            buckets["event"].append(u)
        elif re.search(r"/(post|article|blog|news)/", path):
            buckets["post"].append(u)
        elif re.search(r"/(categor|tag|topic|feed)/", path):
            buckets["category"].append(u)
        elif re.search(r"/(profile|member|user|author|team)/", path):
            buckets["profile"].append(u)
        else:
            buckets["other"].append(u)
    return buckets


# ---------------------------------------------------------------------------
# 2. live-DOM evidence collection (cloakbrowser; read-only)
# ---------------------------------------------------------------------------


def collect_page_evidence(page, url):
    """Pull all in-page evidence from a loaded page. Pure reads — no clicks."""
    ev = {"url": url}
    # anchors: href + text + whether it's same-origin
    try:
        anchors = page.eval_on_selector_all(
            "a[href]",
            """els => els.map(e => ({
                h: e.getAttribute('href'),
                t: (e.textContent || '').trim().slice(0, 60),
                same: e.origin === location.origin
            })).filter(a => a.h)""",
        )
    except Exception:
        anchors = []
    ev["anchors"] = anchors

    # site vocabulary: data-hook / data-testid / data-test / data-cy
    try:
        vocab = page.eval_on_selector_all(
            "[data-hook], [data-testid], [data-test], [data-cy]",
            """els => els.map(e => {
                const a = (e.getAttribute('data-hook') || e.getAttribute('data-testid')
                           || e.getAttribute('data-test') || e.getAttribute('data-cy'));
                return { attr: a, tag: e.tagName.toLowerCase(),
                         cls: (e.className || '').toString().slice(0, 50),
                         t: (e.textContent || '').trim().slice(0, 40) };
            })""",
        )
    except Exception:
        vocab = []
    ev["data_vocab"] = vocab

    # click-target inventory (cards, buttons that aren't anchors)
    try:
        clickables = page.eval_on_selector_all(
            "[role='listitem'], [role='button'], button:not([type='submit']), [onclick]",
            """els => els.slice(0, 40).map(e => ({
                tag: e.tagName.toLowerCase(), role: e.getAttribute('role'),
                type: e.getAttribute('type'),
                hook: e.getAttribute('data-hook') || e.getAttribute('data-testid'),
                cls: (e.className || '').toString().slice(0, 60),
                t: (e.textContent || '').trim().slice(0, 40)
            }))""",
        )
    except Exception:
        clickables = []
    ev["click_targets"] = clickables

    # form actions (read-only: just record where they'd POST)
    try:
        forms = page.eval_on_selector_all(
            "form",
            """els => els.slice(0, 20).map(f => ({
                action: f.getAttribute('action'),
                method: (f.getAttribute('method') || 'GET').toUpperCase(),
                id: f.id, name: f.name,
                inputs: [...f.querySelectorAll('input,textarea,select')]
                          .slice(0, 10)
                          .map(i => ({ name: i.name, type: i.type }))
            }))""",
        )
    except Exception:
        forms = []
    ev["forms"] = forms

    # inline JSON blobs (Next.js / Nuxt / Wix embed config in the HTML)
    try:
        inline = page.evaluate("""() => {
            const out = {};
            const nxt = document.getElementById('__NEXT_DATA__');
            if (nxt) out.__NEXT_DATA__ = JSON.stringify(nxt.textContent.slice(0, 2000));
            const wix = document.getElementById('wix-essential-viewer-model');
            if (wix) out.wix_viewer_model = wix.textContent.slice(0, 2000);
            const wix2 = document.getElementById('wix-viewer-model');
            if (wix2) out.wix_viewer_model_full = wix2.textContent.slice(0, 2000);
            return out;
        }""")
    except Exception:
        inline = {}
    ev["inline_json"] = inline

    # meta signals (generator, csrf token, graphql endpoint hints)
    try:
        gen = page.evaluate(r"""() => {
            const m = document.querySelector('meta[name=generator]');
            const pagination = [...document.querySelectorAll('a[href],button')].some(e =>
              /(?:[?&](?:page|cursor|offset)=|\/page\/\d+)/i.test(e.getAttribute('href') || '') ||
              /^(next|more|older)$/i.test((e.textContent || '').trim()));
            const clientReads = performance.getEntriesByType('resource').filter(e =>
              ['fetch', 'xmlhttprequest'].includes(e.initiatorType)).length;
            return { generator: m ? m.content : null,
                     title: document.title,
                     has_react: !!(window.React || document.querySelector('[data-reactroot],#root,#__next')),
                     graphql_in_html: /\\/graphql\\b|graphql\\.php|\\/gql\\b/i.test(document.documentElement.outerHTML),
                     pagination_hint: pagination,
                     client_read_count: clientReads,
                     ssr_first_page: pagination && clientReads === 0 };
        }""")
    except Exception:
        gen = {}
    ev["meta"] = gen

    try:
        ev["service_workers"] = page.evaluate(
            """async () => ({
                controller: navigator.serviceWorker?.controller?.scriptURL || null,
                registrations: navigator.serviceWorker
                  ? (await navigator.serviceWorker.getRegistrations()).map(r => ({
                      scope: r.scope,
                      script: (r.active || r.waiting || r.installing)?.scriptURL || null
                    })) : []
            })"""
        )
    except Exception:
        ev["service_workers"] = {"controller": None, "registrations": []}

    return ev


# ---------------------------------------------------------------------------
# 3. JS-bundle endpoint mining (LinkFinder-style)
# ---------------------------------------------------------------------------


def mine_static_discovery(
    page,
    base_url,
    log=print,
    *,
    limit_resources=25,
    max_total_bytes=20_000_000,
    max_resource_bytes=4_000_000,
    max_origin_resources=None,
    allowed_hosts=(),
    audit_decision=None,
):
    """Mine first-party bundles, manifests, lazy chunks, and source maps.

    Bundle bodies are fetched through the browser context for TLS/client parity. Third-party
    hosts are denied by default; operators must authorize exact additional static hosts.
    JavaScript is parsed as text and never evaluated.
    """
    try:
        srcs = page.eval_on_selector_all(
            "script[src]", "els => els.map(e => e.src).filter(Boolean)"
        )
    except Exception:
        srcs = []
    try:
        manifest_srcs = page.eval_on_selector_all(
            "link[rel='manifest'][href]", "els => els.map(e => e.href).filter(Boolean)"
        )
    except Exception:
        manifest_srcs = []
    seeds = list(dict.fromkeys([*srcs, *manifest_srcs]))
    seeds.extend(
        up.urljoin(base_url + "/", path)
        for path in ("manifest.json", "asset-manifest.json", "_next/build-manifest.json")
    )
    log(
        f"[scan] mining {len(srcs)} script seeds, {len(manifest_srcs)} web manifests, "
        "and framework manifests …"
    )

    def page_fetch(url):
        response = page.evaluate(
            """async (u) => {
                const r = await fetch(u, {credentials: 'omit', redirect: 'error'});
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                return {body: await r.text(), content_type: r.headers.get('content-type') || ''};
            }""",
            url,
        )
        return StaticResource(url, response["body"], response["content_type"])

    miner = StaticBundleMiner(
        base_url,
        max_resources=limit_resources,
        max_total_bytes=max_total_bytes,
        max_resource_bytes=max_resource_bytes,
        max_origin_resources=max_origin_resources,
        allowed_hosts=allowed_hosts,
        audit_decision=audit_decision,
    )
    try:
        return miner.mine(seeds, page_fetch)
    except Exception as exc:
        log(f"[scan] static resource fetch stopped: {str(exc)[:100]}")
        return StaticMiningResult(truncations=[f"fetch-error:{type(exc).__name__}"])


def mine_endpoints_from_bundles(page, base_host, log=print, limit_bundles=25):
    """Compatibility wrapper returning endpoint strings and resource URLs."""
    result = mine_static_discovery(
        page, f"https://{base_host}", log=log, limit_resources=limit_bundles
    )
    paths = {item.value for item in result.candidates if item.kind == "endpoint"}
    return paths, result.discovered_urls


# ---------------------------------------------------------------------------
# 4. recipe scaffolder
# ---------------------------------------------------------------------------


def scaffold_recipe(
    base_url, surfaces_buckets, evidence_by_url, js_endpoints, wix_meta=None, out_path=None
):
    """Emit a recipe .py whose SURFACES come from the sitemap and whose drive()
    body is commented with OBSERVED evidence (anchors, data-hooks, click targets).
    The result is a starting scaffold, not a finished recipe — the human/agent
    prunes and tightens it against the real client behavior."""
    L = []
    A = L.append
    host = up.urlparse(base_url).netloc
    A(f'"""astrolabe recipe for {host} — SCAFFOLDED by `astrolabe scan`.')
    A("")
    A("This recipe was generated deterministically from a source scan. SURFACES come")
    A("from the sitemap; the selectors in drive() are COMMENTED WITH EVIDENCE — the")
    A("actual attributes/values observed on the live page — not guessed. Review,")
    A("prune, and tighten against real client behavior before relying on it.")
    A("")
    if wix_meta:
        A(f"Wix metaSiteId (API gateway key): {wix_meta}")
        A("")
    A("Read-only / idempotent by construction: only navigates and inspects. Do not")
    A("add cart adds, form submits, bookings, or any mutation without explicit review.")
    A('"""')
    A("")
    A(f'BASE = "{base_url.rstrip("/")}"')
    A("")

    # ---- SURFACES (from sitemap, deduped, capped per bucket) ----
    A("# SURFACES — from sitemap.xml. Each loads a distinct page + fires its on-load API.")
    A("# Buckets are path-shape classifications; prune to the surfaces you actually")
    A("# want to exercise (depth, not breadth — every surface adds capture time).")
    A("SURFACES = [")
    cap = {"root": 1, "product": 6, "event": 4, "post": 4, "category": 3, "profile": 3, "other": 12}
    for bucket, urls in surfaces_buckets.items():
        if not urls:
            continue
        c = cap.get(bucket, 8)
        A(f"    # ---- {bucket} ({len(urls)} in sitemap, first {min(c, len(urls))} sampled) ----")
        for u in urls[:c]:
            A(f'    "{u}",')
    A("]")
    A("")

    # ---- JS-bundle endpoint inventory (latent API surface) ----
    if js_endpoints:
        A("# Latent API endpoints mined from JS bundles (LinkFinder-style). These are")
        A("# paths the client KNOWS about; some fire on the surfaces above, others are")
        A("# dormant. Cross-reference with a capture to find the uncalled surface.")
        A("JS_ENDPOINTS = [")
        # group by prefix for readability
        groups = {}
        for p in sorted(js_endpoints):
            pre = p.split("/", 3)[1] if p.count("/") >= 2 else p
            groups.setdefault(pre, []).append(p)
        for pre, paths in sorted(groups.items()):
            A(f"    # /{pre}/… ({len(paths)} paths)")
            for p in paths[:8]:
                A(f'    "{p}",')
        A("]")
        A("")

    # ---- drive() skeleton with evidence-grounded comments ----
    A("def drive(page, log):")
    A("    def hop(url, wait=3.0, scrolls=0):")
    A("        try:")
    A("            page.goto(url, wait_until='domcontentloaded')")
    A("            page.wait_for_timeout(int(wait * 1000))")
    A("            for _ in range(scrolls):")
    A("                page.mouse.wheel(0, 2500); page.wait_for_timeout(1200)")
    A("            return True")
    A("        except Exception as e:")
    A("            log(f'[drive] {url} skip ({str(e)[:60]})'); return False")
    A("")
    A("    def hrefs(sel, limit=8):")
    A("        try:")
    A("            return page.eval_on_selector_all(")
    A(
        "                sel, \"els => [...new Set(els.map(e => e.getAttribute('href')).filter(Boolean))]\")[:limit]"
    )
    A("        except Exception:")
    A("            return []")
    A("")

    # Per-surface evidence comments + selector suggestions, grounded in what we saw.
    # Pick the first URL per non-empty bucket as the representative.
    wrote_any = False
    for bucket, urls in surfaces_buckets.items():
        if not urls or bucket == "root":
            continue
        rep_url = urls[0]
        ev = evidence_by_url.get(rep_url, {})
        if not ev:
            continue
        wrote_any = True
        anchors = ev.get("anchors", [])
        vocab = ev.get("data_vocab", [])
        clicks = ev.get("click_targets", [])
        # candidate selectors grounded in observed attributes
        same_anchors = [a for a in anchors if a.get("same")][:6]
        hook_attrs = sorted({v["attr"] for v in vocab if v.get("attr")})[:6]
        click_roles = sorted(
            {c.get("role") or c.get("tag") for c in clicks if c.get("role") or c.get("tag")}
        )[:6]
        A(f"    # ---- {bucket}: {rep_url} ----")
        if same_anchors:
            A(f"    # observed same-origin anchors: {same_anchors[:3]}")
        if hook_attrs:
            A(f"    # observed data-hooks/testids: {hook_attrs}")
            # Built as a separate statement: nesting this f-string inside the f-string
            # below needs PEP 701 (3.12+), and this package supports 3.11.
            hook_hint = ", ".join(f'[data-hook="{h}"]' for h in hook_attrs[:3])
            A(f"    # → try: {hook_hint}")
        if click_roles:
            A(f"    # observed click targets (role/tag): {click_roles}")
        if not same_anchors and not hook_attrs and not click_roles:
            A("    # ⚠ no anchors, data-hooks, or click targets observed — surface may be")
            A("    #   empty (no published items) or rendered in an iframe. Verify manually.")
        A(f'    if hop(f"{{BASE}}{up.urlparse(rep_url).path or "/"}", 3.0, 1):')
        A(
            f"        for sel in ('[data-hook*=\"item\"] a', 'a[href*=\"/{bucket}\"]', '[role=listitem] a'):"
        )
        A("            found = hrefs(sel, 6)")
        A("            if found:")
        A("                for h in found:")
        A("                    hop(h if h.startswith('http') else BASE + h, 2.5, 0)")
        A("                break")
        A("")

    if not wrote_any:
        A("    # No non-root surfaces in the sitemap; add drive steps here as you discover them.")
        A("    pass")
    A("")
    text = "\n".join(L)
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        atomic_write_text(out_path, text + "\n")
    return text


# ---------------------------------------------------------------------------
# 5. main — orchestrate the scan
# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(
        prog="astrolabe-scan",
        description="Deterministic source-scan → recipe scaffold. "
        "Pulls sitemap + live DOM evidence + JS-bundle endpoints and "
        "scaffolds a recipe grounded in observed selectors.",
    )
    ap.add_argument("url", help="seed URL (any page on the target site)")
    ap.add_argument("--outdir", default=None, help="output dir (default ./scan-<host>)")
    ap.add_argument("--proxy", default=None, help="cloakbrowser proxy (e.g. http://127.0.0.1:8088)")
    ap.add_argument("--byparr", default=None, help="byparr /v1 endpoint for CF fallback")
    ap.add_argument(
        "--max-surfaces",
        type=int,
        default=20,
        help="cap on number of surfaces to deep-scan (default 20)",
    )
    ap.add_argument("--static-concurrency", type=int, default=4)
    ap.add_argument("--max-static-requests", type=int, default=50)
    ap.add_argument("--max-origin-requests", type=int, default=25)
    ap.add_argument("--max-total-requests", type=int, default=100)
    ap.add_argument("--max-static-resources", type=int, default=25)
    ap.add_argument("--max-static-bytes", type=int, default=20_000_000)
    ap.add_argument("--max-static-resource-bytes", type=int, default=4_000_000)
    ap.add_argument(
        "--allowed-static-host",
        action="append",
        default=[],
        help="authorize one exact additional bundle host (repeatable)",
    )
    ap.add_argument("--delay-ms", type=int, default=250)
    ap.add_argument(
        "--working-hours-utc",
        metavar="START-END",
        help="only perform active discovery during this UTC hour window",
    )
    ap.add_argument(
        "--account-risk",
        choices=("anonymous", "low", "standard", "sensitive", "privileged"),
        default="standard",
    )
    ap.add_argument("--authorized-path", action="append", default=[])
    ap.add_argument("--prohibited-path", action="append", default=[])
    ap.add_argument("--prohibited-action", action="append", default=[])
    ap.add_argument(
        "--operator-seed",
        action="append",
        default=[],
        help="authorized navigation URL supplied by the operator (repeatable)",
    )
    ap.add_argument(
        "--no-js-mine",
        action="store_true",
        help="skip JS-bundle endpoint mining (faster, less complete)",
    )
    args = ap.parse_args()

    for name in (
        "max_surfaces",
        "static_concurrency",
        "max_static_requests",
        "max_origin_requests",
        "max_total_requests",
        "max_static_resources",
        "max_static_bytes",
        "max_static_resource_bytes",
    ):
        if getattr(args, name) < 1:
            ap.error(f"--{name.replace('_', '-')} must be positive")
    if args.delay_ms < 0:
        ap.error("--delay-ms cannot be negative")

    working_hours = None
    if args.working_hours_utc:
        try:
            start, end = args.working_hours_utc.split("-", 1)
            working_hours = (int(start), int(end))
        except (ValueError, TypeError):
            ap.error("--working-hours-utc must be START-END using UTC hours 0..23")
    policy = TargetPolicy(
        max_requests=args.max_total_requests,
        max_origin_requests=args.max_origin_requests,
        concurrency=args.static_concurrency,
        delay_ms=args.delay_ms,
        working_hours_utc=working_hours,
        account_risk=args.account_risk,
        authorized_paths=tuple(args.authorized_path or ["/"]),
        prohibited_paths=tuple(args.prohibited_path),
        prohibited_actions=tuple(
            args.prohibited_action or ["submit", "purchase", "delete", "publish"]
        ),
    )
    ledger = ActionLedger()

    parsed = up.urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit(f"scan: invalid URL {args.url!r} (need full https://… URL)")
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    base_host = parsed.netloc
    outdir = args.outdir or f"./scan-{base_host}"
    os.makedirs(outdir, exist_ok=True)

    def log(m):
        print(m, flush=True)

    request_actions = {
        "fetch discovery metadata",
        "navigate",
        "navigate for static discovery",
        "fetch static resource",
    }

    def request_count(origin=None):
        count = 0
        for record in ledger.records:
            if not record["authorized"] or record["action"] not in request_actions:
                continue
            if origin:
                parsed_target = up.urlparse(record["target"])
                target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
                if target_origin != origin:
                    continue
            count += 1
        return count

    allowed_now, now_reason = policy.authorize(path="/robots.txt", action="discover")
    if not allowed_now:
        ledger.append(
            action_id="discovery-window",
            action="authorize discovery window",
            target=base_url,
            authorized=False,
            reason=now_reason,
        )
        ap.error(f"discovery refused: {now_reason}")

    # ---- 1. sitemap ----
    log(f"[scan] {base_url} — discovering sitemap …")

    def audit_sitemap(url, authorized, reason):
        ledger.append(
            action_id=f"sitemap-{len(ledger.records) + 1}",
            action="fetch discovery metadata",
            target=url,
            authorized=authorized,
            reason=reason,
        )

    sm_urls = sitemap_urls(
        args.url,
        log=log,
        concurrency=policy.effective_concurrency,
        max_requests=min(args.max_static_requests, policy.max_requests),
        max_origin_requests=args.max_origin_requests,
        allowed_hosts=args.allowed_static_host,
        delay_ms=policy.effective_delay_ms,
        audit_decision=audit_sitemap,
    )
    if not sm_urls:
        log("[scan] no sitemap found; falling back to seed URL only")
        sm_urls = [args.url]
    for seed in args.operator_seed:
        parsed_seed = up.urlparse(seed)
        try:
            validate_url(seed, {parsed.hostname}, schemes=(parsed.scheme,), resolve=True)
        except ValueError as exc:
            ap.error(f"invalid operator seed: {exc}")
        if parsed_seed.port != parsed.port or parsed_seed.username or parsed_seed.fragment:
            ap.error(f"operator seed must use the exact target origin: {seed}")
        allowed, reason = policy.authorize(path=parsed_seed.path or "/", action="navigate")
        ledger.append(
            action_id=f"operator-seed-{len(ledger.records) + 1}",
            action="authorize operator seed",
            target=seed,
            authorized=allowed,
            reason=reason,
        )
        if not allowed:
            ap.error(f"operator seed refused ({reason}): {seed}")
        if seed not in sm_urls:
            sm_urls.append(seed)
    log(f"[scan] {len(sm_urls)} candidate surfaces")

    surfaces = classify_surfaces(sm_urls, base_host)
    for k, v in surfaces.items():
        if v:
            log(f"  {k:10} {len(v)}")

    # pick representatives per bucket (cap total deep-scans)
    to_scan, seen = [], set()
    remaining_total = max(0, policy.max_requests - request_count())
    surface_limit = min(args.max_surfaces, remaining_total)
    for k in ("root", "product", "event", "post", "category", "profile", "other"):
        for u in surfaces.get(k, [])[: (1 if k == "root" else 6)]:
            if len(to_scan) >= surface_limit:
                break
            if u not in seen:
                seen.add(u)
                to_scan.append(u)
                if len(to_scan) >= surface_limit:
                    break
        if len(to_scan) >= surface_limit:
            break

    # ---- 2. live-DOM evidence (cloakbrowser) ----
    try:
        from astrolabe.browser import launch_context
    except ImportError:
        from browser import launch_context  # type: ignore[import-not-found,no-redef]

    kw = dict(
        headless=True,
        stealth_args=True,
        geoip=not bool(args.proxy),
        locale="en-US",
        viewport={"width": 1920, "height": 1080},
        ignore_https_errors=bool(args.proxy),
    )
    if args.proxy:
        kw["proxy"] = args.proxy
    ctx = launch_context(**kw)
    ctx.set_default_navigation_timeout(45000)
    page = ctx.new_page()

    evidence = {}
    wix_meta = None
    for u in to_scan:
        allowed, reason = policy.authorize(path=up.urlparse(u).path or "/", action="navigate")
        surface_origin = f"{up.urlparse(u).scheme}://{up.urlparse(u).netloc}"
        if allowed and request_count() >= policy.max_requests:
            allowed, reason = False, "total-request-ceiling"
        if allowed and request_count(surface_origin) >= policy.max_origin_requests:
            allowed, reason = False, "origin-request-ceiling"
        ledger.append(
            action_id=f"surface-{len(ledger.records) + 1}",
            action="navigate",
            target=u,
            authorized=allowed,
            reason=reason,
        )
        if not allowed:
            log(f"[scan] policy refused {u}: {reason}")
            continue
        log(f"[scan] {u}")
        try:
            if policy.effective_delay_ms:
                time.sleep(policy.effective_delay_ms / 1000)
            page.goto(u, wait_until="domcontentloaded")
            page.wait_for_timeout(3500)
            # gentle scroll to trigger lazy widgets
            for _ in range(2):
                page.mouse.wheel(0, 2500)
                page.wait_for_timeout(900)
            evidence[u] = collect_page_evidence(page, u)
            inline = evidence[u].get("inline_json", {}) or {}
            txt = inline.get("wix_viewer_model") or inline.get("wix_viewer_model_full") or ""
            if txt and not wix_meta:
                m = WIX_META_RE.search(txt)
                if m:
                    wix_meta = m.group(1)
                    log(f"[scan] Wix metaSiteId: {wix_meta}")
        except Exception as e:
            log(f"[scan-ERR] {u}: {str(e)[:80]}")
            evidence[u] = {"url": u, "_error": str(e)[:120]}

    # ---- 3. bounded static discovery (on the seed URL's page) ----
    js_endpoints = set()
    js_bundles = []
    static_result = StaticMiningResult()
    if not args.no_js_mine:
        allowed, reason = policy.authorize(
            path=up.urlparse(args.url).path or "/", action="static-discovery"
        )
        target_origin = f"{parsed.scheme}://{parsed.netloc}"
        if allowed and request_count() >= policy.max_requests:
            allowed, reason = False, "total-request-ceiling"
        if allowed and request_count(target_origin) >= policy.max_origin_requests:
            allowed, reason = False, "origin-request-ceiling"
        ledger.append(
            action_id=f"static-seed-{len(ledger.records) + 1}",
            action="navigate for static discovery",
            target=args.url,
            authorized=allowed,
            reason=reason,
        )
        try:
            if not allowed:
                raise PermissionError(reason)
            if policy.effective_delay_ms:
                time.sleep(policy.effective_delay_ms / 1000)
            page.goto(args.url, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)
            remaining_requests = max(0, policy.max_requests - request_count())
            remaining_origin_requests = max(
                0, policy.max_origin_requests - request_count(target_origin)
            )
            if not remaining_requests or not remaining_origin_requests:
                raise PermissionError("request ceiling exhausted")

            def audit_static(url, authorized, decision_reason):
                ledger.append(
                    action_id=f"static-resource-{len(ledger.records) + 1}",
                    action="fetch static resource",
                    target=url,
                    authorized=authorized,
                    reason=decision_reason,
                )
                if authorized and policy.effective_delay_ms:
                    time.sleep(policy.effective_delay_ms / 1000)

            static_result = mine_static_discovery(
                page,
                base_url,
                log=log,
                limit_resources=min(args.max_static_resources, remaining_requests),
                max_total_bytes=args.max_static_bytes,
                max_resource_bytes=args.max_static_resource_bytes,
                max_origin_resources=remaining_origin_requests,
                allowed_hosts=args.allowed_static_host,
                audit_decision=audit_static,
            )
            js_endpoints = {
                item.value for item in static_result.candidates if item.kind == "endpoint"
            }
            js_bundles = static_result.discovered_urls
            log(f"[scan] {len(js_endpoints)} unique endpoint paths in {len(js_bundles)} bundles")
        except Exception as e:
            log(f"[scan] JS mining skipped: {e}")
    ctx.close()

    # ---- 4. emit artifacts ----
    discovered: list[Candidate] = list(static_result.candidates)
    for url in sm_urls:
        discovered.append(
            Candidate(
                "navigation-route",
                url,
                url,
                [Evidence(DiscoverySource.SITEMAP, 0.85, locator=f"{base_url}/sitemap.xml")],
            )
        )
    for url in args.operator_seed:
        discovered.append(
            Candidate(
                "navigation-route",
                url,
                url,
                [Evidence(DiscoverySource.OPERATOR, 0.95, locator="--operator-seed")],
            )
        )
    for url, page_evidence in evidence.items():
        for anchor in page_evidence.get("anchors", []):
            href = anchor.get("h")
            if href and anchor.get("same"):
                absolute = up.urljoin(url, href)
                discovered.append(
                    Candidate(
                        "navigation-route",
                        absolute,
                        absolute,
                        [Evidence(DiscoverySource.DOM, 0.8, locator=url)],
                    )
                )
        workers = page_evidence.get("service_workers", {}) or {}
        for worker in workers.get("registrations", []):
            script = worker.get("script")
            if script:
                discovered.append(
                    Candidate(
                        "service-worker",
                        script,
                        script,
                        [Evidence(DiscoverySource.SERVICE_WORKER, 0.9, locator=url)],
                        {"scope": worker.get("scope")},
                    )
                )
    corpus = DiscoveryCorpus()
    corpus.add_candidates(discovered)
    discovered = corpus.candidates
    interaction_candidates = derive_interactions(evidence)
    policy_allowed_interactions = []
    refused_interactions = []
    for interaction_candidate in interaction_candidates:
        allowed, reason = policy.authorize(
            path=up.urlparse(interaction_candidate.surface).path or "/",
            action=interaction_candidate.action,
        )
        if allowed:
            policy_allowed_interactions.append(interaction_candidate)
        else:
            refused_interactions.append(
                {"action_id": interaction_candidate.action_id, "reason": reason}
            )
    missing_candidate_keys = {
        key
        for interaction_candidate in policy_allowed_interactions
        for key in interaction_candidate.expected_candidates
    }
    interaction_plan = plan_interactions(
        policy_allowed_interactions,
        missing_candidate_keys=missing_candidate_keys,
        request_budget=max(0, policy.max_requests - request_count()),
    )
    coverage = completeness_metrics(
        observed=set(evidence),
        static_candidates={item.value for item in discovered if item.kind == "endpoint"},
        navigation_routes={item.value for item in discovered if item.kind == "navigation-route"},
        recipe_actions={item.action_id for item in interaction_candidates},
    )
    report = {
        "schema_version": 1,
        "base_url": base_url,
        "base_host": base_host,
        "wix_meta_site_id": wix_meta,
        "sitemap_urls_total": len(sm_urls),
        "surfaces_by_bucket": {k: len(v) for k, v in surfaces.items()},
        "scanned": list(evidence.keys()),
        "evidence": evidence,
        "js_endpoints": sorted(js_endpoints),
        "js_bundles_mined": len(js_bundles),
        "discovery_candidates": [item.to_dict() for item in discovered],
        "discovery": corpus.to_dict(),
        "coverage": coverage,
        "interaction_guidance": {
            "proposals": interaction_plan,
            "policy_refusals": refused_interactions,
            "note": "proposals are not executed by scan and still require capture safety gates",
        },
        "action_ledger": ledger.records,
        "action_ledger_verified": ledger.verify(),
        "static_discovery": {
            "source_maps": static_result.source_maps,
            "cache_hits": static_result.cache_hits,
            "bytes_downloaded": static_result.bytes_downloaded,
            "truncations": static_result.truncations,
        },
        "target_policy": {
            "max_requests": policy.max_requests,
            "max_origin_requests": policy.max_origin_requests,
            "requested_concurrency": policy.concurrency,
            "effective_concurrency": policy.effective_concurrency,
            "requested_delay_ms": policy.delay_ms,
            "effective_delay_ms": policy.effective_delay_ms,
            "working_hours_utc": policy.working_hours_utc,
            "account_risk": policy.account_risk,
            "authorized_paths": policy.authorized_paths,
            "prohibited_paths": policy.prohibited_paths,
            "prohibited_actions": policy.prohibited_actions,
        },
        "static_discovery_limits": {
            "concurrency": policy.effective_concurrency,
            "max_requests": args.max_static_requests,
            "max_origin_requests": args.max_origin_requests,
            "max_resources": args.max_static_resources,
            "max_total_bytes": args.max_static_bytes,
            "max_resource_bytes": args.max_static_resource_bytes,
        },
    }
    atomic_write_json(os.path.join(outdir, "scan.json"), report)

    # scan.md — human summary
    L = [
        f"# {base_host} — source scan\n",
        "_Generated by `astrolabe scan`. Evidence-based recipe scaffold._\n",
        "## Summary\n",
        f"- Sitemap URLs discovered: **{len(sm_urls)}**",
        f"- Surfaces deep-scanned: **{len(evidence)}**",
        f"- JS bundles mined: **{len(js_bundles)}** → **{len(js_endpoints)}** endpoint paths",
        f"- Safe next interactions proposed: **{len(interaction_plan)}** (not executed)",
        "- Coverage is relative to named evidence denominators; this is **not** an absolute completeness claim.",
    ]
    if wix_meta:
        L.append(f"- Wix metaSiteId: `{wix_meta}`")
    L.append("")
    L.append("## Surfaces by bucket\n")
    L.append("| bucket | count in sitemap |")
    L.append("|---|---|")
    for k, v in surfaces.items():
        if v:
            L.append(f"| {k} | {len(v)} |")
    L.append("")

    if interaction_plan:
        L.append("## Coverage-guided next interactions\n")
        L.append(
            "Ranked by expected novel evidence per request/time. These are proposals only; run"
        )
        L.append("them through a reviewed recipe and the capture safety gates.\n")
        L.append("| action | surface | request cost | expected candidates |")
        L.append("|---|---|---:|---:|")
        for item in interaction_plan:
            L.append(
                f"| `{item['action']}` | `{item['surface']}` | {item['request_cost']} | "
                f"{len(item['expected_new_candidates'])} |"
            )
        L.append("")

    # per-surface evidence highlights
    L.append("## Per-surface evidence (representative per bucket)\n")
    for u, ev in evidence.items():
        if ev.get("_error"):
            L.append(f"### `{u}`\n⚠ error: {ev['_error']}\n")
            continue
        a = ev.get("anchors", [])
        v = ev.get("data_vocab", [])
        c = ev.get("click_targets", [])
        f_ = ev.get("forms", [])
        same = [x for x in a if x.get("same")]
        hooks = sorted({x["attr"] for x in v if x.get("attr")})
        L.append(f"### `{u}`")
        L.append(f"- anchors: **{len(a)}** total, **{len(same)}** same-origin")
        if hooks:
            L.append(f"- data-hooks/testids: `{', '.join(hooks[:10])}`")
        L.append(
            f"- click targets: **{len(c)}** (roles: `{', '.join(sorted({(x.get('role') or x.get('tag')) for x in c if x.get('role') or x.get('tag')}))}`)"
        )
        if f_:
            L.append(
                f"- forms: **{len(f_)}** (actions: `{', '.join(x.get('action') or x.get('method') or '?' for x in f_[:3])}`)"
            )
        # first 3 same-origin anchors as a hint
        if same[:3]:
            L.append("- sample same-origin anchors:")
            for x in same[:3]:
                L.append(f"  - `{x['h']}` — {x['t']}")
        L.append("")

    if js_endpoints:
        L.append("## JS-bundle endpoints (latent API surface)\n")
        L.append("Paths mined from same-origin/CDN JS bundles. Some fire on the surfaces")
        L.append("above; others are dormant client-known paths. Cross-reference with a")
        L.append("`astrolabe map` capture to find the uncalled (latent) surface.\n")
        groups = {}
        for p in sorted(js_endpoints):
            pre = p.split("/", 3)[1] if p.count("/") >= 2 else "other"
            groups.setdefault(pre, []).append(p)
        for pre, paths in sorted(groups.items()):
            L.append(f"### `/{pre}/…` ({len(paths)})\n")
            for p in paths[:15]:
                L.append(f"- `{p}`")
            if len(paths) > 15:
                L.append(f"- _…{len(paths) - 15} more_")
            L.append("")

    atomic_write_text(os.path.join(outdir, "scan.md"), "\n".join(L))

    # ---- 5. scaffold the recipe ----
    rec_path = os.path.join(outdir, "recipe.py")
    scaffold_recipe(
        base_url, surfaces, evidence, js_endpoints, wix_meta=wix_meta, out_path=rec_path
    )

    log(f"\n✓ {outdir}/scan.json | scan.md | recipe.py")
    log(f"  review scan.md, then: cp {rec_path} surfaces/{base_host}.recipe.py")
    log(
        f"  next: astrolabe map {base_host} --recipe surfaces/{base_host}.recipe.py "
        f"--no-auth --no-burp --schema"
    )


if __name__ == "__main__":
    main()
