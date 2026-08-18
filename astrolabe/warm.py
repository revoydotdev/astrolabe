#!/usr/bin/env python3
"""Warm-browser execution backend — a persistent logged-in CloakBrowser context that
executes a site's own GraphQL/REST in-context, so the browser owns auth, cookie/token
rotation, and CF. Alternative to the curl_cffi replay tier for sites where tokens are
short-lived/context-bound.

Validated in-context: `page.evaluate(fetch)` and `ctx.request` both returned HTTP 200
+ data using the browser's live session, on multiple authenticated GraphQL sites.

Scope & limits (measured, honest):
  * Works where the site's CSP allows same-origin fetch from page context. Some
    sites' CSP `connect-src` may block it (recheck per target).
  * Ops guarded by a PER-REQUEST app-generated nonce (a client-transaction-id style
    header) cannot be hand-crafted — reusing/omitting it yields empty/404. For those,
    DRIVE THE UI to let the app issue the request and capture the response, rather
    than synthesizing it.
  * For ops without such nonces, in-context fetch with the captured auth headers works.
"""
from __future__ import annotations
import json, urllib.parse as up

try:
    from astrolabe.browser import launch_context
except ImportError:
    from browser import launch_context  # type: ignore[import-not-found,no-redef]

# fetch() ignores/forbids caller-set cookie/host/user-agent; forward only app auth headers.
DEFAULT_SAFE = ("authorization", "x-csrf-token", "content-type", "x-requested-with",
                "x-api-tenantid", "x-accept-language",
                "x-active-user", "x-auth-type", "x-client-language")


class WarmBrowser:
    def __init__(self, cookies_path, warmup_urls, safe_headers=DEFAULT_SAFE,
                 gql_marker="/graphql", headless=True):
        self.safe = tuple(h.lower() for h in safe_headers)
        self.marker = gql_marker
        self.catalog = {}  # op-key -> {method, url, headers}
        self.ctx = launch_context(headless=headless, stealth_args=True, geoip=True,
                                   locale="en-US", viewport={"width": 1600, "height": 900})
        self.ctx.set_default_navigation_timeout(45000)
        self.ctx.add_cookies(json.load(open(cookies_path)))
        self.page = self.ctx.new_page()
        self.page.on("request", self._capture)
        for u in warmup_urls:
            try:
                self.page.goto(u, wait_until="domcontentloaded")
                self.page.wait_for_timeout(5000)
            except Exception:
                pass

    def _op_key(self, url):
        # last path segment (/graphql/<id>/<Op>) or ?alias= (some sites' convention)
        qs = dict(up.parse_qsl(up.urlparse(url).query))
        if qs.get("alias"):
            return qs["alias"]
        return up.urlparse(url).path.rstrip("/").split("/")[-1]

    def _capture(self, r):
        if self.marker in r.url:
            k = self._op_key(r.url)
            self.catalog.setdefault(k, {
                "method": r.method, "url": r.url,
                "headers": {h: v for h, v in r.headers.items() if h.lower() in self.safe}})

    def execute(self, op_key, url=None, body=None):
        """Re-issue a captured op in-context. Pass url (with new query params) and/or body
        to parameterize. Returns parsed JSON (or {'_status','_len'} if non-JSON/empty)."""
        c = self.catalog.get(op_key)
        if not c:
            return {"error": f"op '{op_key}' not in catalog; warm up a surface that fires it"}
        js = """async (c) => {
          const opt = {method: c.method, headers: c.headers, credentials: 'include'};
          if (c.body != null) opt.body = c.body;
          const r = await fetch(c.url, opt);
          const t = await r.text();
          let j = null; try { j = JSON.parse(t); } catch(e) {}
          return j !== null ? {_status:r.status, data:j} : {_status:r.status, _len:t.length};
        }"""
        return self.page.evaluate(js, {"method": c["method"], "headers": c["headers"],
                                       "url": url or c["url"], "body": body})

    def close(self):
        try:
            self.ctx.close()
        except Exception:
            pass
