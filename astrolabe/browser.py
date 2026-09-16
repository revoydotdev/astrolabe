"""Pluggable browser backend for astrolabe's capture/scan/verify/warm engines.

Two backends implement the same surface (`launch_context(**kw) -> BrowserContext`):

  * cloakbrowser — third-party stealth Playwright drop-in (optional extra
    `astrolabe[stealth]`). Used unchanged: `cb.launch_context(**kw)`.
  * playwright   — plain Playwright, always available once the core
    `playwright` dependency is installed and `playwright install chromium`
    has been run. This is what makes `astrolabe map --local` a clone-and-go
    demo with no stealth engine required.

Backend selection is controlled by env var ASTROLABE_BROWSER
(auto|playwright|cloakbrowser, default auto). `auto` prefers cloakbrowser
when it is importable, else falls back to playwright.

Deployed flat onto the capture host's tmpfs alongside capture.py (see
cli.py's CAPTURE_HELPERS), so this module must import cleanly with no
`astrolabe` package on sys.path and without either backend installed —
neither `cloakbrowser` nor `playwright` may be imported at module scope.
"""

from __future__ import annotations

import os

_VALID_BACKENDS = ("auto", "playwright", "cloakbrowser")


def resolve_backend() -> str:
    """Resolve which backend `launch_context()` will use, without launching
    anything. Raises a clear error if `cloakbrowser` is explicitly requested
    but not installed."""
    choice = os.environ.get("ASTROLABE_BROWSER", "auto").strip().lower() or "auto"
    if choice not in _VALID_BACKENDS:
        raise ValueError(f"ASTROLABE_BROWSER={choice!r} is not one of {_VALID_BACKENDS}")
    if choice == "playwright":
        return "playwright"
    if choice == "cloakbrowser":
        if not _cloakbrowser_importable():
            raise RuntimeError(
                "ASTROLABE_BROWSER=cloakbrowser but the cloakbrowser package is not "
                "installed. Install it with `pip install astrolabe[stealth]`."
            )
        return "cloakbrowser"
    # auto
    return "cloakbrowser" if _cloakbrowser_importable() else "playwright"


def _cloakbrowser_importable() -> bool:
    try:
        import cloakbrowser  # noqa: F401
    except ImportError:
        return False
    return True


def launch_context(**kw):
    """Launch a browser context on the resolved backend. Returns an object
    that supports the Playwright BrowserContext surface actually used by
    astrolabe's engines: set_default_navigation_timeout, add_cookies,
    new_page, on, route, close."""
    backend = resolve_backend()
    if backend == "cloakbrowser":
        import cloakbrowser as cb

        return cb.launch_context(**kw)
    return _launch_playwright_context(**kw)


def _launch_playwright_context(**kw):
    from playwright.sync_api import sync_playwright

    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch(headless=kw.get("headless", True))
    except Exception:
        pw.stop()
        raise
    # stealth_args/geoip are cloakbrowser-only stealth knobs; plain Playwright
    # has no equivalent, so they are dropped rather than translated.
    opts = {
        key: kw[key]
        for key in (
            "viewport",
            "locale",
            "ignore_https_errors",
            "record_har_path",
            "record_har_mode",
        )
        if key in kw
    }
    if kw.get("proxy"):
        opts["proxy"] = {"server": kw["proxy"]}
    try:
        ctx = browser.new_context(**opts)
    except Exception:
        browser.close()
        pw.stop()
        raise
    return _PlaywrightContextProxy(pw, browser, ctx)


class _PlaywrightContextProxy:
    """Forwards to a real Playwright BrowserContext, except close() also
    tears down the browser and the playwright driver. Plain
    `BrowserContext.close()` stops neither, so without this override the
    chromium process and the playwright driver process both leak past the
    caller's `ctx.close()`."""

    def __init__(self, pw, browser, ctx):
        object.__setattr__(self, "_pw", pw)
        object.__setattr__(self, "_browser", browser)
        object.__setattr__(self, "_ctx", ctx)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_ctx"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_ctx"), name, value)

    def close(self, *args, **kwargs):
        ctx = object.__getattribute__(self, "_ctx")
        browser = object.__getattribute__(self, "_browser")
        pw = object.__getattribute__(self, "_pw")
        try:
            ctx.close(*args, **kwargs)
        finally:
            try:
                browser.close()
            finally:
                pw.stop()


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def validate_cdp_endpoint(endpoint: str) -> str:
    """Accept only a loopback DevTools endpoint.

    Attaching grants full control of that browser and every session in it, so a
    remote or LAN endpoint is never a legitimate capture target.
    """
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(endpoint)
        port = parts.port
    except ValueError as exc:
        raise ValueError("malformed CDP endpoint") from exc
    if parts.scheme not in {"http", "ws"} or (parts.hostname or "") not in _LOOPBACK_HOSTS:
        raise ValueError("CDP endpoint must be an http:// or ws:// loopback address")
    if port is None or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("CDP endpoint must be host:port with no credentials or query")
    return endpoint


def connect_context(endpoint: str):
    """Attach to an already-running Chromium over CDP and use its default context.

    The operator's existing session (cookies, logins, challenge clearance) is reused
    as-is. close() closes only the pages astrolabe opened and then disconnects; the
    browser and the operator's own tabs keep running.
    """
    from playwright.sync_api import sync_playwright

    validate_cdp_endpoint(endpoint)
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.connect_over_cdp(endpoint)
    except Exception:
        pw.stop()
        raise
    if not browser.contexts:
        browser.close()
        pw.stop()
        raise RuntimeError("attached browser exposes no default context")
    return _AttachedContextProxy(pw, browser, browser.contexts[0])


class _AttachedContextProxy:
    """Forwards to the attached browser's default context, tracking owned pages."""

    attached = True

    def __init__(self, pw, browser, ctx):
        object.__setattr__(self, "_pw", pw)
        object.__setattr__(self, "_browser", browser)
        object.__setattr__(self, "_ctx", ctx)
        object.__setattr__(self, "_pages", [])

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_ctx"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_ctx"), name, value)

    def new_page(self):
        page = object.__getattribute__(self, "_ctx").new_page()
        object.__getattribute__(self, "_pages").append(page)
        return page

    def close(self, *_args, **_kwargs):
        try:
            for page in object.__getattribute__(self, "_pages"):
                try:
                    page.close()
                except Exception:
                    pass  # A page the operator already closed needs no cleanup.
        finally:
            try:
                # For a CDP connection this disconnects; it does not close the browser.
                object.__getattribute__(self, "_browser").close()
            finally:
                object.__getattribute__(self, "_pw").stop()
