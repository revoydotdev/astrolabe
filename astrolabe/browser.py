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
