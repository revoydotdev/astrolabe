"""The browser backend layer: backend selection and the CDP attach allowlist.

`validate_cdp_endpoint` is the only thing standing between an operator-supplied
string and `connect_over_cdp()`, which hands over full control of that browser
and every session in it. It is called from mapping_mcp's two session sources and
from the CLI, so it is asserted here directly rather than only through a caller
that might stop calling it.
"""

from __future__ import annotations

import ast
import sys
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

from astrolabe.browser import resolve_backend, validate_cdp_endpoint

BROWSER_ENV = "ASTROLABE_BROWSER"


def _cloakbrowser_present() -> bool:
    try:
        import cloakbrowser  # noqa: F401
    except ImportError:
        return False
    return True


class _BlockCloakbrowser:
    """A meta-path finder that makes `import cloakbrowser` raise.

    Both sides of browser.py's `except ImportError` branch have to be reachable
    from the same test run, and the stealth extra is genuinely installed in some
    environments (this one) and genuinely absent in CI. Blocking the import runs
    the real branch rather than a stubbed replacement of it, and restoring
    sys.modules afterwards means the block cannot leak into another test.
    """

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "cloakbrowser":
            raise ImportError("cloakbrowser is not installed (blocked by tests/test_browser.py)")
        return None


@contextmanager
def _cloakbrowser_absent():
    previous: ModuleType | None = sys.modules.pop("cloakbrowser", None)
    blocker = _BlockCloakbrowser()
    sys.meta_path.insert(0, blocker)
    try:
        yield
    finally:
        sys.meta_path.remove(blocker)
        if previous is not None:
            sys.modules["cloakbrowser"] = previous


# ---- validate_cdp_endpoint: loopback-only ------------------------------------

LOOPBACK_ENDPOINTS = [
    "http://127.0.0.1:9222",
    "ws://127.0.0.1:9222",
    "http://localhost:9222",
    "http://[::1]:9222",
    "ws://[::1]:9222",
    "http://127.0.0.1:1",
    "http://127.0.0.1:65535",
]


@pytest.mark.parametrize("endpoint", LOOPBACK_ENDPOINTS)
def test_loopback_endpoints_are_accepted_unchanged(endpoint):
    assert validate_cdp_endpoint(endpoint) == endpoint


# Every non-loopback host is refused, including ones that are only reachable
# from the host itself: 127.0.0.2 is bound on lo and 0.0.0.0 is this machine's
# wildcard, yet neither is a host astrolabe may attach to.
NON_LOOPBACK_ENDPOINTS = [
    "http://192.168.1.10:9222",
    "https://192.168.1.10:9222",
    "ws://192.168.1.10:9222",
    "http://10.0.0.5:9222",
    "http://example.com:9222",
    "http://attacker.example:9222",
    "http://127.0.0.2:9222",
    "http://127.1:9222",
    "http://0.0.0.0:9222",
    "http://[::ffff:192.168.1.10]:9222",
    "http://169.254.169.254:9222",
    "http://localhost.evil.example:9222",
    "http://localhost@evil.example:9222",
]


@pytest.mark.parametrize("endpoint", NON_LOOPBACK_ENDPOINTS)
def test_non_loopback_hosts_are_refused(endpoint):
    with pytest.raises(ValueError):
        validate_cdp_endpoint(endpoint)


def test_a_refused_host_does_not_leak_an_attachment_path():
    """The refusal is the security property, not the message wording."""
    with pytest.raises(ValueError) as excinfo:
        validate_cdp_endpoint("http://192.168.1.10:9222")
    assert "loopback" in str(excinfo.value)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:9222",
        "file://127.0.0.1:9222",
        "ftp://127.0.0.1:9222",
        "devtools://127.0.0.1:9222",
        "//127.0.0.1:9222",
        "127.0.0.1:9222",
    ],
)
def test_only_http_and_ws_schemes_are_accepted(endpoint):
    with pytest.raises(ValueError):
        validate_cdp_endpoint(endpoint)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://127.0.0.1",
        "ws://127.0.0.1",
        "http://localhost",
        "http://[::1]",
    ],
)
def test_a_missing_port_is_refused(endpoint):
    with pytest.raises(ValueError):
        validate_cdp_endpoint(endpoint)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://user:pw@127.0.0.1:9222",
        "http://user@127.0.0.1:9222",
        "http://127.0.0.1:9222?token=x",
        "http://127.0.0.1:9222#frag",
    ],
)
def test_credentials_query_and_fragment_are_refused(endpoint):
    with pytest.raises(ValueError):
        validate_cdp_endpoint(endpoint)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://127.0.0.1:notaport",
        "http://127.0.0.1:99999",
        "http://127.0.0.1:-1",
        "http://[::1:9222",
    ],
)
def test_malformed_endpoints_are_refused(endpoint):
    with pytest.raises(ValueError):
        validate_cdp_endpoint(endpoint)


@pytest.mark.parametrize("endpoint", ["", "   ", "http://", "ws://", "://", "http:///"])
def test_empty_and_hostless_endpoints_are_refused(endpoint):
    with pytest.raises(ValueError):
        validate_cdp_endpoint(endpoint)


# ---- resolve_backend ---------------------------------------------------------


def test_auto_prefers_cloakbrowser_when_it_is_importable(monkeypatch):
    monkeypatch.delenv(BROWSER_ENV, raising=False)
    expected = "cloakbrowser" if _cloakbrowser_present() else "playwright"
    assert resolve_backend() == expected


def test_auto_falls_back_to_playwright_when_cloakbrowser_is_absent(monkeypatch):
    monkeypatch.delenv(BROWSER_ENV, raising=False)
    with _cloakbrowser_absent():
        assert resolve_backend() == "playwright"


@pytest.mark.parametrize("value", ["playwright", "PLAYWRIGHT", "  playwright  "])
def test_playwright_is_pinned_regardless_of_cloakbrowser(monkeypatch, value):
    monkeypatch.setenv(BROWSER_ENV, value)
    assert resolve_backend() == "playwright"


def test_cloakbrowser_is_pinned_when_the_extra_is_installed(monkeypatch):
    if not _cloakbrowser_present():
        pytest.skip("cloakbrowser is not installed in this environment")
    monkeypatch.setenv(BROWSER_ENV, "cloakbrowser")
    assert resolve_backend() == "cloakbrowser"


def test_pinning_cloakbrowser_without_the_extra_fails_fast(monkeypatch):
    """An explicit pin must not silently fall back to a different engine."""
    monkeypatch.setenv(BROWSER_ENV, "cloakbrowser")
    with _cloakbrowser_absent(), pytest.raises(RuntimeError) as excinfo:
        resolve_backend()
    assert "stealth" in str(excinfo.value)


@pytest.mark.parametrize("value", ["chromium", "", "  ", "cloak browser", "none"])
def test_an_unusable_setting_resolves_to_auto_or_is_rejected(monkeypatch, value):
    """An empty or whitespace-only setting means "auto"; a real typo is a hard error."""
    monkeypatch.setenv(BROWSER_ENV, value)
    if value.strip():
        with pytest.raises(ValueError) as excinfo:
            resolve_backend()
        assert BROWSER_ENV in str(excinfo.value)
    else:
        expected = "cloakbrowser" if _cloakbrowser_present() else "playwright"
        assert resolve_backend() == expected


def test_no_backend_is_imported_at_module_scope():
    """browser.py is deployed flat onto the capture host, where neither engine
    may be installed. A module-scope import would make the file undeployable."""
    from astrolabe import browser as browser_module

    source = Path(browser_module.__file__).read_text(encoding="utf-8")
    for node in ast.parse(source).body:
        if isinstance(node, ast.Import):
            imported = {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported = {(node.module or "").split(".")[0]}
        else:
            continue
        assert not imported & {"cloakbrowser", "playwright"}, (
            f"browser.py imports {sorted(imported)} at module scope"
        )


# ---- the Playwright backend's launch/context split ---------------------------


class _RecordingChromium:
    def __init__(self, launch_kw: dict, context_kw: dict):
        self._launch_kw = launch_kw
        self._context_kw = context_kw

    def launch(self, **kw):
        self._launch_kw.update(kw)
        return self

    def new_context(self, **kw):
        self._context_kw.update(kw)
        return object()

    def close(self):
        return None


class _RecordingDriver:
    def __init__(self, chromium):
        self.chromium = chromium

    def stop(self):
        return None


class _Startable:
    def __init__(self, driver):
        self.driver = driver

    def start(self):
        return self.driver


class _FakeSyncApi(ModuleType):
    sync_playwright: Callable[[], _Startable]


class _FakePlaywrightPkg(ModuleType):
    sync_api: _FakeSyncApi


def _playwright_backend(**kw) -> tuple[dict, dict]:
    """Run `_launch_playwright_context` against a recording `playwright` double.

    Launching Chromium is not something a unit test should need, but *which*
    kwargs reach launch() and which reach new_context() is observable without a
    browser, and that split is exactly what was getting `args` silently dropped.
    Returns the kwargs launch() saw and the kwargs new_context() saw.
    """
    from astrolabe import browser as browser_module

    launch_kw: dict = {}
    context_kw: dict = {}
    sync_api = _FakeSyncApi("playwright.sync_api")
    sync_api.sync_playwright = lambda: _Startable(
        _RecordingDriver(_RecordingChromium(launch_kw, context_kw))
    )
    package = _FakePlaywrightPkg("playwright")
    package.sync_api = sync_api
    saved = {name: sys.modules.get(name) for name in ("playwright", "playwright.sync_api")}
    sys.modules["playwright"] = package
    sys.modules["playwright.sync_api"] = sync_api
    try:
        browser_module._launch_playwright_context(**kw)
    finally:
        for name, previous in saved.items():
            if previous is None:
                del sys.modules[name]
            else:
                sys.modules[name] = previous
    return launch_kw, context_kw


def test_process_args_reach_launch_and_never_new_context():
    rules = ["--host-resolver-rules=MAP a.test 127.0.0.1:1"]
    launch_kw, context_kw = _playwright_backend(headless=True, args=rules, locale="en-US")
    assert launch_kw == {"headless": True, "args": rules}
    assert context_kw == {"locale": "en-US"}


def test_context_options_are_forwarded_and_stealth_knobs_are_dropped():
    launch_kw, context_kw = _playwright_backend(
        headless=False,
        stealth_args=True,
        geoip=True,
        locale="en-US",
        viewport={"width": 1920, "height": 1080},
        ignore_https_errors=True,
        user_agent="UA/1",
        record_har_path="/tmp/c.har",
        record_har_mode="full",
        proxy="http://127.0.0.1:8080",
    )
    assert launch_kw == {"headless": False}
    assert context_kw == {
        "viewport": {"width": 1920, "height": 1080},
        "locale": "en-US",
        "ignore_https_errors": True,
        "record_har_path": "/tmp/c.har",
        "record_har_mode": "full",
        "user_agent": "UA/1",
        "proxy": {"server": "http://127.0.0.1:8080"},
    }
