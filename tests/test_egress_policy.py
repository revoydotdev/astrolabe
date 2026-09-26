"""The browser egress policy, asserted at every layer that can change it.

Three things decide what the capture browser fetches outside the target's own
domain: the operator's policy, an active recipe drive, and the request itself.
Each is asserted against a real two-origin fixture rather than a unit double,
because the failure this guards is silent -- an over-permissive policy looks
exactly like a page that failed to load.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from astrolabe import cli
from astrolabe.mapping_mcp import create_server
from astrolabe.security import (
    EGRESS_ALLOW_THIRD_PARTY,
    EGRESS_ENV,
    EGRESS_FIRST_PARTY_ONLY,
    egress_policy,
    third_party_egress,
)

ROOT = Path(__file__).resolve().parent.parent
SHOP = "shop.astrolabe.test"
CDN = "cdn.astrolabe.test"


# ---- policy resolution -------------------------------------------------------


def test_policy_defaults_to_allowing_third_party_when_unset(monkeypatch):
    monkeypatch.delenv(EGRESS_ENV, raising=False)
    assert egress_policy() == EGRESS_ALLOW_THIRD_PARTY


def test_policy_is_operator_config(monkeypatch):
    monkeypatch.setenv(EGRESS_ENV, f"  {EGRESS_FIRST_PARTY_ONLY.upper()}  ")
    assert egress_policy() == EGRESS_FIRST_PARTY_ONLY


def test_unknown_policy_is_an_error_not_a_silent_permissive_fallback(monkeypatch):
    """A typo must not leave the permissive default in place while reporting a control."""
    monkeypatch.setenv(EGRESS_ENV, "first-party")
    with pytest.raises(ValueError, match=EGRESS_ENV):
        egress_policy()


@pytest.mark.parametrize(
    ("policy", "recipe_active", "expected"),
    [
        (EGRESS_ALLOW_THIRD_PARTY, False, (False, None)),
        (EGRESS_FIRST_PARTY_ONLY, False, (True, "egress-policy")),
        # A recipe drive is strict under either operator policy.
        (EGRESS_ALLOW_THIRD_PARTY, True, (True, "recipe-egress-policy")),
        (EGRESS_FIRST_PARTY_ONLY, True, (True, "recipe-egress-policy")),
    ],
)
def test_third_party_egress_decision(policy, recipe_active, expected):
    assert third_party_egress(policy=policy, recipe_active=recipe_active) == expected


def test_preflight_reports_the_active_policy(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: _Done())
    monkeypatch.setenv(EGRESS_ENV, EGRESS_FIRST_PARTY_ONLY)
    hp = cli.prof.resolve_profile(host="local", config_path=None)
    info = cli.preflight(hp, verbose=True)
    assert info["browser_egress_policy"] == EGRESS_FIRST_PARTY_ONLY
    assert f"browser_egress_policy {EGRESS_FIRST_PARTY_ONLY}" in capsys.readouterr().out


class _Done:
    stdout = ""
    returncode = 0


def test_a_bad_policy_fails_the_capture_before_a_browser_opens(tmp_path, monkeypatch):
    """The gate is up front, so an unusable policy costs no browser and no partial dir."""
    monkeypatch.setenv(EGRESS_ENV, "nope")
    out = tmp_path / "capture"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "astrolabe.capture",
            "--base-domain",
            "example.com",
            "--outdir",
            str(out),
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode != 0
    assert EGRESS_ENV in result.stderr
    assert not list(out.iterdir()), "the run wrote capture artifacts before validating the policy"


# ---- the tool surface --------------------------------------------------------

POLICY_ARGS = {"egress", "egress_policy", "browser_egress", "browser_egress_policy", "policy"}


@pytest.mark.asyncio
async def test_no_tool_exposes_an_egress_policy_argument(tmp_path):
    """Operator-owned, like every other authorization control: a comment is not a gate."""
    async with Client(create_server(tmp_path)) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    assert tools, "no tools were advertised"
    for name, tool in tools.items():
        properties = set((tool.input_schema or {}).get("properties") or {})
        assert not (properties & POLICY_ARGS), (
            f"{name} exposes operator-owned {sorted(properties & POLICY_ARGS)}"
        )


@pytest.mark.asyncio
async def test_calling_a_tool_with_a_policy_argument_is_refused(tmp_path):
    async with Client(create_server(tmp_path)) as client:
        with pytest.raises(ToolError):
            await client.call_tool(
                "map_site", {"domain": "example.com", "egress_policy": EGRESS_FIRST_PARTY_ONLY}
            )


# ---- the real thing: two origins, one browser --------------------------------


def _chromium_binary() -> str | None:
    try:
        import cloakbrowser

        info = cloakbrowser.binary_info()
    except Exception:
        return None
    return info["binary_path"] if info.get("installed") else None


BINARY = _chromium_binary()
needs_browser = pytest.mark.skipif(BINARY is None, reason="no local Chromium for e2e capture")

PAGE = """<!doctype html>
<html><body>
<script src="http://{cdn}/lib.js"></script>
<button id="load-cdn" onclick="
  var s = document.createElement('script');
  s.src = 'http://{cdn}/after-click.js';
  document.head.appendChild(s);">load</button>
<script>fetch('/api/hello').then(function (r) {{ return r.json(); }});</script>
</body></html>"""


class ShopHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _send(self, status, body, content_type):
        payload = body.encode()
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        if self.path == "/":
            self._send(200, PAGE.format(cdn=CDN), "text/html")
        elif self.path == "/api/hello":
            self._send(200, '{"ok":true}', "application/json")
        else:
            self._send(404, "{}", "application/json")


class CdnHandler(BaseHTTPRequestHandler):
    fetched: list[str] = []

    def log_message(self, *_args):
        pass

    def do_GET(self):  # noqa: N802
        type(self).fetched.append(self.path)
        payload = b"window.__cdn = true;"
        self.send_response(200)
        self.send_header("content-type", "application/javascript")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def origins():
    CdnHandler.fetched = []
    servers = [
        ThreadingHTTPServer(("127.0.0.1", 0), handler) for handler in (ShopHandler, CdnHandler)
    ]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield tuple(server.server_address[1] for server in servers)
    finally:
        for server in servers:
            server.shutdown()


# The fixture hosts are loopback by construction, so the child disables only the
# public-DNS check and injects the resolver rules its launched Chromium needs.
CHILD = """
import sys
import astrolabe.security as security
security.resolve_public_addresses = lambda *args, **kwargs: None
import astrolabe.capture as capture
rules = sys.argv.pop(1)
launch = capture.launch_context
capture.launch_context = lambda **kw: launch(**kw, args=[rules])
capture.main()
"""

RECIPE = {
    "schema_version": 1,
    "actions": [
        {
            "action": "click",
            "selector": "#load-cdn",
            "safe_annotation": "load the second-origin script the page itself requests",
        },
        {"action": "wait", "milliseconds": 400},
    ],
}


def _run_capture(tmp_path, ports, *, policy=None, recipe=False):
    shop, cdn = ports
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    env.pop(EGRESS_ENV, None)
    if policy is not None:
        env[EGRESS_ENV] = policy
    args = [
        "--base-domain",
        SHOP,
        "--outdir",
        str(tmp_path / "capture"),
        "--seeds",
        f"http://{SHOP}/",
        "--settle-ms",
        "600",
    ]
    if recipe:
        path = tmp_path / "recipe.json"
        path.write_text(json.dumps(RECIPE))
        args += ["--recipe", str(path)]
    rules = f"--host-resolver-rules=MAP {SHOP} 127.0.0.1:{shop},MAP {CDN} 127.0.0.1:{cdn}"
    result = subprocess.run(
        [sys.executable, "-c", CHILD, rules, *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    out = tmp_path / "capture"
    records = [json.loads(line) for line in (out / "capture.jsonl").read_text().splitlines()]
    return json.loads((out / "meta.json").read_text()), records


def _cross_origin_truncations(meta):
    return [t for t in meta["request_budgets"]["truncations"] if t["origin"] == f"http://{CDN}"]


@needs_browser
def test_default_policy_fetches_the_second_origin_without_recording_it(tmp_path, origins):
    """Allowed and recorded stay different things: fetched, never captured."""
    meta, records = _run_capture(tmp_path, origins)
    assert meta["egress_policy"] == EGRESS_ALLOW_THIRD_PARTY
    assert "/lib.js" in CdnHandler.fetched, "the second origin was not reached at all"
    assert not _cross_origin_truncations(meta)
    assert any(r["url"].endswith("/api/hello") for r in records)
    assert not [r for r in records if CDN in r["url"]], "cross-origin traffic was recorded"


@needs_browser
def test_strict_policy_aborts_the_second_origin_and_records_the_truncation(tmp_path, origins):
    meta, records = _run_capture(tmp_path, origins, policy=EGRESS_FIRST_PARTY_ONLY)
    assert meta["egress_policy"] == EGRESS_FIRST_PARTY_ONLY
    assert CdnHandler.fetched == [], "a strict run still reached the second origin"
    truncations = _cross_origin_truncations(meta)
    assert [t["reason"] for t in truncations] == ["egress-policy"], truncations
    assert meta["request_budgets"]["truncation_count"] >= 1
    # Aborting is not failing: the first-party capture still completed.
    assert meta["partial"] is False
    assert any(r["url"].endswith("/api/hello") for r in records)
    assert not [r for r in records if CDN in r["url"]]


@needs_browser
def test_a_recipe_drive_is_strict_under_the_default_policy(tmp_path, origins):
    """The seed load is permissive; the driven step is not, and the reasons differ."""
    meta, _records = _run_capture(tmp_path, origins, recipe=True)
    assert meta["egress_policy"] == EGRESS_ALLOW_THIRD_PARTY
    assert "/lib.js" in CdnHandler.fetched
    assert "/after-click.js" not in CdnHandler.fetched, "the driven step was not strict"
    assert [t["reason"] for t in _cross_origin_truncations(meta)] == ["recipe-egress-policy"]
