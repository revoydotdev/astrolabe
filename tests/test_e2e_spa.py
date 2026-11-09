"""End-to-end capture against a real browser and a local interaction-gated SPA.

The fixture reproduces the shape that defeated passive capture on a real court
records site: the API calls only fire after typing a name, acknowledging a modal,
and paging. The one double is DNS — the fixture host resolves to loopback inside
Chromium, and astrolabe's public-address check is disabled in the child process —
because the capture safety policy correctly refuses real loopback targets.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "spa"
HOST = "spa.astrolabe.test"
ROOT = Path(__file__).resolve().parent.parent


def _chromium_binary() -> str | None:
    """A Chromium executable for the two tests that launch one as a subprocess.

    Prefers cloakbrowser's bundled build, matching the default backend. Falls
    back to Playwright's, which every environment has after the documented
    `playwright install chromium` -- CI installs only that, because the stealth
    extra is not a dev dependency. Asking cloakbrowser alone made this the only
    skip in a CI run that already had a perfectly good Chromium on disk.
    """
    try:
        import cloakbrowser

        info = cloakbrowser.binary_info()
        if info.get("installed") and Path(info["binary_path"]).exists():
            return info["binary_path"]
    except Exception:
        pass
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            path = pw.chromium.executable_path
    except Exception:
        return None
    return path if path and Path(path).exists() else None


BINARY = _chromium_binary()
pytestmark = pytest.mark.skipif(BINARY is None, reason="no Chromium available for e2e capture")


class Handler(BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []
    header_names: list[set[str]] = []

    def log_message(self, *_args):
        pass

    def _send(self, status, body, content_type, headers=()):
        payload = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(payload)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        type(self).requests.append(("GET", self.path))
        type(self).header_names.append({name.lower() for name in self.headers})
        if self.path in {"/", "/about"}:
            page = "index.html" if self.path == "/" else "about.html"
            self._send(200, (FIXTURES / page).read_text(), "text/html")
        elif self.path == "/publicData/urls.properties":
            self._send(200, "court.url.1=https://example.invalid/a\n", "text/plain")
        elif self.path == "/api/public/termsAccepted":
            self._send(
                200,
                '{"status":"OK"}',
                "application/json",
                [("set-cookie", "SESSION=fixture-session-secret; Path=/api")],
            )
        elif self.path == "/api/public/version":
            self._send(200, '{"version":"3.0.3.5"}', "application/json")
        else:
            self._send(404, "{}", "application/json")

    def do_POST(self):  # noqa: N802
        type(self).requests.append(("POST", self.path))
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if self.path != "/api/public/search":
            self._send(404, "{}", "application/json")
        elif "SESSION=fixture-session-secret" not in (self.headers.get("cookie") or ""):
            self._send(403, '{"error":"terms not accepted"}', "application/json")
        else:
            start = body.get("endingIndex", 0)
            rows = [
                {"caseNumber": f"GT{start + index:08d}-00", "name": "PRIVATE PERSON"}
                for index in range(3)
            ]
            payload = {
                "noOfRecords": 3,
                "hasMoreRecords": "true" if start == 0 else "false",
                "lastResponseIndex": start + 3,
                "searchResults": rows,
            }
            self._send(
                200,
                json.dumps({"context": {"entity": {"status": "SUCCESS", "payload": payload}}}),
                "application/json",
            )


@pytest.fixture
def site():
    Handler.requests = []
    Handler.header_names = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


RECIPE = {
    "schema_version": 1,
    "actions": [
        {
            "action": "search",
            "selector": "#name",
            "value": "synthetic",
            "submit": True,
            "safe_annotation": "read-only name search",
        },
        {
            "action": "click",
            "selector": "#acknowledge",
            "optional": True,
            "safe_annotation": "acknowledge disclaimer",
        },
        {"action": "wait_for", "selector": ".result"},
        {"action": "click", "selector": "#more", "safe_annotation": "load next page"},
    ],
    "active_probes": [{"url": f"http://{HOST}/api/public/version", "method": "GET"}],
}

# Child-process entry point: disable only the public-DNS check (the fixture host is
# loopback by construction) and map the fixture host inside launched Chromium.
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


def _run_capture(tmp_path, port, extra):
    recipe = tmp_path / "recipe.json"
    recipe.write_text(json.dumps(RECIPE))
    out = tmp_path / "capture"
    rules = f"--host-resolver-rules=MAP {HOST} 127.0.0.1:{port}"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            CHILD,
            rules,
            "--base-domain",
            HOST,
            "--outdir",
            str(out),
            "--seeds",
            f"http://{HOST}/",
            "--recipe",
            str(recipe),
            "--crawl",
            "1",
            "--settle-ms",
            "600",
            *extra,
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    records = [json.loads(line) for line in (out / "capture.jsonl").read_text().splitlines()]
    meta = json.loads((out / "meta.json").read_text())
    return out, records, meta


def _assert_interaction_gated_flow_captured(out, records, meta):
    calls = {
        (record["method"], record["url"].split("?")[0], record["status"]) for record in records
    }
    base = f"http://{HOST}"
    assert ("GET", f"{base}/api/public/termsAccepted", 200) in calls
    assert ("POST", f"{base}/api/public/search", 200) in calls
    # The crawl followed a link harvested from the seed page.
    assert ("GET", f"{base}/api/public/version", 200) in calls
    searches = [r for r in records if r["url"].endswith("/api/public/search")]
    assert len(searches) == 2, "the Load More page must be captured after the click settles"
    kinds = {i["id"]: i["kind"] for i in meta["interactions"]}
    assert {kinds[r["interaction_id"]] for r in searches} == {"click"}
    assert searches[0]["resp_shape"]["context"]["entity"]["payload"]["searchResults"]
    assert not [f for f in meta["failures"] if f["category"] == "body-decode"]
    assert meta["partial"] is False
    leaked = "".join(p.read_text(errors="ignore") for p in out.iterdir() if p.is_file())
    assert "fixture-session-secret" not in leaked
    assert "PRIVATE PERSON" not in leaked


def test_launched_browser_captures_interaction_gated_api(tmp_path, site):
    out, records, meta = _run_capture(tmp_path, site, [])
    _assert_interaction_gated_flow_captured(out, records, meta)
    assert any(record.get("_active_probe") for record in records)
    synthetic = {"x-referer", "x-page-unique-id", "x-api-correlation-id"}
    assert all(not (names & synthetic) for names in Handler.header_names)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_attached_browser_captures_without_touching_operator_tabs(tmp_path, site):
    debug_port = _free_port()
    profile = tempfile.mkdtemp(prefix="astrolabe-cdp-")
    browser = subprocess.Popen(
        [
            BINARY,
            "--headless=new",
            f"--remote-debugging-port={debug_port}",
            f"--user-data-dir={profile}",
            f"--host-resolver-rules=MAP {HOST} 127.0.0.1:{site}",
            "--no-first-run",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        endpoint = f"http://127.0.0.1:{debug_port}"
        deadline = time.monotonic() + 30
        while True:
            try:
                urllib.request.urlopen(f"{endpoint}/json/version", timeout=1).read()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
        # The injected resolver rules are unused in attached mode; the browser already maps.
        out, records, meta = _run_capture(tmp_path, site, ["--cdp-endpoint", endpoint])
        _assert_interaction_gated_flow_captured(out, records, meta)
        tabs = json.loads(urllib.request.urlopen(f"{endpoint}/json/list", timeout=5).read())
        pages = [tab for tab in tabs if tab.get("type") == "page"]
        assert [tab["url"] for tab in pages] == ["about:blank"], "operator tab must survive alone"
        assert browser.poll() is None, "detaching must not close the operator's browser"
    finally:
        browser.terminate()
        browser.wait(timeout=15)
        shutil.rmtree(profile, ignore_errors=True)


VERIFY_CHILD = """
import sys
import astrolabe.security as security
security.resolve_public_addresses = lambda *args, **kwargs: None
import astrolabe.contract_verify as verify
rules = sys.argv.pop(1)
launch = verify.launch_context
verify.launch_context = lambda **kw: launch(**kw, args=[rules])
verify.main()
"""


def test_anonymous_verification_re_executes_captured_rest_reads(tmp_path, site):
    out, _records, _meta = _run_capture(tmp_path, site, [])
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    for module in ("astrolabe.analyze", "astrolabe.contract"):
        subprocess.run(
            [sys.executable, "-m", module, str(out)], cwd=ROOT, env=env, check=True, timeout=120
        )
    contract = json.loads((out / "contract.json").read_text())
    assert contract["operations"]["POST /api/public/search"]["type"] == "mutation"
    recipe = tmp_path / "recipe.json"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            VERIFY_CHILD,
            f"--host-resolver-rules=MAP {HOST} 127.0.0.1:{site}",
            "--base-domain",
            HOST,
            "--outdir",
            str(out),
            "--contract",
            str(out / "contract.json"),
            "--urls",
            f"http://{HOST}/about,http://{HOST}/",
            "--recipe",
            str(recipe),
            "--warm-ms",
            "1500",
            "--delay",
            "0",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    verify = json.loads((out / "verify.json").read_text())
    assert verify["GET /api/public/version"]["status"] == 200
    assert verify["GET /api/public/version"]["schema_validated"] is True
    assert verify["GET /api/public/termsAccepted"]["actively_executed"] is True
    # A POST the contract classifies as a write is never replayed.
    assert "POST /api/public/search" not in verify
    subprocess.run(
        [
            sys.executable,
            "-m",
            "astrolabe.contract",
            str(out),
            "--active",
            str(out / "verify.json"),
        ],
        cwd=ROOT,
        env=env,
        check=True,
        timeout=120,
    )
    proven = json.loads((out / "contract.json").read_text())["operations"]
    assert proven["GET /api/public/version"]["status"] == "verified-active"
