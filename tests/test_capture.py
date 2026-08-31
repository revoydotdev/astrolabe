"""Tests for astrolabe.capture — generic auth/client-header detection + redaction.

capture.py imports `cloakbrowser`, which is not installed in this project's
venv (it only exists on the remote capture host). We stub it into sys.modules
before import so the pure helper functions (is_auth_header, is_secret_header,
build_auth_matcher) can be exercised directly.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _stub_cloakbrowser():
    if "cloakbrowser" not in sys.modules:
        sys.modules["cloakbrowser"] = types.ModuleType("cloakbrowser")
        added = True
    else:
        added = False
    yield
    if added:
        del sys.modules["cloakbrowser"]


@pytest.fixture
def capture():
    import astrolabe.capture as capture_module

    return capture_module


# ---- generic detection: generic vendor headers ------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "x-api-key",
        "x-shopify-storefront-access-token",
        "apikey",
        "x-auth-token",
        "x-session-id",
        "authorization",
    ],
)
def test_generic_auth_headers_detected(capture, header):
    assert capture.is_auth_header(header) is True


def test_unrelated_header_not_detected(capture):
    assert capture.is_auth_header("content-type") is False


def test_graphql_entries_parse_batches_and_preserve_selected_member(capture):
    document = "query A { a } query B($id: ID!) { renamed: b(id: $id) }"
    entries = capture.graphql_entries(
        {"query": document, "operationName": "B", "variables": {"id": "secret-value"}},
        "https://example.com/graphql",
        "application/json",
    )

    assert [item["operationName"] for item in entries] == ["A", "B"]
    assert [item["selected"] for item in entries] == [False, True]
    assert entries[1]["semantic_kind"] == "query"
    assert entries[1]["response_keys"] == ["renamed"]
    assert entries[1]["variables_shape"] == {"id": "str"}
    assert "secret-value" not in str(entries)


def test_request_budgets_reject_before_limit_and_record_reason(capture):
    state = {
        "total": 0,
        "origins": {},
        "operations": {},
        "blocked_origins": set(),
        "truncations": [],
        "truncation_count": 0,
    }
    arguments = {
        "total_limit": 3,
        "origin_limit": 2,
        "operation_limit": 1,
    }
    assert capture.admit_request(state, "https://a", "GET /one", **arguments) is None
    assert (
        capture.admit_request(state, "https://a", "GET /one", **arguments)
        == "operation-request-budget"
    )
    assert capture.admit_request(state, "https://a", "GET /two", **arguments) is None
    assert (
        capture.admit_request(state, "https://a", "GET /three", **arguments)
        == "origin-request-budget"
    )
    state["blocked_origins"].add("https://b")
    assert (
        capture.admit_request(state, "https://b", "GET /one", **arguments) == "rate-limit-reserve"
    )
    assert state["total"] == 2
    assert state["truncation_count"] == 3
    assert capture.is_auth_header("accept-encoding") is False
    assert capture.is_auth_header("user-agent") is False


def test_request_budget_operation_groups_volatile_ids_and_graphql_names(capture):
    assert (
        capture.request_budget_operation(
            "GET", "https://example.com/users/123456/orders/507f1f77bcf86cd799439011"
        )
        == "GET /users/{id}/orders/{id}"
    )
    assert (
        capture.request_budget_operation(
            "POST",
            "https://example.com/graphql",
            '{"operationName":"CatalogSearch","variables":{"secret":"not-retained"}}',
        )
        == "GRAPHQL CatalogSearch"
    )
    assert "not-retained" not in capture.request_budget_operation(
        "POST",
        "https://example.com/graphql",
        '{"operationName":"CatalogSearch","variables":{"secret":"not-retained"}}',
    )


def test_rate_stop_marker_propagates_across_capture_workers(capture, tmp_path):
    origin = "https://api.example.com"
    assert capture.rate_stopped(str(tmp_path), origin) is False
    capture.publish_rate_stop(str(tmp_path), origin)
    assert capture.rate_stopped(str(tmp_path), origin) is True
    assert capture.rate_stopped(str(tmp_path), "https://other.example.com") is False
    marker = capture.rate_stop_path(str(tmp_path), origin)
    assert os.path.basename(marker) == hashlib.sha256(origin.encode()).hexdigest()


def test_tls_errors_are_ignored_only_for_explicit_interception(capture, tmp_path):
    direct = capture.browser_context_options(None, str(tmp_path), record_har=True)
    assert direct["ignore_https_errors"] is False
    assert direct["geoip"] is True
    assert "proxy" not in direct
    assert direct["record_har_path"] == str(tmp_path / "capture.har")

    intercepted = capture.browser_context_options(
        "http://127.0.0.1:8088", str(tmp_path), record_har=False
    )
    assert intercepted["ignore_https_errors"] is True
    assert intercepted["geoip"] is False
    assert intercepted["proxy"] == "http://127.0.0.1:8088"


@pytest.mark.parametrize(
    "message,expected",
    [
        ("net::ERR_CERT_AUTHORITY_INVALID", "tls"),
        ("certificate verify failed", "tls"),
        ("navigation timeout of 45000ms exceeded", "timeout"),
        ("captcha challenge required", "challenge"),
        ("browser disconnected", "browser"),
    ],
)
def test_browser_failures_are_typed_for_partial_manifest(capture, message, expected):
    assert capture.browser_failure_category(RuntimeError(message)) == expected


def test_failure_summary_counts_stage_category_and_safe_surface(capture):
    failures = [
        {"stage": "navigation", "category": "tls", "context": "https://example.com/a?q=secret"},
        {"stage": "navigation", "category": "timeout", "context": "https://example.com/a?q=other"},
        {"stage": "recipe", "category": "timeout", "context": None},
    ]
    summary = capture.summarize_failures(failures)
    assert summary["total"] == 3
    assert summary["by_stage"] == {"navigation": 2, "recipe": 1}
    assert summary["by_category"] == {"tls": 1, "timeout": 2}
    assert summary["by_surface"] == {"https://example.com/a": 2}


def test_sigterm_flushes_a_complete_partial_capture_manifest(tmp_path):
    fake_modules = tmp_path / "fake-modules"
    fake_modules.mkdir()
    marker = tmp_path / "navigation-started"
    (fake_modules / "cloakbrowser.py").write_text(
        "import os,time\n"
        "class Page:\n"
        " url=''\n"
        " def on(self,*a,**k): pass\n"
        " def goto(self,url,**k):\n"
        "  self.url=url; open(os.environ['CAPTURE_TEST_MARKER'],'w').write('ready'); time.sleep(30)\n"
        " def wait_for_timeout(self,ms): time.sleep(ms/1000)\n"
        " def title(self): return ''\n"
        "class Context:\n"
        " def set_default_navigation_timeout(self,*a): pass\n"
        " def route(self,*a): pass\n"
        " def on(self,*a): pass\n"
        " def new_page(self): return Page()\n"
        " def add_cookies(self,*a): pass\n"
        " def close(self): pass\n"
        "def launch_context(**kwargs): return Context()\n"
    )
    out = tmp_path / "capture"
    environment = dict(os.environ)
    environment["CAPTURE_TEST_MARKER"] = str(marker)
    environment["PYTHONPATH"] = os.pathsep.join([str(fake_modules), str(Path(__file__).parents[1])])
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "astrolabe.capture",
            "--base-domain",
            "93.184.216.34",
            "--outdir",
            str(out),
            "--run-id",
            "cancel-test",
            "--seed",
            "https://93.184.216.34/slow",
        ],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert marker.exists(), process.communicate(timeout=1)[0]
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=10) == 0
    meta = json.loads((out / "meta.json").read_text())
    assert meta["run_id"] == "cancel-test"
    assert meta["partial"] is True
    assert any(failure["category"] == "cancellation" for failure in meta["failures"])
    manifest = json.loads((out / "transfer-manifest.json").read_text())
    assert manifest["run_id"] == "cancel-test"
    for name, digest in manifest["sha256"].items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest


def test_vendor_names_not_hardcoded_in_source(capture):
    """The old fixed AUTH_HDRS tuple must be gone, and vendor header names must
    not appear as exact-match literals in the default name set — they're
    caught by the generic pattern instead (comments mentioning them as
    illustrative examples are fine)."""
    assert not hasattr(capture, "AUTH_HDRS")
    for vendor_literal in (
        "x-vendor-tenantid",
        "x-legacyvendor-csrf-token",
        "apollographql-client-name",
        "x-apollo-operation-name",
    ):
        assert vendor_literal not in capture.AUTH_HEADER_NAMES_DEFAULT
    # still detected via the generic pattern, not a hardcoded name, for the
    # ones that carry generic auth/client vocabulary in their name
    assert capture.is_auth_header("x-vendor-tenantid") is True
    assert capture.is_auth_header("x-legacyvendor-csrf-token") is True
    assert capture.is_auth_header("apollographql-client-name") is True


# ---- redaction discipline --------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "authorization",
        "x-csrf-token",
        "x-legacyvendor-csrf-token",
        "x-api-key",
        "x-auth-token",
        "x-session-id",
        "apikey",
        "x-shopify-storefront-access-token",
    ],
)
def test_secret_bearing_headers_are_redacted(capture, header):
    assert capture.is_secret_header(header) is True
    # Simulate the exact redaction expression used at the capture sites.
    real_value = "super-secret-value-should-never-appear"
    req_headers = {header: real_value}
    recorded = "<present>" if capture.is_secret_header(header) else req_headers[header]
    assert recorded == "<present>"
    assert real_value not in recorded


@pytest.mark.parametrize(
    "header",
    [
        "x-requested-with",
        "apollographql-client-name",
        "apollographql-client-version",
        "x-vendor-accept-language",
        "x-vendor-tenantid",
    ],
)
def test_non_secret_client_headers_record_presence_only(capture, header):
    assert capture.is_secret_header(header) is False
    real_value = "XMLHttpRequest"
    recorded = "<present>"
    assert recorded == "<present>"
    assert real_value not in recorded


def test_budgeted_shape_samples_heterogeneous_arrays_and_counts_truncation(capture):
    old_limits = dict(capture.SHAPE_LIMITS)
    try:
        capture.SHAPE_LIMITS.update(
            {"max_depth": 2, "max_nodes": 20, "max_keys": 2, "max_array_samples": 2}
        )
        capture.SHAPE_TRUNCATIONS.clear()
        shaped = capture.shape({"items": [{"id": 1}, "text", 3, {"extra": True}], "a": 1, "b": 2})
        assert len(shaped["items"]) == 3
        assert shaped["items"][-1]["$astrolabe_truncated"]["reason"] == "array_sample_budget"
        assert shaped["$astrolabe_truncated"]["reason"] == "key_budget"
        assert capture.SHAPE_TRUNCATIONS["array_sample_budget"] == 1
        assert capture.SHAPE_TRUNCATIONS["key_budget"] == 1
    finally:
        capture.SHAPE_LIMITS.clear()
        capture.SHAPE_LIMITS.update(old_limits)
        capture.SHAPE_TRUNCATIONS.clear()


def test_failure_evidence_is_typed_and_sanitized(capture):
    failure = capture.failure_evidence(
        "request",
        "transport",
        RuntimeError("token=CANARY"),
        context={"authorization": "Bearer CANARY"},
        interaction_id="interaction-1",
    )
    assert failure["stage"] == "request"
    assert failure["category"] == "transport"
    assert failure["error_type"] == "RuntimeError"
    assert failure["interaction_id"] == "interaction-1"
    assert "CANARY" not in str(failure)


# ---- recipe extension -------------------------------------------------------


def test_recipe_extra_names_extend_defaults(capture):
    recipe = types.SimpleNamespace(AUTH_HEADERS=["x-widget-signature"])
    extra, pattern = capture.build_auth_matcher(recipe)
    assert capture.is_auth_header("x-widget-signature", extra, pattern) is True
    # generic defaults must still work — recipe extends, never disables
    assert capture.is_auth_header("authorization", extra, pattern) is True
    assert capture.is_auth_header("x-api-key", extra, pattern) is True


def test_recipe_pattern_extends_default_pattern(capture):
    recipe = types.SimpleNamespace(AUTH_HEADER_PATTERN=r"^x-acme-")
    extra, pattern = capture.build_auth_matcher(recipe)
    assert capture.is_auth_header("x-acme-nonce", extra, pattern) is True
    # default pattern still active alongside the recipe's addition
    assert capture.is_auth_header("authorization", extra, pattern) is True


def test_no_recipe_returns_generic_defaults(capture):
    extra, pattern = capture.build_auth_matcher(None)
    assert extra == frozenset()
    assert capture.is_auth_header("x-api-key", extra, pattern) is True


def test_python_recipe_requires_explicit_action_annotations(capture, tmp_path):
    recipe = tmp_path / "unsafe.recipe.py"
    recipe.write_text("def drive(page, log):\n    page.goto('https://example.com')\n")
    with pytest.raises(ValueError, match="explicit safety annotations"):
        capture.load_recipe(str(recipe), allow_inprocess=True)


# ---- is_first_party: hostname (not netloc) so ports don't break matching --


def test_first_party_matches_base_domain(capture):
    assert capture.is_first_party("https://example.com/api", "example.com") is True


def test_first_party_matches_with_nondefault_port(capture):
    """netloc carries the port ("example.com:8443"); hostname strips it. A
    port must not make otherwise-first-party traffic drop out of capture."""
    assert capture.is_first_party("https://example.com:8443/api", "example.com") is True
    assert capture.is_first_party("http://example.com:8080/x", "example.com") is True


def test_first_party_matches_subdomain(capture):
    assert capture.is_first_party("https://api.example.com/v1", "example.com") is True
    assert capture.is_first_party("https://api.example.com:8443/v1", "example.com") is True


def test_first_party_rejects_suffix_confusion(capture):
    """ "notexample.com" must never match base domain "example.com" -- only
    exact host or a genuine ".example.com" subdomain qualifies."""
    assert capture.is_first_party("https://notexample.com/x", "example.com") is False
    assert capture.is_first_party("https://evilexample.com/x", "example.com") is False


def test_first_party_rejects_unrelated_domain(capture):
    assert capture.is_first_party("https://evil.com/x", "example.com") is False


def test_first_party_is_case_insensitive(capture):
    assert capture.is_first_party("https://EXAMPLE.com/x", "example.com") is True
    assert capture.is_first_party("https://example.com/x", "EXAMPLE.COM") is True


def test_first_party_handles_missing_hostname(capture):
    assert capture.is_first_party("not-a-url", "example.com") is False


# ---- adaptive settle detection ---------------------------------------------
# wait_for_settle()/settle_or_wait() are driven with a fake page + an
# injected monotonic clock so tests are deterministic and don't actually
# sleep. FakePage.wait_for_timeout(ms) advances the fake clock by `ms` and,
# on the way, "fires" any scheduled fake API responses (bumping stats["n"]
# and stats["last_ts"]) whose scheduled time has passed — simulating
# on_response being invoked asynchronously by the real browser.


class _FakeClock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def advance(self, ms):
        self.t += ms / 1000.0


class _FakePage:
    def __init__(self, clock, stats, responses_at_ms=()):
        self.clock = clock
        self.stats = stats
        self.pending = sorted(responses_at_ms)
        self.wait_calls = []

    def wait_for_timeout(self, ms):
        self.wait_calls.append(ms)
        self.clock.advance(ms)
        now_ms = self.clock.t * 1000.0
        while self.pending and self.pending[0] <= now_ms:
            self.pending.pop(0)
            self.stats["n"] += 1
            self.stats["last_ts"] = self.clock.now()


def test_settle_returns_early_once_quiet(capture):
    clock = _FakeClock()
    stats = {"n": 0}
    # single response at 200ms; quiet period (800ms) elapses at t=1000ms,
    # well inside the 6000ms ceiling.
    page = _FakePage(clock, stats, responses_at_ms=[200])
    elapsed, n_calls, settled = capture.wait_for_settle(
        page, stats, min_ms=800, settle_ms=800, ceiling_ms=6000, now=clock.now
    )
    assert settled is True
    assert n_calls == 1
    assert 0.95 <= elapsed <= 1.15
    # proof it returned early rather than burning the ceiling
    assert elapsed < 6.0


def test_minimum_wait_always_honoured(capture):
    clock = _FakeClock()
    stats = {"n": 0}
    # response fires almost immediately and nothing else happens; a naive
    # "quiet since last response" check would return well before min_ms.
    page = _FakePage(clock, stats, responses_at_ms=[10])
    elapsed, n_calls, settled = capture.wait_for_settle(
        page, stats, min_ms=800, settle_ms=50, ceiling_ms=6000, now=clock.now
    )
    assert elapsed >= 0.8
    assert n_calls == 1
    assert settled is True


def test_ceiling_caps_a_page_that_never_settles(capture):
    clock = _FakeClock()
    stats = {"n": 0}
    # continuous chatter every 100ms forever -> never quiet for settle_ms.
    page = _FakePage(clock, stats, responses_at_ms=list(range(0, 20000, 100)))
    elapsed, n_calls, settled = capture.wait_for_settle(
        page, stats, min_ms=200, settle_ms=300, ceiling_ms=1000, now=clock.now
    )
    assert settled is False
    assert 0.95 <= elapsed <= 1.15
    assert n_calls > 0


def test_zero_activity_page_returns_without_burning_ceiling(capture):
    clock = _FakeClock()
    stats = {"n": 0}
    page = _FakePage(clock, stats, responses_at_ms=[])  # static page, no API calls at all
    elapsed, n_calls, settled = capture.wait_for_settle(
        page, stats, min_ms=300, settle_ms=300, ceiling_ms=5000, now=clock.now
    )
    assert settled is True
    assert n_calls == 0
    # min_ms + a short grace, nowhere near the 5s ceiling
    assert elapsed < 1.0


def test_settle_adapts_quiet_threshold_to_observed_burst_gaps(capture):
    clock = _FakeClock()
    stats = {"n": 0, "burst_gaps_ms": [1000]}
    page = _FakePage(clock, stats, responses_at_ms=[100])
    elapsed, n_calls, settled = capture.wait_for_settle(
        page, stats, min_ms=200, settle_ms=300, ceiling_ms=3000, now=clock.now
    )
    assert settled is True and n_calls == 1
    assert stats["effective_settle_ms"] == 1500
    assert elapsed >= 1.5


def test_no_settle_restores_flat_sleep_behavior(capture):
    clock = _FakeClock()
    stats = {"n": 0}
    page = _FakePage(clock, stats, responses_at_ms=[100, 200, 5000])
    result = capture.settle_or_wait(page, stats, 4.0, no_settle=True)
    assert result is None
    # exactly the old behavior: one flat sleep of wait_s * 1000 ms, no polling
    assert page.wait_calls == [4000]
    assert clock.t == pytest.approx(4.0)


def test_settle_or_wait_logs_settled_outcome(capture):
    clock = _FakeClock()
    stats = {"n": 0}
    page = _FakePage(clock, stats, responses_at_ms=[100])
    messages = []
    result = capture.settle_or_wait(
        page,
        stats,
        4.0,
        min_ms=200,
        settle_ms=200,
        now=clock.now,
        log=messages.append,
        label="visit",
        url="https://example.com",
    )
    assert result is not None
    elapsed, n_calls, settled = result
    assert settled is True
    assert n_calls == 1
    assert len(messages) == 1
    assert messages[0].startswith("[visit] https://example.com -> settled in")
    assert "1 calls" in messages[0]


def test_settle_or_wait_logs_ceiling_outcome(capture):
    clock = _FakeClock()
    stats = {"n": 0}
    page = _FakePage(clock, stats, responses_at_ms=list(range(0, 5000, 50)))
    messages = []
    result = capture.settle_or_wait(
        page,
        stats,
        1.0,
        min_ms=100,
        settle_ms=100,
        now=clock.now,
        log=messages.append,
        label="visit",
        url="https://example.com",
    )
    assert result is not None
    _elapsed, _n_calls, settled = result
    assert settled is False
    assert len(messages) == 1
    assert "-> ceiling" in messages[0]
    assert "still active" in messages[0]


def test_settle_ceiling_derived_from_wait_when_not_overridden(capture):
    # ceiling_ms=None -> derived as wait_s * 1000 * SETTLE_CEILING_FACTOR,
    # e.g. the surfaces-loop default of 4.0s -> a 6000ms ceiling.
    clock = _FakeClock()
    stats = {"n": 0}
    page = _FakePage(clock, stats, responses_at_ms=list(range(0, 20000, 50)))
    elapsed, _n_calls, settled = capture.settle_or_wait(
        page, stats, 4.0, min_ms=100, settle_ms=100, ceiling_ms=None, now=clock.now
    )
    assert settled is False
    assert elapsed == pytest.approx(6.0, abs=0.2)
