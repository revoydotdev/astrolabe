"""Tests for astrolabe.scan — import safety and recipe scaffolding."""

from __future__ import annotations

import threading
import time

import astrolabe.scan as scan


def test_scan_module_imports():
    """Regression guard: astrolabe/scan.py must parse on the declared floor (3.11).

    Line 427 previously used PEP 701 f-string syntax (backslash + reused quote
    char inside the {} expression) that only parses on Python 3.12+, breaking
    `import astrolabe.scan` on the project's declared >=3.11 floor.
    """
    assert hasattr(scan, "scaffold_recipe")


def test_sitemap_discovery_parallelizes_with_total_and_origin_budgets(monkeypatch):
    active = 0
    peak = 0
    fetched: list[str] = []
    lock = threading.Lock()

    monkeypatch.setattr(
        scan,
        "_robots_sitemaps",
        lambda *_args, **_kwargs: [
            "https://example.com/a.xml",
            "https://example.com/b.xml",
            "https://example.com/c.xml",
        ],
    )
    monkeypatch.setattr(scan, "validate_url", lambda url, *_args, **_kwargs: url)

    def fetched_body(url, **_kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            fetched.append(url)
        time.sleep(0.02)
        with lock:
            active -= 1
        return f"<urlset><url><loc>{url.removesuffix('.xml')}/page</loc></url></urlset>"

    monkeypatch.setattr(scan, "fetch", fetched_body)
    urls = scan.sitemap_urls(
        "https://example.com/",
        log=lambda _message: None,
        concurrency=2,
        max_requests=4,
        max_origin_requests=4,
    )

    assert peak == 2
    assert len(fetched) == 3
    assert urls == [
        "https://example.com/a/page",
        "https://example.com/b/page",
        "https://example.com/c/page",
    ]


def test_sitemap_discovery_denies_robots_declared_third_party_without_exact_opt_in(monkeypatch):
    fetched = []
    decisions = []
    monkeypatch.setattr(
        scan,
        "_robots_sitemaps",
        lambda *_args, **_kwargs: ["https://cdn.example.net/site.xml"],
    )
    monkeypatch.setattr(scan, "validate_url", lambda url, *_args, **_kwargs: url)

    def fetch(url, **_kwargs):
        fetched.append(url)
        return "<urlset></urlset>"

    monkeypatch.setattr(scan, "fetch", fetch)
    scan.sitemap_urls(
        "https://example.com/",
        log=lambda _message: None,
        audit_decision=lambda *row: decisions.append(row),
    )
    assert fetched == ["https://example.com/sitemap.xml"]
    assert ("https://cdn.example.net/site.xml", False, "third-party-sitemap-denied") in decisions


def test_sitemap_request_ceiling_counts_robots_as_first_request(monkeypatch):
    monkeypatch.setattr(scan, "_robots_sitemaps", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(scan, "validate_url", lambda url, *_args, **_kwargs: url)
    fetched = []
    monkeypatch.setattr(scan, "fetch", lambda url, **_kwargs: fetched.append(url) or "")
    scan.sitemap_urls("https://example.com/", max_requests=1, log=lambda _message: None)
    assert fetched == []  # the mocked robots call represents the one admitted request


def test_integrated_static_mining_is_text_only_and_denies_unapproved_bundle_hosts():
    class Page:
        def eval_on_selector_all(self, *_args):
            return [
                "https://example.com/app.js",
                "https://cdn.example.net/foreign.js",
            ]

        def evaluate(self, _script, url):
            if url == "https://example.com/app.js":
                return {
                    "body": "const q={operationName:'ItemsQuery',url:'/graphql'}",
                    "content_type": "application/javascript",
                }
            raise RuntimeError("HTTP 404")

    decisions = []
    result = scan.mine_static_discovery(
        Page(),
        "https://example.com",
        log=lambda _message: None,
        audit_decision=lambda *row: decisions.append(row),
    )
    assert {item.value for item in result.candidates} >= {"ItemsQuery", "/graphql"}
    assert all(item.execution_state == "inventory-only" for item in result.candidates)
    assert any(item.startswith("third-party-denied:") for item in result.truncations)
    assert ("https://cdn.example.net/foreign.js", False, "third-party-denied") in decisions


def test_scaffold_recipe_emits_data_hook_hint():
    """scaffold_recipe() must still emit the `[data-hook="..."]` selector hint
    line for buckets with observed data-hook/testid vocabulary — this is the
    exact line that broke under Python 3.11's stricter f-string grammar."""
    base_url = "https://example.com"
    surfaces_buckets = {
        "root": ["https://example.com/"],
        "product": ["https://example.com/product/widget"],
    }
    evidence_by_url = {
        "https://example.com/product/widget": {
            "url": "https://example.com/product/widget",
            "anchors": [
                {"h": "/product/other", "t": "Other widget", "same": True},
            ],
            "data_vocab": [
                {"attr": "product-title", "tag": "h1", "cls": "", "t": "Widget"},
                {"attr": "add-to-cart", "tag": "button", "cls": "", "t": "Add"},
            ],
            "click_targets": [
                {
                    "tag": "button",
                    "role": "button",
                    "type": None,
                    "hook": "add-to-cart",
                    "cls": "",
                    "t": "Add",
                },
            ],
            "forms": [],
            "inline_json": {},
            "meta": {},
        },
    }

    text = scan.scaffold_recipe(base_url, surfaces_buckets, evidence_by_url, set())

    assert '# → try: [data-hook="add-to-cart"], [data-hook="product-title"]' in text
    assert "# observed data-hooks/testids:" in text
