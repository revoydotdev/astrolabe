"""Tests for astrolabe.analyze — site-agnostic default categorization + the
optional per-site categories.json override."""

from __future__ import annotations

import json
import os

import pytest

import astrolabe.analyze as analyze

# ---- generic default categorization ---------------------------------------


@pytest.mark.parametrize(
    "op,expected",
    [
        ("addToCart", "Commerce & payments"),
        ("createOrder", "Commerce & payments"),
        ("getProductDetails", "Commerce & payments"),
        ("getFollowers", "Social graph"),
        ("getUserProfile", "Users & profiles"),
        ("sendMessage", "Messaging & notifications"),
        ("searchJobs", "Search & discovery"),
        ("getPostComments", "Content & media"),
        ("updateSettings", "Account & settings"),
    ],
)
def test_generic_categorization_non_other_bucket(op, expected):
    """A plausible e-commerce/social op must land in a sensible non-'Other'
    bucket using the site-agnostic defaults (no vendor-specific tables)."""
    assert analyze.category(op) == expected


def test_no_vendor_tables_in_module():
    """The old vendor-flavored category tables must be gone."""
    assert not hasattr(analyze, "X_CATS")
    assert not hasattr(analyze, "CATS")
    for vendor_term in (
        "dmconversation",
        "tweetdetail",
        "superfollow",
        "jobpost",
        "freelancerprofile",
        "c2h",
        "odesk",
    ):
        for _, pat in analyze.CATS_DEFAULT:
            assert vendor_term not in pat


def test_truly_unrelated_text_falls_to_other():
    assert analyze.category("xyzzyPlughUnmappedThing123") == "Other"


# ---- categories.json override ----------------------------------------------


def test_categories_json_override_applied(tmp_path):
    overrides = [["Box office", r"(ticket|seat|venue|showtime)"]]
    (tmp_path / "categories.json").write_text(json.dumps(overrides))

    cats = analyze.load_categories(str(tmp_path))
    # override bucket comes first, ahead of the generic defaults
    assert cats[0] == ("Box office", r"(ticket|seat|venue|showtime)")
    assert cats[1:] == analyze.CATS_DEFAULT

    assert analyze._categorize("bookTicket", cats) == "Box office"
    # generic defaults still work for ops the override doesn't cover
    assert analyze._categorize("addToCart", cats) == "Commerce & payments"


def test_categories_json_malformed_falls_back_to_defaults(tmp_path):
    (tmp_path / "categories.json").write_text("{not valid json::")
    cats = analyze.load_categories(str(tmp_path))
    assert cats == analyze.CATS_DEFAULT


def test_categories_json_wrong_shape_falls_back_to_defaults(tmp_path):
    # a JSON object instead of a list of [name, regex] pairs
    (tmp_path / "categories.json").write_text(json.dumps({"not": "a list"}))
    cats = analyze.load_categories(str(tmp_path))
    assert cats == analyze.CATS_DEFAULT


def test_categories_json_absent_falls_back_to_defaults(tmp_path):
    cats = analyze.load_categories(str(tmp_path))
    assert cats == analyze.CATS_DEFAULT


def test_categories_json_skips_malformed_entries(tmp_path):
    overrides = [["Box office", r"ticket"], "not-a-pair", [1, 2], ["Only one"]]
    (tmp_path / "categories.json").write_text(json.dumps(overrides))
    cats = analyze.load_categories(str(tmp_path))
    assert cats[0] == ("Box office", r"ticket")
    assert cats[1:] == analyze.CATS_DEFAULT


# ---- render() end-to-end wiring of the override ----------------------------


# ---- evidence-based REST path templating (PathTemplater) -------------------


def _urls(*paths):
    return [f"https://example.com{p}" for p in paths]


def test_thin_evidence_matches_old_path_tmpl_for_single_observation():
    """With only one observation of a position, PathTemplater must fall back
    to path_tmpl()'s lexical guess byte-for-byte -- this is the case that
    keeps the join with mcpgen._template_path (a frozen mirror of the old,
    single-URL path_tmpl) intact."""
    urls = _urls(
        "/api/products/123456",  # 6-digit run -> old regex catches it
        "/api/products/ab",  # non-numeric, single sample -> stays literal
        "/api/session/~abc123",  # tilde-uid pattern
    )
    t = analyze.PathTemplater(urls)
    for u in urls:
        assert t.apply(u) == analyze.path_tmpl(u)


def test_two_digit_id_clustered_with_enough_distinct_samples():
    """/api/user/42 (2 digits) is missed by the old regex entirely. With
    several distinct values observed in the same position, PathTemplater
    must recognise it as a parameter anyway."""
    urls = _urls("/api/user/42", "/api/user/43", "/api/user/44", "/api/user/7", "/api/user/91")
    t = analyze.PathTemplater(urls)
    for u in urls:
        assert t.apply(u) == "/api/user/{id}"
    # the old lexical function, by contrast, never templates a 2-digit id
    assert analyze.path_tmpl(urls[0]) == "/api/user/42"


def test_uuid_clustered_and_named_with_enough_samples():
    urls = _urls(
        "/api/widgets/550e8400-e29b-41d4-a716-446655440000",
        "/api/widgets/6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "/api/widgets/6ba7b811-9dad-11d1-80b4-00c04fd430c8",
        "/api/widgets/16fd2706-8baf-433b-82eb-8c7fada847da",
    )
    t = analyze.PathTemplater(urls)
    for u in urls:
        assert t.apply(u) == "/api/widgets/{uuid}"


def test_distinct_literal_resources_are_not_merged_into_a_parameter():
    """A capture naturally visits many different REST resources sharing a
    prefix (/api/cart, /api/checkout, /api/user, ...). Each resource name is
    repeated across its own traffic, so the position's uniqueness ratio stays
    low -- PathTemplater must NOT collapse these into a bogus {slug}/{id}."""
    urls = []
    for rname, n in (("user", 3), ("cart", 4), ("checkout", 3), ("orders", 2)):
        urls += _urls(*[f"/api/{rname}" for _ in range(n)])
    t = analyze.PathTemplater(urls)
    assert t.apply("https://example.com/api/user") == "/api/user"
    assert t.apply("https://example.com/api/cart") == "/api/cart"
    assert t.apply("https://example.com/api/checkout") == "/api/checkout"
    assert t.apply("https://example.com/api/orders") == "/api/orders"


def test_version_fork_not_collapsed_despite_repeat_traffic():
    urls = []
    for v in ("v1", "v2"):
        urls += _urls(*[f"/api/{v}/widgets" for _ in range(6)])
    t = analyze.PathTemplater(urls)
    assert t.apply("https://example.com/api/v1/widgets") == "/api/v1/widgets"
    assert t.apply("https://example.com/api/v2/widgets") == "/api/v2/widgets"


def test_resource_fork_and_id_space_coexist_under_same_prefix():
    """A literal fork with light repeat traffic (user/cart) and a real,
    high-cardinality id space one level deeper (/api/user/{id}/profile) must
    both be classified correctly in the same templater."""
    urls = []
    for rname, n in (("user", 5), ("cart", 5)):
        urls += _urls(*[f"/api/{rname}" for _ in range(n)])
    urls += _urls(*[f"/api/user/{uid}/profile" for uid in range(20, 30)])
    t = analyze.PathTemplater(urls)
    assert t.apply("https://example.com/api/user") == "/api/user"
    assert t.apply("https://example.com/api/cart") == "/api/cart"
    assert t.apply("https://example.com/api/user/23/profile") == "/api/user/{id}/profile"


def test_build_keys_rest_endpoints_with_evidence_based_templater(tmp_path):
    recs = [
        {"method": "GET", "url": f"https://example.com/api/user/{uid}", "status": 200}
        for uid in (42, 43, 44, 7)
    ]
    meta = {"base_domain": "example.com"}
    ops, rest = analyze.build(recs, meta)
    assert ("GET", "/api/user/{id}") in rest
    assert rest[("GET", "/api/user/{id}")]["n"] == 4


def test_build_excludes_html_navigation_and_static_assets() -> None:
    recs = [
        {
            "method": "GET",
            "url": "https://example.com/app",
            "status": 200,
            "rtype": "document",
            "resp_ct": "text/html",
        },
        {
            "method": "GET",
            "url": "https://example.com/app.js",
            "status": 200,
            "rtype": "script",
            "resp_ct": "application/javascript",
        },
        {
            "method": "GET",
            "url": "https://example.com/api/items",
            "status": 200,
            "rtype": "fetch",
            "resp_ct": "application/json",
        },
    ]
    _, rest = analyze.build(recs, {"base_domain": "example.com"})
    assert list(rest) == [("GET", "/api/items")]
    assert rest[("GET", "/api/items")]["response_kinds"] == {"json-api"}


# ---- websocket_operations() -------------------------------------------------


def test_websocket_operations_normalizes_sent_and_received():
    meta = {
        "websockets": {
            "wss://example.com/socket.io/": {
                "engineio": "4",
                "events_sent": {
                    "presenceSync": {"count": 3, "ns": None, "arg_shape": [{"status": "str"}]},
                },
                "events_received": {
                    "priceUpdate": {
                        "count": 12,
                        "ns": "/prices",
                        "arg_shape": [{"symbol": "str", "price": "float"}],
                    },
                },
            }
        }
    }
    ops = analyze.websocket_operations(meta)
    sent_key = "wss://example.com/socket.io/::sent::presenceSync"
    recv_key = "wss://example.com/socket.io/::received::priceUpdate"
    assert set(ops) == {sent_key, recv_key}

    sent = ops[sent_key]
    assert sent["url"] == "wss://example.com/socket.io/"
    assert sent["event"] == "presenceSync"
    assert sent["direction"] == "sent"
    assert sent["namespace"] is None
    assert sent["calls"] == 3
    assert sent["engineio"] == "4"
    assert sent["input_schema"]["type"] == "array"

    recv = ops[recv_key]
    assert recv["direction"] == "received"
    assert recv["namespace"] == "/prices"
    assert recv["calls"] == 12
    props = recv["input_schema"]["items"]["properties"]
    assert props["symbol"]["type"] == "string"
    assert props["price"]["type"] == "number"


def test_websocket_operations_empty_when_no_websockets():
    assert analyze.websocket_operations({}) == {}
    assert analyze.websocket_operations({"websockets": {}}) == {}


def test_raw_websocket_messages_are_inventoried_as_event_channels():
    operations = analyze.websocket_operations(
        {
            "websockets": {
                "wss://example.com/events": {
                    "engineio": None,
                    "events_sent": {},
                    "events_received": {},
                    "non_socketio": {"sent": 1, "received": 4},
                }
            }
        }
    )
    received = operations["wss://example.com/events::received::raw-message"]
    assert received["direction"] == "received"
    assert received["calls"] == 4
    assert received["engineio"] is None


def test_miscellaneous_protocols_are_inventory_only() -> None:
    records = [
        {
            "url": "https://example.com/rpc",
            "method": "POST",
            "request_shape": {"jsonrpc": "str", "method": "str", "params": {}},
        },
        {
            "url": "https://example.com/trpc/user.list",
            "method": "GET",
            "request_shape": {},
        },
        {
            "url": "https://example.com/Service/Call",
            "method": "POST",
            "request_media_type": "application/grpc-web+proto",
        },
    ]
    inventory = analyze.miscellaneous_operations(
        records,
        {
            "service_workers": ["https://example.com/sw.js"],
            "offline_queues": [{"kind": "indexedDB", "count": 2}],
        },
    )

    assert {item["protocol"] for item in inventory.values()} == {
        "json-rpc",
        "trpc",
        "grpc-web",
        "service-worker",
        "offline-queue",
    }
    assert all(item["executable"] is False for item in inventory.values())


def test_render_emits_websocket_operations_in_endpoints_json(tmp_path):
    meta = {
        "base_domain": "example.com",
        "websockets": {
            "wss://example.com/ws": {
                "engineio": None,
                "events_sent": {"ping": {"count": 1, "ns": None, "arg_shape": None}},
                "events_received": {},
            }
        },
    }
    nops, nrest = analyze.render(str(tmp_path), [], meta)
    inv = json.loads((tmp_path / "endpoints.json").read_text())
    assert "websocket_operations" in inv
    key = "wss://example.com/ws::sent::ping"
    assert inv["websocket_operations"][key]["direction"] == "sent"
    assert inv["websocket_operations"][key]["calls"] == 1
    graph = json.loads((tmp_path / "graph.json").read_text())
    assert graph["event_channels"][0]["sent_events"] == ["ping"]
    event_operation = next(op for op in graph["operations"] if op["protocol"] == "websocket")
    assert event_operation["semantic_kind"] == "mutation"


def test_render_uses_categories_json_override(tmp_path):
    overrides = [["Box office", r"(ticket|seat)"]]
    (tmp_path / "categories.json").write_text(json.dumps(overrides))

    recs = [
        {
            "method": "POST",
            "url": "https://example.com/graphql",
            "status": 200,
            "graphql": [
                {
                    "operationName": "bookTicket",
                    "variables_keys": [],
                    "variables_shape": None,
                    "persistedHash": None,
                    "query": "query bookTicket { id }",
                }
            ],
        },
    ]
    meta = {"base_domain": "example.com", "graphql_endpoints": {"/graphql": {"count": 1}}}

    nops, nrest = analyze.render(str(tmp_path), recs, meta)
    assert nops == 1

    map_md = (tmp_path / "map.md").read_text()
    assert "### Box office" in map_md
    assert os.path.exists(tmp_path / "endpoints.json")


def test_render_emits_fused_discovery_artifact_and_calibrated_coverage(tmp_path):
    (tmp_path / "scan.json").write_text(
        json.dumps(
            {
                "discovery_candidates": [
                    {
                        "kind": "endpoint",
                        "key": "static-graphql",
                        "value": "/graphql",
                        "evidence": [
                            {
                                "source": "js-bundle",
                                "confidence": 0.6,
                                "locator": "app.js",
                            }
                        ],
                        "metadata": {},
                    },
                    {
                        "kind": "navigation-route",
                        "key": "catalog-route",
                        "value": "https://example.com/catalog",
                        "evidence": [
                            {
                                "source": "sitemap",
                                "confidence": 0.85,
                                "locator": "sitemap.xml",
                            }
                        ],
                        "metadata": {},
                    },
                ]
            }
        )
    )
    (tmp_path / "openapi.json").write_text(
        json.dumps({"openapi": "3.1.0", "paths": {"/items": {"get": {"operationId": "items"}}}})
    )
    (tmp_path / "schema.json").write_text(
        json.dumps(
            {"data": {"__schema": {"types": [{"name": "Query", "fields": [{"name": "product"}]}]}}}
        )
    )
    records = [
        {
            "method": "POST",
            "url": "https://example.com/graphql",
            "status": 200,
            "interaction_id": "recipe-1",
            "graphql": [
                {
                    "operationName": "ProductQuery",
                    "semantic_kind": "query",
                    "variables_keys": [],
                    "variables_shape": None,
                    "persistedHash": None,
                    "query": "query ProductQuery { product { id } }",
                }
            ],
        },
        {
            "method": "GET",
            "url": "https://example.com/items",
            "status": 200,
            "resp_ct": "application/json",
        },
    ]
    meta = {
        "base_domain": "example.com",
        "graphql_endpoints": {"/graphql": {"count": 1}},
        "surfaces": ["https://example.com/catalog"],
        "service_workers": ["https://example.com/sw.js"],
        "events": {"introspection": {"enabled": True}},
        "failures": [{"stage": "navigation", "category": "timeout"}],
        "interactions": [
            {
                "id": "recipe-1",
                "kind": "click",
                "surface": "https://example.com/catalog",
                "calls": 1,
                "completed_at": "2026-01-01T00:00:00+00:00",
                "safe_annotation": "read-only pager",
            }
        ],
    }

    analyze.render(str(tmp_path), records, meta)

    discovery = json.loads((tmp_path / "discovery.json").read_text())
    assert {
        "browser-traffic",
        "service-worker",
        "observed-error",
        "recipe",
        "js-bundle",
        "sitemap",
        "openapi",
        "graphql-introspection",
    } <= set(discovery["sources"])
    assert "not absolute" in discovery["coverage"]["claim"]
    assert discovery["coverage"]["static_candidate_coverage"]["ratio"] == 1.0
    assert discovery["coverage"]["navigation_coverage"]["ratio"] == 1.0
    assert discovery["coverage"]["spec_coverage"]["ratio"] == 1.0
    assert discovery["coverage"]["recipe_action_coverage"]["ratio"] == 1.0
    manifest = json.loads((tmp_path / "artifact-manifest.json").read_text())
    assert "discovery.json" in manifest["artifacts"]
