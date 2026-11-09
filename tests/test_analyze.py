"""Tests for astrolabe.analyze — site-agnostic default categorization + the
optional per-site categories.json override."""

from __future__ import annotations

import json
import os
import shutil
import tempfile

import pytest

import astrolabe.analyze as analyze
import astrolabe.contract as contract
import astrolabe.mcpgen as mcpgen

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


def test_rpc_style_siblings_with_different_responses_stay_literal():
    """Light traffic to several RPC-style endpoints under one prefix crosses the
    uniqueness ratio, but their responses differ, so they are not one {slug}."""
    envelope = {"status": "str", "closed": "bool", "buffered": "bool"}
    records = [
        ("/api/public/getVersion", {**envelope, "payload": {"version": "str"}}),
        ("/api/public/getVersion", {**envelope, "payload": {"version": "str"}}),
        (
            "/api/public/search",
            {**envelope, "payload": {"noOfRecords": "int", "searchResults": [{"name": "str"}]}},
        ),
        (
            "/api/public/getCaseDetails",
            {**envelope, "payload": {"caseCharge": {"offenseDate": "str"}, "hearings": ["str"]}},
        ),
        ("/api/public/termsAccepted", {"status": "str"}),
    ]
    t = analyze.PathTemplater(_urls(*[p for p, _ in records]), [s for _, s in records])
    for path, _shape in records:
        assert t.apply(f"https://example.com{path}") == path


def test_id_space_with_matching_responses_is_still_parameterized():
    shape = {"id": "int", "name": "str", "email": "str"}
    shapes = [shape, {**shape, "bio": "str"}, shape, shape, shape]
    urls = _urls("/api/user/42", "/api/user/43", "/api/user/44", "/api/user/7", "/api/user/91")
    t = analyze.PathTemplater(urls, shapes)
    assert t.apply(urls[1]) == "/api/user/{id}"


# ---- both branches of the shape predicate, and the exactness of the memo -----
# A perf change to PathTemplater is a correctness change until proven otherwise:
# the memo in _TrieNode._param decides whether a segment is an id or a literal
# fork, and that flows into mcpgen.rest_tool_name and every contract key. The two
# tests below pin BOTH branches, because a benchmark built on the fast branch
# proves nothing about the slow one.

SHARED_ID_SHAPE = {
    "id": "int",
    "name": "str",
    "price": "float",
    "tags": ["str"],
    "vendor": {"id": "int", "name": "str"},
}


def _shared_shape_urls(n):
    return [f"https://shop.example.test/api/products/{i}" for i in range(n)]


def test_shared_response_shape_across_an_id_space_templates():
    """Many ids, ONE response shape: the expensive branch. _distinct_endpoints
    must scan every pair and still return False, so the position templates."""
    urls = _shared_shape_urls(25)
    t = analyze.PathTemplater(urls, [SHARED_ID_SHAPE] * 25)
    for u in urls:
        assert t.apply(u) == "/api/products/{id}"


def test_distinct_response_shape_across_an_id_space_stays_literal():
    """The same id space with a distinct shape per id: _distinct_endpoints returns
    True on the first pair, the templating branch is never taken, and the segment
    must be left literal. This is the branch a shared-shape benchmark skips."""
    urls = _shared_shape_urls(25)
    shapes = [{"id": "int", f"field_{i}": "str"} for i in range(25)]
    t = analyze.PathTemplater(urls, shapes)
    for u in urls:
        assert t.apply(u) == f"/api/products/{urls.index(u)}"


def test_memoized_node_decision_depends_only_on_the_construction_input():
    """The memo must be a pure function of state fixed at construction, so
    repeating a pass, reversing the order, or building a second templater over
    the same records must all give the same answer for the same record. Call
    history cannot leak into a decision.

    (A templater over a *subset* may legitimately differ: fewer than
    MIN_SAMPLES observations is thin evidence, which is the documented fallback
    to path_tmpl()'s lexical guess. That is about the input, not the memo.)"""
    urls = _shared_shape_urls(12) + _urls(
        "/api/public/getVersion",
        "/api/public/getVersion",
        "/api/public/search",
        "/api/public/search",
    )
    shapes = [SHARED_ID_SHAPE] * 12 + [
        {"status": "str", "payload": {"version": "str"}},
        {"status": "str", "payload": {"version": "str"}},
        {"status": "str", "payload": {"results": ["str"]}},
        {"status": "str", "payload": {"results": ["str"]}},
    ]
    first = analyze.PathTemplater(urls, shapes)
    once = [first.apply(u) for u in urls]
    assert once == [first.apply(u) for u in urls], "a second pass changed its own answers"

    shuffled = analyze.PathTemplater(urls[::-1], shapes[::-1])
    assert [shuffled.apply(u) for u in urls] == once, "construction order changed an answer"

    rebuilt = analyze.PathTemplater(urls, shapes)
    assert [rebuilt.apply(u) for u in urls] == once, "a fresh templater disagreed"


# ---- the golden REST/GraphQL projection (byte-for-byte) --------------------
# A performance refactor of the templater that silently moved one path would
# rename one REST tool and invalidate one contract key while every unit test
# still passed. This drives the real render() + mcpgen.build_pack() over a
# committed fixture and compares the whole downstream surface byte-for-byte.
# Regenerate ONLY with deliberate intent:
#   ASTROLABE_BENCH=1 .venv/bin/python -m pytest tests/test_analyze.py -k golden
# then inspect the diff -- a changed byte here is a changed inference, not a
# re-baseline.

TEMPLATING_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "templating")


def _read_fixture(name, binary=False):
    with open(os.path.join(TEMPLATING_FIXTURE, name), "rb" if binary else "r") as handle:
        return handle.read()


def _golden_projection():
    recs = [json.loads(line) for line in _read_fixture("records.jsonl").splitlines()]
    meta = json.loads(_read_fixture("meta.json"))
    with tempfile.TemporaryDirectory() as tmp:
        analyze.render(tmp, recs, meta)
        endpoints = _read_fixture(os.path.join(tmp, "endpoints.json"), binary=True)
        for name in ("records.jsonl", "meta.json"):
            shutil.copy(os.path.join(TEMPLATING_FIXTURE, name), os.path.join(tmp, name))
        packs = {
            f"include_mutations={mutations}": [
                {
                    "name": tool["name"],
                    "operation": tool["operation"],
                    "transport": tool["transport"],
                    "type": tool["type"],
                    "exposed": tool["exposed"],
                    "reason": tool["reason"],
                    "path": tool.get("path"),
                    "method": tool.get("method"),
                    "input_schema": tool.get("input_schema"),
                    "output_schema": tool.get("output_schema"),
                }
                for tool in mcpgen.build_pack(tmp, include_mutations=mutations)["tools"]
            ]
            for mutations in (False, True)
        }
    inv = json.loads(endpoints)
    return {
        "endpoints_json": endpoints.decode(),
        "rest_paths": [[ep["method"], ep["path"], ep["calls"]] for ep in inv["rest_endpoints"]],
        "graphql_operations": sorted(inv["graphql_operations"]),
        "packs": packs,
    }


def test_render_and_mcpgen_reproduce_the_golden_projection_byte_for_byte():
    expected = _read_fixture("golden.json", binary=True)
    actual = (json.dumps(_golden_projection(), indent=2, sort_keys=True) + "\n").encode()
    if actual != expected:
        pytest.fail(
            "analyze/mcpgen output moved. A performance change altered inference -- find "
            "out which path, tool name or schema changed before touching this file.\n"
            + "\n".join(
                __import__("difflib").unified_diff(
                    expected.decode().splitlines(),
                    actual.decode().splitlines(),
                    "golden",
                    "actual",
                    lineterm="",
                    n=1,
                )
            )[:4000]
        )


def _staged_capture_dir(parent):
    """A capture dir shaped exactly as `astrolabe map` leaves it when the contract
    step runs: rendered first (so graph.json exists), with the raw capture alongside."""
    recs = [json.loads(line) for line in _read_fixture("records.jsonl").splitlines()]
    meta = json.loads(_read_fixture("meta.json"))
    # A fixed directory name: build_from_capture falls back to the capture dir's
    # basename for run_id when meta.json has none, and that lands in the contract's
    # observed proof. A random tmp name would make the golden unmatchable.
    tmp = os.path.join(parent, "capture")
    os.mkdir(tmp)
    analyze.render(tmp, recs, meta)
    shutil.copy(
        os.path.join(TEMPLATING_FIXTURE, "records.jsonl"), os.path.join(tmp, "capture.jsonl")
    )
    shutil.copy(os.path.join(TEMPLATING_FIXTURE, "meta.json"), os.path.join(tmp, "meta.json"))
    return tmp


def _golden_contract():
    """Build the durable contract over the same fixture, the way `astrolabe map`
    does: render() first (it writes the graph.json the contract then reads), then
    the real build_from_capture. Kept beside the projection above so one fixture
    guards both the inventory and the contract derived from it."""
    with tempfile.TemporaryDirectory() as parent:
        built = contract.build_from_capture(_staged_capture_dir(parent))
    return json.dumps(built, indent=2, sort_keys=True) + "\n", contract.render_md(built, None)


def test_contract_reproduces_the_golden_projection_byte_for_byte():
    """The contract decides `observed` proof and every contract key, so sharing a
    capture parse between analyze and contract must not be able to move one."""
    expected_json, expected_md = (
        _read_fixture("contract-golden.json"),
        _read_fixture("contract-golden.md"),
    )
    actual_json, actual_md = _golden_contract()
    if actual_json != expected_json or actual_md != expected_md:
        pytest.fail(
            "contract output moved. A loading change altered the evidence a contract "
            "derives -- find which key before touching this file.\n"
            + "\n".join(
                __import__("difflib").unified_diff(
                    (expected_json + expected_md).splitlines(),
                    (actual_json + actual_md).splitlines(),
                    "golden",
                    "actual",
                    lineterm="",
                    n=1,
                )
            )[:4000]
        )


def test_golden_contract_covers_observed_proof_across_transports():
    """Guards the fixture itself: a golden with no observed proof, or with only one
    transport, would stop being evidence that the loading path is intact."""
    built = json.loads(_golden_contract()[0])
    statuses = {op["status"] for op in built["operations"].values()}
    assert "verified-observed" in statuses
    transports = {op["transport"] for op in built["operations"].values()}
    assert {"graphql", "rest"} <= transports
    observed = [op for op in built["operations"].values() if op["proof"]["observed"]["ok"]]
    assert observed and all(
        op["proof"]["observed"]["source"] == "astrolabe-capture" for op in observed
    )


def test_one_capture_parse_per_analyze_to_contract_tail(monkeypatch):
    """Counts parses on the path `astrolabe map` actually takes.

    render() writes graph.json before the contract step, so build_from_capture reads
    the graph and never re-opens capture.jsonl: the tail parses it exactly once, in
    analyze.load. meta.json is the file that was genuinely parsed twice, so this pins
    the count rather than the reasoning -- if the graph ever stops being written, this
    fails instead of quietly becoming a second full parse.
    """
    raw_records = [
        line + "\n" for line in _read_fixture("records.jsonl").splitlines() if line.strip()
    ]
    fixture_lines = set(raw_records)
    record_count = len(raw_records)
    counts = {"capture.jsonl": 0, "meta.json": 0}
    real_loads, real_load = json.loads, json.load

    def counted_loads(payload, *args, **kwargs):
        if payload in fixture_lines:
            counts["capture.jsonl"] += 1
        return real_loads(payload, *args, **kwargs)

    def counted_load(handle, *args, **kwargs):
        if os.path.basename(str(getattr(handle, "name", ""))) == "meta.json":
            counts["meta.json"] += 1
        return real_load(handle, *args, **kwargs)

    monkeypatch.setattr(json, "loads", counted_loads)
    monkeypatch.setattr(json, "load", counted_load)

    with tempfile.TemporaryDirectory() as parent:
        out = _staged_capture_dir(parent)
        # Measured from here, so the fixture parse inside the helper is not counted.
        before = dict(counts)
        recs, meta = analyze.load(out)
        analyze.render(out, recs, meta)
        assert contract.build_from_capture(out)
        assert os.path.isfile(os.path.join(out, "graph.json"))
        parsed = {name: counts[name] - before[name] for name in counts}
        # One full pass over the file is one json.loads per record; a second pass
        # would double this number.
        assert parsed["capture.jsonl"] == record_count, (
            f"capture.jsonl was parsed {parsed['capture.jsonl']}x for {record_count} records"
        )
        # Two, not three: analyze.load and build_from_capture. The third read, in
        # _analyze_contract_and_seal, was meta.json being re-parsed for the manifest.
        assert parsed["meta.json"] == 2, f"meta.json was parsed {parsed['meta.json']}x"


def test_golden_projection_covers_both_templating_branches():
    """Guards the fixture itself: if the golden ever stopped exercising a real id
    space or a real literal fork it would stop being evidence of anything."""
    paths = {path for _, path, _ in _golden_projection()["rest_paths"]}
    assert "/api/products/{id}" in paths
    assert "/api/invoice/{id}" in paths
    assert "/api/widgets/{uuid}" in paths
    assert "/api/blobs/{hash}" in paths
    # literal forks kept literal by the shape predicate, not by low cardinality
    assert "/api/public/getVersion" in paths
    assert "/api/public/reindex" in paths
    # and a low-cardinality fork kept literal by the ratio
    assert "/api/v1/catalog" in paths and "/api/v2/catalog" in paths
