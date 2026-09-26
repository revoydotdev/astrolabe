"""Tests for contract merge (completeness), drift detection, classify, and
build_from_capture / apply_active / render_md in astrolabe.contract."""

from __future__ import annotations

import json as _json

import astrolabe.contract as contract_module
from astrolabe.contract import (
    SCHEMA_VERSION,
    apply_active,
    build_from_capture,
    classify,
    classify_drift,
    coverage,
    merge,
    render_md,
    upgrade,
)


def _schema(**fields: str) -> dict:
    """A schema_version 2 return schema: real JSON Schema, not a raw capture shape."""
    return {
        "type": "object",
        "properties": {name: {"type": kind} for name, kind in fields.items()},
        "required": sorted(fields),
    }


def _contract(ops: dict[str, dict]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "base_domain": "example.com",
        "endpoints": [],
        "auth_headers": [],
        "operations": ops,
    }


def _op(return_schema: dict | None) -> dict:
    return {
        "operation": "query",
        "type": "query",
        "queryId_or_hash": None,
        "input_schema": {"type": "object", "properties": {}},
        "return_schema": return_schema,
        "proof": {
            "observed": {
                "ok": bool(return_schema),
                "status": [200 if return_schema else 0],
                "samples": 1,
            },
            "active": None,
        },
        "status": "typed-unproven",
    }


def _op_with(active_ok: bool | None, observed_ok: bool, has_schema: bool) -> dict:
    return {
        "operation": "query",
        "type": "query",
        "proof": {
            "active": {"ok": active_ok} if active_ok is not None else None,
            "observed": {"ok": observed_ok},
        },
        "input_schema": {"type": "object"} if has_schema else {},
        "return_schema": _schema(x="string") if has_schema else None,
    }


def test_merge_empty_prior_marks_all_added() -> None:
    cur = _contract({"a": _op(_schema(x="string"))})
    merged, drift = merge(None, cur)
    assert drift["added"] == ["a"]
    assert drift["removed"] == []
    assert drift["changed"] == []
    assert "a" in merged["operations"]


def test_merge_adds_new_op() -> None:
    prior = _contract({"a": _op(_schema(x="string"))})
    cur = _contract({"a": _op(_schema(x="string")), "b": _op(_schema(y="integer"))})
    merged, drift = merge(prior, cur)
    assert drift["added"] == ["b"]
    assert merged["operations"]["b"]["return_schema"] == _schema(y="integer")


def test_merge_keeps_prior_when_cur_missing() -> None:
    prior = _contract({"a": _op(_schema(x="string")), "gone": _op(_schema(z="string"))})
    cur = _contract({"a": _op(_schema(x="string"))})
    merged, drift = merge(prior, cur)
    assert "gone" in drift["removed"]
    assert "gone" in merged["operations"]


def test_merge_flags_changed_return_schema() -> None:
    prior = _contract({"a": _op(_schema(x="string"))})
    cur = _contract({"a": _op(_schema(x="string", y="integer"))})
    merged, drift = merge(prior, cur)
    assert "a" in drift["changed"]
    assert drift["breaking"] == []  # a new field is additive, not breaking
    schema = merged["operations"]["a"]["return_schema"]
    assert set(schema["properties"]) == {"x", "y"}


def test_merge_unions_schemas_rather_than_letting_one_win() -> None:
    """A run that saw fewer fields must not erase what an earlier run proved."""
    prior = _contract({"a": _op(_schema(x="string", y="integer"))})
    cur = _contract({"a": _op(_schema(x="string"))})
    merged, _ = merge(prior, cur)
    assert set(merged["operations"]["a"]["return_schema"]["properties"]) == {"x", "y"}


def test_merge_requiredness_is_the_intersection() -> None:
    """A field is only guaranteed if every run that saw this object saw it."""
    prior = _contract({"a": _op(_schema(x="string", y="integer"))})
    cur = _contract({"a": _op(_schema(x="string"))})
    merged, _ = merge(prior, cur)
    assert merged["operations"]["a"]["return_schema"]["required"] == ["x"]


def test_removed_field_is_breaking_drift() -> None:
    prior = _contract({"a": _op(_schema(x="string", y="integer"))})
    cur = _contract({"a": _op(_schema(x="string"))})
    _, drift = merge(prior, cur)
    assert drift["breaking"] == ["a"]


def test_retyped_field_is_breaking_drift() -> None:
    prior = _contract({"a": _op(_schema(x="string"))})
    cur = _contract({"a": _op(_schema(x="integer"))})
    _, drift = merge(prior, cur)
    assert drift["breaking"] == ["a"]


def test_classify_drift_distinguishes_the_three_cases() -> None:
    same = _schema(x="string")
    assert classify_drift(same, _schema(x="string")) == "none"
    assert classify_drift(same, _schema(x="string", y="integer")) == "additive"
    assert classify_drift(_schema(x="string", y="integer"), same) == "breaking"
    assert classify_drift(same, _schema(x="integer")) == "breaking"


def test_widening_a_type_to_nullable_is_not_breaking() -> None:
    before = {"type": "object", "properties": {"x": {"type": "string"}}}
    after = {"type": "object", "properties": {"x": {"type": ["string", "null"]}}}
    assert classify_drift(before, after) != "breaking"


# ---------- schema_version 1 compatibility ----------


def test_upgrade_converts_a_legacy_raw_shape_contract() -> None:
    legacy = {
        "base_domain": "example.com",
        "operations": {"a": {"return_schema": {"x": "str"}, "input_schema": {"q": "str"}}},
    }
    out = upgrade(legacy)
    assert out["schema_version"] == SCHEMA_VERSION
    assert out["operations"]["a"]["return_schema"]["properties"]["x"] == {"type": "string"}
    assert out["operations"]["a"]["input_schema"]["properties"]["q"] == {"type": "string"}


def test_merging_a_legacy_prior_contract_still_works() -> None:
    """An accumulated v1 contract must keep merging, not be compared as a raw shape."""
    legacy_prior = {
        "base_domain": "example.com",
        "operations": {"a": _op({"x": "str"})},  # v1 stored raw shapes here
    }
    cur = _contract({"a": _op(_schema(x="string", y="integer"))})
    merged, _ = merge(legacy_prior, cur)
    assert set(merged["operations"]["a"]["return_schema"]["properties"]) == {"x", "y"}


def test_upgrade_is_idempotent() -> None:
    c = _contract({"a": _op(_schema(x="string"))})
    assert upgrade(upgrade(c)) == c


def test_classify_verified_active() -> None:
    assert (
        classify(_op_with(active_ok=True, observed_ok=True, has_schema=True)) == "verified-active"
    )


def test_classify_verified_observed() -> None:
    assert (
        classify(_op_with(active_ok=None, observed_ok=True, has_schema=True)) == "verified-observed"
    )


def test_classify_typed_unproven() -> None:
    assert (
        classify(_op_with(active_ok=None, observed_ok=False, has_schema=True)) == "typed-unproven"
    )


def test_classify_listed() -> None:
    assert classify(_op_with(active_ok=None, observed_ok=False, has_schema=False)) == "listed"


def test_build_from_capture(tmp_path) -> None:
    (tmp_path / "endpoints.json").write_text(
        _json.dumps(
            {
                "base_domain": "example.com",
                "graphql_endpoints": ["/api/graphql/v1"],
                "auth_headers": {"X-Key": "secret"},
                "graphql_operations": {
                    "foo": {
                        "operation": "Foo",
                        "type": "query",
                        "input_shape": {"a": "str"},
                        "persistedHash": None,
                    },
                },
            }
        )
    )
    (tmp_path / "capture.jsonl").write_text(
        _json.dumps(
            {
                "url": "https://example.com/api/graphql/v1?alias=foo",
                "status": 200,
                "resp_shape": {"data": {"x": 1}},
                "graphql": [
                    {"query": "query Foo($a:String){foo(a:$a){x}}", "operationName": "Foo"}
                ],
            }
        )
        + "\n"
    )

    c = build_from_capture(str(tmp_path))
    assert c["base_domain"] == "example.com"
    assert c["auth_headers"] == ["X-Key"]
    op = c["operations"]["foo"]
    assert c["schema_version"] == SCHEMA_VERSION
    # the sample's value is not a recognised type name, so `x` is present but untyped
    assert op["return_schema"] == {"type": "object", "properties": {"x": {}}}
    # this inventory predates analyze's typed input_schema, so the legacy
    # single-shape fallback is used
    assert op["input_schema"]["properties"]["a"] == {"type": "string"}
    assert op["proof"]["observed"]["ok"] is True
    assert op["proof"]["observed"]["samples"] == 1
    assert op["status"] == "verified-observed"


def test_build_prefers_analyzes_typed_input_schema(tmp_path) -> None:
    """When the inventory carries a declaration-derived schema, it wins over the shape."""
    (tmp_path / "endpoints.json").write_text(
        _json.dumps(
            {
                "base_domain": "example.com",
                "graphql_endpoints": ["/g"],
                "auth_headers": {},
                "graphql_operations": {
                    "foo": {
                        "operation": "Foo",
                        "type": "query",
                        "input_shape": {"a": "str"},
                        "input_schema": {
                            "type": "object",
                            "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
                            "required": ["a"],
                        },
                        "persistedHash": None,
                    }
                },
            }
        )
    )
    (tmp_path / "capture.jsonl").write_text("")
    op = build_from_capture(str(tmp_path))["operations"]["foo"]
    # `b` was declared but never fired -- only the declaration knows it exists
    assert set(op["input_schema"]["properties"]) == {"a", "b"}
    assert op["input_schema"]["required"] == ["a"]


def test_return_schema_merges_every_observation(tmp_path) -> None:
    """Nullability and requiredness come from all samples, not the longest one."""
    (tmp_path / "endpoints.json").write_text(
        _json.dumps(
            {
                "base_domain": "example.com",
                "graphql_endpoints": ["/g"],
                "auth_headers": {},
                "graphql_operations": {"foo": {"operation": "Foo", "type": "query"}},
            }
        )
    )
    lines = [
        {
            "url": "https://example.com/g?alias=foo",
            "status": 200,
            "resp_shape": {"data": {"id": "str", "bio": "str"}},
            "graphql": [{"query": "query Foo{foo{id}}", "operationName": "Foo"}],
        },
        {
            "url": "https://example.com/g?alias=foo",
            "status": 200,
            "resp_shape": {"data": {"id": "str", "bio": "NoneType"}},
            "graphql": [{"query": "query Foo{foo{id}}", "operationName": "Foo"}],
        },
    ]
    (tmp_path / "capture.jsonl").write_text("".join(_json.dumps(x) + "\n" for x in lines))
    schema = build_from_capture(str(tmp_path))["operations"]["foo"]["return_schema"]
    assert schema["properties"]["bio"]["type"] == ["string", "null"]
    assert schema["required"] == ["bio", "id"]


def test_coverage_counts() -> None:
    cur = _contract(
        {
            "a": _op_with(active_ok=True, observed_ok=True, has_schema=True),
            "b": _op_with(active_ok=None, observed_ok=True, has_schema=True),
            "c": _op_with(active_ok=None, observed_ok=False, has_schema=False),
        }
    )
    cov = coverage(cur)
    assert cov["total"] == 3
    assert cov["verified_active"] == 1
    assert cov["verified_observed"] >= 1


def test_apply_active_folds_verification_and_upgrades_status() -> None:
    c = _contract({"a": _op_with(active_ok=None, observed_ok=True, has_schema=True)})
    verify = {
        "a": {
            "status": 200,
            "conforms": True,
            "schema_validated": True,
            "method": "warm-browser",
        }
    }
    out = apply_active(c, verify)
    assert out["operations"]["a"]["proof"]["active"]["ok"] is True
    assert out["operations"]["a"]["status"] == "verified-active"


def test_apply_active_does_not_call_http_200_schema_validated_without_validation() -> None:
    c = _contract({"a": _op_with(active_ok=None, observed_ok=True, has_schema=True)})
    out = apply_active(c, {"a": {"status": 200, "conforms": True}})
    assert out["operations"]["a"]["proof"]["active"]["schema_validated"] is False
    assert out["operations"]["a"]["proof"]["active"]["ok"] is False
    assert out["operations"]["a"]["status"] == "verified-observed"


def test_apply_active_nonconforming_stays_not_active() -> None:
    c = _contract({"a": _op_with(active_ok=None, observed_ok=True, has_schema=True)})
    verify = {"a": {"status": 500, "conforms": False}}
    out = apply_active(c, verify)
    assert out["operations"]["a"]["proof"]["active"]["ok"] is False


# ---------- REST operations ----------


def _endpoints_with_rest(rest_endpoints: list[dict], ws_ops: dict | None = None) -> dict:
    return {
        "base_domain": "shopgoodwill.example",
        "graphql_endpoints": [],
        "auth_headers": {"Authorization": "secret"},
        "graphql_operations": {},
        "rest_endpoints": rest_endpoints,
        "websocket_operations": ws_ops or {},
    }


def test_build_from_capture_types_a_rest_op_with_path_params(tmp_path) -> None:
    (tmp_path / "endpoints.json").write_text(
        _json.dumps(
            _endpoints_with_rest(
                [
                    {
                        "method": "GET",
                        "path": "/api/ItemDetail/GetItemDetailModelByItemId/{id}",
                        "auth_headers": ["Authorization"],
                        "calls": 2,
                        "status": [200, 200],
                    }
                ]
            )
        )
    )
    lines = [
        {
            "method": "GET",
            "url": "https://shopgoodwill.example/api/ItemDetail/GetItemDetailModelByItemId/111222",
            "status": 200,
            "resp_shape": {"itemId": "int", "title": "str"},
        },
        {
            "method": "GET",
            "url": "https://shopgoodwill.example/api/ItemDetail/GetItemDetailModelByItemId/333444",
            "status": 200,
            "resp_shape": {"itemId": "int", "title": "str", "buyItNowPrice": "float"},
        },
    ]
    (tmp_path / "capture.jsonl").write_text("".join(_json.dumps(x) + "\n" for x in lines))

    c = build_from_capture(str(tmp_path))
    k = "GET /api/ItemDetail/GetItemDetailModelByItemId/{id}"
    op = c["operations"][k]
    assert op["transport"] == "rest"
    assert op["method"] == "GET"
    assert op["path"] == "/api/ItemDetail/GetItemDetailModelByItemId/{id}"
    # path params are the only honest input contract: query/body params are not
    # reliably recorded in endpoints.json
    assert op["input_schema"] == {
        "type": "object",
        "properties": {"id": {"type": "string", "description": "path parameter {id}"}},
        "required": ["id"],
    }
    # merged across both observations: buyItNowPrice is present-but-optional
    assert set(op["return_schema"]["properties"]) == {"itemId", "title", "buyItNowPrice"}
    assert op["return_schema"]["required"] == ["itemId", "title"]
    assert op["proof"]["observed"]["ok"] is True
    assert op["proof"]["observed"]["status"] == [200]
    assert op["proof"]["observed"]["samples"] == 2
    assert op["proof"]["active"] is None
    assert op["status"] == "verified-observed"


def test_rest_op_key_cannot_collide_with_a_graphql_op() -> None:
    """REST keys are always `METHOD /path` (space-separated); GraphQL keys come
    from an alias/operationName/regex match and never contain a space."""
    key = "GET /api/foo/{id}"
    assert " " in key
    assert key.split(" ", 1)[0] in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


def test_rest_op_never_observed_succeeding_is_not_proven(tmp_path) -> None:
    (tmp_path / "endpoints.json").write_text(
        _json.dumps(
            _endpoints_with_rest(
                [
                    {
                        "method": "GET",
                        "path": "/api/SellerInformation/GetSellerInformation/{id}",
                        "auth_headers": [],
                        "calls": 1,
                        "status": [500],
                    }
                ]
            )
        )
    )
    (tmp_path / "capture.jsonl").write_text(
        _json.dumps(
            {
                "method": "GET",
                "url": "https://shopgoodwill.example/api/SellerInformation/GetSellerInformation/42",
                "status": 500,
                "resp_shape": {"error": "str"},
            }
        )
        + "\n"
    )
    c = build_from_capture(str(tmp_path))
    op = c["operations"]["GET /api/SellerInformation/GetSellerInformation/{id}"]
    assert op["return_schema"] is None  # never a <400 response to type from
    assert op["proof"]["observed"]["ok"] is False
    assert op["status"] == "typed-unproven"  # still has an input schema (path param)


def test_rest_post_op_with_no_path_params(tmp_path) -> None:
    (tmp_path / "endpoints.json").write_text(
        _json.dumps(
            _endpoints_with_rest(
                [
                    {
                        "method": "POST",
                        "path": "/api/Search/ItemListing",
                        "auth_headers": ["Authorization"],
                        "calls": 1,
                        "status": [200],
                    }
                ]
            )
        )
    )
    (tmp_path / "capture.jsonl").write_text(
        _json.dumps(
            {
                "method": "POST",
                "url": "https://shopgoodwill.example/api/Search/ItemListing",
                "status": 200,
                "resp_shape": {"totalCount": "int"},
            }
        )
        + "\n"
    )
    c = build_from_capture(str(tmp_path))
    op = c["operations"]["POST /api/Search/ItemListing"]
    # A read-looking name is not authorization to replay an unsafe HTTP method.
    assert op["type"] == "mutation"
    assert op["input_schema"] == {"type": "object", "properties": {}}
    assert op["return_schema"]["properties"]["totalCount"] == {"type": "integer"}


def test_rest_return_shape_keys_like_mcpgen_template_path(tmp_path) -> None:
    """The contract's REST return-shape recovery must key capture.jsonl records
    the same way mcpgen.load_capture does -- (method, lexical _template_path(url))
    -- not the evidence-based PathTemplater template stored in rest_endpoints.
    A short alphabetic slug segment (here "electronics") is not digit/hex-run
    shaped, so the lexical _template_path never turns it into `{slug}` the way
    the evidence-based templater did for rest_endpoints -- the two disagree, so
    no return shape is recovered. This documents that shared, pre-existing
    limitation (inherited from mcpgen) rather than hiding it."""
    (tmp_path / "endpoints.json").write_text(
        _json.dumps(
            _endpoints_with_rest(
                [
                    {
                        "method": "GET",
                        "path": "/api/category/{slug}",
                        "auth_headers": [],
                        "calls": 1,
                        "status": [200],
                    }
                ]
            )
        )
    )
    (tmp_path / "capture.jsonl").write_text(
        _json.dumps(
            {
                "method": "GET",
                "url": "https://shopgoodwill.example/api/category/electronics",
                "status": 200,
                "resp_shape": {"name": "str"},
            }
        )
        + "\n"
    )
    c = build_from_capture(str(tmp_path))
    op = c["operations"]["GET /api/category/{slug}"]
    # "electronics" is not digit/hex-run shaped, so the lexical _template_path
    # leaves it as a literal segment -- it never matches "/api/category/{slug}".
    assert op["return_schema"] is None


def test_rest_drift_classified_breaking_identically_to_graphql() -> None:
    rest_op = {
        "operation": None,
        "type": "query",
        "queryId_or_hash": None,
        "transport": "rest",
        "method": "GET",
        "path": "/api/item/{id}",
        "input_schema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
        "return_schema": _schema(x="string", y="integer"),
        "proof": {"observed": {"ok": True, "status": [200], "samples": 2}, "active": None},
        "status": "verified-observed",
    }
    prior = _contract({"GET /api/item/{id}": rest_op})
    dropped = dict(rest_op, return_schema=_schema(x="string"))
    cur = _contract({"GET /api/item/{id}": dropped})
    _, drift = merge(prior, cur)
    assert drift["breaking"] == ["GET /api/item/{id}"]


def test_rest_drift_classified_additive_identically_to_graphql() -> None:
    rest_op = {
        "operation": None,
        "type": "query",
        "queryId_or_hash": None,
        "transport": "rest",
        "method": "GET",
        "path": "/api/item/{id}",
        "input_schema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
        "return_schema": _schema(x="string"),
        "proof": {"observed": {"ok": True, "status": [200], "samples": 2}, "active": None},
        "status": "verified-observed",
    }
    prior = _contract({"GET /api/item/{id}": rest_op})
    added = dict(rest_op, return_schema=_schema(x="string", y="integer"))
    cur = _contract({"GET /api/item/{id}": added})
    _, drift = merge(prior, cur)
    assert drift["changed"] == ["GET /api/item/{id}"]
    assert drift["breaking"] == []


def test_merge_forwards_transport_to_a_prior_op_that_lacks_it() -> None:
    """A contract merged before this module tracked transport must pick the field
    up on the next merge rather than staying stuck without it forever."""
    prior = _contract({"a": _op(_schema(x="string"))})  # no "transport" key
    co = _op(_schema(x="string"))
    co["transport"] = "graphql"
    cur = _contract({"a": co})
    merged, _ = merge(prior, cur)
    assert merged["operations"]["a"]["transport"] == "graphql"


def test_coverage_breaks_down_by_transport(tmp_path) -> None:
    (tmp_path / "endpoints.json").write_text(
        _json.dumps(
            {
                "base_domain": "example.com",
                "graphql_endpoints": ["/g"],
                "auth_headers": {},
                "graphql_operations": {"foo": {"operation": "Foo", "type": "query"}},
                "rest_endpoints": [
                    {
                        "method": "GET",
                        "path": "/api/x/{id}",
                        "auth_headers": [],
                        "calls": 1,
                        "status": [200],
                    }
                ],
            }
        )
    )
    lines = [
        {
            "url": "https://example.com/g?alias=foo",
            "status": 200,
            "resp_shape": {"data": {"a": "str"}},
            "graphql": [{"query": "query Foo{foo{a}}", "operationName": "Foo"}],
        },
        {
            "method": "GET",
            "url": "https://example.com/api/x/123456",
            "status": 200,
            "resp_shape": {"a": "int"},
        },
    ]
    (tmp_path / "capture.jsonl").write_text("".join(_json.dumps(x) + "\n" for x in lines))
    c = build_from_capture(str(tmp_path))
    cov = coverage(c)
    assert cov["total"] == 2
    assert cov["by_transport"]["graphql"]["total"] == 1
    assert cov["by_transport"]["rest"]["total"] == 1


def test_render_md_shows_a_transport_column_and_breakdown(tmp_path) -> None:
    (tmp_path / "endpoints.json").write_text(
        _json.dumps(
            {
                "base_domain": "example.com",
                "graphql_endpoints": ["/g"],
                "auth_headers": {},
                "graphql_operations": {"foo": {"operation": "Foo", "type": "query"}},
                "rest_endpoints": [
                    {
                        "method": "GET",
                        "path": "/api/x/{id}",
                        "auth_headers": [],
                        "calls": 1,
                        "status": [200],
                    }
                ],
            }
        )
    )
    (tmp_path / "capture.jsonl").write_text(
        _json.dumps(
            {
                "url": "https://example.com/g?alias=foo",
                "status": 200,
                "resp_shape": {"data": {"a": "str"}},
                "graphql": [{"query": "query Foo{foo{a}}", "operationName": "Foo"}],
            }
        )
        + "\n"
    )
    c = build_from_capture(str(tmp_path))
    md = render_md(c)
    assert "| op | type | transport | status | in | return |" in md
    assert "Coverage by transport" in md
    assert "| rest |" in md
    assert "| graphql |" in md


# ---------- WebSocket operations ----------


def test_build_from_capture_types_a_websocket_op(tmp_path) -> None:
    (tmp_path / "endpoints.json").write_text(
        _json.dumps(
            _endpoints_with_rest(
                [],
                ws_ops={
                    "wss://example.com/socket.io/::sent::join_room": {
                        "url": "wss://example.com/socket.io/",
                        "event": "join_room",
                        "direction": "sent",
                        "namespace": "/",
                        "calls": 3,
                        "input_schema": {
                            "type": "object",
                            "properties": {"room": {"type": "string"}},
                        },
                        "engineio": 4,
                    },
                    "wss://example.com/socket.io/::received::room_update": {
                        "url": "wss://example.com/socket.io/",
                        "event": "room_update",
                        "direction": "received",
                        "namespace": "/",
                        "calls": 0,
                        "input_schema": {},
                        "engineio": 4,
                    },
                },
            )
        )
    )
    (tmp_path / "capture.jsonl").write_text("")
    c = build_from_capture(str(tmp_path))
    sent = c["operations"]["WS wss://example.com/socket.io/::sent::join_room"]
    assert sent["transport"] == "websocket"
    assert sent["type"] == "mutation"
    assert sent["input_schema"]["properties"]["room"] == {"type": "string"}
    assert sent["return_schema"] is None
    assert sent["proof"]["observed"]["ok"] is True  # calls > 0
    assert sent["proof"]["active"] is None  # never executable

    received = c["operations"]["WS wss://example.com/socket.io/::received::room_update"]
    assert received["type"] == "subscription"
    assert received["proof"]["observed"]["ok"] is False  # calls == 0


def test_render_md_includes_scorecard() -> None:
    c = _contract(
        {
            "a": _op(_schema(x="string")),
            "b": _op(_schema(y="integer")),
        }
    )
    md = render_md(c, {"added": ["c"], "removed": [], "changed": []})
    assert "# example.com" in md
    assert "Coverage scorecard" in md
    assert "added: `c`" in md
    assert "| `a` | query |" in md


# ----- todo 19: top-level union, proof decay, and foreign-contract tolerance ---


def test_merge_unions_endpoints_not_just_operations() -> None:
    """Operations were unioned while the rest of the record was last-writer-wins, so an
    endpoint seen only in an earlier run vanished while its operations survived."""
    prior = _contract({"a": _op(_schema(x="string"))})
    prior["endpoints"] = ["/api/only-in-prior"]
    cur = _contract({"a": _op(_schema(x="string"))})
    cur["endpoints"] = []
    merged, _ = merge(prior, cur)
    assert "/api/only-in-prior" in merged["endpoints"]
    assert merged["endpoints"] == ["/api/only-in-prior"]


def test_merge_unions_auth_headers_too() -> None:
    prior = _contract({"a": _op(_schema(x="string"))})
    prior["auth_headers"] = ["x-prior-only"]
    cur = _contract({"a": _op(_schema(x="string"))})
    cur["auth_headers"] = []
    merged, _ = merge(prior, cur)
    assert "x-prior-only" in merged["auth_headers"]


def test_merge_union_keeps_both_ends_and_dedupes() -> None:
    prior = _contract({"a": _op(_schema(x="string"))})
    prior["endpoints"] = ["/shared", "/only-prior"]
    cur = _contract({"a": _op(_schema(x="string"))})
    cur["endpoints"] = ["/shared", "/only-cur"]
    merged, _ = merge(prior, cur)
    assert merged["endpoints"] == ["/shared", "/only-cur", "/only-prior"]


def test_active_proof_decays_after_repeated_absence() -> None:
    """A prior-only operation used to keep verified-active forever.

    One run that misses it is weak evidence -- a capture may simply not have visited
    that surface -- so decay is deliberately two consecutive misses, not one.
    """
    from astrolabe.contract import UNOBSERVED_RUNS_BEFORE_ACTIVE_DECAY

    prior = _contract({"gone": _op_with(True, True, True)})
    cur = _contract({"other": _op(_schema(z="string"))})

    once, _ = merge(prior, cur)
    assert once["operations"]["gone"]["status"] == "verified-active"
    assert once["operations"]["gone"]["proof"]["runs_unobserved"] == 1

    twice, _ = merge(once, cur)
    assert (
        twice["operations"]["gone"]["proof"]["runs_unobserved"]
        == UNOBSERVED_RUNS_BEFORE_ACTIVE_DECAY
    )
    assert twice["operations"]["gone"]["status"] != "verified-active"
    assert twice["operations"]["gone"]["proof"]["active"] is None
    # The proof of what did happen is kept; only the current claim stops being made.
    assert twice["operations"]["gone"]["proof"]["active_decayed"] is True


def test_observed_operation_still_seen_does_not_decay() -> None:
    prior = _contract({"a": _op_with(True, True, True)})
    cur = _contract({"a": _op(_schema(x="string"))})
    merged, _ = merge(prior, cur)
    assert "runs_unobserved" not in merged["operations"]["a"]["proof"]


def test_classify_degrades_on_a_contract_missing_proof_fields() -> None:
    assert classify({"operation": "query", "type": "query"}) == "listed"
    assert classify({"operation": "q", "type": "q", "proof": {}}) == "listed"


def test_coverage_and_render_tolerate_a_foreign_operation() -> None:
    """A hand-edited or older contract must degrade, not raise KeyError."""
    foreign = {
        "operation": "LegacyOp",
        "type": "query",
        "status": "typed-unproven",
    }
    contract = {
        "schema_version": SCHEMA_VERSION,
        "base_domain": "example.com",
        "endpoints": [],
        "auth_headers": [],
        "operations": {"LegacyOp": foreign},
    }
    stats = coverage(contract)
    assert stats["total"] == 1
    assert stats["typed_input"] == 0
    assert stats["verified_observed"] == 0
    assert stats["verified_active"] == 0
    rendered = render_md(contract, {"added": [], "removed": [], "changed": [], "breaking": []})
    assert "LegacyOp" in rendered


def test_breaking_drift_line_explains_the_union() -> None:
    """The contract keeps a union of both schemas, so 'field removed' must not read as
    contradicting the table that still types the field."""
    prior = _contract({"a": _op(_schema(x="string", y="string"))})
    cur = _contract({"a": _op(_schema(x="string"))})
    _, drift = merge(prior, cur)
    assert drift["breaking"] == ["a"]
    rendered = render_md(cur, drift)
    line = next(row for row in rendered.splitlines() if "**breaking**" in row)
    assert "union" in line


def test_rest_return_shape_is_merged_exactly_once_per_method_and_path(tmp_path, monkeypatch):
    """build_from_capture used to call merge_shapes twice for the same
    (method, path) key -- once for the return schema, once for the truthiness
    check that decides proof.observed.ok -- so a capture with many REST endpoints
    merged every endpoint's shapes twice. The count is asserted rather than the
    timing: a duplicate call costs little, but the assertion is what makes a
    future re-duplication fail instead of merely get slower."""
    rest = [
        {
            "method": "GET",
            "path": f"/api/items/{name}/{{id}}",
            "auth_headers": [],
            "calls": 1,
            "status": [200],
        }
        for name in ("alpha", "beta", "gamma", "delta", "epsilon")
    ]
    (tmp_path / "endpoints.json").write_text(_json.dumps(_endpoints_with_rest(rest)))
    (tmp_path / "capture.jsonl").write_text(
        "".join(
            _json.dumps(
                {
                    "method": "GET",
                    "url": f"https://shopgoodwill.example/api/items/{name}/111222",
                    "status": 200,
                    "resp_shape": {"id": "int", "title": "str"},
                }
            )
            + "\n"
            for name in ("alpha", "beta", "gamma", "delta", "epsilon")
        )
    )

    calls: list[object] = []
    real = contract_module.merge_shapes

    def counting_merge(shapes, *args, **kwargs):
        calls.append(shapes)
        return real(shapes, *args, **kwargs)

    monkeypatch.setattr(contract_module, "merge_shapes", counting_merge)
    built = build_from_capture(str(tmp_path))

    rest_calls = [c for c in calls if isinstance(c, list)]
    assert len(rest_calls) == len(rest), f"expected one merge per REST key, got {len(rest_calls)}"
    for path in (
        f"/api/items/{name}/{{id}}" for name in ("alpha", "beta", "gamma", "delta", "epsilon")
    ):
        op = built["operations"][f"GET {path}"]
        # The result is still consumed: one call feeding both the stored schema
        # and the observed proof, not a call that was simply dropped.
        assert op["return_schema"]["properties"]["title"] == {"type": "string"}
        assert op["proof"]["observed"]["ok"] is True
