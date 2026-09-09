"""Tests for the pure toolpack-generation functions and mcpgen CLI flow."""

from __future__ import annotations

import json

import pytest

from astrolabe.mcpgen import (
    DEFAULT_NOISE,
    GenerationError,
    build_event_channels,
    build_pack,
    envelope_schema,
    graphql_endpoint,
    main,
    rest_tool_name,
    shape_to_schema,
    tool_name,
)

# ---------- pure functions ----------


def test_shape_to_schema_object() -> None:
    assert shape_to_schema({"q": "str", "n": "int"}) == {
        "type": "object",
        "properties": {"q": {"type": "string"}, "n": {"type": "integer"}},
    }


def test_shape_to_schema_nested_object() -> None:
    assert shape_to_schema({"page": {"offset": "int"}}) == {
        "type": "object",
        "properties": {"page": {"type": "object", "properties": {"offset": {"type": "integer"}}}},
    }


def test_shape_to_schema_list() -> None:
    assert shape_to_schema(["str"]) == {"type": "array", "items": {"type": "string"}}


def test_shape_to_schema_empty_list_has_no_items() -> None:
    assert shape_to_schema([]) == {"type": "array"}


def test_shape_to_schema_scalar_map() -> None:
    assert shape_to_schema("bool") == {"type": "boolean"}
    assert shape_to_schema("float") == {"type": "number"}


def test_shape_to_schema_unknown_is_empty() -> None:
    assert shape_to_schema("bogus-type") == {}


def test_tool_name_uses_alias() -> None:
    assert tool_name("jobSearch", "query") == "jobSearch"


def test_tool_name_falls_back_to_op_when_no_alias() -> None:
    assert tool_name("(none)", "userJobs") == "userJobs"
    assert tool_name("", "userJobs") == "userJobs"


def test_tool_name_slugs_invalid_chars() -> None:
    assert tool_name("a b/c", "op") == "a_b_c"


def test_tool_name_truncates_to_60() -> None:
    assert len(tool_name("x" * 200, "op")) == 60


def test_tool_name_empty_alias_and_op_defaults_to_op() -> None:
    assert tool_name("", None) == "op"


def test_rest_tool_name_is_readable_and_stable() -> None:
    assert rest_tool_name("GET", "/api/v2/products/{id}") == "getApiV2ProductsId"
    assert rest_tool_name("POST", "/api/v2/cart") == "postApiV2Cart"


# ---------- noise policy is generic, not vendor-specific ----------


def test_default_noise_matches_generic_telemetry() -> None:
    for alias in ("jslogger", "clientTelemetry", "pageview-beacon", "abtest.assign"):
        assert DEFAULT_NOISE.search(alias) is not None, alias


def test_default_noise_leaves_data_ops_alone() -> None:
    for alias in ("jobSearch", "userProfile", "productList", "smf.feed"):
        assert DEFAULT_NOISE.search(alias) is None, alias


def test_site_specific_noise_comes_from_an_override(tmp_path) -> None:
    """`smf.` is a site-specific alias prefix. It must not be baked into the generic default, but a
    target that needs it can still supply it."""
    _write_capture(tmp_path, gql_ops={"smf.feed": _op("query", "Feed")})
    pack = build_pack(str(tmp_path))
    assert next(t for t in pack["tools"] if t["alias"] == "smf.feed")["exposed"] is True

    pack = build_pack(str(tmp_path), noise_pattern=r"smf\.")
    gated = next(t for t in pack["tools"] if t["alias"] == "smf.feed")
    assert gated["exposed"] is False
    assert "telemetry" in gated["reason"]


# ---------- endpoint resolution must never be invented ----------


def test_graphql_endpoint_returns_none_when_absent() -> None:
    assert graphql_endpoint({"base_domain": "example.com", "graphql_endpoints": []}) is None


def test_graphql_endpoint_builds_from_path() -> None:
    inv = {"base_domain": "example.com", "graphql_endpoints": ["/api/graphql/v1"]}
    assert graphql_endpoint(inv) == "https://example.com/api/graphql/v1"


def test_graphql_ops_without_endpoint_fail_loudly(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={"jobSearch": _op("query", "JobSearch")}, endpoints=[])
    with pytest.raises(GenerationError, match="no graphql_endpoints"):
        build_pack(str(tmp_path))


def test_empty_capture_fails_loudly_instead_of_emitting_an_empty_pack(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={}, rest=[])
    with pytest.raises(GenerationError, match="nothing to generate"):
        build_pack(str(tmp_path))


def test_missing_inventory_fails_loudly(tmp_path) -> None:
    with pytest.raises(GenerationError, match="no endpoints.json"):
        build_pack(str(tmp_path))


# ---------- REST generation ----------


def test_rest_endpoints_become_typed_tools(tmp_path) -> None:
    _write_capture(
        tmp_path,
        gql_ops={},
        endpoints=[],
        rest=[
            {"method": "GET", "path": "/api/v2/products", "calls": 9, "status": [200]},
            {"method": "GET", "path": "/api/v2/products/{id}", "calls": 4, "status": [200]},
            {"method": "POST", "path": "/api/v2/cart", "calls": 2, "status": [200]},
            {"method": "GET", "path": "/api/v2/gone", "calls": 1, "status": [404]},
            {
                "method": "GET",
                "path": "/api/v2/export",
                "calls": 1,
                "status": [200],
                "response_kinds": ["binary"],
            },
        ],
    )
    pack = build_pack(str(tmp_path))
    by_name = {t["name"]: t for t in pack["tools"]}
    assert "endpoint" not in pack  # no GraphQL anywhere -> no endpoint invented

    listing = by_name["getApiV2Products"]
    assert listing["transport"] == "rest"
    assert listing["exposed"] is True
    assert listing["type"] == "query"

    detail = by_name["getApiV2ProductsId"]
    assert detail["input_schema"]["properties"]["id"] == {
        "type": "string",
        "description": "path parameter {id}",
    }
    assert detail["input_schema"]["required"] == ["id"]

    assert by_name["postApiV2Cart"]["exposed"] is False
    assert "gated" in by_name["postApiV2Cart"]["reason"]

    assert by_name["getApiV2Gone"]["exposed"] is False
    assert "never observed succeeding" in by_name["getApiV2Gone"]["reason"]
    assert by_name["getApiV2Export"]["exposed"] is False
    assert "not JSON/GraphQL" in by_name["getApiV2Export"]["reason"]


def test_classify_rest_requires_safe_method_or_attestation() -> None:
    """Names are hints: unsafe methods require an operator/spec attestation."""
    from astrolabe.mcpgen import classify_rest

    assert classify_rest("POST", "/api/Search/ItemListing") == "mutation"
    assert classify_rest("POST", "/api/Favorite/GetAllFavoriteItemsByType") == "mutation"
    assert classify_rest("GET", "/api/Favorite/AddToFavorite") == "mutation"
    assert classify_rest("GET", "/api/Favorite/RemoveItemFromFavoriteList") == "mutation"
    assert classify_rest("POST", "/api/ItemBid/PlaceBid") == "mutation"
    assert classify_rest("GET", "/api/ItemDetail/GetItemDetailModelByItemId/{id}") == "query"


def test_classify_rest_conflict_resolves_conservatively() -> None:
    """A write verb wins over a read verb — gating a read beats exposing a write."""
    from astrolabe.mcpgen import classify_rest

    # 'get' is a read verb but 'update' is a write verb -> write
    assert classify_rest("GET", "/api/GetOrUpdateProfile") == "mutation"
    # a non-GET with no verb signal defaults to write
    assert classify_rest("POST", "/api/x/y") == "mutation"


def test_classify_rest_read_pattern_override_forces_read() -> None:
    import re

    from astrolabe.mcpgen import classify_rest

    pat = re.compile(r"/Report/Generate", re.I)
    # 'generate' would normally be nothing/POST -> write; the override forces read
    assert classify_rest("POST", "/api/Report/Generate", pat) == "query"


def test_post_based_search_is_gated_without_attestation(tmp_path) -> None:
    """A POST search needs trusted evidence, not a read-looking route name."""
    _write_capture(
        tmp_path,
        gql_ops={},
        endpoints=[],
        rest=[
            {"method": "POST", "path": "/api/Search/ItemListing", "calls": 3, "status": [200]},
            {"method": "GET", "path": "/api/Favorite/AddToFavorite", "calls": 1, "status": [200]},
        ],
    )
    by_name = {t["path"]: t for t in build_pack(str(tmp_path))["tools"]}
    search = by_name["/api/Search/ItemListing"]
    assert search["type"] == "mutation"
    assert search["exposed"] is False
    # a mutating GET is gated despite being a GET
    fav = by_name["/api/Favorite/AddToFavorite"]
    assert fav["type"] == "mutation"
    assert fav["exposed"] is False

    attested = build_pack(str(tmp_path), read_pattern=r"/Search/ItemListing$")
    search = next(t for t in attested["tools"] if t["path"] == "/api/Search/ItemListing")
    assert search["type"] == "query"
    assert search["exposed"] is True


def test_read_pattern_flag_forces_exposure(tmp_path) -> None:
    _write_capture(
        tmp_path,
        gql_ops={},
        endpoints=[],
        rest=[{"method": "POST", "path": "/api/Report/Generate", "calls": 1, "status": [200]}],
    )
    gated = build_pack(str(tmp_path))["tools"][0]
    assert gated["exposed"] is False
    forced = build_pack(str(tmp_path), read_pattern=r"/Report/Generate")["tools"][0]
    assert forced["type"] == "query"
    assert forced["exposed"] is True


def test_rest_writes_expose_with_include_mutations(tmp_path) -> None:
    _write_capture(
        tmp_path,
        gql_ops={},
        endpoints=[],
        rest=[{"method": "POST", "path": "/api/v2/cart", "calls": 2, "status": [200]}],
    )
    pack = build_pack(str(tmp_path), include_mutations=True)
    assert pack["tools"][0]["exposed"] is True
    assert pack["tools"][0]["type"] == "mutation"


# ---------- typed return schemas ----------


def test_envelope_schema_describes_data_and_failure_fields() -> None:
    schema = envelope_schema({"title": "str"})
    assert schema["properties"]["data"] == {
        "type": "object",
        "properties": {"title": {"type": "string"}},
    }
    assert "error_code" in schema["properties"]


def test_envelope_schema_omits_data_when_never_observed() -> None:
    assert "data" not in envelope_schema(None)["properties"]


def test_output_schema_comes_from_the_capture(tmp_path) -> None:
    _write_capture(
        tmp_path,
        gql_ops={"jobSearch": _op("query", "JobSearch")},
        capture_lines=[
            {
                "url": "https://example.com/api/graphql/v1?alias=jobSearch",
                "status": 200,
                "resp_shape": {"data": {"title": "str"}},
                "graphql": [
                    {"query": "query JobSearch{jobs{title}}", "operationName": "JobSearch"}
                ],
            }
        ],
    )
    pack = build_pack(str(tmp_path))
    tool = pack["tools"][0]
    assert tool["output_schema"]["properties"]["data"]["properties"]["title"] == {"type": "string"}


def test_contract_return_schema_wins_over_this_runs_capture(tmp_path) -> None:
    """The contract merges across runs, so it covers operations this run did not
    re-observe — it must take precedence."""
    _write_capture(
        tmp_path,
        gql_ops={"jobSearch": _op("query", "JobSearch")},
        capture_lines=[
            {
                "url": "https://example.com/api/graphql/v1?alias=jobSearch",
                "status": 200,
                "resp_shape": {"data": {"title": "str"}},
                "graphql": [
                    {"query": "query JobSearch{jobs{title}}", "operationName": "JobSearch"}
                ],
            }
        ],
    )
    (tmp_path / "contract.json").write_text(
        json.dumps(
            {
                "base_domain": "example.com",
                "operations": {
                    "jobSearch": {"return_schema": {"title": "str", "salary": "int"}},
                },
            }
        )
    )
    pack = build_pack(str(tmp_path))
    props = pack["tools"][0]["output_schema"]["properties"]["data"]["properties"]
    assert props["salary"] == {"type": "integer"}


def test_typed_input_schema_from_the_inventory_is_used(tmp_path) -> None:
    """analyze's declaration-derived schema carries variables never fired, and
    requiredness that value-inference alone cannot know."""
    _write_capture(tmp_path, gql_ops={"jobSearch": _op("query", "JobSearch")})
    inv = json.loads((tmp_path / "endpoints.json").read_text())
    inv["graphql_operations"]["jobSearch"]["input_schema"] = {
        "type": "object",
        "properties": {"q": {"type": "string"}, "page": {"type": "integer"}},
        "required": ["q"],
    }
    (tmp_path / "endpoints.json").write_text(json.dumps(inv))
    schema = build_pack(str(tmp_path))["tools"][0]["input_schema"]
    assert set(schema["properties"]) == {"q", "page"}
    assert schema["required"] == ["q"]


def test_return_schema_merges_every_response(tmp_path) -> None:
    _write_capture(
        tmp_path,
        gql_ops={"jobSearch": _op("query", "JobSearch")},
        capture_lines=[
            {
                "url": "https://example.com/api/graphql/v1?alias=jobSearch",
                "status": 200,
                "resp_shape": {"data": {"id": "str", "bio": "str"}},
                "graphql": [{"query": "query JobSearch{x}", "operationName": "JobSearch"}],
            },
            {
                "url": "https://example.com/api/graphql/v1?alias=jobSearch",
                "status": 200,
                "resp_shape": {"data": {"id": "str", "bio": "NoneType"}},
                "graphql": [{"query": "query JobSearch{x}", "operationName": "JobSearch"}],
            },
        ],
    )
    data = build_pack(str(tmp_path))["tools"][0]["output_schema"]["properties"]["data"]
    assert data["properties"]["bio"]["type"] == ["string", "null"]
    assert data["required"] == ["bio", "id"]


def test_contract_and_capture_return_schemas_union(tmp_path) -> None:
    """Neither source wins outright: the contract accumulates, the capture is fresh."""
    _write_capture(
        tmp_path,
        gql_ops={"jobSearch": _op("query", "JobSearch")},
        capture_lines=[
            {
                "url": "https://example.com/api/graphql/v1?alias=jobSearch",
                "status": 200,
                "resp_shape": {"data": {"fresh": "str"}},
                "graphql": [{"query": "query JobSearch{x}", "operationName": "JobSearch"}],
            }
        ],
    )
    (tmp_path / "contract.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "operations": {
                    "jobSearch": {
                        "return_schema": {
                            "type": "object",
                            "properties": {"historic": {"type": "integer"}},
                        }
                    }
                },
            }
        )
    )
    data = build_pack(str(tmp_path))["tools"][0]["output_schema"]["properties"]["data"]
    assert set(data["properties"]) == {"fresh", "historic"}


def test_legacy_contract_shapes_are_coerced(tmp_path) -> None:
    """schema_version 1 stored raw capture shapes under the same key."""
    _write_capture(tmp_path, gql_ops={"jobSearch": _op("query", "JobSearch")})
    (tmp_path / "contract.json").write_text(
        json.dumps({"operations": {"jobSearch": {"return_schema": {"legacy": "int"}}}})
    )
    data = build_pack(str(tmp_path))["tools"][0]["output_schema"]["properties"]["data"]
    assert data["properties"]["legacy"] == {"type": "integer"}


# ---------- persisted (APQ) operations ----------


def test_persisted_op_with_a_hash_is_exposed_for_apq(tmp_path) -> None:
    """A persisted op carries a hash instead of query text; that is executable."""
    _write_capture(
        tmp_path,
        gql_ops={"feed": {**_op("query", "Feed"), "persistedHash": "a" * 64}},
        capture_lines=[],
    )
    tool = build_pack(str(tmp_path))["tools"][0]
    assert tool["exposed"] is True
    assert tool["apq_hash"] == "a" * 64
    assert tool["query"] == ""
    assert "APQ" in tool["description"]


def test_persisted_mutation_is_still_gated(tmp_path) -> None:
    _write_capture(
        tmp_path,
        gql_ops={"del": {**_op("mutation", "Del"), "persistedHash": "abc"}},
        capture_lines=[],
    )
    assert build_pack(str(tmp_path))["tools"][0]["exposed"] is False


def test_op_with_neither_query_nor_hash_is_gated(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={"ghost": _op("query", "Ghost")}, capture_lines=[])
    tool = build_pack(str(tmp_path))["tools"][0]
    assert tool["exposed"] is False
    assert "nothing to execute" in tool["reason"]


# ---------- proof status carried from the contract ----------


def test_proof_status_reaches_the_toolpack(tmp_path) -> None:
    """An agent should be able to tell a re-executed tool from an inferred one."""
    _write_capture(tmp_path, gql_ops={"jobSearch": _op("query", "JobSearch")})
    (tmp_path / "contract.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "operations": {"jobSearch": {"status": "verified-active"}},
            }
        )
    )
    tool = build_pack(str(tmp_path))["tools"][0]
    assert tool["proof_status"] == "verified-active"
    assert "verified-active" in tool["description"]


def test_missing_contract_leaves_proof_status_unset(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={"jobSearch": _op("query", "JobSearch")})
    assert build_pack(str(tmp_path))["tools"][0]["proof_status"] is None


# ---------- recovered schema enriches the input types ----------


def test_recovered_schema_fills_in_custom_input_types(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={"search": _op("query", "Search")})
    inv = json.loads((tmp_path / "endpoints.json").read_text())
    inv["graphql_operations"]["search"]["input_schema"] = {
        "type": "object",
        "properties": {"filter": {"description": "GraphQL type F"}},
    }
    (tmp_path / "endpoints.json").write_text(json.dumps(inv))
    (tmp_path / "schema.json").write_text(
        json.dumps(
            {
                "data": {
                    "__schema": {
                        "types": [
                            {
                                "kind": "INPUT_OBJECT",
                                "name": "F",
                                "inputFields": [
                                    {
                                        "name": "minRate",
                                        "type": {
                                            "kind": "NON_NULL",
                                            "ofType": {"kind": "SCALAR", "name": "Int"},
                                        },
                                        "defaultValue": None,
                                    }
                                ],
                            }
                        ]
                    }
                }
            }
        )
    )
    prop = build_pack(str(tmp_path))["tools"][0]["input_schema"]["properties"]["filter"]
    assert prop["properties"]["minRate"] == {"type": "integer"}
    assert prop["required"] == ["minRate"]


def test_absent_schema_json_is_not_an_error(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={"search": _op("query", "Search")})
    assert build_pack(str(tmp_path))["tools"][0]["input_schema"]["type"] == "object"


def test_unreadable_contract_is_tolerated(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={"jobSearch": _op("query", "JobSearch")})
    (tmp_path / "contract.json").write_text("{ not json")
    pack = build_pack(str(tmp_path))
    assert pack["tools"][0]["name"] == "jobSearch"


# ---------- name collisions ----------


def test_colliding_tool_names_are_disambiguated(tmp_path) -> None:
    _write_capture(
        tmp_path,
        gql_ops={"a/b": _op("query", "AB"), "a_b": _op("query", "AB2")},
    )
    pack = build_pack(str(tmp_path))
    names = [t["name"] for t in pack["tools"]]
    assert len(names) == len(set(names)), names


# ---------- CLI flow ----------


def test_main_writes_toolpack_and_reports(tmp_path, capsys) -> None:
    _write_capture(tmp_path, gql_ops={"jobSearch": _op("query", "JobSearch")})
    out = tmp_path / "toolpack.json"
    main([str(tmp_path), "--out", str(out)])
    pack = json.loads(out.read_text())
    assert pack["version"] == 2
    assert pack["endpoint"] == "https://example.com/api/graphql/v1"
    assert "jobSearch" in capsys.readouterr().out


def test_main_exits_nonzero_on_unusable_capture(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={}, rest=[])
    with pytest.raises(SystemExit) as exc:
        main([str(tmp_path)])
    assert "nothing to generate" in str(exc.value)


def test_main_applies_overrides(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={"jobSearch": _op("query", "JobSearch")})
    ov = tmp_path / "ov"
    ov.mkdir()
    (ov / "jobSearch.op.json").write_text(
        json.dumps({"alias": "jobSearch", "query": "query Q{__x}"})
    )
    out = tmp_path / "toolpack2.json"
    main([str(tmp_path), "--overrides", str(ov), "--out", str(out)])
    job = json.loads(out.read_text())["tools"][0]
    assert job["query"] == "query Q{__x}"
    assert job["curated"] is True


def test_mutations_are_gated_by_default(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={"deleteJob": _op("mutation", "DeleteJob")})
    pack = build_pack(str(tmp_path))
    assert pack["tools"][0]["exposed"] is False
    assert "mutation" in pack["tools"][0]["reason"]


def test_persisted_ops_without_query_text_are_gated(tmp_path) -> None:
    _write_capture(tmp_path, gql_ops={"countJob": _op("query", "CountJob")}, capture_lines=[])
    pack = build_pack(str(tmp_path))
    assert pack["tools"][0]["exposed"] is False
    assert "persisted" in pack["tools"][0]["reason"]


def test_event_channels_include_server_pushes_and_sse_but_not_client_emits() -> None:
    channels = build_event_channels(
        {
            "base_domain": "example.com",
            "websocket_operations": {
                "received": {
                    "url": "wss://example.com/socket.io/?EIO=4&transport=websocket",
                    "event": "price",
                    "direction": "received",
                    "namespace": "/market",
                    "engineio": "4",
                },
                "sent": {
                    "url": "wss://example.com/socket.io/?EIO=4&transport=websocket",
                    "event": "placeOrder",
                    "direction": "sent",
                    "namespace": "/market",
                    "engineio": "4",
                },
            },
            "rest_endpoints": [
                {
                    "method": "GET",
                    "path": "/events",
                    "request_url": "https://example.com/events",
                    "response_media_types": ["text/event-stream"],
                }
            ],
        }
    )

    assert {item["protocol"] for item in channels} == {"socketio", "sse"}
    socket_channel = next(item for item in channels if item["protocol"] == "socketio")
    assert socket_channel["received_events"] == ["price"]
    assert "placeOrder" not in socket_channel["received_events"]


# ---------- helpers ----------


def _op(typ: str, operation: str) -> dict:
    return {"type": typ, "operation": operation, "input_shape": {"q": "str"}, "returns": ["title"]}


def _write_capture(
    tmp_path,
    *,
    gql_ops: dict | None = None,
    rest: list | None = None,
    endpoints: list | None = None,
    capture_lines: list | None = None,
) -> None:
    gql_ops = {} if gql_ops is None else gql_ops
    if endpoints is None:
        endpoints = ["/api/graphql/v1"] if gql_ops else []
    inv = {
        "base_domain": "example.com",
        "graphql_endpoints": endpoints,
        "auth_headers": {"x-api-key": 3},
        "graphql_operations": gql_ops,
        "rest_endpoints": rest or [],
    }
    (tmp_path / "endpoints.json").write_text(json.dumps(inv))
    if capture_lines is None:
        capture_lines = [
            {
                "url": f"https://example.com/api/graphql/v1?alias={alias}",
                "status": 200,
                "resp_shape": {"data": {"title": "str"}},
                "graphql": [
                    {
                        "query": f"{meta['type']} {meta['operation']}{{x}}",
                        "operationName": meta["operation"],
                    }
                ],
            }
            for alias, meta in gql_ops.items()
        ]
    (tmp_path / "capture.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in capture_lines)
    )


@pytest.mark.parametrize(
    ("name", "kind", "expected"),
    [
        ("HomeTimeline", "query", "read"),
        ("CreateTweet", "mutation", "create"),
        ("FavoriteTweet", "mutation", "create"),
        ("DeleteBookmark", "mutation", "delete"),
        ("UnfavoriteTweet", "mutation", "delete"),
        ("ModerateTweet", "mutation", "update"),
        ("UpdatePinnedTimelines", "mutation", "update"),
        # A query is a read on compiler evidence, whatever its name suggests.
        ("DeleteSomethingQuery", "query", "read"),
    ],
)
def test_crud_hint_reads_kind_first_then_name(name, kind, expected):
    from astrolabe.mcpgen import crud_hint

    assert crud_hint(name, kind) == expected


def test_declared_operations_are_catalogued_without_becoming_callable():
    from astrolabe.mcpgen import build_declared_operations

    declared = build_declared_operations(
        {
            "declared_operations": [
                {
                    "name": "DeleteTweet",
                    "operation_kind": "mutation",
                    "id": "abc",
                    "observed": False,
                    "source_sha256": "d" * 64,
                    "source_url": "https://cdn.example.com/main.js",
                },
                {"name": "HomeTimeline", "operation_kind": "query", "id": "def", "observed": True},
                {"name": "Broken", "operation_kind": "fragment", "id": "ghi"},
                {"name": "", "operation_kind": "query", "id": "jkl"},
            ]
        }
    )
    assert [item["name"] for item in declared] == ["DeleteTweet", "HomeTimeline"]
    assert declared[0]["crud_hint"] == "delete"
    assert declared[0]["crud_hint_basis"] == "operation-name-heuristic"
    assert declared[0]["evidence"] == "compiler-metadata"
    assert declared[0]["observed"] is False
    assert declared[1]["observed"] is True
    for item in declared:
        assert not {"query", "apq_hash", "request_url", "request_template"} & set(item)
