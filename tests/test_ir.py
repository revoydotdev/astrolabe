from __future__ import annotations

import json
from copy import deepcopy

import pytest

from astrolabe import cli
from astrolabe.artifact import ArtifactError, atomic_write_json, build_manifest, verify_manifest
from astrolabe.ir import (
    evidence_records_from_graph,
    graph_from_inventory,
    inventory_from_graph,
    load_graph,
    merge_graphs,
    migrate_graph,
    stable_id,
    write_graph,
)
from astrolabe.mcpgen import build_pack
from astrolabe.schema import validate_artifact


def _inventory() -> dict:
    return {
        "base_domain": "api.example.com",
        "graphql_endpoints": ["/graphql"],
        "auth_headers": {},
        "graphql_operations": {
            "Viewer": {
                "semantic_kind": "query",
                "protocol": "graphql-inline",
                "http_method": "POST",
                "request_url": "https://api.example.com/graphql",
                "operation": "ViewerQuery",
                "query": "query ViewerQuery($id: ID!) { viewer(id: $id) { id } }",
                "input_schema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                },
                "calls": 1,
            }
        },
        "rest_endpoints": [
            {
                "method": "GET",
                "path": "/v1/items/{id}",
                "operationId": "getItem",
                "semantic_kind": "query",
                "source": "openapi",
                "parameters": [
                    {
                        "name": "id",
                        "location": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "input_schema": {"type": "object", "properties": {}},
                "return_schema": {"type": "object", "properties": {"id": {"type": "string"}}},
            }
        ],
    }


def _records() -> list[dict]:
    return [
        {
            "url": "https://api.example.com/graphql",
            "method": "POST",
            "status": 200,
            "request_media_type": "application/json",
            "resp_ct": "application/json",
            "resp_shape": {"data": {"viewer": {"id": "str"}}},
            "graphql": [
                {
                    "operationName": "ViewerQuery",
                    "query": "query ViewerQuery($id: ID!) { viewer(id: $id) { id } }",
                }
            ],
        }
    ]


def test_stable_ids_are_alias_independent_and_deterministic() -> None:
    assert stable_id("operation", "endpoint", "query") == stable_id(
        "operation", "endpoint", "query"
    )
    assert stable_id("operation", "endpoint", "query") != stable_id(
        "operation", "different", "query"
    )


def test_graph_round_trip_is_valid_and_preserves_exact_template(tmp_path) -> None:
    graph = graph_from_inventory(
        _inventory(),
        _records(),
        {"run_id": "run-1", "captured_at": "2026-08-13T12:00:00+00:00"},
    )
    path = tmp_path / "graph.json"
    write_graph(path, graph)
    loaded = load_graph(path)
    assert loaded["schema_version"] == 1
    assert len(loaded["endpoints"]) == 2
    assert loaded["request_templates"][0]["body_template"]["query"].startswith("query Viewer")
    assert loaded["evidence"][0]["operation_id"] is not None

    projected = inventory_from_graph(loaded)
    assert projected["graphql_operations"]["Viewer"]["query"].startswith("query Viewer")
    assert projected["rest_endpoints"][0]["operationId"] == "getItem"
    evidence = evidence_records_from_graph(loaded)
    assert evidence[0]["graphql"][0]["operationName"] == "ViewerQuery"


def test_graph_preserves_surface_interaction_causality() -> None:
    records = _records()
    records[0]["interaction_id"] = "interaction-1"
    graph = graph_from_inventory(
        _inventory(),
        records,
        {
            "run_id": "run-1",
            "captured_at": "2026-08-13T12:00:00+00:00",
            "surfaces": ["https://api.example.com/app?secret=CANARY"],
            "interactions": [
                {
                    "id": "interaction-1",
                    "kind": "navigation",
                    "surface": "https://api.example.com/app?secret=CANARY",
                    "calls": 1,
                    "settled": True,
                }
            ],
        },
    ).to_dict()
    assert graph["interactions"][0]["caused_evidence_ids"] == [graph["evidence"][0]["id"]]
    assert "CANARY" not in json.dumps(graph)


def test_graph_models_credential_names_and_scopes_without_values() -> None:
    inventory = _inventory()
    inventory["auth_headers"] = {"Authorization": 3, "X-API-Key": 2}
    graph = graph_from_inventory(
        inventory,
        [],
        {
            "run_id": "generation-7",
            "captured_at": "2026-08-13T12:00:00+00:00",
            "surfaces": ["https://api.example.com/app"],
            "interactions": [
                {
                    "id": "interaction-login",
                    "kind": "navigation",
                    "surface": "https://api.example.com/app",
                }
            ],
            "authentication": {
                "public_identifier_names": [],
                "secret_credential_names": ["authorization", "x-api-key"],
                "observations": [
                    {
                        "credential_name": "authorization",
                        "interaction_id": "interaction-login",
                        "event": "observed",
                    }
                ],
            },
        },
    ).to_dict()
    scope = graph["credential_scopes"][0]
    assert scope["header_names"] == ["authorization", "x-api-key"]
    assert scope["generation_id"] == "generation-7"
    assert set(scope["operation_ids"]) == {op["id"] for op in graph["operations"]}
    assert graph["authentication_flows"][0]["credential_scope_ids"] == [scope["id"]]
    assert graph["authentication_flows"][0]["mechanisms"] == ["api-key", "bearer-or-oauth"]
    assert graph["authentication_flows"][0]["secret_credential_names"] == [
        "authorization",
        "x-api-key",
    ]
    assert graph["authentication_flows"][0]["minting_interaction_ids"] == ["interaction-login"]
    assert "CANARY" not in json.dumps(graph)
    assert inventory_from_graph(graph)["auth_headers"] == {
        "authorization": "<present>",
        "x-api-key": "<present>",
    }


def test_websocket_graph_projection_is_not_misclassified_as_graphql() -> None:
    inventory = _inventory()
    inventory["websocket_operations"] = {
        "wss://api.example.com/socket.io/::received::price": {
            "url": "wss://api.example.com/socket.io/",
            "event": "price",
            "direction": "received",
            "namespace": "/market",
            "calls": 3,
            "engineio": "4",
            "input_schema": {"type": "array", "items": {"type": "number"}},
        }
    }
    graph = graph_from_inventory(
        inventory,
        [],
        {"run_id": "run-1", "captured_at": "2026-08-13T12:00:00+00:00"},
    ).to_dict()
    event_operation = next(op for op in graph["operations"] if op["protocol"] == "socketio")
    assert event_operation["semantic_kind"] == "subscription"
    assert graph["event_channels"][0]["received_events"] == ["price"]
    projected = inventory_from_graph(graph)
    assert "wss://api.example.com/socket.io/::received::price" in projected["websocket_operations"]
    assert all(meta["protocol"] != "socketio" for meta in projected["graphql_operations"].values())


def test_misc_protocols_round_trip_as_unknown_non_graphql_inventory() -> None:
    inventory = _inventory()
    inventory["misc_operations"] = {
        "json-rpc:POST:https://api.example.com/rpc": {
            "id": "json-rpc:POST:https://api.example.com/rpc",
            "protocol": "json-rpc",
            "url": "https://api.example.com/rpc",
            "method": "POST",
            "calls": 2,
            "request_shape": {"jsonrpc": "str", "method": "str"},
            "executable": False,
        }
    }
    graph = graph_from_inventory(
        inventory,
        [],
        {"run_id": "run-1", "captured_at": "2026-08-13T12:00:00+00:00"},
    ).to_dict()
    operation = next(item for item in graph["operations"] if item["protocol"] == "json-rpc")

    assert operation["semantic_kind"] == "unknown"
    projected = inventory_from_graph(graph)
    assert projected["misc_operations"][operation["aliases"][0]]["executable"] is False
    assert not any(
        item.get("protocol") == "json-rpc" for item in projected["graphql_operations"].values()
    )


def test_future_graph_version_is_rejected_loudly(tmp_path) -> None:
    value = graph_from_inventory(
        _inventory(), [], {"run_id": "run-1", "captured_at": "2026-08-13T12:00:00+00:00"}
    ).to_dict()
    value["schema_version"] = 99
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ArtifactError, match="unsupported backend graph schema_version 99"):
        load_graph(path)
    with pytest.raises(ArtifactError, match="newer than this astrolabe"):
        migrate_graph(value)


def test_atomic_write_retains_last_known_good(tmp_path) -> None:
    path = tmp_path / "artifact.json"
    atomic_write_json(path, {"generation": 1})
    atomic_write_json(path, {"generation": 2})
    assert json.loads(path.read_text()) == {"generation": 2}
    assert json.loads((tmp_path / ".artifact.json.lkg").read_text()) == {"generation": 1}


def test_manifest_checksums_detect_tampering(tmp_path) -> None:
    atomic_write_json(tmp_path / "graph.json", {"schema_version": 1})
    manifest = build_manifest(
        tmp_path,
        artifact_type="backend-graph",
        artifact_schema_version=1,
        run_id="run-1",
        target="example.com",
        completeness="complete",
        started_at="2026-08-13T12:00:00+00:00",
        completed_at="2026-08-13T12:01:00+00:00",
        artifact_names=["graph.json"],
    )
    validate_artifact(manifest.to_dict(), "artifact-manifest-v1.schema.json")
    assert verify_manifest(tmp_path, manifest) == []
    atomic_write_json(tmp_path / "graph.json", {"schema_version": 2})
    assert verify_manifest(tmp_path, manifest) == ["checksum:graph.json"]


def test_schema_validation_reports_exact_path() -> None:
    value = graph_from_inventory(
        _inventory(), [], {"run_id": "run-1", "captured_at": "2026-08-13T12:00:00+00:00"}
    ).to_dict()
    value["operations"][0]["semantic_kind"] = "persisted"
    with pytest.raises(ArtifactError, match=r"operations/0/semantic_kind"):
        validate_artifact(value, "backend-graph-v1.schema.json")


def test_cli_inspects_graph_and_migrates_without_in_place_overwrite(tmp_path, capsys) -> None:
    graph = graph_from_inventory(
        _inventory(), [], {"run_id": "run-1", "captured_at": "2026-08-13T12:00:00+00:00"}
    )
    source = tmp_path / "graph.json"
    write_graph(source, graph)
    cli.cmd_inspect_artifact(type("Args", (), {"path": str(source)})())
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] is True
    assert report["operations"] == 2

    destination = tmp_path / "migrated.json"
    cli.cmd_migrate_artifact(type("Args", (), {"path": str(source), "out": str(destination)})())
    assert load_graph(destination)["schema_version"] == 1


def test_merge_rotates_identifier_and_retains_history() -> None:
    first_inventory = _inventory()
    first_inventory["graphql_operations"]["Viewer"]["protocol"] = "graphql-x-persisted"
    first_inventory["graphql_operations"]["Viewer"]["persistedHash"] = "old-id"
    first = graph_from_inventory(
        first_inventory,
        _records(),
        {"run_id": "run-1", "captured_at": "2026-08-12T12:00:00+00:00"},
    ).to_dict()
    second_inventory = deepcopy(first_inventory)
    second_inventory["graphql_operations"]["Viewer"]["persistedHash"] = "new-id"
    second = graph_from_inventory(
        second_inventory,
        _records(),
        {"run_id": "run-2", "captured_at": "2026-08-13T12:00:00+00:00"},
    ).to_dict()

    merged = merge_graphs(first, second)
    operation = merged["operations"][0]
    identifiers = {item["value"]: item["current"] for item in operation["identifiers"]}
    assert identifiers == {"old-id": False, "new-id": True}
    assert operation["lifecycle"]["run_ids"] == ["run-1", "run-2"]
    identifier_drift = [item for item in merged["drifts"] if item["dimension"] == "identifiers"]
    assert identifier_drift[0]["severity"] == "breaking"
    assert identifier_drift[0]["remediation"] == "recapture-and-regenerate"


def test_partial_run_absence_does_not_mark_operation_missing() -> None:
    first = graph_from_inventory(
        _inventory(),
        _records(),
        {"run_id": "run-1", "captured_at": "2026-08-12T12:00:00+00:00"},
    ).to_dict()
    empty = _inventory()
    empty["graphql_operations"] = {}
    empty["rest_endpoints"] = []
    partial = graph_from_inventory(
        empty,
        [],
        {
            "run_id": "run-2",
            "captured_at": "2026-08-13T12:00:00+00:00",
            "partial": True,
        },
    ).to_dict()
    merged = merge_graphs(first, partial)
    assert all(op["lifecycle"]["status"] == "current" for op in merged["operations"])
    assert all(op["lifecycle"]["consecutive_misses"] == 0 for op in merged["operations"])


def test_complete_run_absence_records_miss_without_retiring() -> None:
    first = graph_from_inventory(
        _inventory(),
        _records(),
        {"run_id": "run-1", "captured_at": "2026-08-12T12:00:00+00:00"},
    ).to_dict()
    empty = _inventory()
    empty["graphql_operations"] = {}
    empty["rest_endpoints"] = []
    complete = graph_from_inventory(
        empty,
        [],
        {"run_id": "run-2", "captured_at": "2026-08-13T12:00:00+00:00"},
    ).to_dict()
    merged = merge_graphs(first, complete)
    assert all(op["lifecycle"]["status"] == "not_observed_this_run" for op in merged["operations"])
    assert all(op["lifecycle"]["consecutive_misses"] == 1 for op in merged["operations"])

    projected = inventory_from_graph(merged)
    assert projected["graphql_operations"]["Viewer"]["lifecycle_status"] == (
        "not_observed_this_run"
    )
    assert projected["rest_endpoints"][0]["status"] == []


def test_noncurrent_graph_operations_are_not_exposed_by_generator(tmp_path) -> None:
    first = graph_from_inventory(
        _inventory(),
        _records(),
        {"run_id": "run-1", "captured_at": "2026-08-12T12:00:00+00:00"},
    ).to_dict()
    empty = _inventory()
    empty["graphql_operations"] = {}
    empty["rest_endpoints"] = []
    complete = graph_from_inventory(
        empty,
        [],
        {"run_id": "run-2", "captured_at": "2026-08-13T12:00:00+00:00"},
    ).to_dict()
    atomic_write_json(tmp_path / "graph.json", merge_graphs(first, complete))

    pack = build_pack(str(tmp_path))
    assert pack["tools"]
    assert not any(tool["exposed"] for tool in pack["tools"])
    assert all("not_observed_this_run" in tool["reason"] for tool in pack["tools"])
