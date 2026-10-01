from __future__ import annotations

import json
from pathlib import Path

import pytest

from astrolabe.contract import merge
from astrolabe.mcpgen import build_pack
from astrolabe.sanitize import sanitize_capture, sanitize_record
from astrolabe.sextant import Runtime
from astrolabe.toolpack import ConfigurationError, Settings, _validate_pack


def _contract(identifier: str, active: bool) -> dict:
    operation = {
        "operation": "Feed",
        "type": "query",
        "semantic_kind": "query",
        "protocol": "graphql-x-persisted",
        "queryId_or_hash": identifier,
        "identifier_history": [],
        "transport": "graphql",
        "input_schema": {"type": "object", "properties": {}},
        "return_schema": {
            "type": "object",
            "properties": {"timeline": {"type": "object"}},
        },
        "proof": {
            "observed": {"ok": True, "status": [200], "samples": 1},
            "active": {"ok": True} if active else None,
        },
        "status": "verified-active" if active else "verified-observed",
    }
    return {
        "schema_version": 2,
        "base_domain": "example.com",
        "operations": {"Feed": operation},
    }


def test_identifier_rotation_uses_fresh_id_and_invalidates_old_active_proof() -> None:
    merged, drift = merge(_contract("old-id", True), _contract("fresh-id", False))
    feed = merged["operations"]["Feed"]
    assert feed["queryId_or_hash"] == "fresh-id"
    assert feed["identifier_history"] == ["old-id"]
    assert feed["proof"]["active"] is None
    assert "Feed" in drift["changed"]


def test_legacy_persisted_semantic_kind_is_unknown_and_gated(tmp_path: Path) -> None:
    (tmp_path / "endpoints.json").write_text(
        json.dumps(
            {
                "base_domain": "example.com",
                "graphql_endpoints": ["/graphql"],
                "graphql_operations": {
                    "mystery": {
                        "type": "persisted",
                        "operation": "Mystery",
                        "persistedHash": "vendor-id",
                        "input_schema": {"type": "object", "properties": {}},
                    }
                },
            }
        )
    )
    tool = build_pack(str(tmp_path))["tools"][0]
    assert tool["semantic_kind"] == "unknown"
    assert tool["exposed"] is False
    assert "unknown semantic" in tool["reason"]


def test_persisted_query_adapter_preserves_path_method_and_feature_template(
    tmp_path: Path,
) -> None:
    pack = {
        "version": 2,
        "base_domain": "example.com",
        "endpoint": "https://example.com/graphql",
        "tools": [],
    }
    runtime = Runtime(Settings(tmp_path / "pack.json", allow_anonymous=True), pack)
    tool = {
        "protocol": "graphql-x-persisted",
        "request_url": "https://example.com/graphql/current-id/Feed?variables=%3Cpresent%3E",
        "http_method": "GET",
        "request_template": {"features": {"timeline_navigation_enabled": True}},
    }
    method, url, body, params = runtime._build_graphql_request(tool, {"userId": "1"}, {})
    assert method == "GET"
    assert url == "https://example.com/graphql/current-id/Feed"
    assert body is None
    assert params is not None
    assert json.loads(params["variables"]) == {"userId": "1"}
    assert json.loads(params["features"])["timeline_navigation_enabled"]


def test_sanitize_record_and_file_remove_canary_values(tmp_path: Path) -> None:
    canary = "UNIQUE-CANARY-SECRET"
    cleaned = sanitize_record(
        {
            "url": f"https://example.com/api?alias=Feed&variables={canary}",
            "req_body_sample": json.dumps({"token": canary, "ids": [1]}),
        }
    )
    assert canary not in json.dumps(cleaned)
    assert cleaned["request_shape"] == {"token": "str", "ids": ["int"]}

    capture = tmp_path / "capture.jsonl"
    capture.write_text(
        json.dumps({"url": f"https://example.com/x?q={canary}", "req_body_sample": canary}) + "\n"
    )
    assert sanitize_capture(capture) == 1
    assert canary not in capture.read_text()


def test_protocol_override_fixture_generates_runtime_compatible_tools(tmp_path: Path) -> None:
    """A reviewed protocol-overrides.json (persisted-query IDs the capture heuristics
    can't infer on their own) joins into the pack and survives runtime validation."""
    (tmp_path / "endpoints.json").write_text(
        json.dumps(
            {
                "base_domain": "example.com",
                "graphql_endpoints": ["/graphql"],
                "graphql_operations": {
                    "Feed": {
                        "type": "query",
                        "operation": "Feed",
                        "input_schema": {"type": "object", "properties": {}},
                        "return_schema": {"type": "object", "properties": {}},
                    }
                },
            }
        )
    )
    (tmp_path / "protocol-overrides.json").write_text(
        json.dumps(
            {
                "Feed": {
                    "queryId": "current-id",
                    "method": "GET",
                    "features": {"timeline_navigation_enabled": True},
                }
            }
        )
    )
    pack = build_pack(str(tmp_path))
    validated = _validate_pack(pack, Settings(tmp_path / "toolpack.json"))
    feed = next(tool for tool in validated["tools"] if tool["alias"] == "Feed")
    assert feed["protocol"] == "graphql-x-persisted"
    assert feed["exposed"] is True
    assert feed["request_template"]["features"]["timeline_navigation_enabled"]


def test_historical_pack_is_rejected_as_non_executable(tmp_path: Path) -> None:
    pack = {
        "version": 2,
        "base_domain": "example.com",
        "endpoint": "https://example.com/graphql",
        "historical": True,
        "executable": False,
        "tools": [],
    }
    with pytest.raises(ConfigurationError, match="historical"):
        _validate_pack(pack, Settings(tmp_path / "toolpack.json"))
