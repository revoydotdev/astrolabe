"""Tests for configuration, safety gates, execution, and MCP discovery."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import ssl
import stat
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from mcp.types import TextContent
from starlette.middleware import Middleware
from starlette.responses import JSONResponse

import astrolabe.mcp_server as server_module
from astrolabe.ir import graph_from_inventory, write_graph
from astrolabe.mcp_server import (
    ConfigurationError,
    CredentialProvider,
    FileCredentialProvider,
    GraphQLTool,
    RemoteBoundaryMiddleware,
    RemoteHTTPProfile,
    Runtime,
    SemanticKind,
    Settings,
    _parser,
    _provider_specs,
    _remote_auth,
    _remote_profile,
    _safe_headers,
    _validate_pack,
    create_server,
)


@pytest.fixture(autouse=True)
def _close_runtime_executors(monkeypatch):
    """Each test owns any upstream worker pool it creates.

    Production servers close through FastMCP lifespan and Runtime also has a finalizer. Explicit
    per-test cleanup prevents delayed cyclic GC from accumulating idle pools in constrained CI.
    """
    instances = []
    original_init = Runtime.__init__

    def tracked_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        instances.append(self)

    monkeypatch.setattr(Runtime, "__init__", tracked_init)
    yield
    for instance in instances:
        instance.close()


DISCOVERY_TOOLS = {
    "search_operations",
    "describe_operation",
    "trace_surface",
    "diff_contract",
    "coverage_report",
    "verify_operation",
    "invoke_query",
    "subscribe_events",
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "success", "validated"),
    [
        ({"data": {"jobs": []}, "_astrolabe": {"schema_validated": True}}, True, True),
        ({"error_code": "BAD_ARGUMENTS", "ok": False}, False, False),
        (
            {
                "data": {},
                "errors": [{"message": "failed"}],
                "_astrolabe": {"schema_validated": True, "partial": True},
            },
            False,
            True,
        ),
    ],
)
async def test_verify_operation_reports_actual_proof(
    configured, monkeypatch, response, success, validated
):
    async def execute(self, tool, arguments):
        return response

    monkeypatch.setattr(Runtime, "execute", execute)
    settings, _ = configured
    async with Client(create_server(settings)) as client:
        result = await client.call_tool(
            "verify_operation",
            {
                "operation_id": "jobSearch",
                "arguments": {},
            },
        )
    assert result.data["ok"] is success
    assert result.data["proof"]["success"] is success
    assert result.data["proof"]["schema_validated"] is validated
    journal = settings.toolpack_path.with_name("verification.jsonl")
    recorded = json.loads(journal.read_text())
    assert recorded["proof"]["success"] is success
    assert "result" not in recorded
    assert "arguments" not in recorded
    assert result.data["proof_recorded"] is True


def _named_tool(tools: list[Any], name: str) -> Any:
    return next(tool for tool in tools if tool.name == name)


@pytest.fixture
def pack() -> dict[str, Any]:
    return {
        "base_domain": "example.com",
        "endpoint": "https://api.example.com/graphql?client=astrolabe",
        "tools": [
            {
                "name": "jobSearch",
                "description": "find jobs",
                "input_schema": {
                    "type": "object",
                    "properties": {"page": {"type": "integer"}},
                    "additionalProperties": False,
                },
                "query": "query JobSearch($page:Int){jobs(page:$page)}",
                "operation": "JobSearch",
                "alias": "jobSearch",
                "type": "query",
                "exposed": True,
                "curated": True,
                "returns": ["jobs"],
            },
            {
                "name": "deleteJob",
                "description": "delete a job",
                "input_schema": {"type": "object", "properties": {}},
                "query": "mutation DeleteJob { deleteJob }",
                "operation": "DeleteJob",
                "alias": "deleteJob",
                "type": "mutation",
                "exposed": True,
            },
        ],
    }


@pytest.fixture
def configured(
    tmp_path: Path, pack: dict[str, Any], _close_runtime_executors
) -> tuple[Settings, Runtime]:
    toolpack = tmp_path / "toolpack.json"
    auth = tmp_path / "auth.json"
    cookies = tmp_path / "cookies.json"
    toolpack.write_text(json.dumps(pack))
    auth.write_text(json.dumps({"jobSearch": {"authorization": "Bearer JOB"}}))
    cookies.write_text("[]")
    settings = Settings(toolpack, auth, cookies, retries=1)
    return settings, Runtime(settings, _validate_pack(pack, settings))


def test_configuration_is_lazy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASTROLABE_TOOLPACK", raising=False)
    with pytest.raises(ConfigurationError, match="ASTROLABE_TOOLPACK"):
        Settings.from_env()


def test_settings_from_env_parses_operational_limits(tmp_path: Path, monkeypatch) -> None:
    pack_path = tmp_path / "pack.json"
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(pack_path))
    monkeypatch.setenv("ASTROLABE_ALLOW_ANONYMOUS", "1")
    monkeypatch.setenv("ASTROLABE_MAX_CONCURRENCY", "7")
    monkeypatch.setenv("ASTROLABE_TIMEOUT_SECONDS", "12.5")
    monkeypatch.setenv("ASTROLABE_MAX_RESPONSE_BYTES", "9000")
    monkeypatch.setenv("ASTROLABE_RETRIES", "3")
    settings = Settings.from_env()
    assert settings.toolpack_path == pack_path
    assert settings.allow_anonymous is True
    assert settings.max_concurrency == 7
    assert settings.timeout_seconds == 12.5
    assert settings.max_response_bytes == 9000
    assert settings.retries == 3


def test_settings_reject_invalid_limits(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(tmp_path / "pack.json"))
    monkeypatch.setenv("ASTROLABE_MAX_CONCURRENCY", "zero")
    with pytest.raises(ConfigurationError, match="integer"):
        Settings.from_env()


def test_pack_rejects_cross_domain_endpoint(tmp_path: Path, pack: dict[str, Any]) -> None:
    settings = Settings(tmp_path / "pack.json")
    pack["endpoint"] = "https://attacker.invalid/collect"
    with pytest.raises(ConfigurationError, match="endpoint host"):
        _validate_pack(pack, settings)


def test_pack_rejects_cross_domain_operation_endpoint(tmp_path: Path, pack: dict[str, Any]) -> None:
    pack["tools"][0]["request_url"] = "https://attacker.invalid/graphql"
    with pytest.raises(ConfigurationError, match="request URL"):
        _validate_pack(pack, Settings(tmp_path / "pack.json"))


def test_pack_rejects_duplicate_tools(tmp_path: Path, pack: dict[str, Any]) -> None:
    settings = Settings(tmp_path / "pack.json")
    pack["tools"].append(dict(pack["tools"][0]))
    with pytest.raises(ConfigurationError, match="unique"):
        _validate_pack(pack, settings)


def test_pack_rejects_graphql_semantic_mismatch(tmp_path: Path, pack: dict[str, Any]) -> None:
    pack["tools"][0]["query"] = "mutation JobSearch { deleteJob }"
    with pytest.raises(ConfigurationError, match="semantic type disagrees"):
        _validate_pack(pack, Settings(tmp_path / "pack.json"))


def test_pack_rejects_malformed_exposed_graphql(tmp_path: Path, pack: dict[str, Any]) -> None:
    pack["tools"][0]["query"] = "query JobSearch { jobs("
    with pytest.raises(ConfigurationError, match="malformed GraphQL"):
        _validate_pack(pack, Settings(tmp_path / "pack.json"))


def test_safe_headers_are_generic_and_strip_hop_by_hop() -> None:
    result = _safe_headers(
        {"Authorization": "Bearer x", "X-Custom-Tenant": 7, "Host": "evil", "Cookie": "x=y"}
    )
    assert result == {"Authorization": "Bearer x", "X-Custom-Tenant": "7"}


def test_runtime_builds_thread_local_cookie_session(configured) -> None:
    _, runtime = configured
    runtime._cookies = [
        {"name": "session", "value": "secret", "domain": ".example.com", "path": "/"},
        {"broken": True},
    ]
    first = runtime._session()
    assert runtime._session() is first
    assert first.cookies.get("session", domain=".example.com", path="/") == "secret"


def test_runtime_keeps_cookie_snapshot_paired_to_generation(configured) -> None:
    _, runtime = configured
    generation_one = runtime._session(
        "g1", ({"name": "session", "value": "one", "domain": ".example.com", "path": "/"},)
    )
    assert (
        runtime._session(
            "g1", ({"name": "session", "value": "one", "domain": ".example.com", "path": "/"},)
        )
        is generation_one
    )
    generation_two = runtime._session(
        "g2", ({"name": "session", "value": "two", "domain": ".example.com", "path": "/"},)
    )
    assert generation_two is not generation_one
    assert generation_two.cookies.get("session", domain=".example.com", path="/") == "two"


def test_runtime_rejects_v2_cookie_bundle_for_wrong_target(tmp_path, pack) -> None:
    pack_path = tmp_path / "pack.json"
    cookie_path = tmp_path / "cookies.json"
    pack_path.write_text(json.dumps(pack))
    cookie_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "generation_id": "g2",
                "generated_at": "2026-08-14T12:00:00Z",
                "source": "test-bootstrap",
                "target_origin": "https://evil.example",
                "session_binding": "g2",
                "cookies": [],
            }
        )
    )
    with pytest.raises(ConfigurationError, match="target origin"):
        Runtime(
            Settings(pack_path, cookies_path=cookie_path), _validate_pack(pack, Settings(pack_path))
        )


@pytest.mark.asyncio
async def test_missing_scoped_auth_fails_without_fallback(configured) -> None:
    _, runtime = configured
    tool = runtime.pack["tools"][1]
    result = await runtime.execute(tool, {})
    assert result["error_code"] == "MUTATION_GATED"

    runtime.settings = Settings(
        runtime.settings.toolpack_path,
        runtime.settings.auth_path,
        runtime.settings.cookies_path,
        allow_mutations=True,
        retries=1,
    )
    result = await runtime.execute(tool, {})
    assert result["error_code"] == "NO_BEARER"
    assert "jobSearch" not in result["error_detail"]


@pytest.mark.asyncio
async def test_unknown_semantic_kind_is_never_listed_or_executed(tmp_path, pack) -> None:
    """A persisted operation whose kind was never classified stays inventory-only.

    This is the gate that carries every X/Instagram persisted operation recovered
    without a document: the request URL is known but the query text is not, so the
    read/write distinction is unproven. Enabling mutations must not unlock it --
    an unclassified operation is not a mutation that the operator has approved.
    """
    pack["tools"].append(
        {
            "name": "DataSaverMode",
            "description": "persisted operation recovered without a document",
            "input_schema": {"type": "object", "properties": {}},
            "operation": "DataSaverMode",
            "alias": "dataSaverMode",
            "type": SemanticKind.UNKNOWN.value,
            "semantic_kind": SemanticKind.UNKNOWN.value,
            "transport": "graphql",
            "protocol": "graphql-x-persisted",
            "query": "",
            "apq_hash": "Synth3ticQueryId_00A",
            "apq_fallback_allowed": False,
            "request_url": "https://api.example.com/i/api/graphql/xF6sXn/DataSaverMode",
            "exposed": False,
        }
    )
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))
    settings = Settings(pack_path, retries=1)
    runtime = Runtime(settings, _validate_pack(pack, settings))
    tool = runtime.pack["tools"][-1]

    assert "dataSaverMode" not in {t["alias"] for t in _provider_specs(runtime.pack, settings)}
    assert (await runtime.execute(tool, {}))["error_code"] == "UNKNOWN_SEMANTIC_KIND"

    # The mutation flag is a separate gate; it must not double as a bypass here.
    permissive = dataclasses.replace(settings, allow_mutations=True)
    assert "dataSaverMode" not in {t["alias"] for t in _provider_specs(runtime.pack, permissive)}
    runtime.settings = permissive
    assert (await runtime.execute(tool, {}))["error_code"] == "UNKNOWN_SEMANTIC_KIND"


@pytest.mark.asyncio
async def test_execute_builds_generic_request_without_blocking_test_loop(
    configured, monkeypatch
) -> None:
    _, runtime = configured
    captured: dict[str, Any] = {}

    async def immediate(func, *args):
        return func(*args)

    def request(
        method,
        url,
        headers,
        body,
        operation_type,
        params=None,
        output_schema=None,
        transport="graphql",
        alias="unknown",
        response_variants=None,
        cookie_generation=...,
        cookies=None,
    ):
        captured.update(
            method=method,
            url=url,
            headers=headers,
            body=body,
            operation_type=operation_type,
            params=params,
            output_schema=output_schema,
            transport=transport,
            alias=alias,
            response_variants=response_variants,
        )
        return {"data": {"ok": True}}

    monkeypatch.setattr(server_module.asyncio, "to_thread", immediate)
    monkeypatch.setattr(runtime, "_request", request)
    result = await runtime.execute(runtime.pack["tools"][0], {"page": 2})
    assert result["data"] == {"ok": True}
    assert result["_astrolabe"]["queue_ms"] >= 0
    assert captured["method"] == "POST"
    assert captured["headers"]["authorization"] == "Bearer JOB"
    assert captured["body"]["operationName"] == "JobSearch"
    assert captured["body"]["variables"] == {"page": 2}


@pytest.mark.asyncio
async def test_generated_tool_returns_structured_mcp_error(configured, monkeypatch) -> None:
    _, runtime = configured

    async def fail(spec, arguments):
        return {
            "ok": False,
            "error_code": "UPSTREAM_UNAVAILABLE",
            "error_detail": "offline",
            "retryable": True,
        }

    monkeypatch.setattr(runtime, "execute", fail)
    result = await GraphQLTool(runtime, runtime.pack["tools"][0]).run({"page": 1})
    assert result.is_error is True
    assert result.structured_content is not None
    assert result.structured_content["error_code"] == "UPSTREAM_UNAVAILABLE"
    first = result.content[0]
    assert isinstance(first, TextContent)
    assert "offline" in first.text


def test_successful_request_returns_instrumented_json(configured, monkeypatch) -> None:
    _, runtime = configured
    captured: dict[str, Any] = {}

    class Response:
        status_code = 200
        content = b'{"data":{"ok":true}}'
        headers: dict[str, str] = {}

        def json(self):
            return {"data": {"ok": True}}

    class Session:
        def request(self, method, url, **kwargs):
            captured.update(method=method, url=url, **kwargs)
            return Response()

    monkeypatch.setattr(runtime, "_session", lambda *_args: Session())
    result = runtime._request(
        "POST",
        "https://api.example.com/graphql?client=astrolabe&alias=jobSearch",
        {"authorization": "Bearer JOB"},
        {"operationName": "JobSearch", "variables": {"page": 1}},
        "query",
    )
    assert result["data"] == {"ok": True}
    assert captured["headers"]["authorization"] == "Bearer JOB"
    assert captured["json"]["operationName"] == "JobSearch"
    assert captured["json"]["variables"] == {"page": 1}
    assert "client=astrolabe" in captured["url"] and "alias=jobSearch" in captured["url"]


@pytest.mark.asyncio
async def test_execute_validates_input_schema_before_credentials_or_network(
    configured, monkeypatch
) -> None:
    _, runtime = configured
    monkeypatch.setattr(
        runtime._credential_provider,
        "get",
        lambda _alias: (_ for _ in ()).throw(AssertionError("credentials must not load")),
    )
    result = await runtime.execute(runtime.pack["tools"][0], {"page": "not-an-integer"})
    assert result["error_code"] == "BAD_ARGUMENTS"
    assert "/page" in result["error_detail"]


@pytest.mark.asyncio
async def test_execute_enforces_argument_budgets_before_network(configured) -> None:
    settings, runtime = configured
    runtime.settings = Settings(
        settings.toolpack_path,
        settings.auth_path,
        settings.cookies_path,
        max_argument_string_length=4,
    )
    runtime.pack["tools"][0]["input_schema"] = {
        "type": "object",
        "properties": {"page": {"type": "string"}},
    }
    result = await runtime.execute(runtime.pack["tools"][0], {"page": "too-long"})
    assert result["error_code"] == "ARGUMENT_LIMIT_EXCEEDED"
    assert "max-string-length" in result["error_detail"]


def test_output_schema_drift_is_a_typed_failure(configured, monkeypatch) -> None:
    _, runtime = configured
    _stub_upstream(runtime, monkeypatch, 200, {"data": {"id": "wrong"}})
    output_schema = {
        "type": "object",
        "properties": {
            "data": {
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "integer"}},
            }
        },
        "required": ["data"],
        "additionalProperties": True,
    }
    result = runtime._request(
        "POST",
        "https://api.example.com/graphql",
        {},
        {},
        "query",
        output_schema=output_schema,
    )
    assert result["error_code"] == "SCHEMA_DRIFT"
    assert "/data/id" in result["error_detail"]
    assert result["_astrolabe"]["schema_validated"] is False


def test_partial_graphql_data_plus_errors_is_returned_as_partial_success(
    configured, monkeypatch
) -> None:
    _, runtime = configured
    _stub_upstream(
        runtime,
        monkeypatch,
        200,
        {"data": {"viewer": None}, "errors": [{"message": "field unavailable"}]},
    )
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["data"] == {"viewer": None}
    assert result["errors"]
    assert result["_astrolabe"]["partial"] is True


def test_rest_payload_is_wrapped_to_match_declared_output_envelope(configured, monkeypatch) -> None:
    _, runtime = configured
    _stub_upstream(runtime, monkeypatch, 200, {"id": 7})
    result = runtime._request(
        "GET",
        "https://api.example.com/items/7",
        {},
        None,
        "query",
        transport="rest",
    )
    assert result["data"] == {"id": 7}
    assert result["_astrolabe"]["schema_validated"] is True


def test_non_json_response_does_not_leak_body(configured, monkeypatch) -> None:
    _, runtime = configured

    class Response:
        status_code = 502
        content = b"secret upstream html"
        headers: dict[str, str] = {}

        def json(self):
            raise ValueError("not json")

    class Session:
        def request(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(runtime, "_session", lambda *_args: Session())
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["error_code"] == "UPSTREAM_NON_JSON"
    assert "secret" not in result["error_detail"]


def test_response_size_is_bounded(configured, monkeypatch) -> None:
    settings, runtime = configured
    runtime.settings = Settings(
        settings.toolpack_path, settings.auth_path, settings.cookies_path, max_response_bytes=5
    )

    class Response:
        status_code = 200
        content = b"123456"
        headers: dict[str, str] = {}

    class Session:
        def request(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(runtime, "_session", lambda *_args: Session())
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["error_code"] == "RESPONSE_TOO_LARGE"


def test_transport_failure_has_stable_retryable_error(configured, monkeypatch) -> None:
    _, runtime = configured

    class Session:
        def request(self, *_args, **_kwargs):
            raise RuntimeError("connection reset")

    monkeypatch.setattr(runtime, "_session", lambda *_args: Session())
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result == {
        "ok": False,
        "error_code": "UPSTREAM_UNAVAILABLE",
        "error_detail": "connection reset",
        "retryable": True,
    }


def test_retry_after_supports_http_date() -> None:
    assert server_module._retry_delay(0, "Wed, 21 Oct 2099 07:28:00 GMT") == 5.0


def test_rate_headers_reserve_capacity_before_exhaustion(configured) -> None:
    settings, runtime = configured
    runtime.settings = Settings(
        settings.toolpack_path,
        settings.auth_path,
        settings.cookies_path,
        rate_limit_reserve=2,
    )
    runtime._record_rate_headers(
        "jobSearch",
        "https://api.example.com/graphql",
        {"x-ratelimit-limit": "100", "x-ratelimit-remaining": "2", "x-ratelimit-reset": "60"},
    )
    failure = runtime._admission_failure("jobSearch")
    assert failure and failure["error_code"] == "RATE_BUDGET_RESERVED"
    status = runtime.operational_status()
    assert status["rates"]["operation:jobSearch"]["remaining"] == 2


def test_repeated_failures_open_and_success_resets_circuit(configured) -> None:
    settings, runtime = configured
    runtime.settings = Settings(
        settings.toolpack_path,
        settings.auth_path,
        settings.cookies_path,
        circuit_failure_threshold=2,
        circuit_cooldown_seconds=30,
    )
    runtime._record_outcome("jobSearch", {"error_code": "SCHEMA_DRIFT"})
    assert runtime._admission_failure("jobSearch") is None
    runtime._record_outcome("jobSearch", {"error_code": "UPSTREAM_SERVER_ERROR"})
    failure = runtime._admission_failure("jobSearch")
    assert failure and failure["error_code"] == "CIRCUIT_OPEN"
    runtime._record_outcome("jobSearch", {"data": {"ok": True}})
    assert runtime._admission_failure("jobSearch") is None


@pytest.mark.asyncio
async def test_full_queue_fails_before_credentials_or_network(configured) -> None:
    settings, runtime = configured
    runtime.settings = Settings(
        settings.toolpack_path,
        settings.auth_path,
        settings.cookies_path,
        max_queue=1,
    )
    runtime._queue_waiters = 1
    result = await runtime.execute(runtime.pack["tools"][0], {"page": 1})
    assert result["error_code"] == "QUEUE_FULL"


# ---------- upstream failures must surface as tool failures ----------


def _stub_upstream(runtime, monkeypatch, status: int, payload: Any) -> None:
    class Response:
        status_code = status
        headers: dict[str, str] = {}

        def __init__(self) -> None:
            self.content = json.dumps(payload).encode()

        def json(self):
            return payload

    class Session:
        def request(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(runtime, "_session", lambda *_args: Session())


@pytest.mark.parametrize(
    ("status", "code", "retryable"),
    [
        (401, "UPSTREAM_AUTH_EXPIRED", True),
        (403, "UPSTREAM_FORBIDDEN", False),
        (404, "UPSTREAM_NOT_FOUND", False),
        (429, "UPSTREAM_RATE_LIMITED", True),
        (500, "UPSTREAM_SERVER_ERROR", True),
        (400, "UPSTREAM_CLIENT_ERROR", False),
    ],
)
def test_http_failures_become_typed_failures(
    configured, monkeypatch, status: int, code: str, retryable: bool
) -> None:
    settings, runtime = configured
    runtime.settings = Settings(
        settings.toolpack_path, settings.auth_path, settings.cookies_path, retries=1
    )
    _stub_upstream(runtime, monkeypatch, status, {"message": "nope"})
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["ok"] is False
    assert result["error_code"] == code
    assert result["retryable"] is retryable
    assert result["http_status"] == status
    # the upstream body is preserved so the agent can see the real cause
    assert result["upstream"] == {"message": "nope"}
    assert result["_astrolabe"]["http_status"] == status


def test_graphql_level_errors_become_failures(configured, monkeypatch) -> None:
    _, runtime = configured
    _stub_upstream(runtime, monkeypatch, 200, {"errors": [{"message": "Not authorized"}]})
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["ok"] is False
    assert result["error_code"] == "UPSTREAM_FORBIDDEN"
    assert "Not authorized" in result["error_detail"]
    assert result["retryable"] is False


def test_empty_errors_array_is_still_a_success(configured, monkeypatch) -> None:
    _, runtime = configured
    _stub_upstream(runtime, monkeypatch, 200, {"data": {"ok": True}, "errors": []})
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert "error_code" not in result
    assert result["data"] == {"ok": True}


def test_error_detail_is_bounded(configured, monkeypatch) -> None:
    _, runtime = configured
    _stub_upstream(runtime, monkeypatch, 200, {"errors": [{"message": "x" * 5000}]})
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert len(result["error_detail"]) <= 400


@pytest.mark.asyncio
async def test_expired_token_reaches_the_agent_as_an_error(
    tmp_path: Path, pack: dict[str, Any], monkeypatch
) -> None:
    """The regression this whole error path exists for: a short-lived scoped credential
    expiring must not look like a successful, empty answer."""
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))

    class Response:
        status_code = 401
        headers: dict[str, str] = {}
        content = b'{"message":"token expired"}'

        def json(self):
            return {"message": "token expired"}

    class Session:
        def request(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(Runtime, "_session", lambda self, *_args: Session())
    server = create_server(Settings(pack_path, allow_anonymous=True, retries=1))
    async with Client(server) as client:
        result = await client.call_tool("jobSearch", {"page": 1}, raise_on_error=False)
    assert result.is_error is True
    assert result.structured_content["error_code"] == "UPSTREAM_AUTH_EXPIRED"
    assert result.structured_content["retryable"] is True


@pytest.mark.asyncio
async def test_fastmcp_lists_tools_resources_and_prompt(
    tmp_path: Path, pack: dict[str, Any]
) -> None:
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))
    server = create_server(Settings(pack_path, allow_anonymous=True, retries=1))
    async with Client(server) as client:
        tools = await client.list_tools()
        resources = await client.list_resources()
        templates = await client.list_resource_templates()
        prompts = await client.list_prompts()

    assert {tool.name for tool in tools} == {"jobSearch", *DISCOVERY_TOOLS}
    direct = _named_tool(tools, "jobSearch")
    assert direct.annotations.read_only_hint is True
    assert direct.annotations.idempotent_hint is True
    assert {str(resource.uri) for resource in resources} >= {
        "astrolabe://manifest",
        "astrolabe://health",
    }
    assert any(str(template.uriTemplate) == "astrolabe://tools/{name}" for template in templates)
    assert [prompt.name for prompt in prompts] == ["use_astrolabe"]


@pytest.mark.asyncio
async def test_manifest_count_matches_provider_when_subscription_is_inventoried(
    tmp_path: Path, pack: dict[str, Any]
) -> None:
    pack["tools"].append(
        {
            "name": "jobEvents",
            "description": "job event stream",
            "input_schema": {"type": "object", "properties": {}},
            "query": "subscription JobEvents { jobEvents { id } }",
            "operation": "JobEvents",
            "alias": "jobEvents",
            "type": "subscription",
            "exposed": True,
        }
    )
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))
    server = create_server(Settings(pack_path, allow_anonymous=True, retries=1))
    async with Client(server) as client:
        tools = await asyncio.wait_for(client.list_tools(), timeout=5)
        manifest = json.loads(
            (await asyncio.wait_for(client.read_resource("astrolabe://manifest"), timeout=5))[
                0
            ].text
        )

    assert "jobEvents" not in {tool.name for tool in tools}
    assert manifest["tool_count"] == len(tools)
    event = next(item for item in manifest["inventory"] if item["name"] == "jobEvents")
    assert event["invocable"] is False
    assert event["disabled_reason"]


@pytest.mark.asyncio
async def test_graph_discovery_tools_are_safe_and_include_graph_only_operations(
    tmp_path: Path, pack: dict[str, Any]
) -> None:
    inventory = {
        "base_domain": "example.com",
        "graphql_endpoints": ["/graphql"],
        "auth_headers": {},
        "graphql_operations": {
            "Viewer": {
                "semantic_kind": "query",
                "protocol": "graphql-inline",
                "request_url": "https://api.example.com/graphql",
                "operation": "ViewerQuery",
                "query": "query ViewerQuery { viewer { id } }",
                "calls": 1,
            }
        },
        "rest_endpoints": [],
    }
    graph = graph_from_inventory(
        inventory,
        [],
        {
            "run_id": "run-1",
            "captured_at": "2026-08-13T12:00:00+00:00",
            "surfaces": ["https://example.com/app?token=CANARY"],
            "interactions": [
                {
                    "id": "interaction-1",
                    "kind": "navigation",
                    "surface": "https://example.com/app?token=CANARY",
                    "calls": 0,
                }
            ],
        },
    )
    pack_path = tmp_path / "toolpack.json"
    pack_path.write_text(json.dumps(pack))
    write_graph(tmp_path / "graph.json", graph)
    server = create_server(Settings(pack_path, allow_anonymous=True, retries=1))

    async with Client(server) as client:
        search = await client.call_tool("search_operations", {"query": "Viewer"})
        graph_only = search.structured_content["operations"][0]
        described = await client.call_tool("describe_operation", {"operation_id": graph_only["id"]})
        surface_id = graph.to_dict()["surfaces"][0]["id"]
        traced = await client.call_tool("trace_surface", {"surface": surface_id})
        coverage = await client.call_tool("coverage_report", {})
        rejected = await client.call_tool(
            "invoke_query",
            {"operation_id": graph_only["id"], "arguments": {}},
            raise_on_error=False,
        )

    assert described.structured_content["operation"]["invocable"] is False
    assert traced.structured_content["surface"]["url"] == "https://example.com/app"
    assert "CANARY" not in json.dumps(traced.structured_content)
    assert coverage.structured_content["inventory_count"] == 3
    assert coverage.structured_content["recommended_next_actions"] == [
        {
            "action": "navigation",
            "surface_id": surface_id,
            "surface": "https://example.com/app",
            "reason": "prior interaction produced no attributable backend evidence",
        }
    ]
    assert rejected.structured_content["error_code"] == "OPERATION_NOT_INVOCABLE"


def test_event_channel_rejects_persisted_secret_query_values(
    tmp_path: Path, pack: dict[str, Any]
) -> None:
    pack["event_channels"] = [
        {
            "id": "events",
            "alias": "events",
            "protocol": "websocket",
            "url": "wss://api.example.com/events?session=CANARY",
        }
    ]
    with pytest.raises(ConfigurationError, match="secret-bearing query"):
        _validate_pack(pack, Settings(tmp_path / "pack.json"))


def test_misc_protocol_inventory_can_never_be_marked_executable(
    tmp_path: Path, pack: dict[str, Any]
) -> None:
    pack["misc_operations"] = {
        "rpc": {
            "id": "rpc",
            "protocol": "json-rpc",
            "url": "https://api.example.com/rpc",
            "executable": True,
        }
    }
    with pytest.raises(ConfigurationError, match="inventory-only"):
        _validate_pack(pack, Settings(tmp_path / "pack.json"))


@pytest.mark.asyncio
async def test_runtime_event_subscription_uses_exact_scoped_auth_and_budget(
    tmp_path: Path,
    pack: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack["event_channels"] = [
        {
            "id": "events",
            "alias": "jobEvents",
            "protocol": "sse",
            "url": "https://api.example.com/events",
            "read_only_setup_attested": True,
            "resume_understood": True,
        }
    ]
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps({"jobEvents": {"authorization": "Bearer EVENT"}}))
    settings = Settings(
        tmp_path / "pack.json",
        auth,
        allow_anonymous=False,
        max_event_messages=5,
        event_reconnects=0,
    )
    runtime = Runtime(settings, _validate_pack(pack, settings))
    captured: dict[str, Any] = {}

    async def subscribed(channel, headers, **kwargs):
        captured.update(channel=channel, headers=headers, **kwargs)
        return {"ok": True, "events": [{"event": "message", "data": 1}]}

    monkeypatch.setattr(server_module, "subscribe_channel", subscribed)
    result = await runtime.subscribe_events("events", max_events=2, last_event_id="7")

    assert result["ok"] is True
    assert captured["headers"] == {"authorization": "Bearer EVENT"}
    assert captured["max_events"] == 2
    assert captured["last_event_id"] == "7"
    too_many = await runtime.subscribe_events("events", max_events=6)
    assert too_many["error_code"] == "BAD_ARGUMENTS"


@pytest.mark.asyncio
async def test_socketio_setup_stays_gated_without_read_only_attestation(
    tmp_path: Path, pack: dict[str, Any]
) -> None:
    pack["event_channels"] = [
        {
            "id": "chat",
            "alias": "chat",
            "protocol": "socketio",
            "url": "wss://api.example.com/socket.io/?EIO=4&transport=websocket",
            "read_only_setup_attested": False,
        }
    ]
    settings = Settings(tmp_path / "pack.json", allow_anonymous=True)
    runtime = Runtime(settings, _validate_pack(pack, settings))
    result = await runtime.subscribe_events("chat", max_events=1)
    assert result["error_code"] == "SUBSCRIPTION_SETUP_GATED"


# ---------- REST transport ----------


@pytest.fixture
def rest_pack() -> dict[str, Any]:
    return {
        "version": 2,
        "base_domain": "example.com",
        "tools": [
            {
                "name": "getProduct",
                "transport": "rest",
                "alias": "/api/v2/products/{id}",
                "operation": "GET /api/v2/products/{id}",
                "type": "query",
                "method": "GET",
                "path": "/api/v2/products/{id}",
                "description": "one product",
                "input_schema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}, "fields": {"type": "string"}},
                    "required": ["id"],
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"data": {"type": "object"}},
                },
                "exposed": True,
            },
            {
                "name": "createCart",
                "transport": "rest",
                "alias": "/api/v2/cart",
                "type": "mutation",
                "method": "POST",
                "path": "/api/v2/cart",
                "description": "make a cart",
                "input_schema": {"type": "object", "properties": {"sku": {"type": "string"}}},
                "exposed": True,
            },
        ],
    }


def test_rest_pack_validates_without_a_graphql_endpoint(tmp_path, rest_pack) -> None:
    assert _validate_pack(rest_pack, Settings(tmp_path / "p.json")) is rest_pack


def test_rest_path_must_stay_on_the_mapped_domain(tmp_path, rest_pack) -> None:
    rest_pack["tools"][0]["path"] = "/../../evil"
    with pytest.raises(ConfigurationError):
        _validate_pack(rest_pack, Settings(tmp_path / "p.json"))


def test_graphql_pack_without_endpoint_is_rejected(tmp_path, pack) -> None:
    del pack["endpoint"]
    with pytest.raises(ConfigurationError, match="no endpoint"):
        _validate_pack(pack, Settings(tmp_path / "p.json"))


@pytest.mark.asyncio
async def test_rest_read_sends_path_params_and_query_string(tmp_path, rest_pack) -> None:
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(rest_pack))
    settings = Settings(pack_path, allow_anonymous=True, retries=1)
    runtime = Runtime(settings, _validate_pack(rest_pack, settings))
    method, url, body, params = runtime._build_request(
        rest_pack["tools"][0], {"id": "42", "fields": "name"}, {}
    )
    assert method == "GET"
    assert url == "https://example.com/api/v2/products/42"
    assert body is None
    assert params == {"fields": "name"}


@pytest.mark.asyncio
async def test_rest_write_sends_a_json_body(tmp_path, rest_pack) -> None:
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(rest_pack))
    settings = Settings(pack_path, allow_anonymous=True, allow_mutations=True, retries=1)
    runtime = Runtime(settings, _validate_pack(rest_pack, settings))
    headers: dict[str, str] = {}
    method, url, body, params = runtime._build_request(
        rest_pack["tools"][1], {"sku": "abc"}, headers
    )
    assert (method, url) == ("POST", "https://example.com/api/v2/cart")
    assert body == {"sku": "abc"}
    assert params is None
    assert headers["content-type"] == "application/json"


@pytest.mark.asyncio
async def test_rest_path_params_are_encoded_and_cannot_traverse(tmp_path, rest_pack) -> None:
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(rest_pack))
    settings = Settings(pack_path, allow_anonymous=True, retries=1)
    runtime = Runtime(settings, _validate_pack(rest_pack, settings))
    _, url, _, _ = runtime._build_request(rest_pack["tools"][0], {"id": "../../admin"}, {})
    assert url == "https://example.com/api/v2/products/..%2F..%2Fadmin"


@pytest.mark.parametrize(
    "style,explode,expected",
    [
        ("simple", True, "role=admin%2Fowner,active=True"),
        ("simple", False, "role,admin%2Fowner,active,True"),
        ("label", True, ".role=admin%2Fowner.active=True"),
        ("label", False, ".role,admin%2Fowner,active,True"),
        ("matrix", True, ";role=admin%2Fowner;active=True"),
        ("matrix", False, ";id=role,admin%2Fowner,active,True"),
    ],
)
def test_path_object_serialization_preserves_delimiters(style, explode, expected) -> None:
    assert (
        server_module._path_parameter("id", {"role": "admin/owner", "active": True}, style, explode)
        == expected
    )


def test_openapi_parameter_locations_and_serialization_are_honored(tmp_path, rest_pack) -> None:
    tool = rest_pack["tools"][0]
    tool.update(
        request_url="https://example.com/api/v2/items/{id}",
        path="/api/v2/items/{id}",
        parameters=[
            {
                "name": "id",
                "argument": "path_id",
                "location": "path",
                "style": "simple",
                "explode": False,
            },
            {
                "name": "tags",
                "argument": "tags",
                "location": "query",
                "style": "form",
                "explode": False,
            },
            {
                "name": "prefs",
                "argument": "prefs",
                "location": "query",
                "style": "deepObject",
                "explode": True,
                "allow_reserved": True,
            },
            {
                "name": "X-Tenant",
                "argument": "tenant",
                "location": "header",
                "style": "simple",
                "explode": False,
            },
            {
                "name": "locale",
                "argument": "locale",
                "location": "cookie",
                "style": "form",
                "explode": True,
            },
        ],
    )
    settings = Settings(tmp_path / "pack.json", allow_anonymous=True)
    runtime = Runtime(settings, _validate_pack(rest_pack, settings))
    headers: dict[str, str] = {}
    method, url, body, params = runtime._build_request(
        tool,
        {
            "path_id": "a/b",
            "tags": [1, 2],
            "prefs": {"next": "a/b"},
            "tenant": "west",
            "locale": "en US",
        },
        headers,
    )

    assert method == "GET"
    assert url == ("https://example.com/api/v2/items/a%2Fb?tags=1%2C2&prefs[next]=a/b")
    assert body is None and params is None
    assert headers["X-Tenant"] == "west"
    assert headers["cookie"] == "locale=en%20US"


def test_openapi_json_body_is_separate_from_query_and_headers(tmp_path, rest_pack) -> None:
    tool = rest_pack["tools"][1]
    tool.update(
        request_url="https://example.com/api/v2/search",
        parameters=[
            {"name": "q", "argument": "q", "location": "body"},
            {
                "name": "page",
                "argument": "page",
                "location": "query",
                "style": "form",
                "explode": True,
            },
        ],
        body_media_type="application/json",
    )
    settings = Settings(tmp_path / "pack.json", allow_anonymous=True, allow_mutations=True)
    runtime = Runtime(settings, _validate_pack(rest_pack, settings))
    headers: dict[str, str] = {}
    _, url, body, params = runtime._build_request(tool, {"q": "term", "page": 2}, headers)

    assert url == "https://example.com/api/v2/search?page=2"
    assert body == {"q": "term"}
    assert params is None
    assert headers["content-type"] == "application/json"


@pytest.mark.asyncio
async def test_missing_path_parameter_is_a_clean_failure(tmp_path, rest_pack) -> None:
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(rest_pack))
    settings = Settings(pack_path, allow_anonymous=True, retries=1)
    runtime = Runtime(settings, _validate_pack(rest_pack, settings))
    result = await runtime.execute(rest_pack["tools"][0], {})
    assert result["error_code"] == "BAD_ARGUMENTS"


@pytest.mark.asyncio
async def test_rest_tools_are_listed_with_transport_metadata(tmp_path, rest_pack) -> None:
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(rest_pack))
    server = create_server(Settings(pack_path, allow_anonymous=True, retries=1))
    async with Client(server) as client:
        tools = await client.list_tools()
        manifest = json.loads((await client.read_resource("astrolabe://manifest"))[0].text)
    assert {t.name for t in tools} == {"getProduct", *DISCOVERY_TOOLS}
    assert _named_tool(tools, "getProduct").annotations.read_only_hint is True
    assert (
        next(item for item in manifest["tools"] if item["name"] == "getProduct")["transport"]
        == "rest"
    )
    assert manifest["tool_count"] == len(tools)


def test_rest_204_is_a_typed_empty_success(configured, monkeypatch) -> None:
    _, runtime = configured

    class Response:
        status_code = 204
        content = b""
        headers: dict[str, str] = {}

        def json(self):
            raise ValueError("no body")

    class Session:
        def request(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(runtime, "_session", lambda *_args: Session())
    result = runtime._request(
        "GET",
        "https://example.com/items",
        {},
        None,
        "query",
        transport="rest",
        response_variants=[{"status": "204", "success": True, "media_type": None, "schema": None}],
    )
    assert result["data"] is None
    assert result["_astrolabe"]["http_status"] == 204


def test_rest_validates_the_exact_status_media_schema(configured, monkeypatch) -> None:
    _, runtime = configured
    _stub_upstream(runtime, monkeypatch, 200, {"id": "wrong-type"})
    result = runtime._request(
        "GET",
        "https://example.com/items/1",
        {},
        None,
        "query",
        transport="rest",
        response_variants=[
            {
                "status": "200",
                "success": True,
                "media_type": "application/json",
                "schema": {
                    "type": "object",
                    "properties": {"id": {"type": "integer"}},
                    "required": ["id"],
                },
            }
        ],
    )
    assert result["error_code"] == "SCHEMA_DRIFT"


# ---------- typed return schemas ----------


@pytest.mark.asyncio
async def test_generated_output_schema_is_advertised(tmp_path, pack) -> None:
    pack["tools"][0]["output_schema"] = {
        "type": "object",
        "additionalProperties": True,
        "properties": {"data": {"type": "object", "properties": {"title": {"type": "string"}}}},
    }
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))
    server = create_server(Settings(pack_path, allow_anonymous=True, retries=1))
    async with Client(server) as client:
        tools = await client.list_tools()
        manifest = json.loads((await client.read_resource("astrolabe://manifest"))[0].text)
    assert _named_tool(tools, "jobSearch").output_schema["properties"]["data"]["properties"][
        "title"
    ] == {"type": "string"}
    assert (
        next(item for item in manifest["tools"] if item["name"] == "jobSearch")["typed_return"]
        is True
    )


@pytest.mark.asyncio
async def test_output_schema_falls_back_to_open_object(tmp_path, pack) -> None:
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))
    server = create_server(Settings(pack_path, allow_anonymous=True, retries=1))
    async with Client(server) as client:
        tools = await client.list_tools()
    assert _named_tool(tools, "jobSearch").output_schema == {
        "type": "object",
        "additionalProperties": True,
    }


@pytest.mark.asyncio
async def test_fastmcp_enforces_generated_input_schema(
    tmp_path: Path, pack: dict[str, Any]
) -> None:
    # FastMCP 4 no longer pre-validates the generated schema at the SDK boundary,
    # so the refusal now arrives as astrolabe's own structured envelope instead of
    # a generic SDK "Input validation error". Enforcement is unchanged and strictly
    # more legible: the envelope names the offending path and the failing validator.
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))
    server = create_server(Settings(pack_path, allow_anonymous=True, retries=1))
    async with Client(server) as client:
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("jobSearch", {"page": "not-an-integer"})
    envelope = json.loads(str(excinfo.value))
    assert envelope["ok"] is False
    assert envelope["error_code"] == "BAD_ARGUMENTS"
    (detail,) = json.loads(envelope["error_detail"])
    assert detail["path"] == "/page"
    assert detail["validator"] == "type"


# ---------- credential refresh: FileCredentialProvider ----------


class _FakeProc:
    """Stand-in for a Popen handle: minimal surface `_run_refresh_command` needs."""

    def __init__(self, returncode: int = 0, delay: float = 0.0, pid: int = 4242) -> None:
        self.returncode = returncode
        self._delay = delay
        self.pid = pid

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        if self._delay:
            time.sleep(self._delay)
        return b"", b""


def test_file_provider_refresh_is_a_noop_without_a_command(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("no subprocess may be spawned when refresh is unconfigured")

    monkeypatch.setattr(server_module.subprocess, "Popen", _boom)
    provider = FileCredentialProvider(None)
    assert provider.is_refresh_configured() is False
    assert provider.refresh("jobSearch") is False


def test_file_provider_rejects_empty_refresh_command() -> None:
    with pytest.raises(ConfigurationError):
        FileCredentialProvider(None, refresh_command=())


def test_file_provider_loads_versioned_generation(tmp_path: Path) -> None:
    auth = tmp_path / "auth.json"
    auth.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generation_id": "generation-1",
                "credentials": {"jobSearch": {"authorization": "Bearer SECRET"}},
            }
        )
    )
    provider = FileCredentialProvider(auth)
    assert provider.get("jobSearch") == {"authorization": "Bearer SECRET"}
    status = provider.status()
    assert status["generation_id"] == "generation-1"
    assert "SECRET" not in json.dumps(status)


@pytest.mark.parametrize(
    "record_override,bundle_override,reason",
    [
        ({"target_origin": "https://evil.example"}, {}, "target origin mismatch"),
        ({"operation_scope": ["Other"]}, {}, "operation scope mismatch"),
        ({"session_binding": "different"}, {}, "session binding mismatch"),
        ({}, {"expires_at": "2020-01-01T00:00:00Z"}, "expired"),
    ],
)
def test_file_provider_rejects_invalid_v2_metadata_before_network(
    tmp_path, record_override, bundle_override, reason
) -> None:
    generation = "generation-2"
    record = {
        "headers": {"authorization": "Bearer SECRET"},
        "operation_scope": ["jobSearch"],
        "target_origin": "https://api.example.com",
        "session_binding": generation,
        **record_override,
    }
    bundle = {
        "schema_version": 2,
        "generation_id": generation,
        "generated_at": "2026-08-14T12:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "issuer": "https://example.com",
        "source": "test-bootstrap",
        "target_origin": "https://example.com",
        "session_binding": generation,
        "credentials": {"jobSearch": record},
        **bundle_override,
    }
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps(bundle))
    provider = FileCredentialProvider(
        auth, expected_origins={"jobSearch": "https://api.example.com/graphql"}
    )
    assert provider.get("jobSearch") is None
    assert reason in provider.status()["last_load_error"]
    assert "SECRET" not in json.dumps(provider.status())


def test_file_provider_accepts_valid_v2_origin_scope_and_binding(tmp_path) -> None:
    generation = "generation-2"
    auth = tmp_path / "auth.json"
    auth.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "generation_id": generation,
                "generated_at": "2026-08-14T12:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "issuer": "https://example.com",
                "source": "test-bootstrap",
                "target_origin": "https://example.com",
                "session_binding": generation,
                "credentials": {
                    "jobSearch": {
                        "headers": {"authorization": "Bearer SECRET"},
                        "form_fields": {"fb_dtsg": "FORM_SECRET"},
                        "operation_scope": ["jobSearch"],
                        "target_origin": "https://api.example.com",
                        "session_binding": generation,
                    }
                },
            }
        )
    )
    provider = FileCredentialProvider(
        auth, expected_origins={"jobSearch": "https://api.example.com/graphql"}
    )
    assert provider.get("jobSearch") == {"authorization": "Bearer SECRET"}
    assert provider.get_with_form_fields("jobSearch") == (
        {"authorization": "Bearer SECRET"},
        {"fb_dtsg": "FORM_SECRET"},
    )
    assert provider.get_with_form_fields("another") == (None, {})
    assert "FORM_SECRET" not in json.dumps(provider.status(), default=str)


@pytest.mark.asyncio
async def test_runtime_refuses_mismatched_credential_cookie_generations(
    tmp_path: Path, pack: dict[str, Any]
) -> None:
    pack_path = tmp_path / "pack.json"
    auth_path = tmp_path / "auth.json"
    cookies_path = tmp_path / "cookies.json"
    pack_path.write_text(json.dumps(pack))
    auth_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generation_id": "auth-generation",
                "credentials": {"jobSearch": {"authorization": "Bearer SECRET"}},
            }
        )
    )
    cookies_path.write_text(
        json.dumps({"schema_version": 1, "generation_id": "cookie-generation", "cookies": []})
    )
    settings = Settings(pack_path, auth_path, cookies_path, retries=1)
    runtime = Runtime(settings, _validate_pack(pack, settings))
    result = await runtime.execute(runtime.pack["tools"][0], {"page": 1})
    assert result["error_code"] == "AUTH_GENERATION_MISMATCH"
    assert "SECRET" not in json.dumps(result)


def test_refresh_command_runs_argv_directly_never_via_shell_and_only_alias_via_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_popen(argv: Any, **kwargs: Any) -> _FakeProc:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _FakeProc(returncode=0)

    monkeypatch.setattr(server_module.subprocess, "Popen", fake_popen)
    provider = FileCredentialProvider(None, refresh_command=("mint-token", "--rotate"))
    assert provider.refresh("jobSearch") is True
    # argv is exactly the configured command -- nothing spliced in, no shell.
    assert captured["argv"] == ["mint-token", "--rotate"]
    assert captured["kwargs"].get("shell") is not True
    # the alias reaches the child only via an environment variable
    assert captured["kwargs"]["env"]["ASTROLABE_REFRESH_ALIAS"] == "jobSearch"
    assert "jobSearch" not in captured["argv"]


@pytest.mark.asyncio
async def test_runtime_refresh_never_leaks_tool_arguments_to_the_command(
    tmp_path: Path, pack: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_path = tmp_path / "pack.json"
    auth_path = tmp_path / "auth.json"
    pack_path.write_text(json.dumps(pack))
    auth_path.write_text(json.dumps({"jobSearch": {"authorization": "Bearer OLD"}}))
    settings = Settings(pack_path, auth_path, retries=1, auth_refresh_command=("mint-token",))
    runtime = Runtime(settings, _validate_pack(pack, settings))

    captured: dict[str, Any] = {}

    def fake_popen(argv: Any, **kwargs: Any) -> _FakeProc:
        captured["argv"] = argv
        captured["env"] = kwargs["env"]
        return _FakeProc(returncode=0)

    monkeypatch.setattr(server_module.subprocess, "Popen", fake_popen)
    _stub_upstream(runtime, monkeypatch, 401, {"message": "expired"})

    secret_marker = "tool-argument-should-never-reach-the-command-9182"
    runtime.pack["tools"][0]["input_schema"] = {
        "type": "object",
        "properties": {"page": {"type": "string"}},
        "additionalProperties": False,
    }
    await runtime.execute(runtime.pack["tools"][0], {"page": secret_marker})

    assert captured["argv"] == ["mint-token"]
    serialized = json.dumps({"argv": captured["argv"], "env": captured["env"]})
    assert secret_marker not in serialized


def test_refresh_command_timeout_kills_the_process_group() -> None:
    provider = FileCredentialProvider(
        None,
        refresh_command=(sys.executable, "-c", "import time; time.sleep(5)"),
        refresh_timeout=0.3,
    )
    started = time.monotonic()
    assert provider.refresh("alias") is False
    assert time.monotonic() - started < 2.0
    assert provider.status()["last_refresh_error"] == "refresh command timed out"


def test_refresh_failure_never_leaks_stdout_or_stderr() -> None:
    script = (
        "import sys; "
        "sys.stdout.write('SECRET_TOKEN_ABC'); "
        "sys.stderr.write('SECRET_ERR_XYZ'); "
        "sys.exit(1)"
    )
    provider = FileCredentialProvider(None, refresh_command=(sys.executable, "-c", script))
    assert provider.refresh("alias") is False
    status = provider.status()
    assert status["last_refresh_error"] == "refresh command exited with status 1"
    serialized = json.dumps(status)
    assert "SECRET_TOKEN_ABC" not in serialized
    assert "SECRET_ERR_XYZ" not in serialized


def test_refresh_is_rate_limited_between_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []

    def fake_popen(argv: Any, **kwargs: Any) -> _FakeProc:
        calls.append(argv)
        return _FakeProc(returncode=0)

    monkeypatch.setattr(server_module.subprocess, "Popen", fake_popen)
    provider = FileCredentialProvider(None, refresh_command=("mint",), refresh_min_interval=10.0)
    assert provider.refresh("a") is True
    assert provider.refresh("a") is True  # within the cooldown -> reused, no new subprocess
    assert len(calls) == 1


def test_refresh_cooldown_after_failure_does_not_double_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_popen(argv: Any, **kwargs: Any) -> _FakeProc:
        return _FakeProc(returncode=1)

    monkeypatch.setattr(server_module.subprocess, "Popen", fake_popen)
    provider = FileCredentialProvider(None, refresh_command=("mint",), refresh_min_interval=10.0)
    assert provider.refresh("a") is False
    assert provider.refresh("a") is False  # deduped by the cooldown, not a second attempt
    assert provider.status()["consecutive_refresh_failures"] == 1


def test_file_provider_refresh_is_single_flight_under_real_thread_concurrency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Any] = []
    call_lock = threading.Lock()

    def fake_popen(argv: Any, **kwargs: Any) -> _FakeProc:
        with call_lock:
            calls.append(argv)
        # Held while `refresh()`'s lock is held, so concurrent callers pile up on
        # that lock rather than each starting their own subprocess.
        return _FakeProc(returncode=0, delay=0.05)

    monkeypatch.setattr(server_module.subprocess, "Popen", fake_popen)
    provider = FileCredentialProvider(None, refresh_command=("mint",), refresh_min_interval=30.0)
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda _: provider.refresh("alias"), range(10)))
    assert len(calls) == 1
    assert all(results)


# ---------- credential refresh: Runtime refresh-and-retry ----------


class _FakeCredentialProvider(CredentialProvider):
    """Directly-injected double for exercising Runtime's retry-once orchestration
    without going through a real subprocess."""

    def __init__(
        self, tokens: dict[str, str] | None = None, *, refresh_result: bool = True
    ) -> None:
        self._tokens = dict(tokens or {})
        self.refresh_calls: list[str] = []
        self._refresh_result = refresh_result

    def get(self, alias: str) -> dict[str, Any] | None:
        token = self._tokens.get(alias)
        return {"authorization": f"Bearer {token}"} if token else None

    def load_all(self) -> dict[str, Any]:
        return {k: {"authorization": f"Bearer {v}"} for k, v in self._tokens.items()}

    def refresh(self, alias: str) -> bool:
        self.refresh_calls.append(alias)
        return self._refresh_result

    def is_refresh_configured(self) -> bool:
        return True

    def is_stale(self) -> bool:
        return False

    def status(self) -> dict[str, Any]:
        return {
            "refresh_configured": True,
            "last_refresh_attempt_at": None,
            "last_refresh_ok": None,
            "last_refresh_error": None,
            "consecutive_refresh_failures": 0,
            "ttl_seconds": None,
        }


class _SequencedSession:
    """Replays one HTTP status per call, holding on the last entry once exhausted."""

    def __init__(self, statuses: list[int]) -> None:
        self._statuses = statuses
        self.request_count = 0

    def request(self, *_args: object, **_kwargs: object) -> Any:
        self.request_count += 1
        status = self._statuses[min(self.request_count - 1, len(self._statuses) - 1)]
        payload = {"message": "nope"} if status >= 400 else {"data": {"ok": True}}

        class Response:
            status_code = status
            headers: dict[str, str] = {}

            def __init__(self) -> None:
                self.content = json.dumps(payload).encode()

            def json(self) -> Any:
                return payload

        return Response()


@pytest.mark.asyncio
async def test_no_refresh_configured_leaves_401_behavior_unchanged(
    configured: tuple[Settings, Runtime], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default-behavior baseline: with no refresh command configured, a 401 is
    reported exactly as it was before this feature existed, and nothing spawns."""
    _, runtime = configured

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("subprocess must not be spawned with no refresh configured")

    monkeypatch.setattr(server_module.subprocess, "Popen", _boom)
    _stub_upstream(runtime, monkeypatch, 401, {"message": "expired"})
    result = await runtime.execute(runtime.pack["tools"][0], {"page": 1})
    assert result["error_code"] == "UPSTREAM_AUTH_EXPIRED"
    assert "refresh_attempted" not in result.get("_astrolabe", {})
    assert "retried" not in result.get("_astrolabe", {})


@pytest.mark.asyncio
async def test_401_then_refresh_then_successful_retry_reaches_agent_as_success(
    configured: tuple[Settings, Runtime], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, runtime = configured
    provider = _FakeCredentialProvider({"jobSearch": "OLD"})
    runtime._credential_provider = provider
    session = _SequencedSession([401, 200])
    monkeypatch.setattr(runtime, "_session", lambda *_args: session)

    result = await runtime.execute(runtime.pack["tools"][0], {"page": 1})

    assert "error_code" not in result
    assert result["data"] == {"ok": True}
    assert session.request_count == 2
    assert provider.refresh_calls == ["jobSearch"]
    assert result["_astrolabe"]["refresh_attempted"] is True
    assert result["_astrolabe"]["retried"] is True


@pytest.mark.asyncio
async def test_401_with_failed_refresh_returns_one_clean_failure_no_retry(
    configured: tuple[Settings, Runtime], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, runtime = configured
    provider = _FakeCredentialProvider({"jobSearch": "OLD"}, refresh_result=False)
    runtime._credential_provider = provider
    session = _SequencedSession([401, 401])
    monkeypatch.setattr(runtime, "_session", lambda *_args: session)

    result = await runtime.execute(runtime.pack["tools"][0], {"page": 1})

    assert result["error_code"] == "UPSTREAM_AUTH_EXPIRED"
    assert session.request_count == 1  # no retry was attempted
    assert provider.refresh_calls == ["jobSearch"]
    assert result["_astrolabe"]["refresh_attempted"] is True
    assert result["_astrolabe"]["retried"] is False


@pytest.mark.asyncio
async def test_401_retry_also_401s_makes_exactly_two_attempts_and_one_refresh(
    configured: tuple[Settings, Runtime], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, runtime = configured
    provider = _FakeCredentialProvider(
        {"jobSearch": "OLD"}
    )  # refresh "succeeds" but doesn't fix it
    runtime._credential_provider = provider
    session = _SequencedSession([401, 401])
    monkeypatch.setattr(runtime, "_session", lambda *_args: session)

    result = await runtime.execute(runtime.pack["tools"][0], {"page": 1})

    assert result["error_code"] == "UPSTREAM_AUTH_EXPIRED"
    assert session.request_count == 2
    assert provider.refresh_calls == ["jobSearch"]
    assert result["_astrolabe"]["retried"] is True


@pytest.mark.asyncio
async def test_refresh_and_retry_happens_at_most_once_per_credential_generation(
    configured, monkeypatch
) -> None:
    _, runtime = configured
    provider = _FakeCredentialProvider({"jobSearch": "OLD"})
    runtime._credential_provider = provider
    calls = 0

    def always_expired(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return {
            "ok": False,
            "error_code": "UPSTREAM_AUTH_EXPIRED",
            "error_detail": "expired",
            "retryable": True,
        }

    monkeypatch.setattr(runtime, "_request", always_expired)
    first = await runtime.execute(runtime.pack["tools"][0], {"page": 1})
    second = await runtime.execute(runtime.pack["tools"][0], {"page": 2})
    assert first["_astrolabe"]["retried"] is True
    assert second["_astrolabe"]["refresh_skipped"] == (
        "already attempted for credential generation"
    )
    assert provider.refresh_calls == ["jobSearch"]
    assert calls == 3


@pytest.mark.asyncio
async def test_mutation_is_never_auto_retried_on_401(
    configured: tuple[Settings, Runtime], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, runtime = configured
    runtime.settings = Settings(
        settings.toolpack_path,
        settings.auth_path,
        settings.cookies_path,
        allow_mutations=True,
        retries=1,
    )
    provider = _FakeCredentialProvider({"deleteJob": "OLD"})
    runtime._credential_provider = provider
    session = _SequencedSession([401])
    monkeypatch.setattr(runtime, "_session", lambda *_args: session)

    result = await runtime.execute(runtime.pack["tools"][1], {})

    assert result["error_code"] == "UPSTREAM_AUTH_EXPIRED"
    assert session.request_count == 1
    assert provider.refresh_calls == []  # a mutation must never trigger a refresh+retry


@pytest.mark.asyncio
async def test_concurrent_401s_across_many_calls_trigger_exactly_one_refresh(
    tmp_path: Path, pack: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The concurrency contract: up to ASTROLABE_MAX_CONCURRENCY tool calls run at once,
    and if several hit 401 together, only one refresh subprocess is spawned -- the
    rest wait for it and reuse the outcome."""
    pack_path = tmp_path / "pack.json"
    auth_path = tmp_path / "auth.json"
    pack_path.write_text(json.dumps(pack))
    auth_path.write_text(json.dumps({"jobSearch": {"authorization": "Bearer OLD"}}))
    settings = Settings(
        pack_path,
        auth_path,
        retries=1,
        max_concurrency=8,
        auth_refresh_command=("mint",),
        auth_refresh_min_interval=30.0,
    )
    runtime = Runtime(settings, _validate_pack(pack, settings))

    popen_calls: list[Any] = []
    call_lock = threading.Lock()

    def fake_popen(argv: Any, **kwargs: Any) -> _FakeProc:
        with call_lock:
            popen_calls.append(argv)
        return _FakeProc(returncode=0, delay=0.05)

    monkeypatch.setattr(server_module.subprocess, "Popen", fake_popen)
    _stub_upstream(runtime, monkeypatch, 401, {"message": "expired"})

    tool = runtime.pack["tools"][0]
    results = await asyncio.gather(*(runtime.execute(tool, {"page": i}) for i in range(10)))

    assert len(popen_calls) == 1
    assert all(r["error_code"] == "UPSTREAM_AUTH_EXPIRED" for r in results)


@pytest.mark.asyncio
async def test_proactive_refresh_fires_when_credential_is_stale(
    tmp_path: Path, pack: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pack_path = tmp_path / "pack.json"
    auth_path = tmp_path / "auth.json"
    pack_path.write_text(json.dumps(pack))
    auth_path.write_text(json.dumps({"jobSearch": {"authorization": "Bearer OLD"}}))
    stale_time = time.time() - 120
    os.utime(auth_path, (stale_time, stale_time))
    settings = Settings(
        pack_path,
        auth_path,
        retries=1,
        auth_refresh_command=("mint",),
        auth_ttl_seconds=5.0,
        auth_refresh_min_interval=0.01,
    )
    runtime = Runtime(settings, _validate_pack(pack, settings))

    calls: list[Any] = []

    def fake_popen(argv: Any, **kwargs: Any) -> _FakeProc:
        calls.append(argv)
        return _FakeProc(returncode=0)

    monkeypatch.setattr(server_module.subprocess, "Popen", fake_popen)
    _stub_upstream(runtime, monkeypatch, 200, {"data": {"ok": True}})

    result = await runtime.execute(runtime.pack["tools"][0], {"page": 1})

    assert len(calls) == 1
    assert result["_astrolabe"]["proactive_refresh"] is True


@pytest.mark.asyncio
async def test_no_ttl_configured_never_triggers_proactive_refresh(
    configured: tuple[Settings, Runtime], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, runtime = configured

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("no TTL configured -> no proactive refresh, no subprocess")

    monkeypatch.setattr(server_module.subprocess, "Popen", _boom)
    _stub_upstream(runtime, monkeypatch, 200, {"data": {"ok": True}})
    result = await runtime.execute(runtime.pack["tools"][0], {"page": 1})
    assert "proactive_refresh" not in result.get("_astrolabe", {})


# ---------- Settings: refresh configuration ----------


def test_settings_from_env_parses_refresh_config(tmp_path: Path, monkeypatch) -> None:
    pack_path = tmp_path / "pack.json"
    auth_path = tmp_path / "auth.json"
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(pack_path))
    monkeypatch.setenv("ASTROLABE_AUTH", str(auth_path))
    monkeypatch.setenv("ASTROLABE_AUTH_REFRESH_COMMAND", "mint-token --flag 'quoted value'")
    monkeypatch.setenv("ASTROLABE_AUTH_REFRESH_TIMEOUT", "7")
    monkeypatch.setenv("ASTROLABE_AUTH_REFRESH_MIN_INTERVAL", "2.5")
    monkeypatch.setenv("ASTROLABE_AUTH_TTL_SECONDS", "90")
    settings = Settings.from_env()
    assert settings.auth_refresh_command == ("mint-token", "--flag", "quoted value")
    assert settings.auth_refresh_timeout == 7
    assert settings.auth_refresh_min_interval == 2.5
    assert settings.auth_ttl_seconds == 90


def test_settings_default_refresh_config_is_disabled(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(tmp_path / "pack.json"))
    monkeypatch.delenv("ASTROLABE_AUTH_REFRESH_COMMAND", raising=False)
    monkeypatch.delenv("ASTROLABE_AUTH_TTL_SECONDS", raising=False)
    settings = Settings.from_env()
    assert settings.auth_refresh_command is None
    assert settings.auth_ttl_seconds is None


def test_settings_refresh_command_requires_auth_path(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(tmp_path / "pack.json"))
    monkeypatch.delenv("ASTROLABE_AUTH", raising=False)
    monkeypatch.setenv("ASTROLABE_AUTH_REFRESH_COMMAND", "mint-token")
    with pytest.raises(ConfigurationError, match="ASTROLABE_AUTH"):
        Settings.from_env()


def test_settings_rejects_invalid_refresh_command_syntax(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(tmp_path / "pack.json"))
    monkeypatch.setenv("ASTROLABE_AUTH", str(tmp_path / "auth.json"))
    monkeypatch.setenv("ASTROLABE_AUTH_REFRESH_COMMAND", "mint-token 'unclosed")
    with pytest.raises(ConfigurationError, match="shell syntax"):
        Settings.from_env()


# ---------- astrolabe://health exposes refresh state without leaking secrets ----------


@pytest.mark.asyncio
async def test_health_resource_exposes_refresh_state_without_leaking_secrets(
    tmp_path: Path, pack: dict[str, Any]
) -> None:
    pack_path = tmp_path / "pack.json"
    auth_path = tmp_path / "auth.json"
    pack_path.write_text(json.dumps(pack))
    secret_token = "sk-live-TOTALLY-SECRET-TOKEN-VALUE"  # noqa: S105 - test fixture, not a real secret
    auth_path.write_text(json.dumps({"jobSearch": {"authorization": f"Bearer {secret_token}"}}))
    settings = Settings(
        pack_path,
        auth_path,
        retries=1,
        auth_refresh_command=("mint-token", "--secret-flag", secret_token),
    )
    server = create_server(settings)
    async with Client(server) as client:
        health = json.loads((await client.read_resource("astrolabe://health"))[0].text)
        manifest = json.loads((await client.read_resource("astrolabe://manifest"))[0].text)

    assert health["auth"]["refresh"]["configured"] is True
    assert "last_attempt_at" in health["auth"]["refresh"]
    assert "consecutive_failures" in health["auth"]["refresh"]
    serialized = json.dumps(health) + json.dumps(manifest)
    assert secret_token not in serialized
    assert "mint-token" not in serialized
    assert "--secret-flag" not in serialized


# ---------- persisted queries (APQ) ----------


@pytest.fixture
def apq_pack() -> dict[str, Any]:
    return {
        "version": 2,
        "base_domain": "example.com",
        "endpoint": "https://api.example.com/graphql",
        "tools": [
            {
                "name": "feed",
                "transport": "graphql",
                "alias": "feed",
                "operation": "Feed",
                "type": "query",
                "description": "persisted feed",
                "input_schema": {"type": "object", "properties": {}},
                "query": "",
                "apq_hash": "a" * 64,
                "exposed": True,
            }
        ],
    }


def test_apq_tool_validates_without_query_text(tmp_path, apq_pack) -> None:
    assert _validate_pack(apq_pack, Settings(tmp_path / "p.json")) is apq_pack


def test_tool_with_neither_query_nor_hash_is_rejected(tmp_path, apq_pack) -> None:
    apq_pack["tools"][0]["apq_hash"] = None
    with pytest.raises(ConfigurationError, match="neither query text nor a persisted hash"):
        _validate_pack(apq_pack, Settings(tmp_path / "p.json"))


def test_apq_request_sends_the_hash_extension(tmp_path, apq_pack) -> None:
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(apq_pack))
    settings = Settings(pack_path, allow_anonymous=True, retries=1)
    runtime = Runtime(settings, _validate_pack(apq_pack, settings))
    _, _, body, _ = runtime._build_request(apq_pack["tools"][0], {"n": 1}, {})
    assert body is not None
    assert body["extensions"]["persistedQuery"] == {"version": 1, "sha256Hash": "a" * 64}
    assert "query" not in body
    assert body["variables"] == {"n": 1}


@pytest.mark.asyncio
@pytest.mark.parametrize("fallback_allowed", [False, True])
async def test_apq_full_query_fallback_requires_explicit_authorization(
    tmp_path: Path,
    apq_pack: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    fallback_allowed: bool,
) -> None:
    tool = apq_pack["tools"][0]
    tool["query"] = "query Feed($n: Int) { feed(n: $n) }"
    tool["protocol"] = "graphql-apq"
    tool["apq_fallback_allowed"] = fallback_allowed
    calls: list[dict[str, Any]] = []
    payloads = [
        {"errors": [{"message": "PersistedQueryNotFound"}]},
        {"data": {"feed": []}},
    ]

    class Response:
        status_code = 200
        headers: dict[str, str] = {}

        def __init__(self, payload: dict[str, Any]) -> None:
            self.content = json.dumps(payload).encode()

        def json(self):
            return json.loads(self.content)

    class Session:
        def request(self, *_args, **kwargs):
            calls.append(kwargs)
            return Response(payloads[len(calls) - 1])

    settings = Settings(tmp_path / "pack.json", allow_anonymous=True, retries=1)
    runtime = Runtime(settings, _validate_pack(apq_pack, settings))
    monkeypatch.setattr(runtime, "_session", lambda *_args: Session())
    result = await runtime.execute(tool, {"n": 1})

    assert "query" not in calls[0]["json"]
    if fallback_allowed:
        assert result["data"] == {"feed": []}
        assert result["_astrolabe"]["apq_fallback"] is True
        assert calls[1]["json"]["query"] == tool["query"]
    else:
        assert result["error_code"] == "APQ_HASH_UNKNOWN"
        assert len(calls) == 1


def test_inline_query_still_wins_over_a_hash(configured) -> None:
    _, runtime = configured
    tool = dict(runtime.pack["tools"][0])
    tool["apq_hash"] = "should-be-ignored"
    _, _, body, _ = runtime._build_request(tool, {}, {})
    assert body is not None
    assert body["query"].startswith("query JobSearch")
    assert "extensions" not in body


def test_inline_graphql_uses_exact_method_and_operation_endpoint_without_alias(configured) -> None:
    _, runtime = configured
    tool = dict(runtime.pack["tools"][0])
    tool.update(
        http_method="GET",
        request_url="https://api.example.com/second/graphql?client=astrolabe",
    )
    method, url, body, params = runtime._build_request(tool, {"page": 2}, {})

    assert method == "GET"
    assert url == "https://api.example.com/second/graphql?client=astrolabe"
    assert "alias=" not in url
    assert body is None
    assert params == {
        "variables": '{"page":2}',
        "query": "query JobSearch($page:Int){jobs(page:$page)}",
        "operationName": "JobSearch",
    }


def test_meta_doc_id_uses_exact_form_adapter(tmp_path: Path, pack: dict[str, Any]) -> None:
    tool = pack["tools"][0]
    tool.update(
        query="",
        apq_hash="987654321",
        protocol="graphql-meta-doc-id",
        request_url="https://api.example.com/api/graphql",
        request_media_type="application/x-www-form-urlencoded",
        request_template={"fb_api_req_friendly_name": "JobSearch"},
    )
    runtime = Runtime(
        Settings(tmp_path / "pack.json", allow_anonymous=True),
        _validate_pack(pack, Settings(tmp_path / "pack.json", allow_anonymous=True)),
    )
    method, url, body, params = runtime._build_request(tool, {"page": 2}, {})

    assert (method, url, params) == ("POST", "https://api.example.com/api/graphql", None)
    assert body == {
        "doc_id": "987654321",
        "variables": '{"page":2}',
        "fb_api_req_friendly_name": "JobSearch",
    }


def test_application_graphql_uses_raw_document_body(configured) -> None:
    _, runtime = configured
    tool = dict(runtime.pack["tools"][0])
    tool["request_media_type"] = "application/graphql"
    headers: dict[str, str] = {}
    _, _, body, _ = runtime._build_request(tool, {}, headers)

    assert body == tool["query"]
    assert headers["content-type"] == "application/graphql"
    with pytest.raises(ConfigurationError, match="cannot encode runtime variables"):
        runtime._build_request(tool, {"page": 1}, {})


def test_unknown_persisted_hash_gets_its_own_error_code(configured, monkeypatch) -> None:
    """A rotated hash needs a re-capture, not narrower inputs -- say so distinctly."""
    _, runtime = configured
    _stub_upstream(runtime, monkeypatch, 200, {"errors": [{"message": "PersistedQueryNotFound"}]})
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["error_code"] == "APQ_HASH_UNKNOWN"


def test_ordinary_operation_errors_keep_their_code(configured, monkeypatch) -> None:
    _, runtime = configured
    _stub_upstream(runtime, monkeypatch, 200, {"errors": [{"message": "Field resolver failed"}]})
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["error_code"] == "UPSTREAM_OPERATION_ERROR"


def test_graphql_200_expired_auth_is_refreshable_but_ordinary_errors_are_not(
    configured, monkeypatch
) -> None:
    _, runtime = configured
    _stub_upstream(
        runtime,
        monkeypatch,
        200,
        {"errors": [{"message": "jwt expired", "extensions": {"code": "TOKEN_EXPIRED"}}]},
    )
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["error_code"] == "UPSTREAM_AUTH_EXPIRED"
    assert result["retryable"] is True


# ---------- response size is bounded before buffering ----------


def test_oversized_body_is_abandoned_mid_stream(configured, monkeypatch) -> None:
    """The guard must stop pulling chunks, not measure an already-buffered body."""
    settings, runtime = configured
    runtime.settings = Settings(
        settings.toolpack_path, settings.auth_path, settings.cookies_path, max_response_bytes=100
    )
    pulled = []

    class Response:
        status_code = 200
        headers: dict[str, str] = {}

        def iter_content(self, chunk_size=65536):
            for i in range(1000):
                pulled.append(i)
                yield b"x" * 64

    class Session:
        def request(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(runtime, "_session", lambda *_args: Session())
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["error_code"] == "RESPONSE_TOO_LARGE"
    # stopped as soon as the limit was passed rather than draining all 1000 chunks
    assert len(pulled) < 10


def test_declared_content_length_short_circuits_the_read(configured, monkeypatch) -> None:
    settings, runtime = configured
    runtime.settings = Settings(
        settings.toolpack_path, settings.auth_path, settings.cookies_path, max_response_bytes=100
    )

    class Response:
        status_code = 200
        headers = {"content-length": "999999"}

        def iter_content(self, chunk_size=65536):
            raise AssertionError("must not read the body when content-length already exceeds")

    class Session:
        def request(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(runtime, "_session", lambda *_args: Session())
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["error_code"] == "RESPONSE_TOO_LARGE"


def test_streamed_body_within_the_limit_is_parsed(configured, monkeypatch) -> None:
    _, runtime = configured

    class Response:
        status_code = 200
        headers: dict[str, str] = {}

        def iter_content(self, chunk_size=65536):
            yield b'{"data":'
            yield b'{"ok":true}}'

    class Session:
        def request(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(runtime, "_session", lambda *_args: Session())
    result = runtime._request("POST", "https://api.example.com/graphql", {}, {}, "query")
    assert result["data"] == {"ok": True}


# ---------- the upstream pool honours the configured concurrency ----------


def test_request_executor_is_sized_to_max_concurrency(tmp_path, pack) -> None:
    """asyncio.to_thread caps at min(32, cpu+4); the setting accepts up to 64."""
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))
    settings = Settings(pack_path, allow_anonymous=True, max_concurrency=48)
    runtime = Runtime(settings, _validate_pack(pack, settings))
    try:
        assert runtime._request_executor()._max_workers == 48
    finally:
        runtime.close()


def test_executor_is_lazy_and_close_is_idempotent(tmp_path, pack) -> None:
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))
    settings = Settings(pack_path, allow_anonymous=True)
    runtime = Runtime(settings, _validate_pack(pack, settings))
    assert runtime._executor is None  # no threads for a Runtime that never requests
    runtime._request_executor()
    assert runtime._executor is not None
    runtime.close()
    runtime.close()
    assert runtime._executor is None


# ---------- authenticated remote HTTP deployment boundary ----------


def _test_remote_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key_pair: RSAKeyPair,
    *extra: str,
) -> RemoteHTTPProfile:
    cert = tmp_path / "server.crt"
    tls_key = tmp_path / "server.key"
    public_key = tmp_path / "issuer.pem"
    cert.write_text("test certificate")
    tls_key.write_text("test private key")
    tls_key.chmod(0o600)
    public_key.write_text(key_pair.public_key)
    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", lambda *_args, **_kwargs: None)
    args = _parser().parse_args(
        [
            "--transport",
            "http",
            "--host",
            "0.0.0.0",
            "--public-url",
            "https://mcp.example.com",
            "--auth-issuer",
            "https://login.example.com",
            "--auth-audience",
            "https://mcp.example.com/mcp",
            "--auth-public-key",
            str(public_key),
            "--required-scope",
            "astrolabe:invoke",
            "--trusted-host",
            "mcp.example.com",
            "--trusted-origin",
            "https://console.example.com",
            "--tls-cert",
            str(cert),
            "--tls-key",
            str(tls_key),
            "--audit-log",
            str(tmp_path / "remote-audit.jsonl"),
            *extra,
        ]
    )
    return _remote_profile(args)


def test_remote_bind_cannot_be_enabled_by_environment_acknowledgement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(tmp_path / "pack.json"))
    monkeypatch.setenv("ASTROLABE_ALLOW_REMOTE_HTTP", "1")
    with pytest.raises(ConfigurationError, match="authenticated deployment profile"):
        server_module.main_sync(["--transport", "http", "--host", "0.0.0.0"])


def test_remote_profile_is_fail_closed_and_binds_audience_to_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair = RSAKeyPair.generate()
    profile = _test_remote_profile(tmp_path, monkeypatch, pair)
    assert profile.audience == f"{profile.public_url}{profile.path}"
    assert profile.required_scopes == ("astrolabe:invoke",)
    assert profile.trusted_hosts == ("mcp.example.com",)
    assert stat.S_IMODE(profile.tls_key.stat().st_mode) == 0o600
    assert stat.S_IMODE(profile.audit_log.stat().st_mode) == 0o600

    args = _parser().parse_args(
        [
            "--transport",
            "http",
            "--host",
            "0.0.0.0",
            "--public-url",
            "https://mcp.example.com",
            "--auth-issuer",
            "https://login.example.com",
            "--auth-audience",
            "https://another.example/mcp",
        ]
    )
    with pytest.raises(ConfigurationError, match="missing --tls-cert"):
        _remote_profile(args)

    bad = dataclasses.replace(profile, audience="https://another.example/mcp")
    with pytest.raises(ConfigurationError, match="exactly match"):
        bad.validated()
    bad = dataclasses.replace(profile, trusted_hosts=("*.example.com",))
    with pytest.raises(ConfigurationError, match="without ports or wildcards"):
        bad.validated()
    bad = dataclasses.replace(profile, required_scopes=())
    with pytest.raises(ConfigurationError, match="at least one"):
        bad.validated()


@pytest.mark.asyncio
async def test_remote_jwt_verifier_rejects_wrong_audience_and_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair = RSAKeyPair.generate()
    profile = _test_remote_profile(tmp_path, monkeypatch, pair)
    verifier = _remote_auth(profile).token_verifier
    valid = pair.create_token(
        issuer=profile.issuer,
        audience=profile.audience,
        scopes=list(profile.required_scopes),
    )
    wrong_audience = pair.create_token(
        issuer=profile.issuer,
        audience="https://other.example/mcp",
        scopes=list(profile.required_scopes),
    )
    wrong_scope = pair.create_token(
        issuer=profile.issuer,
        audience=profile.audience,
        scopes=["astrolabe:other"],
    )
    assert await verifier.verify_token(valid) is not None
    assert await verifier.verify_token(wrong_audience) is None
    assert await verifier.verify_token(wrong_scope) is None


@pytest.mark.asyncio
async def test_remote_http_publishes_metadata_and_rejects_untrusted_headers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pack: dict[str, Any],
) -> None:
    pair = RSAKeyPair.generate()
    profile = _test_remote_profile(tmp_path, monkeypatch, pair)
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))
    server = create_server(Settings(pack_path, allow_anonymous=True), auth=_remote_auth(profile))
    app = server.http_app(
        path=profile.path,
        stateless_http=True,
        host_origin_protection=True,
        allowed_hosts=list(profile.trusted_hosts),
        allowed_origins=list(profile.trusted_origins),
        middleware=[Middleware(RemoteBoundaryMiddleware, profile=profile)],
    )
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url=profile.public_url) as client,
    ):
        metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        document = metadata.json()
        assert document["resource"] == profile.audience
        assert [item.rstrip("/") for item in document["authorization_servers"]] == [profile.issuer]
        assert document["scopes_supported"] == list(profile.required_scopes)

        assert (
            await client.get(
                "/.well-known/oauth-protected-resource/mcp", headers={"Host": "evil.example"}
            )
        ).status_code == 421
        assert (
            await client.get(
                "/.well-known/oauth-protected-resource/mcp",
                headers={"Origin": "https://evil.example"},
            )
        ).status_code == 403
        assert (await client.post(profile.path, json={})).status_code == 401

        valid = pair.create_token(
            issuer=profile.issuer,
            audience=profile.audience,
            scopes=list(profile.required_scopes),
        )
        response = await client.post(
            profile.path,
            headers={
                "Authorization": f"Bearer {valid}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "security-test", "version": "1"},
                },
            },
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_remote_boundary_rate_limits_and_never_audits_bearer_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair = RSAKeyPair.generate()
    profile = dataclasses.replace(
        _test_remote_profile(tmp_path, monkeypatch, pair),
        requests_per_minute=1,
        burst=1,
    )

    async def endpoint(_scope, _receive, send) -> None:
        await JSONResponse({"ok": True})(_scope, _receive, send)

    boundary = RemoteBoundaryMiddleware(endpoint, profile=profile)
    secret = "canary-REMOTE-BEARER-secret"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=boundary), base_url=profile.public_url
    ) as client:
        assert (
            await client.get("/mcp", headers={"Authorization": f"Bearer {secret}"})
        ).status_code == 200
        response = await client.get("/mcp", headers={"Authorization": f"Bearer {secret}"})
        assert response.status_code == 429
        assert response.headers["retry-after"] == "60"

    records = [json.loads(line) for line in profile.audit_log.read_text().splitlines()]
    assert any(record.get("status") == 429 and record.get("rate_limited") for record in records)
    assert secret not in profile.audit_log.read_text()


def test_runtime_revalidates_relay_metadata_and_rejects_removed_evidence(tmp_path, pack):
    from astrolabe.relay import RelayCatalog

    catalog = RelayCatalog()
    catalog.add(
        b'const q={kind:"Request",params:{id:"987654321",name:"JobSearch",operationKind:"query"}};',
        "https://cdn.example.com/app.js",
    )
    entry = catalog.bind(
        {
            "protocol": "graphql-meta-doc-id",
            "persistedHash": "987654321",
            "operationName": "JobSearch",
        },
        True,
    )
    tool = pack["tools"][0]
    tool.update(
        query="",
        apq_hash="987654321",
        protocol="graphql-meta-doc-id",
        parse_confidence="compiler-metadata",
        request_template=entry["request_template"],
    )
    settings = Settings(tmp_path / "pack.json", allow_anonymous=True)
    _validate_pack(pack, settings)
    tool["request_template"]["relay_evidence"]["id"] = "different"
    with pytest.raises(ConfigurationError, match="Relay evidence"):
        _validate_pack(pack, settings)
    tool["request_template"] = {}
    with pytest.raises(ConfigurationError, match="Relay evidence"):
        _validate_pack(pack, settings)


@pytest.mark.asyncio
async def test_meta_form_credentials_are_injected_only_into_meta_body(configured, monkeypatch):
    _, runtime = configured
    provider = runtime._credential_provider
    monkeypatch.setattr(
        provider,
        "get_with_form_fields",
        lambda alias: ({"x-csrftoken": "header-secret"}, {"fb_dtsg": "form-secret", "__a": "1"}),
    )
    captured = {}

    def request(*args):
        captured.update(headers=args[2], body=args[3])
        return {"data": {"jobs": []}, "_astrolabe": {"http_status": 200}}

    monkeypatch.setattr(runtime, "_request", request)
    tool = runtime.pack["tools"][0]
    tool.update(query="", apq_hash="987654321", protocol="graphql-meta-doc-id")
    await runtime.execute(tool, {"page": 1})
    assert captured["body"]["fb_dtsg"] == "form-secret"
    assert captured["body"]["doc_id"] == "987654321"
    assert "form-secret" not in json.dumps(captured["headers"])
    tool.update(protocol="graphql-inline", query="query JobSearch($page:Int){jobs(page:$page)}")
    await runtime.execute(tool, {"page": 1})
    assert "form-secret" not in json.dumps(captured)


def test_declared_operations_cannot_smuggle_a_callable_request(tmp_path, pack):
    pack["declared_operations"] = [
        {
            "name": "DeleteTweet",
            "operation_kind": "mutation",
            "request_url": "https://api.example.com/graphql/abc/DeleteTweet",
        }
    ]
    with pytest.raises(ConfigurationError, match="carries request fields"):
        _validate_pack(pack, Settings(tmp_path / "pack.json"))


def test_declared_operations_reject_an_unsupported_kind(tmp_path, pack):
    pack["declared_operations"] = [{"name": "Odd", "operation_kind": "fragment"}]
    with pytest.raises(ConfigurationError, match="unsupported kind"):
        _validate_pack(pack, Settings(tmp_path / "pack.json"))


def test_declared_operations_accept_pure_inventory(tmp_path, pack):
    pack["declared_operations"] = [
        {"name": "DeleteTweet", "operation_kind": "mutation", "observed": False},
        {"name": "HomeTimeline", "operation_kind": "query", "observed": True},
    ]
    validated = _validate_pack(pack, Settings(tmp_path / "pack.json"))
    assert len(validated["declared_operations"]) == 2
