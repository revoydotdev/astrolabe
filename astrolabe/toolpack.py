#!/usr/bin/env python3
"""The toolpack contract chokepoint.

A generated toolpack is capture-derived, untrusted data, and the rules that decide
what may be generated and what may be served are the same rules. This module is the
single place they live, so generation (:mod:`astrolabe.mcpgen`) and serving
(:mod:`astrolabe.sextant`) cannot drift: a pack that ``astrolabe mcp-gen``
accepts is a pack the installed runtime can actually serve, and one it refuses is
one no server will expose. It is simultaneously the inventory contract check and
the execution security gate -- host validation, path-traversal refusal, denied-header
refusal, unknown-kind exposure refusal, historical/non-executable refusal, and
declared-operations-must-carry-no-request-fields. Nothing here may be weakened to
make a check pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from .event_runtime import EventAdapterError, validate_event_channel
from .graphql_doc import parse_graphql_document
from .operation import Protocol, SemanticKind
from .security import DENIED_HEADERS, validate_url

_DENIED_HEADERS = DENIED_HEADERS
# A tool description is read by the model as if it were ours, so its size is bounded
# rather than accepted at whatever length a target can induce. Relocated target text
# lives behind astrolabe://tools/{name}, not in here.
MAX_TOOL_DESCRIPTION_CHARS = 1000

_SENSITIVE_QUERY_KEY = re.compile(
    r"authorization|cookie|token|secret|password|api[-_]?key|csrf|session|credential",
    re.I,
)
_DISCOVERY_TOOL_NAMES = frozenset(
    {
        "search_operations",
        "describe_operation",
        "trace_surface",
        "diff_contract",
        "coverage_report",
        "verify_operation",
        "invoke_query",
        "subscribe_events",
    }
)


class ConfigurationError(ValueError):
    """Raised when server configuration would be invalid or unsafe."""


def _read_json(path: Path, label: str) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot read {label} at {path}: {exc}") from exc


def _positive_int(value: str, label: str, *, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigurationError(f"{label} must be an integer") from exc
    if not 1 <= parsed <= maximum:
        raise ConfigurationError(f"{label} must be between 1 and {maximum}")
    return parsed


def _positive_float(value: str, label: str, *, maximum: float) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ConfigurationError(f"{label} must be a number") from exc
    if not 0 < parsed <= maximum:
        raise ConfigurationError(f"{label} must be greater than 0 and at most {maximum}")
    return parsed


def _nonnegative_int(value: str, label: str, *, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigurationError(f"{label} must be an integer") from exc
    if not 0 <= parsed <= maximum:
        raise ConfigurationError(f"{label} must be between 0 and {maximum}")
    return parsed


@dataclass(frozen=True, slots=True)
class Settings:
    toolpack_path: Path
    auth_path: Path | None = None
    cookies_path: Path | None = None
    allow_mutations: bool = False
    allow_anonymous: bool = False
    allow_insecure_endpoint: bool = False
    max_concurrency: int = 4
    timeout_seconds: float = 30.0
    max_response_bytes: int = 1_000_000
    retries: int = 2
    # Operator-configured credential-refresh hook. Opt-in only: when
    # auth_refresh_command is None (the default), FileCredentialProvider.refresh() is a
    # no-op and no subprocess is ever spawned -- default behavior is unchanged.
    auth_refresh_command: tuple[str, ...] | None = None
    auth_refresh_timeout: float = 10.0
    auth_refresh_min_interval: float = 5.0
    auth_ttl_seconds: float | None = None
    max_argument_depth: int = 10
    max_argument_properties: int = 1000
    max_argument_string_length: int = 10_000
    max_argument_array_length: int = 1000
    max_queue: int = 100
    max_operation_concurrency: int = 2
    rate_limit_reserve: int = 1
    circuit_failure_threshold: int = 5
    circuit_cooldown_seconds: float = 30.0
    event_timeout_seconds: float = 30.0
    max_event_messages: int = 100
    max_event_queue: int = 16
    event_reconnects: int = 1
    graph_path: Path | None = None

    @classmethod
    def from_env(cls) -> Settings:
        toolpack = os.environ.get("ASTROLABE_TOOLPACK")
        if not toolpack:
            raise ConfigurationError("ASTROLABE_TOOLPACK is required")
        timeout = float(os.environ.get("ASTROLABE_TIMEOUT_SECONDS", "30"))
        if not 0 < timeout <= 300:
            raise ConfigurationError("ASTROLABE_TIMEOUT_SECONDS must be in (0, 300]")
        auth_path = Path(value) if (value := os.environ.get("ASTROLABE_AUTH")) else None

        refresh_command_raw = os.environ.get("ASTROLABE_AUTH_REFRESH_COMMAND")
        auth_refresh_command: tuple[str, ...] | None = None
        if refresh_command_raw:
            try:
                parsed_command = tuple(shlex.split(refresh_command_raw))
            except ValueError as exc:
                raise ConfigurationError(
                    f"ASTROLABE_AUTH_REFRESH_COMMAND is not valid shell syntax: {exc}"
                ) from exc
            if not parsed_command:
                raise ConfigurationError("ASTROLABE_AUTH_REFRESH_COMMAND must not be empty")
            if auth_path is None:
                raise ConfigurationError(
                    "ASTROLABE_AUTH_REFRESH_COMMAND requires ASTROLABE_AUTH to be set"
                )
            auth_refresh_command = parsed_command

        ttl_raw = os.environ.get("ASTROLABE_AUTH_TTL_SECONDS")
        auth_ttl_seconds = (
            _positive_float(ttl_raw, "ASTROLABE_AUTH_TTL_SECONDS", maximum=3600)
            if ttl_raw
            else None
        )

        return cls(
            toolpack_path=Path(toolpack),
            graph_path=Path(value) if (value := os.environ.get("ASTROLABE_GRAPH")) else None,
            auth_path=auth_path,
            cookies_path=Path(value) if (value := os.environ.get("ASTROLABE_COOKIES")) else None,
            allow_mutations=os.environ.get("ASTROLABE_ALLOW_MUTATIONS") == "1",
            allow_anonymous=os.environ.get("ASTROLABE_ALLOW_ANONYMOUS") == "1",
            allow_insecure_endpoint=os.environ.get("ASTROLABE_ALLOW_INSECURE_ENDPOINT") == "1",
            max_concurrency=_positive_int(
                os.environ.get("ASTROLABE_MAX_CONCURRENCY", "4"),
                "ASTROLABE_MAX_CONCURRENCY",
                maximum=64,
            ),
            timeout_seconds=timeout,
            max_response_bytes=_positive_int(
                os.environ.get("ASTROLABE_MAX_RESPONSE_BYTES", "1000000"),
                "ASTROLABE_MAX_RESPONSE_BYTES",
                maximum=20_000_000,
            ),
            retries=_positive_int(
                os.environ.get("ASTROLABE_RETRIES", "2"), "ASTROLABE_RETRIES", maximum=5
            ),
            auth_refresh_command=auth_refresh_command,
            auth_refresh_timeout=_positive_float(
                os.environ.get("ASTROLABE_AUTH_REFRESH_TIMEOUT", "10"),
                "ASTROLABE_AUTH_REFRESH_TIMEOUT",
                maximum=120,
            ),
            auth_refresh_min_interval=_positive_float(
                os.environ.get("ASTROLABE_AUTH_REFRESH_MIN_INTERVAL", "5"),
                "ASTROLABE_AUTH_REFRESH_MIN_INTERVAL",
                maximum=3600,
            ),
            auth_ttl_seconds=auth_ttl_seconds,
            max_argument_depth=_positive_int(
                os.environ.get("ASTROLABE_MAX_ARGUMENT_DEPTH", "10"),
                "ASTROLABE_MAX_ARGUMENT_DEPTH",
                maximum=100,
            ),
            max_argument_properties=_positive_int(
                os.environ.get("ASTROLABE_MAX_ARGUMENT_PROPERTIES", "1000"),
                "ASTROLABE_MAX_ARGUMENT_PROPERTIES",
                maximum=100_000,
            ),
            max_argument_string_length=_positive_int(
                os.environ.get("ASTROLABE_MAX_ARGUMENT_STRING_LENGTH", "10000"),
                "ASTROLABE_MAX_ARGUMENT_STRING_LENGTH",
                maximum=1_000_000,
            ),
            max_argument_array_length=_positive_int(
                os.environ.get("ASTROLABE_MAX_ARGUMENT_ARRAY_LENGTH", "1000"),
                "ASTROLABE_MAX_ARGUMENT_ARRAY_LENGTH",
                maximum=100_000,
            ),
            max_queue=_positive_int(
                os.environ.get("ASTROLABE_MAX_QUEUE", "100"),
                "ASTROLABE_MAX_QUEUE",
                maximum=10_000,
            ),
            max_operation_concurrency=_positive_int(
                os.environ.get("ASTROLABE_MAX_OPERATION_CONCURRENCY", "2"),
                "ASTROLABE_MAX_OPERATION_CONCURRENCY",
                maximum=64,
            ),
            rate_limit_reserve=_positive_int(
                os.environ.get("ASTROLABE_RATE_LIMIT_RESERVE", "1"),
                "ASTROLABE_RATE_LIMIT_RESERVE",
                maximum=100_000,
            ),
            circuit_failure_threshold=_positive_int(
                os.environ.get("ASTROLABE_CIRCUIT_FAILURE_THRESHOLD", "5"),
                "ASTROLABE_CIRCUIT_FAILURE_THRESHOLD",
                maximum=1000,
            ),
            circuit_cooldown_seconds=_positive_float(
                os.environ.get("ASTROLABE_CIRCUIT_COOLDOWN_SECONDS", "30"),
                "ASTROLABE_CIRCUIT_COOLDOWN_SECONDS",
                maximum=3600,
            ),
            event_timeout_seconds=_positive_float(
                os.environ.get("ASTROLABE_EVENT_TIMEOUT_SECONDS", "30"),
                "ASTROLABE_EVENT_TIMEOUT_SECONDS",
                maximum=300,
            ),
            max_event_messages=_positive_int(
                os.environ.get("ASTROLABE_MAX_EVENT_MESSAGES", "100"),
                "ASTROLABE_MAX_EVENT_MESSAGES",
                maximum=10_000,
            ),
            max_event_queue=_positive_int(
                os.environ.get("ASTROLABE_MAX_EVENT_QUEUE", "16"),
                "ASTROLABE_MAX_EVENT_QUEUE",
                maximum=1024,
            ),
            event_reconnects=_nonnegative_int(
                os.environ.get("ASTROLABE_EVENT_RECONNECTS", "1"),
                "ASTROLABE_EVENT_RECONNECTS",
                maximum=10,
            ),
        )


def _validate_pack(raw: Any, settings: Settings) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ConfigurationError("toolpack root must be an object")
    # Packs predating versioned artifacts are migrated in memory. Newly generated
    # packs always carry version 2; future versions fail loudly.
    version = raw.get("version", 1)
    if version not in {1, 2}:
        raise ConfigurationError("unsupported toolpack version; expected version 2")
    if raw.get("historical") or raw.get("executable") is False:
        raise ConfigurationError("historical toolpack fixture is intentionally non-executable")
    domain, endpoint, tools = raw.get("base_domain"), raw.get("endpoint"), raw.get("tools")
    if not isinstance(domain, str) or not domain:
        raise ConfigurationError("toolpack.base_domain must be a non-empty string")
    if not isinstance(tools, list):
        raise ConfigurationError("toolpack requires a tools array")
    base = domain.rstrip(".").lower()

    def _check_host(url: str, label: str) -> None:
        """Every request target must stay inside the mapped domain — a toolpack is
        capture-derived data, so it is treated as untrusted input."""
        schemes = ("https", "http") if settings.allow_insecure_endpoint else ("https",)
        try:
            validate_url(url, {base}, schemes=schemes)
        except ValueError as exc:
            raise ConfigurationError(f"{label} host/target is unsafe: {exc}") from exc

    needs_endpoint = any(
        isinstance(t, dict)
        and t.get("transport", "graphql") == "graphql"
        and not t.get("request_url")
        for t in tools
    )
    if endpoint is not None:
        if not isinstance(endpoint, str):
            raise ConfigurationError("toolpack.endpoint must be a string")
        _check_host(endpoint, "toolpack endpoint")
    elif needs_endpoint:
        raise ConfigurationError("toolpack has GraphQL tools but no endpoint")

    names: set[str] = set()
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            raise ConfigurationError(f"toolpack.tools[{index}] must be an object")
        transport = tool.get("transport", "graphql")
        if transport not in {"graphql", "rest"}:
            raise ConfigurationError(f"toolpack.tools[{index}] has unsupported transport")
        required = ["name", "alias", "type", "description", "input_schema", "exposed"]
        required += ["query"] if transport == "graphql" else ["method", "path"]
        missing = [key for key in required if key not in tool]
        if missing:
            raise ConfigurationError(f"toolpack.tools[{index}] missing: {', '.join(missing)}")
        if len(str(tool["description"])) > MAX_TOOL_DESCRIPTION_CHARS:
            raise ConfigurationError(
                f"toolpack.tools[{index}] description exceeds "
                f"{MAX_TOOL_DESCRIPTION_CHARS} characters"
            )
        if transport == "graphql" and not tool.get("query") and not tool.get("apq_hash"):
            raise ConfigurationError(
                f"tool {tool.get('name')!r} has neither query text nor a persisted hash"
            )
        if transport == "graphql" and tool.get("request_url"):
            if not isinstance(tool["request_url"], str):
                raise ConfigurationError(f"tool {tool.get('name')!r} request_url must be a string")
            _check_host(tool["request_url"], f"tool {tool.get('name')!r} request URL")
        if transport == "graphql" and str(tool.get("http_method") or "POST").upper() not in {
            "GET",
            "POST",
        }:
            raise ConfigurationError(f"tool {tool.get('name')!r} has unsupported GraphQL method")
        name = tool["name"]
        if not isinstance(name, str) or not name or name in names:
            raise ConfigurationError(f"tool name must be non-empty and unique: {name!r}")
        if name in _DISCOVERY_TOOL_NAMES:
            raise ConfigurationError(f"tool name {name!r} is reserved for MCP discovery")
        names.add(name)
        schema = tool["input_schema"]
        if not isinstance(schema, dict) or schema.get("type", "object") != "object":
            raise ConfigurationError(f"tool {name!r} input_schema must describe an object")
        if tool["type"] not in {kind.value for kind in SemanticKind}:
            raise ConfigurationError(f"tool {name!r} has unsupported operation type")
        if tool["type"] == SemanticKind.UNKNOWN.value and tool.get("exposed"):
            raise ConfigurationError(f"tool {name!r} cannot expose an unknown semantic kind")
        if tool.get("exposed") and (tool.get("request_template") or {}).get("payload_packaging"):
            raise ConfigurationError(f"tool {name!r} has no exact packaged-request replay adapter")
        protocol = tool.get("protocol")
        if protocol is None:
            if transport == "rest":
                protocol = Protocol.REST.value
            elif tool.get("query"):
                protocol = Protocol.GRAPHQL_INLINE.value
            elif re.fullmatch(r"[0-9a-fA-F]{64}", str(tool.get("apq_hash") or "")):
                protocol = Protocol.GRAPHQL_APQ.value
            else:
                protocol = Protocol.GRAPHQL_VENDOR_PERSISTED.value
            tool["protocol"] = protocol
        if protocol is not None and protocol not in {item.value for item in Protocol}:
            raise ConfigurationError(f"tool {name!r} has an unsupported protocol")
        if transport == "graphql" and tool.get("query") and tool.get("exposed"):
            parsed_operations = parse_graphql_document(tool["query"], tool.get("operation"))
            selected_operations = [item for item in parsed_operations if item.selected]
            if len(selected_operations) != 1:
                raise ConfigurationError(
                    f"tool {name!r} does not select exactly one GraphQL operation"
                )
            selected = selected_operations[0]
            if selected.parse_confidence != "parsed":
                raise ConfigurationError(
                    f"tool {name!r} cannot expose a malformed GraphQL document"
                )
            if selected.semantic_kind != tool["type"]:
                raise ConfigurationError(
                    f"tool {name!r} semantic type disagrees with its GraphQL document"
                )
        if protocol == Protocol.GRAPHQL_APQ.value and not re.fullmatch(
            r"[0-9a-fA-F]{64}", str(tool.get("apq_hash") or "")
        ):
            raise ConfigurationError(f"tool {name!r} has an invalid Apollo APQ SHA-256 hash")
        if tool.get("document_evidence") and tool.get("exposed"):
            evidence = tool["document_evidence"]
            query = tool.get("query") or ""
            digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
            if (
                protocol != Protocol.GRAPHQL_APQ.value
                or digest != str(tool.get("apq_hash") or "").lower()
                or evidence.get("sha256") != digest
                or evidence.get("binding") != "exact-sha256"
                or evidence.get("observed_response_success") is not True
            ):
                raise ConfigurationError(f"tool {name!r} has invalid recovered document evidence")
        if (
            tool.get("parse_confidence") == "compiler-metadata"
            or (tool.get("request_template") or {}).get("relay_evidence")
        ) and tool.get("exposed"):
            from .relay import valid_evidence

            if not valid_evidence(tool):
                raise ConfigurationError(f"tool {name!r} has invalid recovered Relay evidence")
        if protocol == Protocol.GRAPHQL_VENDOR_PERSISTED.value and tool.get("exposed"):
            raise ConfigurationError(
                f"tool {name!r} exposes a persisted protocol without a reviewed adapter"
            )
        if transport == "rest":
            method = tool["method"]
            if not isinstance(method, str) or not method.isalpha():
                raise ConfigurationError(f"tool {name!r} has an invalid HTTP method")
            path = tool["path"]
            if not isinstance(path, str) or not path.startswith("/"):
                raise ConfigurationError(f"tool {name!r} path must be an absolute path")
            # A toolpack is capture-derived data. A traversal segment would let it reach
            # outside the mapped surface once the origin server normalises the path.
            if ".." in path.split("/") or "\\" in path:
                raise ConfigurationError(f"tool {name!r} path must not contain traversal segments")
            _check_host(f"https://{base}{path}", f"tool {name!r} path")
            if tool.get("request_url"):
                if not isinstance(tool["request_url"], str):
                    raise ConfigurationError(f"tool {name!r} request_url must be a string")
                _check_host(tool["request_url"], f"tool {name!r} request URL")
            parameters = tool.get("parameters") or []
            if not isinstance(parameters, list):
                raise ConfigurationError(f"tool {name!r} parameters must be an array")
            for parameter in parameters:
                if not isinstance(parameter, dict) or parameter.get("location") not in {
                    "path",
                    "query",
                    "header",
                    "cookie",
                    "body",
                    "form",
                }:
                    raise ConfigurationError(f"tool {name!r} has an invalid parameter contract")
                if (
                    parameter.get("location") == "header"
                    and str(parameter.get("name") or "").lower() in _DENIED_HEADERS
                ):
                    raise ConfigurationError(
                        f"tool {name!r} attempts to parameterize a protected header"
                    )
    channels = raw.get("event_channels") or []
    if not isinstance(channels, list):
        raise ConfigurationError("toolpack.event_channels must be an array")
    channel_ids: set[str] = set()
    for index, channel in enumerate(channels):
        if not isinstance(channel, dict):
            raise ConfigurationError(f"event channel {index} must be an object")
        channel_id = channel.get("id")
        if not isinstance(channel_id, str) or not channel_id or channel_id in channel_ids:
            raise ConfigurationError("event channel IDs must be non-empty and unique")
        channel_ids.add(channel_id)
        try:
            validate_event_channel(
                channel,
                {base},
                allow_insecure=settings.allow_insecure_endpoint,
            )
        except (ValueError, EventAdapterError) as exc:
            raise ConfigurationError(f"event channel {channel_id!r} is unsafe: {exc}") from exc
        parsed_channel = urlparse(channel["url"])
        if any(_SENSITIVE_QUERY_KEY.search(name) for name, _ in parse_qsl(parsed_channel.query)):
            raise ConfigurationError(
                f"event channel {channel_id!r} persists a secret-bearing query parameter"
            )
        if not isinstance(channel.get("read_only_setup_attested", False), bool):
            raise ConfigurationError(f"event channel {channel_id!r} has invalid setup attestation")
    declared_operations = raw.get("declared_operations") or []
    if not isinstance(declared_operations, list):
        raise ConfigurationError("toolpack.declared_operations must be an array")
    # Inventory describes what exists; it must never be able to describe how to call it.
    # Refusing request-bearing fields keeps that boundary structural rather than a
    # convention the generator is trusted to have followed.
    for index, declared in enumerate(declared_operations):
        if not isinstance(declared, dict):
            raise ConfigurationError(f"toolpack.declared_operations[{index}] must be an object")
        smuggled = {"query", "apq_hash", "request_url", "request_template", "endpoint"} & set(
            declared
        )
        if smuggled:
            raise ConfigurationError(
                f"declared operation {declared.get('name')!r} carries request fields: "
                f"{', '.join(sorted(smuggled))}"
            )
        if declared.get("operation_kind") not in {"query", "mutation", "subscription"}:
            raise ConfigurationError(
                f"declared operation {declared.get('name')!r} has an unsupported kind"
            )
    miscellaneous = raw.get("misc_operations") or {}
    if not isinstance(miscellaneous, dict):
        raise ConfigurationError("toolpack.misc_operations must be an object")
    inventory_protocols = {
        Protocol.GRPC_WEB.value,
        Protocol.PROTOBUF.value,
        Protocol.JSON_RPC.value,
        Protocol.TRPC.value,
        Protocol.WEBTRANSPORT.value,
        Protocol.WEBHOOK.value,
        Protocol.SERVICE_WORKER.value,
        Protocol.OFFLINE_QUEUE.value,
    }
    for identifier, operation in miscellaneous.items():
        if (
            not isinstance(identifier, str)
            or not isinstance(operation, dict)
            or operation.get("protocol") not in inventory_protocols
            or operation.get("executable") not in {None, False}
        ):
            raise ConfigurationError("miscellaneous operations must remain inventory-only")
    return raw
