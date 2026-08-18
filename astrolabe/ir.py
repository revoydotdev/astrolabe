"""Schema-versioned backend graph intermediate representation.

The graph owns immutable run evidence and a typed current materialization. Human
maps, contracts, and MCP packs are projections of this model rather than separate
sources of truth.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse as up
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .artifact import JSON_SCHEMA_DIALECT, ArtifactError, atomic_write_json, read_json_artifact
from .operation import Protocol, SemanticKind
from .security import normalize_host, safe_url

GRAPH_SCHEMA_VERSION = 1
SUPPORTED_GRAPH_VERSIONS = frozenset({GRAPH_SCHEMA_VERSION})


class SourceKind(StrEnum):
    CAPTURE = "capture"
    STATIC_BUNDLE = "static-bundle"
    OPENAPI = "openapi"
    INTROSPECTION = "introspection"
    RECOVERED_SCHEMA = "recovered-schema"
    RECIPE_ASSERTION = "recipe-assertion"
    OPERATOR_OVERRIDE = "operator-override"
    ACTIVE_VERIFICATION = "active-verification"
    MIGRATION = "migration"


class Completeness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class LifecycleStatus(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    NOT_OBSERVED = "not_observed_this_run"
    RETIRED = "retired"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class DriftSeverity(StrEnum):
    ADDITIVE = "additive"
    COMPATIBLE = "compatible"
    POTENTIALLY_BREAKING = "potentially-breaking"
    BREAKING = "breaking"
    SECURITY = "security-relevant"
    FRESHNESS = "freshness-only"


def stable_id(kind: str, *parts: Any) -> str:
    canonical = json.dumps([kind, *parts], sort_keys=True, separators=(",", ":"))
    return f"{kind}_{hashlib.sha256(canonical.encode()).hexdigest()[:20]}"


@dataclass(slots=True)
class FieldEvidence:
    source: SourceKind
    run_id: str
    confidence: float
    observed_at: str | None = None
    detail: str | None = None


@dataclass(slots=True)
class Conflict:
    field: str
    values: list[Any]
    sources: list[SourceKind]
    resolution: str | None = None


@dataclass(slots=True)
class Run:
    id: str
    target: str
    started_at: str
    completed_at: str | None
    completeness: Completeness
    profile: str | None = None
    safety_mode: str = "read-only"
    failures: list[dict[str, Any]] = field(default_factory=list)
    truncations: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class Evidence:
    id: str
    run_id: str
    source: SourceKind
    observed_at: str | None
    operation_id: str | None
    endpoint_id: str | None
    status: int | None
    request_media_type: str | None = None
    response_media_type: str | None = None
    resource_type: str | None = None
    response_kind: str | None = None
    request_shape: Any = None
    response_shape: Any = None
    successful: bool = False
    failure: dict[str, Any] | None = None
    interaction_id: str | None = None


@dataclass(slots=True)
class Origin:
    id: str
    scheme: str
    host: str
    port: int | None
    field_evidence: dict[str, list[FieldEvidence]] = field(default_factory=dict)
    conflicts: list[Conflict] = field(default_factory=list)


@dataclass(slots=True)
class Endpoint:
    id: str
    origin_id: str
    path: str
    protocols: list[Protocol]
    request_media_types: list[str] = field(default_factory=list)
    response_media_types: list[str] = field(default_factory=list)
    field_evidence: dict[str, list[FieldEvidence]] = field(default_factory=dict)
    conflicts: list[Conflict] = field(default_factory=list)


@dataclass(slots=True)
class Identifier:
    kind: str
    value: str
    current: bool
    first_seen_at: str | None
    last_seen_at: str | None
    source: SourceKind


@dataclass(slots=True)
class Parameter:
    name: str
    location: str
    required: bool
    schema: dict[str, Any]
    argument: str | None = None
    style: str | None = None
    explode: bool | None = None
    allow_reserved: bool = False
    collection_format: str | None = None


@dataclass(slots=True)
class RequestTemplate:
    id: str
    endpoint_id: str
    method: str
    path_segments: list[str]
    query_encoding: str
    parameters: list[Parameter] = field(default_factory=list)
    required_headers: list[str] = field(default_factory=list)
    optional_headers: list[str] = field(default_factory=list)
    volatile_headers: list[str] = field(default_factory=list)
    body_media_type: str | None = None
    body_template: Any = None
    operation_name: str | None = None
    variables_envelope: Any = None
    extensions: dict[str, Any] = field(default_factory=dict)
    field_evidence: dict[str, list[FieldEvidence]] = field(default_factory=dict)
    conflicts: list[Conflict] = field(default_factory=list)


@dataclass(slots=True)
class AuthenticationFlow:
    id: str
    kind: str
    source_surface_ids: list[str]
    credential_scope_ids: list[str]
    field_evidence: dict[str, list[FieldEvidence]] = field(default_factory=dict)
    mechanisms: list[str] = field(default_factory=list)
    public_identifier_names: list[str] = field(default_factory=list)
    secret_credential_names: list[str] = field(default_factory=list)
    minting_interaction_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CredentialScope:
    id: str
    origin_ids: list[str]
    operation_ids: list[str]
    header_names: list[str]
    generation_id: str | None = None
    expires_at: str | None = None


@dataclass(slots=True)
class Schema:
    id: str
    dialect: str
    role: str
    document: dict[str, Any]
    source: SourceKind
    confidence: float


@dataclass(slots=True)
class Surface:
    id: str
    url: str
    title: str | None = None
    field_evidence: dict[str, list[FieldEvidence]] = field(default_factory=dict)


@dataclass(slots=True)
class Interaction:
    id: str
    surface_id: str
    kind: str
    selector: str | None = None
    safe_annotation: str | None = None
    caused_evidence_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EventChannel:
    id: str
    endpoint_id: str
    protocol: Protocol
    namespace: str | None
    sent_events: list[str]
    received_events: list[str]


@dataclass(slots=True)
class Proof:
    id: str
    operation_id: str
    run_id: str
    adapter: str
    observed: bool
    actively_executed: bool
    schema_validated: bool
    side_effect_reviewed: bool
    fresh: bool | None
    attempted_at: str | None
    status: int | None
    success: bool
    indeterminate: bool = False
    failure: dict[str, Any] | None = None


@dataclass(slots=True)
class Drift:
    id: str
    operation_id: str
    dimension: str
    severity: DriftSeverity
    before: Any
    after: Any
    detected_at: str
    remediation: str


@dataclass(slots=True)
class RatePolicy:
    id: str
    origin_id: str
    operation_id: str | None
    limit: int | None
    remaining: int | None
    resets_at: str | None
    source: SourceKind


@dataclass(slots=True)
class Lifecycle:
    first_seen_at: str | None
    last_seen_at: str | None
    last_verified_at: str | None
    run_ids: list[str]
    observation_count: int
    consecutive_misses: int
    freshness_ttl_seconds: int | None
    status: LifecycleStatus
    retirement_reason: str | None = None


@dataclass(slots=True)
class Operation:
    id: str
    semantic_kind: SemanticKind
    protocol: Protocol
    endpoint_ids: list[str]
    request_template_ids: list[str]
    aliases: list[str]
    operation_names: list[str]
    identifiers: list[Identifier]
    input_schema_ids: list[str]
    output_schema_ids: list[str]
    proof_ids: list[str]
    credential_scope_ids: list[str]
    lifecycle: Lifecycle
    field_evidence: dict[str, list[FieldEvidence]] = field(default_factory=dict)
    conflicts: list[Conflict] = field(default_factory=list)


@dataclass(slots=True)
class BackendGraph:
    target: str
    runs: list[Run]
    evidence: list[Evidence]
    origins: list[Origin]
    endpoints: list[Endpoint]
    operations: list[Operation]
    request_templates: list[RequestTemplate]
    authentication_flows: list[AuthenticationFlow] = field(default_factory=list)
    credential_scopes: list[CredentialScope] = field(default_factory=list)
    schemas: list[Schema] = field(default_factory=list)
    surfaces: list[Surface] = field(default_factory=list)
    interactions: list[Interaction] = field(default_factory=list)
    event_channels: list[EventChannel] = field(default_factory=list)
    proofs: list[Proof] = field(default_factory=list)
    drifts: list[Drift] = field(default_factory=list)
    rate_policies: list[RatePolicy] = field(default_factory=list)
    schema_version: int = GRAPH_SCHEMA_VERSION
    schema_dialect: str = JSON_SCHEMA_DIALECT

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


def _serialize(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {key: _serialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    return value


def _field_evidence(
    source: SourceKind, run_id: str, fields: list[str]
) -> dict[str, list[FieldEvidence]]:
    return {name: [FieldEvidence(source=source, run_id=run_id, confidence=1.0)] for name in fields}


def _origin_for_url(
    url: str, origins: dict[tuple[str, str, int | None], Origin], source: SourceKind, run_id: str
) -> Origin:
    parsed = up.urlsplit(url)
    scheme = parsed.scheme or "https"
    host = normalize_host(parsed.hostname or "invalid.local")
    port = parsed.port
    key = (scheme, host, port)
    if key not in origins:
        identifier = stable_id("origin", scheme, host, port)
        origins[key] = Origin(
            id=identifier,
            scheme=scheme,
            host=host,
            port=port,
            field_evidence=_field_evidence(source, run_id, ["scheme", "host", "port"]),
        )
    return origins[key]


def _endpoint_for(
    origin: Origin,
    path: str,
    protocol: Protocol,
    endpoints: dict[tuple[str, str], Endpoint],
    source: SourceKind,
    run_id: str,
) -> Endpoint:
    key = (origin.id, path)
    if key not in endpoints:
        endpoints[key] = Endpoint(
            id=stable_id("endpoint", origin.id, path),
            origin_id=origin.id,
            path=path,
            protocols=[protocol],
            field_evidence=_field_evidence(source, run_id, ["origin_id", "path", "protocols"]),
        )
    elif protocol not in endpoints[key].protocols:
        endpoints[key].protocols.append(protocol)
    return endpoints[key]


def graph_from_inventory(
    inventory: dict[str, Any],
    records: list[dict[str, Any]],
    metadata: dict[str, Any],
    *,
    source: SourceKind = SourceKind.CAPTURE,
) -> BackendGraph:
    target = normalize_host(str(inventory["base_domain"]))
    run_id = str(
        metadata.get("run_id")
        or stable_id("run", target, metadata.get("captured_at"), len(records))
    )
    started = str(
        metadata.get("started_at") or metadata.get("captured_at") or "1970-01-01T00:00:00+00:00"
    )
    completed = metadata.get("completed_at") or metadata.get("captured_at")
    completeness = Completeness.PARTIAL if metadata.get("partial") else Completeness.COMPLETE
    run = Run(
        id=run_id,
        target=target,
        started_at=started,
        completed_at=str(completed) if completed else None,
        completeness=completeness,
        profile=metadata.get("profile"),
        safety_mode=str(metadata.get("safety_mode") or "read-only"),
        failures=list(metadata.get("failures") or []),
        truncations=dict(metadata.get("truncations") or {}),
    )
    origins: dict[tuple[str, str, int | None], Origin] = {}
    endpoints: dict[tuple[str, str], Endpoint] = {}
    templates: dict[str, RequestTemplate] = {}
    operations: dict[str, Operation] = {}
    evidence: list[Evidence] = []
    schemas: list[Schema] = []
    event_channels: dict[tuple[str, str | None], EventChannel] = {}

    gql_inventory = inventory.get("graphql_operations") or {}
    for alias, raw in gql_inventory.items():
        protocol = _protocol(raw.get("protocol"))
        kind = _semantic(raw.get("semantic_kind") or raw.get("type"))
        request_url = raw.get("request_url")
        if not isinstance(request_url, str) or not request_url.startswith(("http://", "https://")):
            endpoint_path = next(iter(inventory.get("graphql_endpoints") or []), "/graphql")
            request_url = f"https://{target}{endpoint_path}"
        origin = _origin_for_url(request_url, origins, source, run_id)
        path = up.urlsplit(request_url).path or "/"
        endpoint = _endpoint_for(origin, path, protocol, endpoints, source, run_id)
        semantic_name = raw.get("operation") or alias or "anonymous"
        operation_id = stable_id("operation", endpoint.id, protocol.value, semantic_name)
        request_template = dict(raw.get("request_template") or {})
        if raw.get("query") and "query" not in request_template:
            request_template["query"] = raw["query"]
        template_id = stable_id(
            "template",
            operation_id,
            raw.get("http_method") or "POST",
            request_template,
        )
        template = RequestTemplate(
            id=template_id,
            endpoint_id=endpoint.id,
            method=str(raw.get("http_method") or "POST").upper(),
            path_segments=[part for part in path.split("/") if part],
            query_encoding="rfc3986",
            required_headers=sorted(str(item) for item in raw.get("required_headers") or []),
            optional_headers=sorted(str(item) for item in raw.get("optional_headers") or []),
            body_media_type=raw.get("request_media_type") or "application/json",
            body_template=request_template,
            operation_name=raw.get("operation"),
            variables_envelope={"variables": raw.get("input_schema") or {}},
            extensions=request_template.get("extensions", {}),
            field_evidence=_field_evidence(
                source,
                run_id,
                ["endpoint_id", "method", "path_segments", "body_template", "operation_name"],
            ),
        )
        templates[template.id] = template
        input_schema = raw.get("input_schema") or {"type": "object", "properties": {}}
        input_schema_id = stable_id("schema", operation_id, "input", input_schema)
        schemas.append(
            Schema(input_schema_id, JSON_SCHEMA_DIALECT, "input", input_schema, source, 1.0)
        )
        current_identifier = raw.get("persistedHash")
        identifiers = []
        if current_identifier:
            identifiers.append(
                Identifier(
                    kind="persisted-id",
                    value=str(current_identifier),
                    current=True,
                    first_seen_at=started,
                    last_seen_at=str(completed) if completed else None,
                    source=source,
                )
            )
        operations[operation_id] = Operation(
            id=operation_id,
            semantic_kind=kind,
            protocol=protocol,
            endpoint_ids=[endpoint.id],
            request_template_ids=[template.id],
            aliases=[str(alias)] if alias else [],
            operation_names=[str(raw["operation"])] if raw.get("operation") else [],
            identifiers=identifiers,
            input_schema_ids=[input_schema_id],
            output_schema_ids=[],
            proof_ids=[],
            credential_scope_ids=[],
            lifecycle=Lifecycle(
                first_seen_at=started,
                last_seen_at=str(completed) if completed else None,
                last_verified_at=None,
                run_ids=[run_id],
                observation_count=int(raw.get("calls") or 0),
                consecutive_misses=0,
                freshness_ttl_seconds=raw.get("freshness_ttl_seconds"),
                status=LifecycleStatus.CURRENT,
            ),
            field_evidence=_field_evidence(
                source,
                run_id,
                ["semantic_kind", "protocol", "aliases", "operation_names", "identifiers"],
            ),
        )

    rest_lookup: dict[tuple[str, str], str] = {}
    misc_lookup: dict[tuple[str, str], str] = {}
    for raw in inventory.get("rest_endpoints") or []:
        method = str(raw.get("method") or "GET").upper()
        path = str(raw.get("path") or "/")
        request_url = raw.get("request_url")
        if isinstance(request_url, str) and up.urlsplit(request_url).hostname:
            parsed_request = up.urlsplit(request_url)
            origin_url = f"{parsed_request.scheme}://{parsed_request.netloc}"
            path = parsed_request.path or path
        else:
            origin_url = raw.get("origin") or raw.get("server_url") or f"https://{target}"
        origin = _origin_for_url(
            str(origin_url),
            origins,
            SourceKind.OPENAPI if raw.get("source") == "openapi" else source,
            run_id,
        )
        endpoint = _endpoint_for(origin, path, Protocol.REST, endpoints, source, run_id)
        semantic_name = raw.get("operationId") or f"{method} {path}"
        operation_id = stable_id("operation", endpoint.id, Protocol.REST.value, semantic_name)
        rest_lookup[(method, path)] = operation_id
        parameters = [Parameter(**parameter) for parameter in raw.get("parameters") or []]
        template_id = stable_id(
            "template",
            operation_id,
            method,
            raw.get("parameters") or [],
            raw.get("body_template"),
        )
        templates[template_id] = RequestTemplate(
            id=template_id,
            endpoint_id=endpoint.id,
            method=method,
            path_segments=[part for part in path.split("/") if part],
            query_encoding="openapi",
            parameters=parameters,
            required_headers=sorted(str(item) for item in raw.get("auth_headers") or []),
            body_media_type=raw.get("body_media_type") or raw.get("request_media_type"),
            body_template=raw.get("body_template"),
            field_evidence=_field_evidence(source, run_id, ["endpoint_id", "method", "parameters"]),
        )
        input_schema = raw.get("input_schema") or {"type": "object", "properties": {}}
        input_schema_id = stable_id("schema", operation_id, "input", input_schema)
        schemas.append(
            Schema(input_schema_id, JSON_SCHEMA_DIALECT, "input", input_schema, source, 1.0)
        )
        output_ids = []
        if raw.get("return_schema"):
            output_id = stable_id("schema", operation_id, "output", raw["return_schema"])
            schemas.append(
                Schema(output_id, JSON_SCHEMA_DIALECT, "output", raw["return_schema"], source, 1.0)
            )
            output_ids.append(output_id)
        operations[operation_id] = Operation(
            id=operation_id,
            semantic_kind=_semantic(raw.get("semantic_kind") or raw.get("type")),
            protocol=Protocol.REST,
            endpoint_ids=[endpoint.id],
            request_template_ids=[template_id],
            aliases=[str(raw.get("alias") or semantic_name)],
            operation_names=[str(semantic_name)],
            identifiers=[],
            input_schema_ids=[input_schema_id],
            output_schema_ids=output_ids,
            proof_ids=[],
            credential_scope_ids=[],
            lifecycle=Lifecycle(
                first_seen_at=started,
                last_seen_at=str(completed) if completed else None,
                last_verified_at=None,
                run_ids=[run_id],
                observation_count=int(raw.get("calls") or 0),
                consecutive_misses=0,
                freshness_ttl_seconds=raw.get("freshness_ttl_seconds"),
                status=LifecycleStatus.CURRENT,
            ),
            field_evidence=_field_evidence(source, run_id, ["semantic_kind", "protocol"]),
        )
    for alias, raw in (inventory.get("websocket_operations") or {}).items():
        url = str(raw.get("url") or "")
        parsed = up.urlsplit(url)
        if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
            continue
        origin = _origin_for_url(url, origins, source, run_id)
        path = parsed.path or "/"
        protocol = Protocol.SOCKETIO if raw.get("engineio") else Protocol.WEBSOCKET
        endpoint = _endpoint_for(origin, path, protocol, endpoints, source, run_id)
        direction = str(raw.get("direction") or "received")
        event_name = str(raw.get("event") or "unknown")
        namespace = raw.get("namespace")
        semantic = SemanticKind.SUBSCRIPTION if direction == "received" else SemanticKind.MUTATION
        operation_id = stable_id(
            "operation", endpoint.id, protocol.value, namespace, direction, event_name
        )
        input_schema = raw.get("input_schema") or {"type": "object", "properties": {}}
        input_schema_id = stable_id("schema", operation_id, "input", input_schema)
        schemas.append(
            Schema(input_schema_id, JSON_SCHEMA_DIALECT, "input", input_schema, source, 1.0)
        )
        template_id = stable_id(
            "template", operation_id, direction, namespace, event_name, input_schema
        )
        templates[template_id] = RequestTemplate(
            id=template_id,
            endpoint_id=endpoint.id,
            method="WEBSOCKET",
            path_segments=[part for part in path.split("/") if part],
            query_encoding="socketio" if protocol is Protocol.SOCKETIO else "websocket",
            body_media_type="application/json",
            body_template={"event": event_name, "namespace": namespace, "shape": input_schema},
            field_evidence=_field_evidence(source, run_id, ["endpoint_id", "body_template"]),
        )
        operations[operation_id] = Operation(
            id=operation_id,
            semantic_kind=semantic,
            protocol=protocol,
            endpoint_ids=[endpoint.id],
            request_template_ids=[template_id],
            aliases=[str(alias)],
            operation_names=[event_name],
            identifiers=[],
            input_schema_ids=[input_schema_id],
            output_schema_ids=[],
            proof_ids=[],
            credential_scope_ids=[],
            lifecycle=Lifecycle(
                first_seen_at=started,
                last_seen_at=str(completed) if completed else None,
                last_verified_at=None,
                run_ids=[run_id],
                observation_count=int(raw.get("calls") or 0),
                consecutive_misses=0,
                freshness_ttl_seconds=raw.get("freshness_ttl_seconds"),
                status=LifecycleStatus.CURRENT,
            ),
            field_evidence=_field_evidence(
                source, run_id, ["semantic_kind", "protocol", "operation_names"]
            ),
        )
        channel_key = (endpoint.id, namespace)
        if channel_key not in event_channels:
            event_channels[channel_key] = EventChannel(
                id=stable_id("event-channel", endpoint.id, namespace),
                endpoint_id=endpoint.id,
                protocol=protocol,
                namespace=namespace,
                sent_events=[],
                received_events=[],
            )
        event_list = (
            event_channels[channel_key].sent_events
            if direction == "sent"
            else event_channels[channel_key].received_events
        )
        if event_name not in event_list:
            event_list.append(event_name)
        evidence.append(
            Evidence(
                id=stable_id("evidence", run_id, "event", operation_id),
                run_id=run_id,
                source=source,
                observed_at=str(completed) if completed else None,
                operation_id=operation_id,
                endpoint_id=endpoint.id,
                status=None,
                resource_type="websocket",
                response_kind="stream",
                request_shape=input_schema if direction == "sent" else None,
                response_shape=input_schema if direction == "received" else None,
                successful=int(raw.get("calls") or 0) > 0,
            )
        )

    for alias, raw in (inventory.get("misc_operations") or {}).items():
        if not isinstance(raw, dict):
            continue
        protocol = _protocol(raw.get("protocol"))
        url = str(raw.get("url") or "")
        parsed = up.urlsplit(url)
        if parsed.scheme in {"http", "https", "ws", "wss"} and parsed.hostname:
            origin = _origin_for_url(url, origins, source, run_id)
            path = parsed.path or "/"
        else:
            origin = _origin_for_url(f"https://{target}", origins, source, run_id)
            path = f"/__inventory__/{protocol.value}/{stable_id('path', alias)}"
        endpoint = _endpoint_for(origin, path, protocol, endpoints, source, run_id)
        operation_id = stable_id("operation", endpoint.id, protocol.value, alias)
        input_schema = raw.get("input_schema") or raw.get("request_shape") or {}
        input_schema_id = stable_id("schema", operation_id, "input", input_schema)
        schemas.append(
            Schema(input_schema_id, JSON_SCHEMA_DIALECT, "input", input_schema, source, 0.5)
        )
        template_id = stable_id("template", operation_id, raw.get("method"), protocol.value)
        templates[template_id] = RequestTemplate(
            id=template_id,
            endpoint_id=endpoint.id,
            method=str(raw.get("method") or "INVENTORY"),
            path_segments=[part for part in path.split("/") if part],
            query_encoding="inventory-only",
            body_media_type=raw.get("request_media_type"),
            body_template={"protocol": protocol.value, "executable": False},
            field_evidence=_field_evidence(source, run_id, ["endpoint_id", "method"]),
        )
        operations[operation_id] = Operation(
            id=operation_id,
            semantic_kind=SemanticKind.UNKNOWN,
            protocol=protocol,
            endpoint_ids=[endpoint.id],
            request_template_ids=[template_id],
            aliases=[str(alias)],
            operation_names=[],
            identifiers=[],
            input_schema_ids=[input_schema_id],
            output_schema_ids=[],
            proof_ids=[],
            credential_scope_ids=[],
            lifecycle=Lifecycle(
                first_seen_at=started,
                last_seen_at=str(completed) if completed else None,
                last_verified_at=None,
                run_ids=[run_id],
                observation_count=int(raw.get("calls") or 0),
                consecutive_misses=0,
                freshness_ttl_seconds=None,
                status=LifecycleStatus.CURRENT,
            ),
            field_evidence=_field_evidence(source, run_id, ["semantic_kind", "protocol"]),
        )
        if parsed.scheme in {"http", "https"}:
            misc_lookup[(str(raw.get("method") or "POST").upper(), path)] = operation_id

    alias_lookup = {
        alias: operation.id for operation in operations.values() for alias in operation.aliases
    }
    operation_name_lookup = {
        name: operation.id
        for operation in operations.values()
        for name in operation.operation_names
    }
    operation_map = {operation.id: operation for operation in operations.values()}
    endpoint_id_map = {endpoint.id: endpoint for endpoint in endpoints.values()}
    for index, record in enumerate(records):
        url = str(record.get("url") or "")
        parsed = up.urlsplit(url)
        evidence_operation_id: str | None = None
        if record.get("graphql"):
            for graphql in record["graphql"]:
                alias = dict(up.parse_qsl(parsed.query)).get("alias") or graphql.get(
                    "operationName"
                )
                evidence_operation_id = alias_lookup.get(str(alias)) or operation_name_lookup.get(
                    str(graphql.get("operationName"))
                )
                if evidence_operation_id:
                    break
        else:
            signature = (str(record.get("method") or "GET").upper(), parsed.path)
            evidence_operation_id = misc_lookup.get(signature) or rest_lookup.get(signature)
        evidence_endpoint: Endpoint | None = None
        if evidence_operation_id:
            operation = operation_map[evidence_operation_id]
            evidence_endpoint = endpoint_id_map.get(operation.endpoint_ids[0])
        elif parsed.hostname:
            origin = _origin_for_url(url, origins, source, run_id)
            evidence_endpoint = _endpoint_for(
                origin, parsed.path or "/", Protocol.REST, endpoints, source, run_id
            )
        evidence_item = Evidence(
            id=stable_id("evidence", run_id, index),
            run_id=run_id,
            source=source,
            observed_at=record.get("observed_at") or completed,
            operation_id=evidence_operation_id,
            endpoint_id=evidence_endpoint.id if evidence_endpoint else None,
            status=record.get("status"),
            request_media_type=record.get("request_media_type"),
            response_media_type=record.get("resp_ct"),
            resource_type=record.get("rtype"),
            response_kind=record.get("response_kind"),
            request_shape=record.get("request_shape"),
            response_shape=record.get("resp_shape"),
            successful=isinstance(record.get("status"), int) and record["status"] < 400,
            failure=record.get("failure"),
            interaction_id=record.get("interaction_id"),
        )
        evidence.append(evidence_item)
        if evidence_endpoint:
            if (
                evidence_item.request_media_type
                and evidence_item.request_media_type not in evidence_endpoint.request_media_types
            ):
                evidence_endpoint.request_media_types.append(evidence_item.request_media_type)
            if (
                evidence_item.response_media_type
                and evidence_item.response_media_type not in evidence_endpoint.response_media_types
            ):
                evidence_endpoint.response_media_types.append(evidence_item.response_media_type)

    surfaces = [
        Surface(
            id=stable_id("surface", safe_url(str(url))),
            url=safe_url(str(url)),
            field_evidence=_field_evidence(source, run_id, ["url"]),
        )
        for url in metadata.get("surfaces") or []
    ]
    surface_ids = {surface.url: surface.id for surface in surfaces}
    interactions = []
    for raw_interaction in metadata.get("interactions") or []:
        surface_url = safe_url(str(raw_interaction.get("surface") or ""))
        if surface_url not in surface_ids:
            surface = Surface(
                id=stable_id("surface", surface_url),
                url=surface_url,
                field_evidence=_field_evidence(source, run_id, ["url"]),
            )
            surfaces.append(surface)
            surface_ids[surface_url] = surface.id
        interactions.append(
            Interaction(
                id=str(raw_interaction.get("id") or stable_id("interaction", run_id, surface_url)),
                surface_id=surface_ids[surface_url],
                kind=str(raw_interaction.get("kind") or "unknown"),
                safe_annotation=(
                    f"calls={raw_interaction.get('calls', 0)}; "
                    f"settled={raw_interaction.get('settled')}; "
                    f"truncation={raw_interaction.get('truncation_reason')}"
                ),
                caused_evidence_ids=[
                    item.id for item in evidence if item.interaction_id == raw_interaction.get("id")
                ],
            )
        )
    auth_header_names = sorted(str(name).lower() for name in (inventory.get("auth_headers") or {}))
    credential_scopes = []
    authentication_flows = []
    if auth_header_names and origins:
        authentication = metadata.get("authentication") or {}
        public_identifier_names = sorted(
            str(name) for name in authentication.get("public_identifier_names") or []
        )
        secret_credential_names = sorted(
            str(name) for name in authentication.get("secret_credential_names") or []
        )
        if not public_identifier_names and not secret_credential_names:
            public_identifier_names = sorted(
                name
                for name in auth_header_names
                if re.search(r"client-(?:name|version)|accept-language|app[-_]?id", name, re.I)
            )
            secret_credential_names = sorted(
                name for name in auth_header_names if name not in public_identifier_names
            )
        observations = authentication.get("observations") or []
        minting_interaction_ids = sorted(
            {
                str(item["interaction_id"])
                for item in observations
                if isinstance(item, dict) and item.get("interaction_id")
            }
        )
        mechanisms = set()
        for name in auth_header_names:
            lowered = name.lower()
            if lowered == "authorization":
                mechanisms.add("bearer-or-oauth")
            if "csrf" in lowered:
                mechanisms.add("csrf")
            if "api" in lowered and "key" in lowered:
                mechanisms.add("api-key")
            if "session" in lowered:
                mechanisms.add("session")
            if "nonce" in lowered or "transaction" in lowered:
                mechanisms.add("nonce-or-transaction")
            if "device" in lowered:
                mechanisms.add("device-binding")
        scope_id = stable_id("credential-scope", target, auth_header_names)
        credential_scopes.append(
            CredentialScope(
                id=scope_id,
                origin_ids=sorted(origin.id for origin in origins.values()),
                operation_ids=sorted(operations),
                header_names=auth_header_names,
                generation_id=run_id,
            )
        )
        authentication_flows.append(
            AuthenticationFlow(
                id=stable_id("authentication-flow", target, "captured-headers"),
                kind="captured-request-headers",
                source_surface_ids=sorted(surface_ids.values()),
                credential_scope_ids=[scope_id],
                field_evidence=_field_evidence(source, run_id, ["kind", "credential_scope_ids"]),
                mechanisms=sorted(mechanisms),
                public_identifier_names=public_identifier_names,
                secret_credential_names=secret_credential_names,
                minting_interaction_ids=minting_interaction_ids,
            )
        )
        for operation in operations.values():
            operation.credential_scope_ids = [scope_id]
    return BackendGraph(
        target=target,
        runs=[run],
        evidence=evidence,
        origins=list(origins.values()),
        endpoints=list(endpoints.values()),
        operations=list(operations.values()),
        request_templates=list(templates.values()),
        authentication_flows=authentication_flows,
        credential_scopes=credential_scopes,
        schemas=schemas,
        surfaces=surfaces,
        interactions=interactions,
        event_channels=list(event_channels.values()),
    )


def _semantic(value: Any) -> SemanticKind:
    try:
        return SemanticKind(str(value))
    except ValueError:
        return SemanticKind.UNKNOWN


def _protocol(value: Any) -> Protocol:
    try:
        return Protocol(str(value))
    except ValueError:
        return Protocol.GRAPHQL_VENDOR_PERSISTED


def write_graph(path: str | Path, graph: BackendGraph) -> None:
    value = graph.to_dict()
    from .schema import validate_artifact

    validate_artifact(value, "backend-graph-v1.schema.json")
    atomic_write_json(path, value)


def load_graph(path: str | Path) -> dict[str, Any]:
    value = read_json_artifact(
        path,
        label="backend graph",
        supported_versions=SUPPORTED_GRAPH_VERSIONS,
    )
    if not isinstance(value, dict) or not isinstance(value.get("operations"), list):
        raise ArtifactError("backend graph operations must be an array")
    from .schema import validate_artifact

    validate_artifact(value, "backend-graph-v1.schema.json")
    return value


def migrate_graph(value: dict[str, Any]) -> dict[str, Any]:
    version = value.get("schema_version")
    if version == GRAPH_SCHEMA_VERSION:
        return value
    if isinstance(version, int) and version > GRAPH_SCHEMA_VERSION:
        raise ArtifactError(
            f"backend graph version {version} is newer than this astrolabe; upgrade astrolabe"
        )
    raise ArtifactError(f"no migration exists for backend graph schema_version {version!r}")


def _merge_identifiers(
    previous: list[dict[str, Any]], current: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    current_keys = {(item.get("kind"), item.get("value")) for item in current}
    merged: dict[tuple[Any, Any], dict[str, Any]] = {}
    for item in previous:
        copy = deepcopy(item)
        if copy.get("current") and (copy.get("kind"), copy.get("value")) not in current_keys:
            copy["current"] = False
        merged[(copy.get("kind"), copy.get("value"))] = copy
    for item in current:
        key = (item.get("kind"), item.get("value"))
        copy = deepcopy(item)
        old = merged.get(key)
        if old:
            copy["first_seen_at"] = old.get("first_seen_at") or copy.get("first_seen_at")
        merged[key] = copy
    return list(merged.values())


def _merge_field_evidence(
    previous: dict[str, list[dict[str, Any]]], current: dict[str, list[dict[str, Any]]]
) -> dict[str, list[dict[str, Any]]]:
    merged = deepcopy(previous)
    for field_name, entries in current.items():
        existing = merged.setdefault(field_name, [])
        known = {(item.get("source"), item.get("run_id"), item.get("detail")) for item in existing}
        existing.extend(
            deepcopy(item)
            for item in entries
            if (item.get("source"), item.get("run_id"), item.get("detail")) not in known
        )
    return merged


def _drift(
    operation_id: str,
    dimension: str,
    before: Any,
    after: Any,
    detected_at: str,
) -> dict[str, Any]:
    severity = {
        "semantic_kind": DriftSeverity.SECURITY,
        "protocol": DriftSeverity.BREAKING,
        "identifiers": DriftSeverity.BREAKING,
        "endpoint_ids": DriftSeverity.BREAKING,
        "request_template_ids": DriftSeverity.BREAKING,
        "input_schema_ids": DriftSeverity.POTENTIALLY_BREAKING,
        "output_schema_ids": DriftSeverity.POTENTIALLY_BREAKING,
    }.get(dimension, DriftSeverity.COMPATIBLE)
    remediation = {
        "semantic_kind": "operator-review",
        "protocol": "recapture-and-regenerate",
        "identifiers": "recapture-and-regenerate",
        "endpoint_ids": "recapture-and-regenerate",
        "request_template_ids": "recapture-and-regenerate",
        "input_schema_ids": "schema-migration",
        "output_schema_ids": "schema-migration",
    }.get(dimension, "operator-review")
    return _serialize(
        asdict(
            Drift(
                id=stable_id("drift", operation_id, dimension, before, after, detected_at),
                operation_id=operation_id,
                dimension=dimension,
                severity=severity,
                before=before,
                after=after,
                detected_at=detected_at,
                remediation=remediation,
            )
        )
    )


def merge_graphs(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Append immutable observations and update a conservative current materialization."""
    if previous.get("schema_version") != GRAPH_SCHEMA_VERSION:
        previous = migrate_graph(previous)
    if current.get("schema_version") != GRAPH_SCHEMA_VERSION:
        current = migrate_graph(current)
    if previous.get("target") != current.get("target"):
        raise ArtifactError(
            f"cannot merge graph targets {previous.get('target')!r} and {current.get('target')!r}"
        )
    merged = deepcopy(current)
    for collection in (
        "runs",
        "evidence",
        "origins",
        "endpoints",
        "request_templates",
        "authentication_flows",
        "credential_scopes",
        "schemas",
        "surfaces",
        "interactions",
        "event_channels",
        "proofs",
        "rate_policies",
    ):
        by_id = {item["id"]: deepcopy(item) for item in previous.get(collection) or []}
        by_id.update({item["id"]: deepcopy(item) for item in current.get(collection) or []})
        merged[collection] = list(by_id.values())

    prior_operations = {item["id"]: item for item in previous.get("operations") or []}
    current_operations = {item["id"]: item for item in current.get("operations") or []}
    current_run = (current.get("runs") or [{}])[-1]
    current_run_id = current_run.get("id")
    completed_at = current_run.get("completed_at") or current_run.get("started_at")
    complete = current_run.get("completeness") == Completeness.COMPLETE.value
    materialized: dict[str, dict[str, Any]] = {}
    new_drifts = list(previous.get("drifts") or []) + list(current.get("drifts") or [])

    for operation_id, operation in current_operations.items():
        prior = prior_operations.get(operation_id)
        if not prior:
            materialized[operation_id] = deepcopy(operation)
            new_drifts.append(_drift(operation_id, "operation", None, "added", str(completed_at)))
            continue
        value = deepcopy(operation)
        value["aliases"] = list(
            dict.fromkeys([*(prior.get("aliases") or []), *(value.get("aliases") or [])])
        )
        value["operation_names"] = list(
            dict.fromkeys(
                [*(prior.get("operation_names") or []), *(value.get("operation_names") or [])]
            )
        )
        value["identifiers"] = _merge_identifiers(
            prior.get("identifiers") or [], value.get("identifiers") or []
        )
        value["field_evidence"] = _merge_field_evidence(
            prior.get("field_evidence") or {}, value.get("field_evidence") or {}
        )
        lifecycle = value["lifecycle"]
        old_lifecycle = prior.get("lifecycle") or {}
        lifecycle["first_seen_at"] = old_lifecycle.get("first_seen_at") or lifecycle.get(
            "first_seen_at"
        )
        lifecycle["run_ids"] = list(
            dict.fromkeys(
                [*(old_lifecycle.get("run_ids") or []), *(lifecycle.get("run_ids") or [])]
            )
        )
        lifecycle["observation_count"] = int(old_lifecycle.get("observation_count") or 0) + int(
            lifecycle.get("observation_count") or 0
        )
        lifecycle["consecutive_misses"] = 0
        lifecycle["status"] = LifecycleStatus.CURRENT.value
        for dimension in (
            "semantic_kind",
            "protocol",
            "endpoint_ids",
            "request_template_ids",
            "input_schema_ids",
            "output_schema_ids",
        ):
            if prior.get(dimension) != operation.get(dimension):
                new_drifts.append(
                    _drift(
                        operation_id,
                        dimension,
                        prior.get(dimension),
                        operation.get(dimension),
                        str(completed_at),
                    )
                )
        old_current = [
            (item.get("kind"), item.get("value"))
            for item in prior.get("identifiers") or []
            if item.get("current")
        ]
        new_current = [
            (item.get("kind"), item.get("value"))
            for item in operation.get("identifiers") or []
            if item.get("current")
        ]
        if old_current != new_current:
            new_drifts.append(
                _drift(operation_id, "identifiers", old_current, new_current, str(completed_at))
            )
        materialized[operation_id] = value

    for operation_id, operation in prior_operations.items():
        if operation_id in materialized:
            continue
        value = deepcopy(operation)
        lifecycle = value["lifecycle"]
        if complete:
            lifecycle["consecutive_misses"] = int(lifecycle.get("consecutive_misses") or 0) + 1
            lifecycle["status"] = LifecycleStatus.NOT_OBSERVED.value
            lifecycle["run_ids"] = list(
                dict.fromkeys([*(lifecycle.get("run_ids") or []), current_run_id])
            )
            new_drifts.append(
                _drift(
                    operation_id,
                    "lifecycle",
                    LifecycleStatus.CURRENT.value,
                    LifecycleStatus.NOT_OBSERVED.value,
                    str(completed_at),
                )
            )
        materialized[operation_id] = value

    merged["operations"] = list(materialized.values())
    drift_by_id = {item["id"]: item for item in new_drifts}
    merged["drifts"] = list(drift_by_id.values())
    from .schema import validate_artifact

    validate_artifact(merged, "backend-graph-v1.schema.json")
    return merged


def inventory_from_graph(graph: dict[str, Any]) -> dict[str, Any]:
    origins = {item["id"]: item for item in graph.get("origins") or []}
    endpoints = {item["id"]: item for item in graph.get("endpoints") or []}
    templates = {item["id"]: item for item in graph.get("request_templates") or []}
    schemas = {item["id"]: item for item in graph.get("schemas") or []}
    graphql: dict[str, Any] = {}
    rest: list[dict[str, Any]] = []
    websocket: dict[str, Any] = {}
    misc: dict[str, Any] = {}
    gql_endpoints: list[str] = []
    evidence_by_operation: dict[str, list[dict[str, Any]]] = {}
    for evidence in graph.get("evidence") or []:
        if evidence.get("operation_id"):
            evidence_by_operation.setdefault(evidence["operation_id"], []).append(evidence)
    for operation in graph.get("operations") or []:
        template = templates.get((operation.get("request_template_ids") or [None])[0], {})
        endpoint = endpoints.get((operation.get("endpoint_ids") or [None])[0], {})
        origin = origins.get(endpoint.get("origin_id"), {})
        origin_url = f"{origin.get('scheme', 'https')}://{origin.get('host', graph['target'])}"
        if origin.get("port"):
            origin_url += f":{origin['port']}"
        path = endpoint.get("path") or "/"
        input_document: dict[str, Any] = {}
        input_ids = operation.get("input_schema_ids") or []
        if input_ids and input_ids[0] in schemas:
            input_document = schemas[input_ids[0]].get("document") or {}
        output_document = None
        output_ids = operation.get("output_schema_ids") or []
        if output_ids and output_ids[0] in schemas:
            output_document = schemas[output_ids[0]].get("document")
        identifiers = operation.get("identifiers") or []
        current = next((item for item in identifiers if item.get("current")), None)
        aliases = operation.get("aliases") or [operation["id"]]
        observations = evidence_by_operation.get(operation["id"], [])
        statuses = sorted(
            {item["status"] for item in observations if isinstance(item.get("status"), int)}
        )
        response_kinds = sorted(
            {item["response_kind"] for item in observations if item.get("response_kind")}
        )
        lifecycle = operation.get("lifecycle") or {}
        if operation.get("protocol") in {
            Protocol.WEBSOCKET.value,
            Protocol.SOCKETIO.value,
        }:
            direction = (
                "received"
                if operation.get("semantic_kind") == SemanticKind.SUBSCRIPTION.value
                else "sent"
            )
            alias = aliases[0]
            body_template = template.get("body_template") or {}
            websocket[alias] = {
                "url": f"{origin_url}{path}",
                "event": (operation.get("operation_names") or ["unknown"])[0],
                "direction": direction,
                "namespace": body_template.get("namespace"),
                "calls": lifecycle.get("observation_count", 0),
                "input_schema": input_document,
                "engineio": "4" if operation.get("protocol") == Protocol.SOCKETIO.value else None,
                "protocol": operation.get("protocol"),
                "semantic_kind": operation.get("semantic_kind"),
                "lifecycle_status": lifecycle.get("status"),
            }
            continue
        if operation.get("protocol") == Protocol.REST.value:
            schema_source = schemas.get(input_ids[0], {}).get("source") if input_ids else None
            rest.append(
                {
                    "method": template.get("method") or "GET",
                    "path": path,
                    "origin": origin_url,
                    "operationId": (operation.get("operation_names") or [None])[0],
                    "alias": aliases[0],
                    "semantic_kind": operation.get("semantic_kind"),
                    "type": operation.get("semantic_kind"),
                    "protocol": operation.get("protocol"),
                    "parameters": template.get("parameters") or [],
                    "auth_headers": template.get("required_headers") or [],
                    "request_media_type": template.get("body_media_type"),
                    "body_template": template.get("body_template"),
                    "input_schema": input_document,
                    "return_schema": output_document,
                    "calls": (operation.get("lifecycle") or {}).get("observation_count", 0),
                    "status": statuses,
                    "response_kinds": response_kinds,
                    "response_media_types": endpoint.get("response_media_types") or [],
                    "source": "openapi" if schema_source == SourceKind.OPENAPI.value else "capture",
                    "lifecycle_status": lifecycle.get("status"),
                    "last_seen_at": lifecycle.get("last_seen_at"),
                }
            )
            continue
        if operation.get("protocol") not in {
            Protocol.GRAPHQL_INLINE.value,
            Protocol.GRAPHQL_APQ.value,
            Protocol.GRAPHQL_X_PERSISTED.value,
            Protocol.GRAPHQL_META_DOC_ID.value,
            Protocol.GRAPHQL_VENDOR_PERSISTED.value,
        }:
            alias = aliases[0]
            misc[alias] = {
                "id": operation.get("id"),
                "protocol": operation.get("protocol"),
                "url": f"{origin_url}{path}",
                "method": template.get("method") or "INVENTORY",
                "calls": lifecycle.get("observation_count", 0),
                "request_shape": input_document,
                "executable": False,
                "disabled_reason": "inventory-only protocol; no reviewed execution adapter",
                "lifecycle_status": lifecycle.get("status"),
            }
            continue
        alias = aliases[0]
        request_url = f"{origin_url}{path}"
        graphql[alias] = {
            "semantic_kind": operation.get("semantic_kind"),
            "type": operation.get("semantic_kind"),
            "protocol": operation.get("protocol"),
            "http_method": template.get("method") or "POST",
            "request_url": request_url,
            "request_template": template.get("body_template") or {},
            "query": (template.get("body_template") or {}).get("query"),
            "operation": (operation.get("operation_names") or [None])[0],
            "persistedHash": current.get("value") if current else None,
            "input_schema": input_document,
            "calls": (operation.get("lifecycle") or {}).get("observation_count", 0),
            "status": statuses,
            "response_kinds": response_kinds,
            "response_media_types": endpoint.get("response_media_types") or [],
            "lifecycle_status": lifecycle.get("status"),
            "last_seen_at": lifecycle.get("last_seen_at"),
        }
        if path not in gql_endpoints:
            gql_endpoints.append(path)
    header_names = sorted(
        {
            name
            for scope in graph.get("credential_scopes") or []
            for name in scope.get("header_names") or []
        }
    )
    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "base_domain": graph["target"],
        "graphql_endpoints": gql_endpoints,
        "auth_headers": {name: "<present>" for name in header_names},
        "graphql_operations": graphql,
        "rest_endpoints": rest,
        "websocket_operations": websocket,
        "misc_operations": misc,
    }


def evidence_records_from_graph(graph: dict[str, Any]) -> list[dict[str, Any]]:
    endpoint_map = {item["id"]: item for item in graph.get("endpoints") or []}
    origin_map = {item["id"]: item for item in graph.get("origins") or []}
    operation_map = {item["id"]: item for item in graph.get("operations") or []}
    template_map = {item["id"]: item for item in graph.get("request_templates") or []}
    records = []
    for item in graph.get("evidence") or []:
        endpoint = endpoint_map.get(item.get("endpoint_id"), {})
        origin = origin_map.get(endpoint.get("origin_id"), {})
        url = f"{origin.get('scheme', 'https')}://{origin.get('host', graph['target'])}{endpoint.get('path', '/')}"
        operation = operation_map.get(item.get("operation_id"), {})
        record = {
            "url": url,
            "method": (
                template_map.get((operation.get("request_template_ids") or [None])[0], {}).get(
                    "method", "GET"
                )
            ),
            "status": item.get("status"),
            "rtype": item.get("resource_type"),
            "resp_ct": item.get("response_media_type"),
            "request_media_type": item.get("request_media_type"),
            "request_shape": item.get("request_shape"),
            "resp_shape": item.get("response_shape"),
            "failure": item.get("failure"),
            "response_kind": item.get("response_kind"),
        }
        if operation and operation.get("protocol") != Protocol.REST.value:
            template = template_map.get((operation.get("request_template_ids") or [None])[0], {})
            body = template.get("body_template") or {}
            record["graphql"] = [
                {
                    "operationName": (operation.get("operation_names") or [None])[0],
                    "semantic_kind": operation.get("semantic_kind"),
                    "protocol": operation.get("protocol"),
                    "query": body.get("query"),
                    "persistedHash": next(
                        (
                            identifier.get("value")
                            for identifier in operation.get("identifiers") or []
                            if identifier.get("current")
                        ),
                        None,
                    ),
                }
            ]
            record["operation_alias"] = (operation.get("aliases") or [operation["id"]])[0]
        records.append(record)
    return records
