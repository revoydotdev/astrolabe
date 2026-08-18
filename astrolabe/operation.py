"""Shared operation semantics and protocol model."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any


class SemanticKind(StrEnum):
    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"
    UNKNOWN = "unknown"


class Protocol(StrEnum):
    GRAPHQL_INLINE = "graphql-inline"
    GRAPHQL_APQ = "graphql-apq"
    GRAPHQL_X_PERSISTED = "graphql-x-persisted"
    GRAPHQL_META_DOC_ID = "graphql-meta-doc-id"
    GRAPHQL_VENDOR_PERSISTED = "graphql-vendor-persisted"
    REST = "rest"
    SSE = "sse"
    WEBSOCKET = "websocket"
    SOCKETIO = "socketio"
    GRPC_WEB = "grpc-web"
    PROTOBUF = "protobuf"
    JSON_RPC = "json-rpc"
    TRPC = "trpc"
    WEBTRANSPORT = "webtransport"
    WEBHOOK = "webhook"
    SERVICE_WORKER = "service-worker"
    OFFLINE_QUEUE = "offline-queue"


_DECLARATION = re.compile(r"(?:^|[\s,{])(query|mutation|subscription)\b", re.I)


def semantic_kind(query: str | None, declared: Any = None) -> SemanticKind:
    """Classify only from trusted query text or an explicit shared enum value."""
    if query:
        kinds = {SemanticKind(m.group(1).lower()) for m in _DECLARATION.finditer(query)}
        if len(kinds) == 1:
            return kinds.pop()
        if query.lstrip().startswith("{"):
            return SemanticKind.QUERY
        return SemanticKind.UNKNOWN
    try:
        kind = SemanticKind(str(declared))
    except ValueError:
        return SemanticKind.UNKNOWN
    # Legacy `persisted` and name-inferred values arrive here as unknown.
    return kind


def graphql_protocol(
    *, query: str | None, persisted_id: str | None, url: str = "", media_type: str = ""
) -> Protocol:
    if "/graphql/" in url:
        return Protocol.GRAPHQL_X_PERSISTED
    if "form" in media_type and persisted_id:
        return Protocol.GRAPHQL_META_DOC_ID
    if persisted_id and re.fullmatch(r"[0-9a-fA-F]{64}", persisted_id):
        return Protocol.GRAPHQL_APQ
    if query:
        return Protocol.GRAPHQL_INLINE
    return Protocol.GRAPHQL_VENDOR_PERSISTED


def verification_allowed(
    operation_id: str,
    kinds: list[SemanticKind],
    mutation_allowlist: set[str] | frozenset[str] = frozenset(),
    mutation_runtime_enabled: bool = False,
) -> tuple[bool, SemanticKind]:
    """Fail-closed active-verification policy, including GraphQL batches."""
    unique = set(kinds)
    kind = kinds[0] if len(unique) == 1 and kinds else SemanticKind.UNKNOWN
    if len(kinds) == 1 and kind is SemanticKind.QUERY:
        return True, kind
    mutation_ok = (
        len(kinds) == 1
        and kind is SemanticKind.MUTATION
        and operation_id in mutation_allowlist
        and mutation_runtime_enabled
    )
    return mutation_ok, kind
