"""Evidence-preserving discovery, static mining, planning, and coverage metrics.

Discovery is inventory construction, not authorization to execute.  Every candidate keeps
its sources and confidence, and static-only candidates remain ``inventory-only`` until an
independent source proves their request semantics and safety.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence, Set as AbstractSet
from dataclasses import dataclass, field
from datetime import UTC, datetime, time
from enum import StrEnum
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    from .artifact import JSON_SCHEMA_DIALECT
except ImportError:  # standalone deployment beside scan.py
    JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"


class DiscoverySource(StrEnum):
    TRAFFIC = "browser-traffic"
    DOM = "dom-navigation"
    SERVICE_WORKER = "service-worker"
    BUNDLE = "js-bundle"
    SOURCE_MAP = "source-map"
    MANIFEST = "chunk-manifest"
    OPENAPI = "openapi"
    INTROSPECTION = "graphql-introspection"
    RECOVERY = "graphql-recovery"
    ERROR = "observed-error"
    ROBOTS = "robots"
    SITEMAP = "sitemap"
    RECIPE = "recipe"
    OPERATOR = "operator-seed"


STATIC_SOURCES = {
    DiscoverySource.BUNDLE,
    DiscoverySource.SOURCE_MAP,
    DiscoverySource.MANIFEST,
}
SEMANTIC_PROOF_SOURCES = {
    DiscoverySource.TRAFFIC,
    DiscoverySource.OPENAPI,
    DiscoverySource.INTROSPECTION,
    DiscoverySource.RECIPE,
    DiscoverySource.OPERATOR,
}


def candidate_key(kind: str, value: str) -> str:
    normalized = value.strip()
    return hashlib.sha256(f"{kind}\0{normalized}".encode()).hexdigest()[:24]


@dataclass(frozen=True)
class Evidence:
    source: DiscoverySource
    confidence: float
    locator: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("evidence confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.value,
            "confidence": self.confidence,
            **({"locator": self.locator} if self.locator else {}),
            **({"detail": self.detail} if self.detail else {}),
        }


@dataclass
class Candidate:
    """A normalized discovery candidate with non-flattened supporting evidence."""

    kind: str
    key: str
    value: str
    evidence: list[Evidence] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def confidence(self) -> float:
        # Independent-evidence aggregation: multiple weak observations raise confidence
        # without ever pretending uncertainty has disappeared.
        miss_probability = 1.0
        for item in self.evidence:
            miss_probability *= 1.0 - item.confidence
        return round(1.0 - miss_probability, 6)

    @property
    def execution_state(self) -> str:
        sources = {item.source for item in self.evidence}
        if sources and sources <= STATIC_SOURCES:
            return "inventory-only"
        if self.metadata.get("conflicts"):
            return "inventory-only"
        semantics = bool(sources & SEMANTIC_PROOF_SOURCES)
        semantic_kind = self.metadata.get("semantic_kind")
        request_template = self.metadata.get("request_template")
        safe = self.metadata.get("safety_proven") is True
        if semantics and semantic_kind in {"query", "subscription"} and request_template and safe:
            return "eligible"
        return "inventory-only"

    def merge(self, other: Candidate) -> None:
        if (self.kind, self.key) != (other.kind, other.key):
            raise ValueError("cannot merge different discovery candidates")
        seen = {(e.source, e.locator, e.detail) for e in self.evidence}
        self.evidence.extend(
            item for item in other.evidence if (item.source, item.locator, item.detail) not in seen
        )
        for key, value in other.metadata.items():
            if key not in self.metadata:
                self.metadata[key] = value
            elif self.metadata[key] != value:
                conflicts = self.metadata.setdefault("conflicts", {})
                values = conflicts.setdefault(key, [self.metadata[key]])
                if value not in values:
                    values.append(value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "key": self.key,
            "value": self.value,
            "confidence": self.confidence,
            "execution_state": self.execution_state,
            "evidence": [item.to_dict() for item in self.evidence],
            "metadata": self.metadata,
        }


def fuse_candidates(groups: Iterable[Iterable[Candidate]]) -> list[Candidate]:
    """Fuse candidates by stable kind/key while retaining every source and conflict."""
    fused: dict[tuple[str, str], Candidate] = {}
    for group in groups:
        for candidate in group:
            identity = (candidate.kind, candidate.key)
            if identity not in fused:
                fused[identity] = Candidate(
                    candidate.kind,
                    candidate.key,
                    candidate.value,
                    list(candidate.evidence),
                    dict(candidate.metadata),
                )
            else:
                fused[identity].merge(candidate)
    return [fused[key] for key in sorted(fused)]


@dataclass
class DiscoveryCorpus:
    """Fused inventory accepting evidence from every discovery workstream source."""

    _groups: list[list[Candidate]] = field(default_factory=list)

    def add_candidates(self, candidates: Iterable[Candidate]) -> None:
        self._groups.append(list(candidates))

    def add_serialized(self, candidates: Iterable[Mapping[str, Any]]) -> None:
        """Import candidates emitted by another discovery-v1 producer."""
        group = []
        for value in candidates:
            evidence = [
                Evidence(
                    DiscoverySource(item["source"]),
                    float(item["confidence"]),
                    locator=item.get("locator"),
                    detail=item.get("detail"),
                )
                for item in value.get("evidence", [])
            ]
            if evidence:
                group.append(
                    Candidate(
                        str(value["kind"]),
                        str(value["key"]),
                        str(value["value"]),
                        evidence,
                        dict(value.get("metadata") or {}),
                    )
                )
        self._groups.append(group)

    def add_records(
        self,
        source: DiscoverySource,
        records: Iterable[Mapping[str, Any]],
        *,
        default_confidence: float = 0.5,
    ) -> None:
        group = []
        for record in records:
            kind = str(record["kind"])
            value = str(record["value"])
            key = str(record.get("key") or candidate_key(kind, value))
            confidence = float(record.get("confidence", default_confidence))
            group.append(
                Candidate(
                    kind,
                    key,
                    value,
                    [
                        Evidence(
                            source,
                            confidence,
                            locator=str(record["locator"]) if record.get("locator") else None,
                            detail=str(record["detail"]) if record.get("detail") else None,
                        )
                    ],
                    dict(record.get("metadata") or {}),
                )
            )
        self._groups.append(group)

    @property
    def candidates(self) -> list[Candidate]:
        return fuse_candidates(self._groups)

    def to_dict(self) -> dict[str, Any]:
        candidates = self.candidates
        return {
            "schema_version": 1,
            "schema_dialect": JSON_SCHEMA_DIALECT,
            "candidate_count": len(candidates),
            "sources": sorted(
                {evidence.source.value for item in candidates for evidence in item.evidence}
            ),
            "candidates": [item.to_dict() for item in candidates],
        }


def pipeline_discovery_corpus(
    records: Iterable[Mapping[str, Any]],
    meta: Mapping[str, Any],
    *,
    scan_report: Mapping[str, Any] | None = None,
    openapi: Mapping[str, Any] | None = None,
    schema: Mapping[str, Any] | None = None,
    operator_seeds: Iterable[str] = (),
) -> DiscoveryCorpus:
    """Fuse concrete capture, scan, spec, schema, recipe, error, and operator artifacts."""
    corpus = DiscoveryCorpus()
    traffic_records: list[dict[str, Any]] = []
    for record in records:
        url = str(record.get("url") or "")
        method = str(record.get("method") or "GET").upper()
        if url:
            traffic_records.append(
                {
                    "kind": "endpoint",
                    "value": url,
                    "locator": str(record.get("interaction_id") or "capture.jsonl"),
                    "confidence": 0.98,
                    "metadata": {
                        "method": method,
                        "status": record.get("status"),
                        "request_template": {"method": method, "url": url},
                        "semantic_kind": "query"
                        if method in {"GET", "HEAD", "OPTIONS"}
                        else "unknown",
                        "safety_proven": method in {"GET", "HEAD", "OPTIONS"},
                    },
                }
            )
        for operation in record.get("graphql", []) or []:
            name = operation.get("operationName")
            persisted = operation.get("persistedHash")
            kind = str(operation.get("semantic_kind") or "unknown")
            request_template = {
                "method": method,
                "url": url,
                "protocol": operation.get("protocol"),
            }
            if name:
                traffic_records.append(
                    {
                        "kind": "graphql-operation-name",
                        "value": str(name),
                        "confidence": 0.99,
                        "locator": str(record.get("interaction_id") or "capture.jsonl"),
                        "metadata": {
                            "semantic_kind": kind,
                            "request_template": request_template,
                            "safety_proven": kind == "query",
                            **({"persisted_identifier": persisted} if persisted else {}),
                        },
                    }
                )
            if persisted:
                traffic_records.append(
                    {
                        "kind": "persisted-identifier",
                        "value": str(persisted),
                        "confidence": 0.99,
                        "locator": str(record.get("interaction_id") or "capture.jsonl"),
                        "metadata": {
                            "semantic_kind": kind,
                            "request_template": request_template,
                            "safety_proven": kind == "query",
                            **({"operation_name": name} if name else {}),
                        },
                    }
                )
    corpus.add_records(DiscoverySource.TRAFFIC, traffic_records)

    corpus.add_records(
        DiscoverySource.SERVICE_WORKER,
        (
            {"kind": "service-worker", "value": str(url), "confidence": 0.95}
            for url in meta.get("service_workers", []) or []
        ),
    )
    corpus.add_records(
        DiscoverySource.ERROR,
        (
            {
                "kind": "observed-error",
                "value": str(item.get("category") or item.get("stage") or "unknown"),
                "locator": str(item.get("context") or "meta.json"),
                "confidence": 0.9,
            }
            for item in meta.get("failures", []) or []
            if isinstance(item, Mapping)
        ),
    )
    corpus.add_records(
        DiscoverySource.RECIPE,
        (
            {
                "kind": "recipe-action",
                "key": str(item.get("id")),
                "value": str(item.get("kind") or "interaction"),
                "locator": str(item.get("surface") or "meta.json"),
                "confidence": 0.9,
                "metadata": {
                    "calls": item.get("calls"),
                    "safe_annotation": item.get("safe_annotation"),
                    "completed": bool(item.get("completed_at")),
                },
            }
            for item in meta.get("interactions", []) or []
            if isinstance(item, Mapping)
        ),
    )
    if scan_report:
        serialized = scan_report.get("discovery_candidates") or (
            scan_report.get("discovery", {}) or {}
        ).get("candidates", [])
        corpus.add_serialized(serialized)
    if openapi:
        spec_records = []
        for path, path_item in (openapi.get("paths") or {}).items():
            if not isinstance(path_item, Mapping):
                continue
            for method, operation in path_item.items():
                upper = str(method).upper()
                if upper not in {
                    "GET",
                    "PUT",
                    "POST",
                    "DELETE",
                    "PATCH",
                    "HEAD",
                    "OPTIONS",
                    "TRACE",
                }:
                    continue
                operation = operation if isinstance(operation, Mapping) else {}
                semantic = "query" if upper in {"GET", "HEAD", "OPTIONS"} else "unknown"
                spec_records.append(
                    {
                        "kind": "spec-operation",
                        "value": f"{upper} {path}",
                        "locator": str(operation.get("operationId") or path),
                        "confidence": 0.99,
                        "metadata": {
                            "semantic_kind": semantic,
                            "request_template": {"method": upper, "path": path},
                            "safety_proven": semantic == "query",
                        },
                    }
                )
        corpus.add_records(DiscoverySource.OPENAPI, spec_records)
    if schema:
        root = schema.get("data", {}).get("__schema") or schema.get("__schema") or schema
        schema_records = []
        for type_value in root.get("types", []) if isinstance(root, Mapping) else []:
            if not isinstance(type_value, Mapping) or not type_value.get("name"):
                continue
            for field_value in type_value.get("fields", []) or []:
                if isinstance(field_value, Mapping) and field_value.get("name"):
                    schema_records.append(
                        {
                            "kind": "schema-field",
                            "value": f"{type_value['name']}.{field_value['name']}",
                            "confidence": 0.98,
                        }
                    )
        introspection = ((meta.get("events") or {}).get("introspection") or {}).get("enabled")
        corpus.add_records(
            DiscoverySource.INTROSPECTION if introspection else DiscoverySource.RECOVERY,
            schema_records,
        )
    corpus.add_records(
        DiscoverySource.OPERATOR,
        ({"kind": "navigation-route", "value": seed, "confidence": 1.0} for seed in operator_seeds),
    )
    return corpus


# Conservative extractors work on minified text and source-map sourcesContent. They collect
# strings and identifiers but never evaluate JavaScript.
ENDPOINT_RE = re.compile(
    r"[\"'`]((?:https?://[^\s\"'`]+|/(?:_?api|graphql|gql|rest|oauth)(?:[/?.][^\s\"'`]*)?))[\"'`]",
    re.IGNORECASE,
)
GRAPHQL_DOCUMENT_RE = re.compile(
    r"(?:graphql\s*\(\s*)?[\"'`]\s*((?:query|mutation|subscription|fragment)\s+"
    r"[A-Za-z_][A-Za-z0-9_]*[\s\S]{0,12000}?)[\"'`]",
)
OPERATION_RE = re.compile(
    r"(?:operationName|operation_name)[\"']?\s*[:=]\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']"
)
PERSISTED_RE = re.compile(
    r"(?:sha256Hash|queryId|doc_id|documentId|persistedQueryId)[\"']?\s*[:=]\s*"
    r"[\"']([A-Za-z0-9_-]{8,128})[\"']"
)
FLAG_RE = re.compile(
    r"(?:featureFlags?|featureSwitches?|experiments?|toggles?)[\"']?\s*[:=]\s*(?:\{|\[)?\s*"
    r"[\"']?([A-Za-z_][A-Za-z0-9_.-]{2,80})[\"']?\s*[:=]",
    re.IGNORECASE,
)
SERIALIZER_RE = re.compile(r"\b(?:serialize|serializer|toJSON|encodeVariables|buildRequest)\b")
ROUTE_RE = re.compile(
    r"(?:path|route)[\"']?\s*[:=]\s*[\"'](/[^\"']{1,200})[\"']",
    re.IGNORECASE,
)
RELAY_PARAMS_RE = re.compile(
    r"params\s*:\s*\{[^}]{0,500}?\bid\s*:\s*[\"']([A-Za-z0-9_-]{8,128})[\"']"
    r"[^}]{0,500}?\bname\s*:\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']"
    r"[^}]{0,500}?\boperationKind\s*:\s*[\"'](query|mutation|subscription)[\"']",
)
DYNAMIC_IMPORT_RE = re.compile(r"(?:import\s*\(\s*|[\"'])([^\"'`()\s]+\.js)(?:[\"']?\s*\)|[\"'])")
SOURCE_MAP_RE = re.compile(r"//#\s*sourceMappingURL\s*=\s*([^\s]+)")


def _candidate(
    kind: str,
    value: str,
    source: DiscoverySource,
    locator: str,
    confidence: float,
    **metadata: Any,
) -> Candidate:
    normalized = value.strip()
    key = candidate_key(kind, normalized)
    return Candidate(
        kind,
        key,
        normalized,
        [Evidence(source, confidence, locator=locator)],
        metadata,
    )


def mine_javascript(
    text: str,
    locator: str,
    *,
    source: DiscoverySource = DiscoverySource.BUNDLE,
) -> list[Candidate]:
    """Inventory useful client knowledge from JavaScript without executing it."""
    found: list[Candidate] = []
    for value in ENDPOINT_RE.findall(text):
        found.append(_candidate("endpoint", value, source, locator, 0.55))
    for value in OPERATION_RE.findall(text):
        found.append(_candidate("graphql-operation-name", value, source, locator, 0.6))
    for value in PERSISTED_RE.findall(text):
        found.append(_candidate("persisted-identifier", value, source, locator, 0.6))
    for persisted_id, operation_name, semantic_kind in RELAY_PARAMS_RE.findall(text):
        found.append(
            _candidate(
                "persisted-identifier",
                persisted_id,
                source,
                locator,
                0.68,
                operation_name=operation_name,
                semantic_kind=semantic_kind,
                protocol_hint="graphql-relay-persisted",
            )
        )
        found.append(
            _candidate(
                "graphql-operation-name",
                operation_name,
                source,
                locator,
                0.68,
                persisted_identifier=persisted_id,
                semantic_kind=semantic_kind,
                protocol_hint="graphql-relay-persisted",
            )
        )
    for value in GRAPHQL_DOCUMENT_RE.findall(text):
        semantic = value.lstrip().split(None, 1)[0].lower()
        found.append(
            _candidate("graphql-document", value, source, locator, 0.72, semantic_kind=semantic)
        )
    for value in FLAG_RE.findall(text):
        found.append(_candidate("feature-flag", value, source, locator, 0.4))
    for match in SERIALIZER_RE.finditer(text):
        found.append(_candidate("serializer", match.group(0), source, locator, 0.35))
    for value in ROUTE_RE.findall(text):
        found.append(_candidate("navigation-route", value, source, locator, 0.45))
    return fuse_candidates([found])


@dataclass(frozen=True)
class StaticResource:
    url: str
    body: str
    content_type: str = "application/javascript"


@dataclass
class StaticMiningResult:
    candidates: list[Candidate] = field(default_factory=list)
    discovered_urls: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    cache_hits: int = 0
    bytes_downloaded: int = 0
    truncations: list[str] = field(default_factory=list)


class StaticBundleMiner:
    """Bounded first-party crawler for chunks, manifests, and source maps."""

    def __init__(
        self,
        base_url: str,
        *,
        max_resources: int = 50,
        max_total_bytes: int = 20_000_000,
        max_resource_bytes: int = 4_000_000,
        max_origin_resources: int | None = None,
        allow_source_maps: bool = True,
        allowed_hosts: Iterable[str] = (),
        audit_decision: Callable[[str, bool, str], None] | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if min(max_resources, max_total_bytes, max_resource_bytes) < 1:
            raise ValueError("static mining limits must be positive")
        self.base_url = base_url
        self.base_host = parsed.hostname.lower()
        self.allowed_hosts = {self.base_host, *(host.lower() for host in allowed_hosts)}
        self.max_resources = max_resources
        self.max_total_bytes = max_total_bytes
        self.max_resource_bytes = max_resource_bytes
        self.max_origin_resources = max_origin_resources or max_resources
        self.allow_source_maps = allow_source_maps
        self.audit_decision = audit_decision

    def allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        return parsed.scheme in {"http", "https"} and host in self.allowed_hosts

    def mine(self, seeds: Sequence[str], fetcher: Any) -> StaticMiningResult:
        result = StaticMiningResult()
        queue = list(dict.fromkeys(urljoin(self.base_url, seed) for seed in seeds))
        routes_by_url: dict[str, set[str]] = {}
        fetched_urls: set[str] = set()
        origin_counts: dict[str, int] = {}
        body_cache: dict[str, list[Candidate]] = {}
        while queue and len(fetched_urls) < self.max_resources:
            url = queue.pop(0)
            if url in fetched_urls:
                continue
            if not self.allowed(url):
                if self.audit_decision:
                    self.audit_decision(url, False, "third-party-denied")
                result.truncations.append(f"third-party-denied:{url}")
                continue
            if self.audit_decision:
                self.audit_decision(url, True, "first-party-or-explicit-host")
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin_counts.get(origin, 0) >= self.max_origin_resources:
                result.truncations.append(f"origin-resource-count:{origin}")
                continue
            origin_counts[origin] = origin_counts.get(origin, 0) + 1
            fetched_urls.add(url)
            try:
                resource: StaticResource = fetcher(url)
            except Exception as exc:
                result.truncations.append(f"fetch-error:{url}:{type(exc).__name__}")
                continue
            raw = resource.body.encode("utf-8", "ignore")
            if len(raw) > self.max_resource_bytes:
                result.truncations.append(f"resource-bytes:{url}")
                continue
            if result.bytes_downloaded + len(raw) > self.max_total_bytes:
                result.truncations.append("total-bytes")
                break
            result.bytes_downloaded += len(raw)
            digest = hashlib.sha256(raw).hexdigest()
            source = (
                DiscoverySource.SOURCE_MAP
                if url.endswith(".map")
                else DiscoverySource.MANIFEST
                if "manifest" in url.lower() or "json" in resource.content_type.lower()
                else DiscoverySource.BUNDLE
            )
            if digest in body_cache:
                result.cache_hits += 1
                candidates = [
                    Candidate(c.kind, c.key, c.value, list(c.evidence), dict(c.metadata))
                    for c in body_cache[digest]
                ]
            else:
                texts = [resource.body]
                if source is DiscoverySource.SOURCE_MAP:
                    try:
                        source_map = json.loads(resource.body)
                        texts = [
                            item
                            for item in source_map.get("sourcesContent", [])
                            if isinstance(item, str)
                        ] or texts
                    except (ValueError, AttributeError):
                        result.truncations.append(f"invalid-source-map:{url}")
                candidates = fuse_candidates(
                    [mine_javascript(text, url, source=source) for text in texts]
                )
                body_cache[digest] = candidates
            routes = sorted(routes_by_url.get(url, set()))
            if routes:
                for candidate in candidates:
                    candidate.metadata["navigation_routes"] = routes
            result.candidates.extend(candidates)
            result.discovered_urls.append(url)

            for relative in DYNAMIC_IMPORT_RE.findall(resource.body):
                child = urljoin(url, relative)
                routes_by_url.setdefault(child, set()).update(routes)
                if child not in fetched_urls:
                    queue.append(child)
            for map_ref in SOURCE_MAP_RE.findall(resource.body):
                child = urljoin(url, map_ref.strip())
                if self.allow_source_maps and child not in fetched_urls:
                    routes_by_url.setdefault(child, set()).update(routes)
                    result.source_maps.append(child)
                    queue.append(child)
            if source is DiscoverySource.MANIFEST:
                try:
                    manifest = json.loads(resource.body)
                    for route, value in _manifest_assets(manifest):
                        if value.endswith((".js", ".mjs", ".map")):
                            child = urljoin(url, value)
                            if route:
                                routes_by_url.setdefault(child, set()).add(route)
                            queue.append(child)
                except ValueError:
                    pass
        if queue:
            result.truncations.append("resource-count")
        result.candidates = fuse_candidates([result.candidates])
        return result


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def _manifest_assets(value: Any, route: str | None = None) -> Iterable[tuple[str | None, str]]:
    """Yield manifest asset strings with their nearest route-like mapping key."""
    if isinstance(value, str):
        yield route, value
    elif isinstance(value, Mapping):
        for key, child in value.items():
            next_route = key if isinstance(key, str) and key.startswith("/") else route
            yield from _manifest_assets(child, next_route)
    elif isinstance(value, list):
        for child in value:
            yield from _manifest_assets(child, route)


@dataclass(frozen=True)
class InteractionCandidate:
    action_id: str
    surface: str
    action: str
    expected_candidates: frozenset[str]
    cost_requests: int = 1
    cost_seconds: float = 1.0
    risk: str = "low"
    evidence: str = ""


def derive_interactions(
    evidence_by_url: Mapping[str, Mapping[str, Any]],
) -> list[InteractionCandidate]:
    """Derive safe pagination/filter/scroll candidates from DOM evidence.

    This deliberately proposes interactions only; execution still passes through target policy
    and capture safety gates.
    """
    interactions: list[InteractionCandidate] = []
    for surface, evidence in sorted(evidence_by_url.items()):
        anchors = evidence.get("anchors", []) or []
        for index, anchor in enumerate(anchors):
            href = str(anchor.get("h") or "")
            text = str(anchor.get("t") or "").lower()
            if anchor.get("same") and (
                re.search(r"(?:[?&](?:page|cursor|offset)=|/page/\d+)", href)
                or text in {"next", "more", "older"}
            ):
                key = candidate_key("navigation-route", urljoin(surface, href))
                interactions.append(
                    InteractionCandidate(
                        f"paginate-{candidate_key('action', surface + href)}",
                        surface,
                        f"navigate:{href}",
                        frozenset({key}),
                        evidence=f"DOM pagination anchor {index}",
                    )
                )
        for index, form in enumerate(evidence.get("forms", []) or []):
            method = str(form.get("method") or "GET").upper()
            inputs = form.get("inputs", []) or []
            if method == "GET" and inputs:
                expected = {
                    candidate_key("filter-input", str(item.get("name")))
                    for item in inputs
                    if item.get("name")
                }
                if expected:
                    interactions.append(
                        InteractionCandidate(
                            f"filter-{candidate_key('action', surface + str(index))}",
                            surface,
                            "change-get-filter",
                            frozenset(expected),
                            evidence=f"GET form {index}",
                        )
                    )
        meta = evidence.get("meta", {}) or {}
        if meta.get("ssr_first_page") is True:
            interactions.append(
                InteractionCandidate(
                    f"scroll-{candidate_key('action', surface)}",
                    surface,
                    "scroll-for-client-pagination",
                    frozenset({candidate_key("pagination-boundary", surface)}),
                    cost_seconds=2.0,
                    evidence="SSR first-page marker with unexercised client boundary",
                )
            )
    return interactions


def plan_interactions(
    candidates: Iterable[InteractionCandidate],
    *,
    missing_candidate_keys: set[str],
    attempted: Mapping[str, int] | None = None,
    no_evidence_actions: set[str] | None = None,
    request_budget: int = 20,
) -> list[dict[str, Any]]:
    """Rank cheapest safe, novel interactions and fit them within a request budget."""
    attempted = attempted or {}
    no_evidence_actions = no_evidence_actions or set()
    ranked = []
    for item in candidates:
        if item.risk != "low" or item.action_id in no_evidence_actions:
            continue
        novelty = item.expected_candidates & missing_candidate_keys
        if not novelty:
            continue
        repeat_penalty = 1.0 + attempted.get(item.action_id, 0)
        cost = max(1, item.cost_requests) + max(0.0, item.cost_seconds) / 5.0
        score = len(novelty) / (cost * repeat_penalty)
        ranked.append((score, item, novelty))
    ranked.sort(key=lambda row: (-row[0], row[1].action_id))
    remaining = max(0, request_budget)
    planned: list[dict[str, Any]] = []
    cumulative = 0
    for score, item, novelty in ranked:
        if item.cost_requests > remaining:
            continue
        remaining -= item.cost_requests
        cumulative += len(novelty)
        planned.append(
            {
                "action_id": item.action_id,
                "surface": item.surface,
                "action": item.action,
                "expected_new_candidates": sorted(novelty),
                "score": round(score, 6),
                "request_cost": item.cost_requests,
                "marginal_curve": {
                    "requests": request_budget - remaining,
                    "expected_candidates": cumulative,
                },
                "evidence": item.evidence,
            }
        )
    return planned


def completeness_metrics(
    *,
    observed: AbstractSet[str],
    static_candidates: AbstractSet[str] = frozenset(),
    navigation_routes: AbstractSet[str] = frozenset(),
    spec_operations: AbstractSet[str] = frozenset(),
    schema_fields: AbstractSet[str] = frozenset(),
    recipe_actions: AbstractSet[str] = frozenset(),
    completed_actions: AbstractSet[str] = frozenset(),
    run_operation_sets: Sequence[set[str]] = (),
) -> dict[str, Any]:
    def ratio(numerator: int, denominator: int) -> dict[str, Any]:
        return {
            "covered": numerator,
            "total": denominator,
            "ratio": round(numerator / denominator, 6) if denominator else None,
        }

    convergence: dict[str, Any] = {"runs": len(run_operation_sets), "confidence": "unknown"}
    if len(run_operation_sets) >= 2:
        previous, current = run_operation_sets[-2:]
        union = previous | current
        similarity = len(previous & current) / len(union) if union else 1.0
        convergence.update(
            similarity=round(similarity, 6),
            new_in_latest=len(current - previous),
            confidence="high" if len(run_operation_sets) >= 3 and similarity >= 0.95 else "medium",
        )
    return {
        "claim": "calibrated-relative-coverage; not absolute backend completeness",
        "observed_coverage": {
            "observed": len(observed),
            "ratio": None,
            "denominator": "none; observed inventory is a count, not a completeness claim",
        },
        "static_candidate_coverage": ratio(
            len(observed & static_candidates), len(static_candidates)
        ),
        "navigation_coverage": ratio(len(observed & navigation_routes), len(navigation_routes)),
        "spec_coverage": ratio(len(observed & spec_operations), len(spec_operations)),
        "schema_field_coverage": ratio(len(observed & schema_fields), len(schema_fields)),
        "recipe_action_coverage": ratio(
            len(completed_actions & recipe_actions), len(recipe_actions)
        ),
        "convergence": convergence,
    }


RISK_RANK = {"anonymous": 0, "low": 1, "standard": 2, "sensitive": 3, "privileged": 4}


@dataclass(frozen=True)
class TargetPolicy:
    max_requests: int = 100
    max_origin_requests: int = 50
    concurrency: int = 1
    delay_ms: int = 250
    working_hours_utc: tuple[int, int] | None = None
    account_risk: str = "standard"
    authorized_paths: tuple[str, ...] = ("/",)
    prohibited_paths: tuple[str, ...] = ()
    prohibited_actions: tuple[str, ...] = ("submit", "purchase", "delete", "publish")
    allow_schema_recovery: bool = False

    def __post_init__(self) -> None:
        if min(self.max_requests, self.max_origin_requests, self.concurrency) < 1:
            raise ValueError("request ceilings and concurrency must be positive")
        if self.delay_ms < 0:
            raise ValueError("delay_ms cannot be negative")
        if self.account_risk not in RISK_RANK:
            raise ValueError("unknown account risk profile")
        if self.working_hours_utc:
            start, end = self.working_hours_utc
            if not (0 <= start <= 23 and 0 <= end <= 23 and start != end):
                raise ValueError("working hours must be distinct UTC hours in 0..23")

    def authorize(
        self,
        *,
        path: str,
        action: str,
        now: datetime | None = None,
        schema_recovery: bool = False,
        recovery_evidence: bool = False,
    ) -> tuple[bool, str]:
        if self.working_hours_utc:
            current = (now or datetime.now(UTC)).astimezone(UTC).time()
            start, end = self.working_hours_utc
            in_hours = (
                time(start) <= current < time(end)
                if start < end
                else current >= time(start) or current < time(end)
            )
            if not in_hours:
                return False, "outside-working-hours"
        if any(
            path == prefix or path.startswith(prefix.rstrip("/") + "/")
            for prefix in self.prohibited_paths
        ):
            return False, "prohibited-path"
        if not any(
            path == prefix or path.startswith(prefix.rstrip("/") + "/")
            for prefix in self.authorized_paths
        ):
            return False, "outside-authorization-scope"
        lowered = action.lower()
        if any(term.lower() in lowered for term in self.prohibited_actions):
            return False, "prohibited-action"
        if schema_recovery and not self.allow_schema_recovery:
            return False, "schema-recovery-not-enabled"
        if schema_recovery and not recovery_evidence:
            return False, "schema-recovery-not-evidence-gated"
        return True, "authorized"

    @property
    def effective_concurrency(self) -> int:
        cap = {"anonymous": 8, "low": 4, "standard": 2, "sensitive": 1, "privileged": 1}
        return min(self.concurrency, cap[self.account_risk])

    @property
    def effective_delay_ms(self) -> int:
        floor = {"anonymous": 0, "low": 100, "standard": 250, "sensitive": 750, "privileged": 1000}
        return max(self.delay_ms, floor[self.account_risk])


@dataclass
class ActionLedger:
    """Append-only, hash-chained audit records for active discovery decisions."""

    records: list[dict[str, Any]] = field(default_factory=list)

    def append(
        self,
        *,
        action_id: str,
        action: str,
        target: str,
        authorized: bool,
        reason: str,
        write_authorized: bool = False,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        previous = self.records[-1]["record_hash"] if self.records else None
        record = {
            "sequence": len(self.records) + 1,
            "timestamp": timestamp or datetime.now(UTC).isoformat(),
            "action_id": action_id,
            "action": action,
            "target": target,
            "authorized": authorized,
            "reason": reason,
            "write_authorized": write_authorized,
            "previous_hash": previous,
        }
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        record["record_hash"] = hashlib.sha256(encoded).hexdigest()
        self.records.append(record)
        return record

    def verify(self) -> bool:
        previous = None
        for expected_sequence, stored in enumerate(self.records, 1):
            record = dict(stored)
            digest = record.pop("record_hash", None)
            if (
                record.get("sequence") != expected_sequence
                or record.get("previous_hash") != previous
            ):
                return False
            encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(encoded).hexdigest() != digest:
                return False
            previous = digest
        return True
