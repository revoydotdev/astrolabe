"""Bounded, non-executing compiler metadata recovery for precomputed query IDs.

Covers Meta `doc_id` (Relay `Request` params) and X `queryId` (persisted-registry
module exports). Both are server lookup keys the client never hashes, so the
operation kind comes from the application's own compiler output. Only literal
fields count. Names alone, regex matches, computed properties, spreads and
malformed syntax never authorize execution. Source bodies stay in memory;
evidence contains only metadata and digests.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

try:
    from .security import safe_url
except ImportError:
    from security import safe_url  # type: ignore[import-not-found,no-redef]

MAX_SCRIPT_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SCRIPTS = 512
MAX_ARTIFACTS = 4096

# A script without one of these substrings cannot contain a Relay `Request`,
# a Meta RelayOperation module, or an X `queryId` record, so it can never yield
# an artifact. Large marker-less bundles (framework/vendor code) must not consume
# the recovery byte/script budget on their way to producing nothing.
RECOVERY_MARKERS = (b"operationKind", b"RelayOperation", b"queryId")


class RelayBudgetError(ValueError):
    pass


def _literal(node: Any) -> str | None:
    if node is None or node.type not in {"string", "property_identifier"}:
        return None
    text = node.text.decode("utf-8")
    if node.type == "property_identifier":
        return text
    # Compiler IDs/names/kinds need no escapes. Reject rather than interpret JS.
    if len(text) < 2 or text[0] not in "\"'" or text[-1] != text[0] or "\\" in text:
        return None
    return text[1:-1]


def _properties(node: Any) -> dict[str, Any] | None:
    if node is None or node.type != "object" or node.has_error:
        return None
    result = {}
    for child in node.named_children:
        if child.type == "comment":
            continue
        if child.type != "pair":
            return None
        key = _literal(child.child_by_field_name("key"))
        if key is None or key in result:
            return None
        result[key] = child.child_by_field_name("value")
    return result


def _module(node: Any) -> tuple[Any, Any, Any] | None:
    """Recognize a top-level Metro/Meta registration, not an arbitrary call."""
    if (
        node.type != "call_expression"
        or node.child_by_field_name("function").text != b"__d"
        or node.parent.type != "expression_statement"
        or node.parent.parent.type != "program"
    ):
        return None
    args = node.child_by_field_name("arguments").named_children
    if len(args) < 3 or args[1].type != "array":
        return None
    factory = args[2]
    while factory.type == "parenthesized_expression" and len(factory.named_children) == 1:
        factory = factory.named_children[0]
    if factory.type != "function_expression":
        return None
    return args[0], args[1], factory


def _export(node: Any) -> tuple[str, str | None] | None:
    module = _module(node)
    if not module:
        return None
    name = _literal(module[0])
    if not name or not re.fullmatch(
        r"[_A-Za-z][_0-9A-Za-z]{0,255}_(?:instagram|facebook)RelayOperation", name
    ):
        return None
    # Any recognized but nonliteral/ambiguous definition poisons this module name.
    factory = module[2]
    parameters = factory.child_by_field_name("parameters").named_children
    body = [n for n in factory.child_by_field_name("body").named_children if n.type != "comment"]
    if len(parameters) < 5 or len(body) != 1 or body[0].type != "expression_statement":
        return name, None
    assignment = body[0].named_children[0]
    if assignment.type != "assignment_expression":
        return name, None
    left = assignment.child_by_field_name("left")
    right = assignment.child_by_field_name("right")
    if (
        left.type != "member_expression"
        or left.child_by_field_name("object").text != parameters[4].text
        or left.child_by_field_name("property").text != b"exports"
    ):
        return name, None
    value = _literal(right)
    return name, value if re.fullmatch(r"[0-9]{8,128}", value or "") else None


def _reference(node: Any) -> str | None:
    if node is None or node.type != "call_expression":
        return None
    callee = node.child_by_field_name("function")
    args = node.child_by_field_name("arguments").named_children
    if callee.type != "identifier" or len(args) != 1:
        return None
    name = _literal(args[0])
    if not name or not re.fullmatch(
        r"[_A-Za-z][_0-9A-Za-z]{0,255}_(?:instagram|facebook)RelayOperation", name
    ):
        return None
    current = node.parent
    scopes = []
    while current is not None:
        if current.type in {"function_expression", "arrow_function", "function_declaration"}:
            scopes.append(current)
        module = _module(current)
        if module:
            factory = module[2]
            params = factory.child_by_field_name("parameters").named_children
            if len(params) < 3 or callee.text not in {params[1].text, params[2].text}:
                return None
            if name not in {_literal(n) for n in module[1].named_children}:
                return None
            for scope in scopes:
                parameters = scope.child_by_field_name("parameters")
                if (
                    scope != factory
                    and parameters
                    and any(p.text == callee.text for p in parameters.named_children)
                ):
                    return None
                # Reject locally rebound loaders, without resolving or running them.
                pending = list(scope.child_by_field_name("body").named_children)
                while pending:
                    child = pending.pop()
                    if child.type in {
                        "function_expression",
                        "arrow_function",
                        "function_declaration",
                    }:
                        if (
                            child.child_by_field_name("name")
                            and child.child_by_field_name("name").text == callee.text
                        ):
                            return None
                        continue
                    if child.type in {
                        "variable_declarator",
                        "assignment_expression",
                        "augmented_assignment_expression",
                    }:
                        binding = child.child_by_field_name("name") or child.child_by_field_name(
                            "left"
                        )
                        if binding and (
                            binding.text == callee.text
                            or binding.type in {"object_pattern", "array_pattern"}
                        ):
                            return None
                    pending.extend(child.named_children)
            return name
        current = current.parent
    return None


def _x_registry(node: Any) -> dict[str, str] | None:
    """Recognize a webpack module whose only statement exports a literal X query record.

    X is the same precomputed-ID case as Meta `doc_id`: the client never hashes the
    document, so the ID must be resolved from compiler output rather than observed.
    It ships one module per persisted operation:
    `123456(e){e.exports={queryId:"...",operationName:"...",operationType:"query",...}}`
    Extra statements, a rebound exports target, computed keys or any non-literal
    field disqualify the module instead of being interpreted.
    """
    if node.type != "method_definition":
        return None
    parameters = node.child_by_field_name("parameters")
    body = node.child_by_field_name("body")
    if parameters is None or body is None:
        return None
    params = parameters.named_children
    statements = [n for n in body.named_children if n.type != "comment"]
    if len(params) != 1 or params[0].type != "identifier" or len(statements) != 1:
        return None
    if statements[0].type != "expression_statement":
        return None
    assignment = statements[0].named_children[0]
    if assignment.type != "assignment_expression":
        return None
    left = assignment.child_by_field_name("left")
    if (
        left.type != "member_expression"
        or left.child_by_field_name("object").text != params[0].text
        or left.child_by_field_name("property").text != b"exports"
    ):
        return None
    fields = _properties(assignment.child_by_field_name("right"))
    if not fields:
        return None
    values = {k: _literal(fields.get(k)) for k in ("queryId", "operationName", "operationType")}
    if (
        not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", values["queryId"] or "")
        or not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,255}", values["operationName"] or "")
        or values["operationType"] not in {"query", "mutation", "subscription"}
    ):
        return None
    return {
        "id": str(values["queryId"]),
        "name": str(values["operationName"]),
        "operation_kind": str(values["operationType"]),
    }


def extract_artifacts(body: bytes, source_url: str) -> list[dict[str, Any]]:
    """Parse loaded JavaScript; resolve only literal registered ID exports, never execute."""
    if len(body) > MAX_SCRIPT_BYTES or not any(m in body for m in RECOVERY_MARKERS):
        return []
    from tree_sitter import Language, Parser
    import tree_sitter_javascript

    tree = Parser(Language(tree_sitter_javascript.language())).parse(body)
    if tree.root_node.has_error:
        return []
    digest = hashlib.sha256(body).hexdigest()
    result: list[dict[str, Any]] = []
    stack = [tree.root_node]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > 2_000_000:
            raise RelayBudgetError("Relay AST node budget exhausted")
        stack.extend(node.named_children)
        exported = _export(node)
        if exported:
            result.append(
                {
                    "export_module": exported[0],
                    "id": exported[1],
                    "source_url": safe_url(source_url),
                    "source_sha256": digest,
                }
            )
            if len(result) > MAX_ARTIFACTS:
                raise RelayBudgetError("Relay artifact budget exhausted")
        registry = _x_registry(node)
        if registry:
            result.append(
                {
                    **registry,
                    "source": "x-persisted-registry",
                    "source_url": safe_url(source_url),
                    "source_sha256": digest,
                }
            )
            if len(result) > MAX_ARTIFACTS:
                raise RelayBudgetError("Relay artifact budget exhausted")
        if node.type != "object":
            continue
        fields = _properties(node)
        if not fields or _literal(fields.get("kind")) not in {
            "Request",
            "PreloadableConcreteRequest",
        }:
            continue
        params = _properties(fields.get("params"))
        if not params:
            continue
        values = {k: _literal(params.get(k)) for k in ("id", "name", "operationKind")}
        reference = _reference(params.get("id")) if values["id"] is None else None
        if (
            (not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", values["id"] or "") and not reference)
            or not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,255}", values["name"] or "")
            or values["operationKind"] not in {"query", "mutation", "subscription"}
        ):
            continue
        # Retain a minimal, independently inspectable metadata record, not vendor code.
        result.append(
            {
                "id": values["id"],
                "id_module": reference,
                "name": values["name"],
                "operation_kind": values["operationKind"],
                "source": "relay-compiler-ast",
                "source_url": safe_url(source_url),
                "source_sha256": digest,
            }
        )
        if len(result) > MAX_ARTIFACTS:
            raise RelayBudgetError("Relay artifact budget exhausted")
    return result


class RelayCatalog:
    def __init__(self) -> None:
        self.entries: dict[str, list[dict[str, Any]]] = {}
        self.exports: dict[str, list[dict[str, Any]]] = {}
        self.references: list[dict[str, Any]] = []
        self.bytes = 0
        self.scripts = 0
        self.count = 0
        self.exhausted = False

    def add(self, body: bytes, source_url: str) -> None:
        # Marker-less scripts yield nothing; skipping them here keeps the byte and
        # script budgets for candidate bundles rather than framework/vendor code.
        if not any(marker in body for marker in RECOVERY_MARKERS):
            return
        self.scripts += 1
        self.bytes += len(body)
        if (
            len(body) > MAX_SCRIPT_BYTES
            or self.bytes > MAX_TOTAL_BYTES
            or self.scripts > MAX_SCRIPTS
        ):
            self.exhausted = True
            return
        try:
            artifacts = extract_artifacts(body, source_url)
        except RelayBudgetError:
            self.exhausted = True
            return
        for artifact in artifacts:
            self.count += 1
            if self.count > MAX_ARTIFACTS:
                self.exhausted = True
                return
            if artifact.get("export_module"):
                self.exports.setdefault(artifact["export_module"], []).append(artifact)
            elif artifact.get("id_module"):
                self.references.append(artifact)
            else:
                self.entries.setdefault(artifact["id"], []).append(artifact)

    def bind(self, entry: dict[str, Any], success: bool) -> dict[str, Any]:
        if self.exhausted or entry.get("protocol") not in {
            "graphql-meta-doc-id",
            "graphql-x-persisted",
        }:
            return entry
        identifier = str(entry.get("persistedHash"))
        candidates = list(self.entries.get(identifier, []))
        for reference in self.references:
            exports = self.exports.get(reference["id_module"], [])
            if {e["id"] for e in exports} == {identifier}:
                candidates.append(
                    {
                        **reference,
                        "id": identifier,
                        "id_source_sha256": exports[0]["source_sha256"],
                        "id_source_url": exports[0]["source_url"],
                    }
                )
        signatures = {(a["name"], a["operation_kind"]) for a in candidates}
        if len(signatures) != 1 or not candidates:
            return entry
        artifact = candidates[0]
        if artifact["name"] != entry.get("operationName"):
            return entry
        evidence = {
            **artifact,
            "binding": "exact-id-and-name",
            "observed_response_success": success is True,
        }
        return {
            **entry,
            "semantic_kind": artifact["operation_kind"],
            "parse_confidence": "compiler-metadata",
            "selected": True,
            "request_template": {
                **(entry.get("request_template") or {}),
                "relay_evidence": evidence,
            },
        }

    def enrich_capture(self, path: str) -> None:
        # Capture is bounded by its request budget. Rewrite one record at a time,
        # after all scripts have arrived so late conflicts cannot leave early trust.
        import os
        import tempfile

        fd, temporary = tempfile.mkstemp(prefix=".relay-", dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, "w") as output, open(path) as source:
                for line in source:
                    record = json.loads(line)
                    if record.get("graphql"):
                        record["graphql"] = [
                            self.bind(entry, record.get("graphql_response_success") is True)
                            for entry in record["graphql"]
                        ]
                    output.write(json.dumps(record) + "\n")
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def valid_evidence(tool: dict[str, Any]) -> bool:
    evidence = (tool.get("request_template") or {}).get("relay_evidence")
    if not isinstance(evidence, dict):
        return False
    # Each protocol trusts a set of compiler-output shapes. X's web client is itself
    # Relay-based, so an X persisted id resolves either from a webpack queryId module
    # or from a genuine Relay `Request` object in the same bundles; both are compiler
    # metadata with identical trust. Meta ships only the Relay form. The binding is
    # still gated by exact id-and-name agreement below, so the source set guards
    # provenance, not the match itself.
    trusted_sources = {
        "graphql-meta-doc-id": {"relay-compiler-ast"},
        "graphql-x-persisted": {"relay-compiler-ast", "x-persisted-registry"},
    }.get(str(tool.get("protocol")))
    return (
        trusted_sources is not None
        and evidence.get("source") in trusted_sources
        and evidence.get("binding") == "exact-id-and-name"
        and evidence.get("id") == tool.get("apq_hash")
        and evidence.get("name") == tool.get("operation")
        and evidence.get("operation_kind") == tool.get("type")
        and evidence.get("observed_response_success") is True
        and bool(re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("source_sha256") or "")))
    )
