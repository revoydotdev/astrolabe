"""GraphQL document parsing with an explicit, downgraded tolerant fallback."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from graphql import GraphQLError, parse
from graphql.language import ast

try:
    from .operation import SemanticKind
except ImportError:  # standalone deployment on the capture host (flat modules, no package)
    from operation import SemanticKind  # type: ignore[import-not-found,no-redef]

_FALLBACK_DECLARATION = re.compile(
    r"(?:^|[\s,{])(query|mutation|subscription)\s*([_A-Za-z][_0-9A-Za-z]*)?",
    re.I,
)
_FALLBACK_FIELD = re.compile(r"\{\s*(?:[_A-Za-z][_0-9A-Za-z]*\s*:\s*)?([_A-Za-z][_0-9A-Za-z]*)")


@dataclass(frozen=True, slots=True)
class ParsedGraphQLOperation:
    name: str | None
    semantic_kind: str
    variable_names: list[str]
    response_keys: list[str]
    root_fields: list[str]
    directives: list[str]
    selected: bool
    parse_confidence: str
    parse_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _directives(node: Any) -> list[str]:
    return [directive.name.value for directive in node.directives or ()]


def _root_selections(
    selection_set: ast.SelectionSetNode | None,
    fragments: dict[str, ast.FragmentDefinitionNode],
    *,
    visited: frozenset[str] = frozenset(),
) -> tuple[list[str], list[str], list[str]]:
    response_keys: list[str] = []
    fields: list[str] = []
    directives: list[str] = []
    if selection_set is None:
        return response_keys, fields, directives
    for selection in selection_set.selections:
        directives.extend(_directives(selection))
        if isinstance(selection, ast.FieldNode):
            fields.append(selection.name.value)
            response_keys.append(selection.alias.value if selection.alias else selection.name.value)
        elif isinstance(selection, ast.InlineFragmentNode):
            nested = _root_selections(selection.selection_set, fragments, visited=visited)
            response_keys.extend(nested[0])
            fields.extend(nested[1])
            directives.extend(nested[2])
        elif isinstance(selection, ast.FragmentSpreadNode):
            name = selection.name.value
            if name in visited or name not in fragments:
                continue
            fragment = fragments[name]
            directives.extend(_directives(fragment))
            nested = _root_selections(
                fragment.selection_set,
                fragments,
                visited=visited | {name},
            )
            response_keys.extend(nested[0])
            fields.extend(nested[1])
            directives.extend(nested[2])
    return (
        list(dict.fromkeys(response_keys)),
        list(dict.fromkeys(fields)),
        list(dict.fromkeys(directives)),
    )


def parse_graphql_document(
    document: str,
    operation_name: str | None = None,
) -> list[ParsedGraphQLOperation]:
    """Parse every operation and mark the operation selected by the transport envelope.

    A malformed capture remains useful for inventory through the tolerant fallback, but its
    confidence and error are explicit so it can never be mistaken for parser-backed evidence.
    """
    try:
        parsed = parse(document)
    except GraphQLError as exc:
        match = _FALLBACK_DECLARATION.search(document)
        if match:
            kind = match.group(1).lower()
            name = match.group(2)
        elif document.lstrip().startswith("{"):
            kind, name = SemanticKind.QUERY.value, None
        else:
            kind, name = SemanticKind.UNKNOWN.value, operation_name
        field = _FALLBACK_FIELD.search(document)
        return [
            ParsedGraphQLOperation(
                name=name,
                semantic_kind=kind,
                variable_names=[],
                response_keys=[field.group(1)] if field else [],
                root_fields=[field.group(1)] if field else [],
                directives=[],
                selected=operation_name is None or name == operation_name,
                parse_confidence="tolerant-fallback",
                parse_error=str(exc).splitlines()[0][:200],
            )
        ]

    fragments = {
        definition.name.value: definition
        for definition in parsed.definitions
        if isinstance(definition, ast.FragmentDefinitionNode)
    }
    operations = [
        definition
        for definition in parsed.definitions
        if isinstance(definition, ast.OperationDefinitionNode)
    ]
    out: list[ParsedGraphQLOperation] = []
    for operation in operations:
        name = operation.name.value if operation.name else None
        response_keys, fields, nested_directives = _root_selections(
            operation.selection_set, fragments
        )
        selected = name == operation_name if operation_name is not None else len(operations) == 1
        out.append(
            ParsedGraphQLOperation(
                name=name,
                semantic_kind=operation.operation.value,
                variable_names=[
                    definition.variable.name.value
                    for definition in operation.variable_definitions or ()
                ],
                response_keys=response_keys,
                root_fields=fields,
                directives=list(dict.fromkeys([*_directives(operation), *nested_directives])),
                selected=selected,
                parse_confidence="parsed",
            )
        )
    return out
