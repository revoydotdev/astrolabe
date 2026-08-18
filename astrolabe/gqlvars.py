#!/usr/bin/env python3
"""Parse a GraphQL operation's variable declarations out of its captured query text.

Every captured query opens with a typed, nullability-annotated signature:

    query JobSearch($page: Int!, $limit: Int = 10, $filter: JobFilter)

That is authoritative: it states which variables exist, their exact types, and
which are required -- including variables a particular capture never exercised.
Inferring input types from observed *values* alone (the historic approach) sees
only the variables that happened to fire, cannot distinguish required from
optional, and cannot recover a type for a variable that was always null.

This module reads the declaration instead. It is a scanner rather than a regex
because default values may contain nested braces, brackets, commas and string
literals -- `$f: F = {a: [1, 2], b: "x)y"}` must not be split on the wrong
comma or terminated at the wrong paren.

Scope: the variable-definition block only. Selection sets are not parsed; the
recovered GraphQL schema (schema.json) remains the source for return types.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# GraphQL built-in scalars -> JSON Schema primitive types. Anything else is a
# custom scalar or an input object: we know its name but not its structure, so we
# emit an unconstrained schema and let observed values supply the shape.
SCALARS = {
    "Int": "integer",
    "Float": "number",
    "String": "string",
    "Boolean": "boolean",
    "ID": "string",
}

_OPERATION = re.compile(r"\b(query|mutation|subscription)\b")
_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_OPEN = {"(": ")", "[": "]", "{": "}"}
_CLOSE = {")", "]", "}"}


@dataclass(frozen=True)
class GraphQLType:
    """A parsed GraphQL type reference: `[Foo!]!` etc."""

    name: str | None  # named type, or None for a list
    non_null: bool
    of_type: GraphQLType | None = None  # element type when this is a list

    @property
    def is_list(self) -> bool:
        return self.of_type is not None


@dataclass(frozen=True)
class VariableDef:
    name: str  # without the leading '$'
    type: GraphQLType
    has_default: bool
    raw_type: str

    @property
    def required(self) -> bool:
        """A variable is required only if it is non-null AND has no default.

        A non-null variable *with* a default may be omitted by the caller, so
        treating `!` alone as required would over-constrain the tool schema.
        """
        return self.type.non_null and not self.has_default


def _skip_ws_and_comments(src: str, i: int) -> int:
    """Advance past whitespace, commas (insignificant in GraphQL) and # comments."""
    while i < len(src):
        c = src[i]
        if c in " \t\r\n,﻿":
            i += 1
        elif c == "#":
            nl = src.find("\n", i)
            i = len(src) if nl == -1 else nl + 1
        else:
            break
    return i


def _skip_string(src: str, i: int) -> int:
    """Advance past a GraphQL string literal starting at src[i] == '"'."""
    if src.startswith('"""', i):
        end = src.find('"""', i + 3)
        return len(src) if end == -1 else end + 3
    i += 1
    while i < len(src):
        if src[i] == "\\":
            i += 2
            continue
        if src[i] == '"':
            return i + 1
        i += 1
    return i


def _matching(src: str, start: int) -> int:
    """Index just past the bracket that closes the one at src[start].

    Bracket-aware and string-aware, so a `)` inside a default-value string or a
    nested object does not terminate the block early.
    """
    stack = [_OPEN[src[start]]]
    i = start + 1
    while i < len(src) and stack:
        c = src[i]
        if c == '"':
            i = _skip_string(src, i)
            continue
        if c == "#":
            nl = src.find("\n", i)
            i = len(src) if nl == -1 else nl + 1
            continue
        if c in _OPEN:
            stack.append(_OPEN[c])
            i += 1
            continue
        if c in _CLOSE:
            if c == stack[-1]:
                stack.pop()
            i += 1
            continue
        i += 1
    return i


def _find_variable_block(query: str) -> str | None:
    """Return the source between the parens of the first operation's variable list.

    Returns None for an anonymous/shorthand operation, an operation with no
    variables, or unparseable input -- all of which are normal, not errors.
    """
    for match in _OPERATION.finditer(query):
        # The keyword must be at brace depth 0; inside a selection set a field
        # could legitimately be named "query".
        prefix = query[: match.start()]
        if _brace_depth(prefix) != 0:
            continue
        i = _skip_ws_and_comments(query, match.end())
        name_match = _NAME.match(query, i)
        if name_match:
            i = _skip_ws_and_comments(query, name_match.end())
        if i < len(query) and query[i] == "(":
            end = _matching(query, i)
            return query[i + 1 : end - 1]
        return None  # operation found, but it declares no variables
    return None


def _brace_depth(src: str) -> int:
    """Net `{}` depth of src, ignoring braces inside strings and comments."""
    depth = 0
    i = 0
    while i < len(src):
        c = src[i]
        if c == '"':
            i = _skip_string(src, i)
            continue
        if c == "#":
            nl = src.find("\n", i)
            i = len(src) if nl == -1 else nl + 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return depth


def _strip_comments(src: str) -> str:
    """Remove `#` comments, preserving string literals and line structure.

    Done once over the whole block before splitting: stripping them only at
    split boundaries leaves a trailing comment glued to the last definition's
    type source, where it silently fails to parse.
    """
    out: list[str] = []
    i = 0
    while i < len(src):
        c = src[i]
        if c == '"':
            end = _skip_string(src, i)
            out.append(src[i:end])
            i = end
            continue
        if c == "#":
            nl = src.find("\n", i)
            if nl == -1:
                break
            out.append("\n")
            i = nl + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _split_definitions(block: str) -> list[str]:
    """Split a variable block on the commas that separate definitions.

    Only top-level commas count; `$f: F = {a: 1, b: 2}` is one definition.
    """
    parts: list[str] = []
    start = 0
    i = 0
    while i < len(block):
        c = block[i]
        if c == '"':
            i = _skip_string(block, i)
            continue
        if c == "#":
            nl = block.find("\n", i)
            i = len(block) if nl == -1 else nl + 1
            continue
        if c in _OPEN:
            i = _matching(block, i)
            continue
        if c == "$" and i > start:
            # GraphQL treats commas as whitespace, so `$a: Int $b: Int` is legal.
            # A '$' at depth 0 therefore also starts a new definition.
            chunk = block[start:i].strip()
            if chunk:
                parts.append(chunk)
            start = i
            i += 1
            continue
        i += 1
    tail = block[start:].strip()
    if tail:
        parts.append(tail)
    return [p.strip().rstrip(",").strip() for p in parts if p.strip().strip(",")]


def _parse_type(src: str) -> GraphQLType | None:
    src = src.strip()
    if not src:
        return None
    non_null = src.endswith("!")
    if non_null:
        src = src[:-1].strip()
    if src.startswith("[") and src.endswith("]"):
        inner = _parse_type(src[1:-1])
        if inner is None:
            return None
        return GraphQLType(name=None, non_null=non_null, of_type=inner)
    if not _NAME.fullmatch(src):
        return None
    return GraphQLType(name=src, non_null=non_null)


def parse_variable_definitions(query: str) -> dict[str, VariableDef]:
    """Map variable name -> VariableDef for the first operation in `query`.

    Returns {} for persisted operations (no text), anonymous shorthand queries,
    operations without variables, and anything that fails to parse. Never raises:
    a malformed capture must degrade to value-inference, not break generation.
    """
    if not query or "$" not in query:
        return {}
    try:
        block = _find_variable_block(query)
    except Exception:
        return {}
    if not block:
        return {}
    block = _strip_comments(block)
    out: dict[str, VariableDef] = {}
    for raw in _split_definitions(block):
        if not raw.startswith("$"):
            continue
        colon = _top_level_index(raw, ":")
        if colon == -1:
            continue
        name = raw[1:colon].strip()
        if not _NAME.fullmatch(name):
            continue
        rest = raw[colon + 1 :]
        eq = _top_level_index(rest, "=")
        type_src = (rest if eq == -1 else rest[:eq]).strip()
        parsed = _parse_type(type_src)
        if parsed is None:
            continue
        out[name] = VariableDef(
            name=name, type=parsed, has_default=eq != -1, raw_type=type_src
        )
    return out


def _top_level_index(src: str, target: str) -> int:
    """Index of `target` at bracket depth 0, ignoring strings and comments."""
    i = 0
    while i < len(src):
        c = src[i]
        if c == '"':
            i = _skip_string(src, i)
            continue
        if c == "#":
            nl = src.find("\n", i)
            i = len(src) if nl == -1 else nl + 1
            continue
        if c in _OPEN:
            i = _matching(src, i)
            continue
        if c == target:
            return i
        i += 1
    return -1


def type_to_schema(gql: GraphQLType) -> dict[str, Any]:
    """JSON Schema for a GraphQL type reference.

    Nullability is expressed as a union with "null" so an agent can tell an
    optional-and-nullable field from a guaranteed one. Custom scalars and input
    objects yield an unconstrained schema carrying the GraphQL type name --
    observed values fill in the structure (see merge_declared_with_observed).
    """
    if gql.is_list:
        assert gql.of_type is not None
        schema: dict[str, Any] = {"type": "array", "items": type_to_schema(gql.of_type)}
    elif gql.name in SCALARS:
        schema = {"type": SCALARS[gql.name]}
    else:
        schema = {"description": f"GraphQL type {gql.name}"}
    if not gql.non_null and "type" in schema:
        primitive = schema["type"]
        schema["type"] = [primitive, "null"] if isinstance(primitive, str) else primitive
    return schema


def merge_declared_with_observed(
    declared: dict[str, VariableDef], observed_schema: dict[str, Any] | None
) -> dict[str, Any]:
    """Build an input JSON Schema from the declaration, enriched by observations.

    The two sources are complementary rather than competing:
      * the declaration knows every variable, its exact type, and requiredness --
        including variables this capture never exercised;
      * observed values know the *structure* of custom input objects, whose
        fields the declaration only names (`$filter: JobFilter`).

    So the declaration decides the property set, the types, and the required
    list; observed structure is grafted in wherever the declared type is not a
    built-in scalar and therefore carries no structure of its own.

    `observed_schema` is the merged schema over *every* observation of the
    variables object (see astrolabe.shapemerge), not a single sample.
    """
    observed_props: dict[str, Any] = {}
    if isinstance(observed_schema, dict):
        props = observed_schema.get("properties")
        if isinstance(props, dict):
            observed_props = props

    properties: dict[str, Any] = {}
    required: list[str] = []
    for name, var in declared.items():
        schema = type_to_schema(var.type)
        obs = observed_props.get(name)
        if isinstance(obs, dict) and obs:
            schema = _graft(schema, obs, var.type)
        properties[name] = schema
        if var.required:
            required.append(name)
    # A variable seen in traffic but absent from the declaration means the
    # captured text belongs to a different revision of the operation; keep it
    # rather than dropping a parameter we have direct evidence for.
    for name, obs in observed_props.items():
        if name not in properties:
            properties[name] = obs
    result: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        result["required"] = sorted(required)
    return result


def _graft(declared: dict[str, Any], observed: dict[str, Any], gql: GraphQLType) -> dict[str, Any]:
    """Fill an unconstrained declared type with structure from observed values.

    The declaration is authoritative on type, so a built-in scalar is never
    widened by a coincidental observation; only structure (properties, required,
    items) is taken from what was seen.
    """
    if gql.is_list:
        assert gql.of_type is not None
        obs_items = observed.get("items")
        if isinstance(obs_items, dict) and obs_items:
            items = _graft(declared.get("items", {}), obs_items, gql.of_type)
            return {**declared, "items": items}
        return declared
    if gql.name in SCALARS:
        return declared
    merged = dict(declared)
    for key in ("type", "properties", "required", "items"):
        if key in observed:
            merged[key] = observed[key]
    return merged
