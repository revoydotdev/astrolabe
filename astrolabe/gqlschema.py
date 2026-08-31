#!/usr/bin/env python3
"""Resolve custom GraphQL types against a recovered schema.

`astrolabe map --schema` runs clairvoyance (or reads a live introspection result)
and writes `schema.json` into the capture dir. Until now that file was rendered
as a type count in `map.md` and then dropped: it never reached the contract or
the toolpack, even though it is the single most authoritative description of the
target's types that astrolabe ever obtains.

The gap it fills is specific. `astrolabe.gqlvars` parses an operation's own
variable declarations, which give exact types and requiredness -- but for a
custom input object it can only learn the *name*:

    $filter: JobFilter   ->   {"description": "GraphQL type JobFilter"}

Observed values can fill in whichever fields a capture happened to exercise. The
recovered schema knows every field, its type, and whether it is required, even
for fields no capture ever sent. This module turns those name-only placeholders
into real structure.

Return types are deliberately out of scope: resolving them needs selection-set
analysis against the operation text, which is a materially bigger job than
resolving a named input type.
"""

from __future__ import annotations

import json
import os
from typing import Any

# The placeholder gqlvars emits for a type it can name but not describe.
PLACEHOLDER_PREFIX = "GraphQL type "

SCALARS = {
    "Int": "integer",
    "Float": "number",
    "String": "string",
    "Boolean": "boolean",
    "ID": "string",
}

# Input objects are routinely self-referential (a filter type with `and`/`or`
# arms referencing itself). Expansion is depth-bounded rather than cycle-tracked
# so a diamond shape still expands on both arms.
MAX_DEPTH = 6


class SchemaIndex:
    """Name -> type definition, from an introspection or clairvoyance schema."""

    def __init__(self, types: dict[str, dict[str, Any]]) -> None:
        self._types = types

    def __bool__(self) -> bool:
        return bool(self._types)

    def __len__(self) -> int:
        return len(self._types)

    @classmethod
    def from_obj(cls, raw: Any) -> SchemaIndex:
        """Accept the several shapes these files come in.

        clairvoyance and a raw introspection response differ in nesting, and some
        tools strip the envelope entirely.
        """
        node = raw
        if isinstance(node, dict) and "data" in node and isinstance(node["data"], dict):
            node = node["data"]
        if isinstance(node, dict) and "__schema" in node:
            node = node["__schema"]
        types = node.get("types") if isinstance(node, dict) else None
        if not isinstance(types, list):
            return cls({})
        index = {
            t["name"]: t for t in types if isinstance(t, dict) and isinstance(t.get("name"), str)
        }
        return cls(index)

    @classmethod
    def load(cls, capture_dir: str) -> SchemaIndex:
        """Load `<capture_dir>/schema.json`; absent or unreadable yields an empty index."""
        path = os.path.join(capture_dir, "schema.json")
        if not os.path.exists(path):
            return cls({})
        try:
            with open(path, encoding="utf-8") as fh:
                return cls.from_obj(json.load(fh))
        except (OSError, json.JSONDecodeError):
            return cls({})

    def resolve(self, name: str, depth: int = 0) -> dict[str, Any]:
        """JSON Schema for a named type, expanding input objects and enums."""
        if depth > MAX_DEPTH:
            return {}
        definition = self._types.get(name)
        if not isinstance(definition, dict):
            return {}
        kind = definition.get("kind")
        if kind == "ENUM":
            values = [
                v["name"]
                for v in definition.get("enumValues") or []
                if isinstance(v, dict) and isinstance(v.get("name"), str)
            ]
            return {"type": "string", "enum": values} if values else {"type": "string"}
        if kind == "SCALAR":
            mapped = SCALARS.get(name)
            return {"type": mapped} if mapped else {}
        if kind == "INPUT_OBJECT":
            return self._input_object(definition, depth)
        return {}

    def _input_object(self, definition: dict[str, Any], depth: int) -> dict[str, Any]:
        properties: dict[str, Any] = {}
        required: list[str] = []
        for field in definition.get("inputFields") or []:
            if not isinstance(field, dict) or not isinstance(field.get("name"), str):
                continue
            field_name = field["name"]
            properties[field_name] = self._type_ref(field.get("type"), depth + 1)
            # Same rule as a variable declaration: non-null with a default is
            # still optional for the caller.
            if _is_non_null(field.get("type")) and field.get("defaultValue") is None:
                required.append(field_name)
        schema: dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            schema["required"] = sorted(required)
        return schema

    def _type_ref(self, ref: Any, depth: int, non_null: bool = False) -> dict[str, Any]:
        """Convert an introspection type reference (NON_NULL/LIST/named) to schema.

        Non-nullness is carried down the recursion rather than read off the node
        being converted: by the time a NON_NULL wrapper has been unwrapped, the
        inner node no longer knows it was wrapped.
        """
        if not isinstance(ref, dict) or depth > MAX_DEPTH:
            return {}
        kind = ref.get("kind")
        if kind == "NON_NULL":
            return self._type_ref(ref.get("ofType"), depth, non_null=True)
        if kind == "LIST":
            schema: dict[str, Any] = {
                "type": "array",
                "items": self._type_ref(ref.get("ofType"), depth + 1),
            }
            return schema if non_null else {**schema, "type": ["array", "null"]}
        name = ref.get("name")
        if not isinstance(name, str):
            return {}
        base: dict[str, Any] = (
            {"type": SCALARS[name]} if name in SCALARS else self.resolve(name, depth + 1)
        )
        if not base:
            return {}
        primitive = base.get("type")
        if not non_null and isinstance(primitive, str):
            base = {**base, "type": [primitive, "null"]}
        return base

    def enrich(self, schema: Any, depth: int = 0) -> Any:
        """Walk a JSON Schema, replacing name-only placeholders with real structure.

        Anything already carrying structure is left alone -- observed values and
        the declaration have already been merged by this point, and the schema is
        additive evidence, not a replacement for what was actually seen.
        """
        if not isinstance(schema, dict) or depth > MAX_DEPTH * 2:
            return schema
        name = _named_type(schema)
        if name:
            resolved = self.resolve(name)
            if resolved:
                return _graft(schema, resolved)
            return schema
        out = dict(schema)
        props = out.get("properties")
        if isinstance(props, dict):
            out["properties"] = {k: self.enrich(v, depth + 1) for k, v in props.items()}
        if isinstance(out.get("items"), dict):
            out["items"] = self.enrich(out["items"], depth + 1)
        return out


def _named_type(schema: dict[str, Any]) -> str | None:
    """The GraphQL type name this node was tagged with by gqlvars, if any.

    Nodes that already carry observed structure still qualify: partial structure
    from whichever fields a capture happened to send is exactly what the schema
    is here to complete.
    """
    description = schema.get("description")
    if not isinstance(description, str) or not description.startswith(PLACEHOLDER_PREFIX):
        return None
    return description[len(PLACEHOLDER_PREFIX) :].strip() or None


def _graft(observed: dict[str, Any], resolved: dict[str, Any]) -> dict[str, Any]:
    """Combine a schema-resolved type with structure already observed in traffic.

    Union of properties, because each side knows things the other does not: the
    schema knows every field including ones never sent, and observations prove
    what a live client actually sends. `required` comes from the schema alone --
    it is the authority on what the endpoint will reject, and observations carry
    no requiredness for inputs, so intersecting would silently erase it.
    """
    merged: dict[str, Any] = {**observed}
    for key in ("type", "enum"):
        if key in resolved:
            merged[key] = resolved[key]
    obs_props = observed.get("properties")
    res_props = resolved.get("properties")
    if isinstance(obs_props, dict) or isinstance(res_props, dict):
        obs_props = obs_props if isinstance(obs_props, dict) else {}
        res_props = res_props if isinstance(res_props, dict) else {}
        merged["properties"] = {**obs_props, **res_props}
    if "required" in resolved:
        merged["required"] = resolved["required"]
    elif "required" in merged:
        del merged["required"]
    if "items" in resolved:
        merged["items"] = resolved["items"]
    return merged


def _is_non_null(ref: Any) -> bool:
    return isinstance(ref, dict) and ref.get("kind") == "NON_NULL"
