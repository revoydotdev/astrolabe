#!/usr/bin/env python3
"""Union-merge many observed response/variable shapes into one JSON Schema.

`capture.shape()` records one sample per response as a tree of type-name strings
(`{"id": "str", "next": "NoneType"}`). Historically the downstream tools picked a
single *representative* sample -- whichever serialised to the longest JSON string
-- and converted that. That heuristic is wrong in ways that matter:

  * it prefers whichever response happened to carry the most array elements,
    which is unrelated to schema completeness;
  * a field that was null in the chosen sample becomes untyped, even though
    other samples typed it;
  * a field seen as int in one response and float in another flips type;
  * arrays only ever sampled element 0, so mixed arrays were mistyped;
  * nothing distinguished always-present fields from sometimes-present ones,
    so every property was emitted as optional.

Merging every observation instead removes the heuristic entirely and recovers
nullability and requiredness, which is what an agent actually needs in order to
know whether it must handle a missing field.

Requiredness is evidence-based and deliberately conservative: a field counts as
required only if it appeared in *every* observation of its parent object and we
have at least `min_required_samples` observations. One sample is not evidence
that a field is guaranteed, so with a single observation no `required` is
emitted at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# capture.shape() emits Python type names; map them to JSON Schema primitives.
TYPE_NAMES = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "NoneType": "null",
}

# Ordering for stable, readable output.
_TYPE_ORDER = ["object", "array", "string", "integer", "number", "boolean", "null"]

DEFAULT_MIN_REQUIRED_SAMPLES = 2


@dataclass
class ShapeNode:
    """Accumulator for every observation seen at one position in the tree."""

    total: int = 0  # times this position was observed at all
    object_count: int = 0  # times it was observed as an object
    types: set[str] = field(default_factory=set)
    props: dict[str, ShapeNode] = field(default_factory=dict)
    items: ShapeNode | None = None

    def observe(self, shape: Any) -> None:
        self.total += 1
        if isinstance(shape, dict):
            self.types.add("object")
            self.object_count += 1
            for key, value in shape.items():
                self.props.setdefault(str(key), ShapeNode()).observe(value)
            return
        if isinstance(shape, list):
            self.types.add("array")
            if self.items is None:
                self.items = ShapeNode()
            for element in shape:
                self.items.observe(element)
            return
        if isinstance(shape, str):
            mapped = TYPE_NAMES.get(shape)
            if mapped:
                self.types.add(mapped)
            # An unrecognised name (capture's "…" depth marker, or a type we do
            # not model) contributes no constraint rather than a wrong one.

    def to_schema(self, min_required_samples: int = DEFAULT_MIN_REQUIRED_SAMPLES) -> dict[str, Any]:
        types = set(self.types)
        # `number` already admits integers; keeping both would imply a union
        # that no validator needs and that reads as a modelling error.
        if "number" in types and "integer" in types:
            types.discard("integer")

        schema: dict[str, Any] = {}
        if self.props:
            schema["properties"] = {
                name: child.to_schema(min_required_samples)
                for name, child in sorted(self.props.items())
            }
            if self.object_count >= max(min_required_samples, 1):
                required = sorted(
                    name for name, child in self.props.items() if child.total == self.object_count
                )
                if required:
                    schema["required"] = required
        if self.items is not None and self.items.total:
            schema["items"] = self.items.to_schema(min_required_samples)

        ordered = [t for t in _TYPE_ORDER if t in types]
        if ordered:
            schema["type"] = ordered[0] if len(ordered) == 1 else ordered
        elif not schema:
            return {}  # nothing was ever learned about this position
        return schema


def merge_shapes(
    shapes: Any, min_required_samples: int = DEFAULT_MIN_REQUIRED_SAMPLES
) -> dict[str, Any]:
    """Merge an iterable of capture shapes into a single JSON Schema."""
    root = ShapeNode()
    seen = False
    for shape in shapes:
        if shape is None:
            continue
        seen = True
        root.observe(shape)
    if not seen:
        return {}
    return root.to_schema(min_required_samples)


def is_json_schema(value: Any) -> bool:
    """Distinguish an already-merged JSON Schema from a raw capture shape.

    Contracts written before schema_version 2 stored raw shapes under the same
    key, so readers must be able to tell them apart to stay compatible.
    """
    if not isinstance(value, dict) or not value:
        return False
    if any(key in value for key in ("type", "properties", "items", "required", "anyOf")):
        # A raw shape could coincidentally have a field literally named "type",
        # but only a schema pairs it with a JSON Schema type value.
        if "type" in value:
            candidate = value["type"]
            if isinstance(candidate, str):
                return candidate in {
                    "object",
                    "array",
                    "string",
                    "integer",
                    "number",
                    "boolean",
                    "null",
                }
            return isinstance(candidate, list)
        return True
    return False


def merge_json_schemas(a: Any, b: Any) -> dict[str, Any]:
    """Union two already-derived schemas, for merging contracts across runs.

    Union semantics throughout: a property present in either schema is present
    in the result, and `required` is the *intersection* -- a field is only
    guaranteed if every run that observed this object saw it. Widening on merge
    is the safe direction; claiming a field is required because one run always
    saw it would mislead an agent into skipping a presence check.
    """
    if not isinstance(a, dict) or not a:
        return b if isinstance(b, dict) else {}
    if not isinstance(b, dict) or not b:
        return a

    out: dict[str, Any] = {}
    types = _type_set(a) | _type_set(b)
    if "number" in types and "integer" in types:
        types.discard("integer")
    ordered = [t for t in _TYPE_ORDER if t in types]
    if ordered:
        out["type"] = ordered[0] if len(ordered) == 1 else ordered

    props_a, props_b = a.get("properties"), b.get("properties")
    if isinstance(props_a, dict) or isinstance(props_b, dict):
        props_a = props_a if isinstance(props_a, dict) else {}
        props_b = props_b if isinstance(props_b, dict) else {}
        out["properties"] = {
            key: merge_json_schemas(props_a.get(key, {}), props_b.get(key, {}))
            for key in sorted(set(props_a) | set(props_b))
        }
        required = sorted(set(a.get("required") or []) & set(b.get("required") or []))
        if required:
            out["required"] = required

    if "items" in a or "items" in b:
        out["items"] = merge_json_schemas(a.get("items", {}), b.get("items", {}))

    for key in ("description",):
        if key in a or key in b:
            out[key] = a.get(key) or b.get(key)
    return out


def _type_set(schema: dict[str, Any]) -> set[str]:
    value = schema.get("type")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {t for t in value if isinstance(t, str)}
    return set()


def schema_properties(schema: Any) -> set[str]:
    """Top-level property names, for comparing coverage between two schemas."""
    if not isinstance(schema, dict):
        return set()
    props = schema.get("properties")
    return set(props) if isinstance(props, dict) else set()


def coerce_to_schema(
    value: Any, min_required_samples: int = DEFAULT_MIN_REQUIRED_SAMPLES
) -> dict[str, Any]:
    """Return `value` as a JSON Schema, converting it if it is a legacy shape."""
    if value is None:
        return {}
    if is_json_schema(value):
        return value
    return merge_shapes([value], min_required_samples)
