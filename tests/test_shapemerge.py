"""Tests for union-merging observed capture shapes into a JSON Schema."""

from __future__ import annotations

from astrolabe.shapemerge import (
    coerce_to_schema,
    is_json_schema,
    merge_shapes,
)

# ---------- primitives ----------


def test_scalar_type_names_map_to_json_schema() -> None:
    schema = merge_shapes([{"s": "str", "i": "int", "f": "float", "b": "bool"}])
    props = schema["properties"]
    assert props["s"] == {"type": "string"}
    assert props["i"] == {"type": "integer"}
    assert props["f"] == {"type": "number"}
    assert props["b"] == {"type": "boolean"}


def test_no_observations_yields_an_empty_schema() -> None:
    assert merge_shapes([]) == {}
    assert merge_shapes([None, None]) == {}


def test_unknown_type_names_add_no_constraint() -> None:
    """capture's depth marker and unmodelled names must not invent a wrong type."""
    assert merge_shapes([{"deep": "…"}])["properties"]["deep"] == {}


# ---------- nullability ----------


def test_null_in_one_sample_widens_the_type() -> None:
    schema = merge_shapes([{"bio": "str"}, {"bio": "NoneType"}])
    assert schema["properties"]["bio"]["type"] == ["string", "null"]


def test_always_null_field_is_typed_null_not_dropped() -> None:
    schema = merge_shapes([{"x": "NoneType"}, {"x": "NoneType"}])
    assert schema["properties"]["x"] == {"type": "null"}


# ---------- requiredness is evidence-based ----------


def test_field_present_in_every_observation_is_required() -> None:
    schema = merge_shapes([{"id": "str", "bio": "str"}, {"id": "str"}])
    assert schema["required"] == ["id"]


def test_single_observation_emits_no_required() -> None:
    """One sample is not evidence that a field is guaranteed."""
    schema = merge_shapes([{"a": "str", "b": "str"}])
    assert "required" not in schema


def test_min_required_samples_is_configurable() -> None:
    schema = merge_shapes([{"a": "str"}], min_required_samples=1)
    assert schema["required"] == ["a"]


def test_requiredness_is_scoped_to_the_parent_object() -> None:
    """A nested object seen fewer times than the root must not inherit its count."""
    schema = merge_shapes(
        [
            {"user": {"id": "str", "nick": "str"}},
            {"user": {"id": "str"}},
            {},  # user absent entirely
        ]
    )
    user = schema["properties"]["user"]
    assert user["required"] == ["id"]
    assert "required" not in schema or "user" not in schema.get("required", [])


# ---------- type unification ----------


def test_int_and_float_collapse_to_number() -> None:
    """`number` already admits integers; a union would read as a modelling error."""
    schema = merge_shapes([{"p": "int"}, {"p": "float"}])
    assert schema["properties"]["p"] == {"type": "number"}


def test_genuinely_mixed_types_produce_a_union() -> None:
    schema = merge_shapes([{"v": "str"}, {"v": "bool"}])
    assert set(schema["properties"]["v"]["type"]) == {"string", "boolean"}


# ---------- arrays ----------


def test_array_elements_merge_across_all_observations() -> None:
    schema = merge_shapes([{"xs": [{"a": "str"}]}, {"xs": [{"b": "int"}]}])
    items = schema["properties"]["xs"]["items"]
    assert set(items["properties"]) == {"a", "b"}


def test_heterogeneous_array_elements_union() -> None:
    schema = merge_shapes([{"xs": ["int", "str"]}])
    assert set(schema["properties"]["xs"]["items"]["type"]) == {"integer", "string"}


def test_empty_array_has_no_items() -> None:
    schema = merge_shapes([{"xs": []}])
    assert schema["properties"]["xs"] == {"type": "array"}


def test_array_and_object_at_the_same_position_union() -> None:
    schema = merge_shapes([{"v": ["str"]}, {"v": {"a": "str"}}])
    assert set(schema["properties"]["v"]["type"]) == {"array", "object"}


# ---------- the behaviour that replaced longest-JSON-wins ----------


def test_merge_beats_picking_a_single_representative_sample() -> None:
    """The old heuristic kept the longest sample and lost every field the others had."""
    long_but_narrow = {"items": [{"a": "str"}, {"a": "str"}, {"a": "str"}]}
    short_but_wide = {"items": [{"a": "str"}], "total": "int", "cursor": "str"}
    schema = merge_shapes([long_but_narrow, short_but_wide])
    assert set(schema["properties"]) == {"items", "total", "cursor"}


def test_deeply_nested_structures_merge() -> None:
    schema = merge_shapes([{"a": {"b": {"c": "str"}}}, {"a": {"b": {"d": "int"}}}])
    inner = schema["properties"]["a"]["properties"]["b"]["properties"]
    assert set(inner) == {"c", "d"}


# ---------- legacy contract compatibility ----------


def test_is_json_schema_recognises_a_schema() -> None:
    assert is_json_schema({"type": "object", "properties": {}}) is True
    assert is_json_schema({"type": ["string", "null"]}) is True
    assert is_json_schema({"items": {}}) is True


def test_is_json_schema_rejects_a_raw_capture_shape() -> None:
    assert is_json_schema({"id": "str", "name": "str"}) is False
    assert is_json_schema({}) is False
    assert is_json_schema("str") is False
    # a shape whose field is literally named "type" is still a shape
    assert is_json_schema({"type": "str"}) is False


def test_coerce_converts_legacy_shapes_and_passes_schemas_through() -> None:
    schema = {"type": "object", "properties": {"a": {"type": "string"}}}
    assert coerce_to_schema(schema) is schema
    converted = coerce_to_schema({"a": "str"})
    assert converted["properties"]["a"] == {"type": "string"}
    assert coerce_to_schema(None) == {}


def test_native_null_and_truncation_markers_are_not_schema_fields():
    from astrolabe.shapemerge import merge_shapes

    marker = {"$astrolabe_truncated": {"reason": "depth_budget"}}
    schema = merge_shapes([{"next": "null", "deep": marker}, {"next": "str", "deep": marker}])
    assert schema["properties"]["next"]["type"] == ["string", "null"]
    assert schema["properties"]["deep"] == {}
    assert "$astrolabe_truncated" not in str(schema)


def test_incomplete_array_and_object_do_not_manufacture_constraints():
    from astrolabe.shapemerge import merge_shapes

    array_marker = {"$astrolabe_truncated": {"reason": "array_sample_budget"}}
    assert merge_shapes([["str", array_marker]])["items"] == {}
    obj = {"x": "str", "$astrolabe_truncated": {"reason": "key_budget"}}
    schema = merge_shapes([obj, obj])
    assert "required" not in schema
    assert set(schema["properties"]) == {"x"}
