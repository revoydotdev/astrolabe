"""Tests for resolving custom GraphQL types against a recovered schema."""

from __future__ import annotations

import json

from astrolabe.gqlschema import SchemaIndex
from astrolabe.gqlvars import merge_declared_with_observed, parse_variable_definitions


def _schema(*types: dict) -> dict:
    return {"data": {"__schema": {"types": list(types)}}}


def _input_object(name: str, *fields: dict) -> dict:
    return {"kind": "INPUT_OBJECT", "name": name, "inputFields": list(fields)}


def _field(name: str, type_ref: dict, default=None) -> dict:
    return {"name": name, "type": type_ref, "defaultValue": default}


NON_NULL_INT = {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "Int"}}
NULLABLE_INT = {"kind": "SCALAR", "name": "Int"}


# ---------- loading the several shapes these files come in ----------


def test_accepts_full_introspection_envelope() -> None:
    idx = SchemaIndex.from_obj(_schema(_input_object("F")))
    assert len(idx) == 1


def test_accepts_bare_schema_and_bare_types() -> None:
    assert len(SchemaIndex.from_obj({"__schema": {"types": [_input_object("F")]}})) == 1
    assert len(SchemaIndex.from_obj({"types": [_input_object("F")]})) == 1


def test_garbage_yields_an_empty_index_rather_than_raising() -> None:
    bad: list[object] = [{}, {"data": {}}, {"types": "nope"}, [], None, {"__schema": {}}]
    for item in bad:
        assert not SchemaIndex.from_obj(item)


def test_missing_or_unreadable_file_yields_empty_index(tmp_path) -> None:
    assert not SchemaIndex.load(str(tmp_path))
    (tmp_path / "schema.json").write_text("{ not json")
    assert not SchemaIndex.load(str(tmp_path))


def test_load_reads_schema_json(tmp_path) -> None:
    (tmp_path / "schema.json").write_text(json.dumps(_schema(_input_object("F"))))
    assert len(SchemaIndex.load(str(tmp_path))) == 1


# ---------- type resolution ----------


def test_non_null_field_is_required_and_not_nullable() -> None:
    idx = SchemaIndex.from_obj(_schema(_input_object("F", _field("a", NON_NULL_INT))))
    resolved = idx.resolve("F")
    assert resolved["properties"]["a"] == {"type": "integer"}
    assert resolved["required"] == ["a"]


def test_nullable_field_is_a_union_and_not_required() -> None:
    idx = SchemaIndex.from_obj(_schema(_input_object("F", _field("a", NULLABLE_INT))))
    resolved = idx.resolve("F")
    assert resolved["properties"]["a"] == {"type": ["integer", "null"]}
    assert "required" not in resolved


def test_non_null_with_a_default_is_not_required() -> None:
    """Same rule as a variable declaration: a default makes it optional to send."""
    idx = SchemaIndex.from_obj(_schema(_input_object("F", _field("a", NON_NULL_INT, default="5"))))
    resolved = idx.resolve("F")
    assert resolved["properties"]["a"] == {"type": "integer"}
    assert "required" not in resolved


def test_list_types_unwrap_through_non_null() -> None:
    ref = {
        "kind": "NON_NULL",
        "ofType": {
            "kind": "LIST",
            "ofType": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}},
        },
    }
    idx = SchemaIndex.from_obj(_schema(_input_object("F", _field("xs", ref))))
    assert idx.resolve("F")["properties"]["xs"] == {
        "type": "array",
        "items": {"type": "string"},
    }


def test_enums_carry_their_values() -> None:
    idx = SchemaIndex.from_obj(
        _schema({"kind": "ENUM", "name": "Sort", "enumValues": [{"name": "ASC"}, {"name": "DESC"}]})
    )
    assert idx.resolve("Sort") == {"type": "string", "enum": ["ASC", "DESC"]}


def test_self_referential_input_object_terminates() -> None:
    """Filter types routinely reference themselves; expansion must be bounded."""
    idx = SchemaIndex.from_obj(
        _schema(
            _input_object(
                "F",
                _field("a", NULLABLE_INT),
                _field("nested", {"kind": "INPUT_OBJECT", "name": "F"}),
            )
        )
    )
    resolved = idx.resolve("F")
    assert resolved["properties"]["nested"]["properties"]["a"] == {"type": ["integer", "null"]}


def test_unknown_type_resolves_to_nothing() -> None:
    assert SchemaIndex.from_obj(_schema()).resolve("Nope") == {}


# ---------- the join that closes the gap ----------


def test_enrich_replaces_a_name_only_placeholder() -> None:
    """gqlvars can name a custom input type but not describe it; the schema can."""
    idx = SchemaIndex.from_obj(_schema(_input_object("JobFilter", _field("minRate", NON_NULL_INT))))
    declared = parse_variable_definitions("query Q($filter: JobFilter) { x }")
    before = merge_declared_with_observed(declared, None)
    assert before["properties"]["filter"] == {"description": "GraphQL type JobFilter"}

    after = idx.enrich(before)
    prop = after["properties"]["filter"]
    assert prop["properties"]["minRate"] == {"type": "integer"}
    assert prop["required"] == ["minRate"]
    assert "JobFilter" in prop["description"]


def test_enrich_recovers_fields_no_capture_ever_sent() -> None:
    idx = SchemaIndex.from_obj(
        _schema(_input_object("F", _field("seen", NULLABLE_INT), _field("neverSent", NULLABLE_INT)))
    )
    declared = parse_variable_definitions("query Q($f: F) { x }")
    from astrolabe.shapemerge import merge_shapes

    observed = merge_shapes([{"f": {"seen": "int"}}])
    enriched = idx.enrich(merge_declared_with_observed(declared, observed))
    assert set(enriched["properties"]["f"]["properties"]) == {"seen", "neverSent"}


def test_enrich_unions_with_structure_already_observed() -> None:
    """Each side knows something the other does not, so neither may win outright."""
    idx = SchemaIndex.from_obj(_schema(_input_object("F", _field("a", NULLABLE_INT))))
    already = {
        "type": "object",
        "properties": {
            # `b` was seen in traffic but is absent from the recovered schema
            "f": {"description": "GraphQL type F", "properties": {"b": {"type": "string"}}}
        },
    }
    props = idx.enrich(already)["properties"]["f"]["properties"]
    assert props == {"a": {"type": ["integer", "null"]}, "b": {"type": "string"}}


def test_enrich_is_a_noop_without_a_schema() -> None:
    schema = {"type": "object", "properties": {"f": {"description": "GraphQL type F"}}}
    assert SchemaIndex({}).enrich(schema) == schema


def test_enrich_descends_into_arrays() -> None:
    idx = SchemaIndex.from_obj(_schema(_input_object("F", _field("a", NULLABLE_INT))))
    schema = {
        "type": "object",
        "properties": {"xs": {"type": "array", "items": {"description": "GraphQL type F"}}},
    }
    items = idx.enrich(schema)["properties"]["xs"]["items"]
    assert items["properties"]["a"] == {"type": ["integer", "null"]}
