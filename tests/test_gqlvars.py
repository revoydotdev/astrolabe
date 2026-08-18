"""Tests for parsing GraphQL variable declarations out of captured query text."""

from __future__ import annotations

from astrolabe.gqlvars import (
    merge_declared_with_observed,
    parse_variable_definitions,
    type_to_schema,
)
from astrolabe.shapemerge import merge_shapes

# ---------- parsing ----------


def test_parses_types_and_requiredness() -> None:
    d = parse_variable_definitions("query Job($page: Int!, $limit: Int) { jobs { id } }")
    assert set(d) == {"page", "limit"}
    assert d["page"].required is True
    assert d["limit"].required is False


def test_non_null_with_default_is_not_required() -> None:
    """`!` alone does not make a variable required at the call site."""
    d = parse_variable_definitions("query Q($n: Int! = 5) { x }")
    assert d["n"].type.non_null is True
    assert d["n"].has_default is True
    assert d["n"].required is False


def test_default_value_with_nested_braces_and_strings() -> None:
    q = 'query Q($f: F = {a: [1,2], b: "x)y,z"}, $after: String) { x }'
    d = parse_variable_definitions(q)
    assert set(d) == {"f", "after"}
    assert d["f"].raw_type == "F"
    assert d["after"].raw_type == "String"


def test_list_types_nest() -> None:
    d = parse_variable_definitions("query Q($tags: [String!]!, $ids: [[Int]]) { x }")
    tags = d["tags"].type
    assert tags.is_list and tags.non_null
    assert tags.of_type is not None and tags.of_type.name == "String"
    outer = d["ids"].type
    assert outer.is_list and outer.of_type is not None and outer.of_type.is_list


def test_commas_are_optional_between_definitions() -> None:
    d = parse_variable_definitions("query Q($a: Int $b: String) { x }")
    assert set(d) == {"a", "b"}


def test_comments_inside_the_block_are_ignored() -> None:
    q = "query Q(\n  $a: Int!  # the page\n  $b: String\n) { x }"
    d = parse_variable_definitions(q)
    assert set(d) == {"a", "b"}
    assert d["a"].required is True


def test_mutation_and_subscription_are_parsed() -> None:
    assert set(parse_variable_definitions("mutation M($id: ID!) { del(id:$id) }")) == {"id"}
    assert set(parse_variable_definitions("subscription S($t: String) { feed }")) == {"t"}


def test_field_named_query_inside_a_selection_is_not_an_operation() -> None:
    """A selection-set field called `query` must not be mistaken for the operation."""
    d = parse_variable_definitions("query Real($a: Int!) { search { query results } }")
    assert set(d) == {"a"}


# ---------- graceful degradation ----------


def test_operations_without_variables_return_empty() -> None:
    assert parse_variable_definitions("query Q { jobs { id } }") == {}
    assert parse_variable_definitions("{ jobs { id } }") == {}


def test_persisted_and_empty_queries_return_empty() -> None:
    assert parse_variable_definitions("") == {}
    assert parse_variable_definitions(None) == {}  # type: ignore[arg-type]


def test_malformed_input_never_raises() -> None:
    for bad in ("query Q($", "query Q($a:", "query Q($a: [Int) { x }", "$$$", "query Q(((("):
        assert isinstance(parse_variable_definitions(bad), dict)


def test_unterminated_string_does_not_hang() -> None:
    assert isinstance(parse_variable_definitions('query Q($a: S = "oops) { x }'), dict)


# ---------- schema emission ----------


def test_scalars_map_to_json_schema_types() -> None:
    d = parse_variable_definitions(
        "query Q($i: Int!, $f: Float!, $s: String!, $b: Boolean!, $id: ID!) { x }"
    )
    assert type_to_schema(d["i"].type) == {"type": "integer"}
    assert type_to_schema(d["f"].type) == {"type": "number"}
    assert type_to_schema(d["s"].type) == {"type": "string"}
    assert type_to_schema(d["b"].type) == {"type": "boolean"}
    assert type_to_schema(d["id"].type) == {"type": "string"}


def test_nullable_scalars_become_a_union_with_null() -> None:
    d = parse_variable_definitions("query Q($s: String) { x }")
    assert type_to_schema(d["s"].type) == {"type": ["string", "null"]}


def test_custom_types_are_unconstrained_but_named() -> None:
    d = parse_variable_definitions("query Q($f: JobFilter!) { x }")
    assert type_to_schema(d["f"].type) == {"description": "GraphQL type JobFilter"}


def test_declaration_drives_properties_and_required() -> None:
    d = parse_variable_definitions("query Q($page: Int!, $limit: Int) { x }")
    schema = merge_declared_with_observed(d, None)
    assert schema["type"] == "object"
    assert set(schema["properties"]) == {"page", "limit"}
    assert schema["required"] == ["page"]


def test_declaration_recovers_variables_never_exercised() -> None:
    """The point of parsing: variables the capture never fired still appear."""
    d = parse_variable_definitions("query Q($a: Int!, $b: String, $c: Boolean) { x }")
    schema = merge_declared_with_observed(d, merge_shapes([{"a": "int"}]))
    assert set(schema["properties"]) == {"a", "b", "c"}


def test_observed_structure_fills_in_a_custom_input_object() -> None:
    d = parse_variable_definitions("query Q($filter: JobFilter) { x }")
    observed = merge_shapes([{"filter": {"minRate": "int", "tags": ["str"]}}])
    prop = merge_declared_with_observed(d, observed)["properties"]["filter"]
    assert prop["properties"]["minRate"] == {"type": "integer"}
    assert prop["properties"]["tags"] == {"type": "array", "items": {"type": "string"}}
    assert "JobFilter" in prop["description"]


def test_observed_structure_merges_across_all_observations() -> None:
    """Structure comes from every sample, not whichever one was picked."""
    d = parse_variable_definitions("query Q($filter: JobFilter) { x }")
    observed = merge_shapes([{"filter": {"a": "str"}}, {"filter": {"b": "int"}}])
    prop = merge_declared_with_observed(d, observed)["properties"]["filter"]
    assert set(prop["properties"]) == {"a", "b"}


def test_declared_scalar_beats_observed_value() -> None:
    """The declaration is authoritative; a coincidental observation must not widen it."""
    d = parse_variable_definitions("query Q($n: Int!) { x }")
    schema = merge_declared_with_observed(d, merge_shapes([{"n": "str"}]))
    assert schema["properties"]["n"] == {"type": "integer"}


def test_observed_variable_absent_from_declaration_is_kept() -> None:
    """Evidence of a real parameter is not discarded when the text is stale."""
    d = parse_variable_definitions("query Q($a: Int!) { x }")
    schema = merge_declared_with_observed(d, merge_shapes([{"a": "int", "extra": "str"}]))
    assert schema["properties"]["extra"] == {"type": "string"}


def test_no_declaration_yields_an_object_schema() -> None:
    assert merge_declared_with_observed({}, None) == {"type": "object", "properties": {}}
