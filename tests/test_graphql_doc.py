from __future__ import annotations

from astrolabe.graphql_doc import parse_graphql_document


def test_parser_resolves_aliases_fragments_directives_and_selected_operation() -> None:
    document = """
    query First($id: ID!) @client {
      account: viewer(id: $id) { ...ViewerFields }
    }
    query Second { health @include(if: true) }
    fragment ViewerFields on Viewer { id }
    """
    operations = parse_graphql_document(document, "First")

    assert [item.name for item in operations] == ["First", "Second"]
    assert operations[0].selected is True
    assert operations[1].selected is False
    assert operations[0].semantic_kind == "query"
    assert operations[0].variable_names == ["id"]
    assert operations[0].response_keys == ["account"]
    assert operations[0].root_fields == ["viewer"]
    assert operations[0].directives == ["client"]
    assert operations[1].directives == ["include"]


def test_parser_handles_anonymous_query_and_subscription() -> None:
    anonymous = parse_graphql_document("{ viewer { id } }")
    subscription = parse_graphql_document("subscription Events { events { id } }")

    assert anonymous[0].name is None
    assert anonymous[0].semantic_kind == "query"
    assert anonymous[0].selected is True
    assert subscription[0].semantic_kind == "subscription"


def test_malformed_document_uses_explicit_low_confidence_fallback() -> None:
    operation = parse_graphql_document("mutation Broken { update(")[0]

    assert operation.semantic_kind == "mutation"
    assert operation.parse_confidence == "tolerant-fallback"
    assert operation.parse_error
