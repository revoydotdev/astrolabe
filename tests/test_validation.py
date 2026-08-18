from __future__ import annotations

from astrolabe.validation import validate_json_schema, validate_response, validate_value_budget


def test_draft_202012_validation_reports_exact_paths() -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["items"],
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {"id": {"type": "integer"}},
                },
            }
        },
    }
    result = validate_json_schema({"items": [{"id": "wrong"}]}, schema)
    assert result["valid"] is False
    assert result["failure_kind"] == "upstream-drift"
    assert result["errors"][0]["path"] == "/items/0/id"


def test_invalid_declared_schema_is_distinguished_from_drift() -> None:
    result = validate_json_schema({}, {"type": "not-a-json-schema-type"})
    assert result["failure_kind"] == "schema-defect"


def test_graphql_data_plus_errors_can_validate_partial_payload() -> None:
    result = validate_response(
        {"data": {"viewer": None}, "errors": [{"message": "field unavailable"}]},
        {
            "type": "object",
            "properties": {"viewer": {"type": ["object", "null"]}},
            "required": ["viewer"],
        },
        status=200,
        media_type="application/graphql-response+json",
        graphql=True,
    )
    assert result["valid"] is True


def test_status_and_media_type_precede_schema_validation() -> None:
    schema = {"type": "object"}
    assert (
        validate_response({}, schema, status=401, media_type="application/json", graphql=False)[
            "failure_kind"
        ]
        == "response-status"
    )
    assert (
        validate_response({}, schema, status=200, media_type="text/html", graphql=False)[
            "failure_kind"
        ]
        == "response-media-type"
    )


def test_value_budget_reports_path_without_echoing_values() -> None:
    secret = "CANARY-VALUE"
    result = validate_value_budget({"nested": {"secret": secret}}, max_string_length=3)
    assert result["failure_kind"] == "argument-budget"
    assert result["errors"] == [{"path": "/nested/secret", "validator": "max-string-length"}]
    assert secret not in str(result)
