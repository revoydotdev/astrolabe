"""JSON Schema 2020-12 request/response validation with safe diagnostics."""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]


def _path(parts: Any) -> str:
    return "/" + "/".join(str(part) for part in parts) if parts else "/"


def validate_json_schema(instance: Any, schema: dict[str, Any]) -> dict[str, Any]:
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        return {
            "valid": False,
            "failure_kind": "schema-defect",
            "errors": [{"path": _path(exc.absolute_schema_path), "validator": "schema"}],
        }
    errors = sorted(
        Draft202012Validator(schema).iter_errors(instance),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    return {
        "valid": not errors,
        "failure_kind": None if not errors else "upstream-drift",
        "errors": [
            {
                "path": _path(error.absolute_path),
                "schema_path": _path(error.absolute_schema_path),
                "validator": str(error.validator),
            }
            for error in errors[:50]
        ],
    }


def validate_response(
    payload: Any,
    schema: dict[str, Any] | None,
    *,
    status: int | None,
    media_type: str,
    graphql: bool,
) -> dict[str, Any]:
    if not isinstance(status, int) or not 200 <= status < 300:
        return {
            "valid": False,
            "failure_kind": "response-status",
            "errors": [{"path": "/", "validator": "2xx-status"}],
        }
    normalized_media = media_type.split(";", 1)[0].strip().lower()
    if "json" not in normalized_media and normalized_media not in {
        "multipart/mixed",
        "application/graphql-response+json",
    }:
        return {
            "valid": False,
            "failure_kind": "response-media-type",
            "errors": [{"path": "/", "validator": "json-media-type"}],
        }
    if graphql:
        if not isinstance(payload, dict) or not ({"data", "errors"} & set(payload)):
            return {
                "valid": False,
                "failure_kind": "graphql-envelope",
                "errors": [{"path": "/", "validator": "graphql-envelope"}],
            }
        instance = payload.get("data")
        # GraphQL permits partial data alongside errors. The declared data schema
        # still validates the available data; errors remain proof evidence.
    else:
        instance = payload
    if not schema:
        return {
            "valid": False,
            "failure_kind": "schema-missing",
            "errors": [{"path": "/", "validator": "declared-schema"}],
        }
    return validate_json_schema(instance, schema)


def validate_value_budget(
    value: Any,
    *,
    max_depth: int = 10,
    max_properties: int = 1000,
    max_string_length: int = 10_000,
    max_array_length: int = 1000,
) -> dict[str, Any]:
    properties = 0
    failure: dict[str, Any] | None = None

    def visit(item: Any, depth: int, path: list[Any]) -> None:
        nonlocal properties, failure
        if failure:
            return
        if depth > max_depth:
            failure = {"path": _path(path), "validator": "max-depth"}
        elif isinstance(item, dict):
            properties += len(item)
            if properties > max_properties:
                failure = {"path": _path(path), "validator": "max-properties"}
                return
            for key, member in item.items():
                visit(member, depth + 1, [*path, key])
        elif isinstance(item, list):
            if len(item) > max_array_length:
                failure = {"path": _path(path), "validator": "max-array-length"}
                return
            for index, member in enumerate(item):
                visit(member, depth + 1, [*path, index])
        elif isinstance(item, str) and len(item) > max_string_length:
            failure = {"path": _path(path), "validator": "max-string-length"}

    visit(value, 0, [])
    return {
        "valid": failure is None,
        "failure_kind": None if failure is None else "argument-budget",
        "errors": [] if failure is None else [failure],
    }
