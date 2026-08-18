"""Published artifact schemas and Draft 2020-12 validation helpers."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from .artifact import ArtifactError

SCHEMA_DIRECTORY = Path(__file__).with_name("schemas")


def load_schema(name: str) -> dict[str, Any]:
    path = SCHEMA_DIRECTORY / name
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"cannot load published schema {name}: {exc}") from exc
    Draft202012Validator.check_schema(value)
    return value


def validate_artifact(value: Any, schema_name: str) -> None:
    errors = sorted(
        Draft202012Validator(load_schema(schema_name)).iter_errors(value),
        key=lambda error: tuple(str(item) for item in error.absolute_path),
    )
    if errors:
        error = errors[0]
        location = "/".join(str(item) for item in error.absolute_path) or "$"
        raise ArtifactError(f"{schema_name} validation failed at {location}: {error.message}")
