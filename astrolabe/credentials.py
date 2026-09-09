"""Versioned credential-generation envelopes shared by bootstrap, replay, and MCP."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

CREDENTIAL_SCHEMA_VERSION = 2
META_AUTH_FORM_FIELDS = frozenset(
    {"fb_dtsg", "jazoest", "lsd", "__a", "__user", "__comet_req", "av"}
)
SUPPORTED_CREDENTIAL_SCHEMA_VERSIONS = frozenset({1, 2})


class CredentialBundleError(ValueError):
    pass


def browser_cookies(value: Any) -> list[dict[str, Any]]:
    """Normalize Playwright/storage-state and common extension exports for add_cookies."""
    cookies = value.get("cookies") if isinstance(value, dict) else value
    if not isinstance(cookies, list):
        raise CredentialBundleError("cookie export must be an array or contain a cookies array")
    result = []
    for item in cookies:
        if not isinstance(item, dict) or not all(
            isinstance(item.get(k), str) for k in ("name", "value")
        ):
            raise CredentialBundleError("cookie export contains an invalid record")
        cookie = {
            key: item[key]
            for key in ("name", "value", "domain", "path", "url", "secure", "httpOnly")
            if key in item
        }
        if "url" not in cookie:
            if not isinstance(cookie.get("domain"), str) or not cookie["domain"]:
                raise CredentialBundleError("cookie requires a domain or URL")
            cookie.setdefault("path", "/")
        same_site = str(item.get("sameSite") or "").lower()
        if same_site in {"strict", "lax", "none", "no_restriction"}:
            cookie["sameSite"] = {
                "strict": "Strict",
                "lax": "Lax",
                "none": "None",
                "no_restriction": "None",
            }[same_site]
        expires = item.get("expires", item.get("expirationDate"))
        if not item.get("session") and isinstance(expires, (float, int)) and expires > 0:
            cookie["expires"] = expires
        result.append(cookie)
    return result


def _timestamp(value: Any, label: str, *, nullable: bool = False) -> datetime | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value:
        raise CredentialBundleError(f"credential bundle requires {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CredentialBundleError(f"credential bundle has invalid {label}") from exc
    if parsed.tzinfo is None:
        raise CredentialBundleError(f"credential bundle {label} must include a timezone")
    return parsed.astimezone(UTC)


def inspect_credentials(
    value: Any,
) -> tuple[str | None, dict[str, dict[str, Any]], dict[str, Any]]:
    """Return generation, normalized records, and non-secret bundle metadata.

    Version 1 and bare maps remain readable as legacy inputs. Version 2 records
    expose headers separately from the metadata used for pre-send admission.
    """
    if not isinstance(value, dict):
        raise CredentialBundleError("credential map must be an object")
    if "schema_version" not in value:
        legacy_records = {
            str(alias): {"headers": record, "metadata": {"legacy": True}}
            for alias, record in value.items()
            if isinstance(record, dict)
        }
        return None, legacy_records, {"schema_version": None, "legacy": True}
    version = value.get("schema_version")
    if version not in SUPPORTED_CREDENTIAL_SCHEMA_VERSIONS:
        raise CredentialBundleError(f"unsupported credential schema_version {version!r}")
    generation = value.get("generation_id")
    credentials = value.get("credentials")
    if not isinstance(generation, str) or not generation:
        raise CredentialBundleError("credential bundle requires generation_id")
    if not isinstance(credentials, dict):
        raise CredentialBundleError("credential bundle requires credentials object")
    if version == 1:
        return (
            generation,
            {
                str(alias): {"headers": record, "metadata": {"legacy": True}}
                for alias, record in credentials.items()
                if isinstance(record, dict)
            },
            {"schema_version": 1, "legacy": True},
        )

    generated_at = _timestamp(value.get("generated_at"), "generated_at")
    expires_at = _timestamp(value.get("expires_at"), "expires_at", nullable=True)
    for field in ("issuer", "source", "target_origin", "session_binding"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise CredentialBundleError(f"credential bundle requires {field}")
    bundle_metadata = {
        "schema_version": 2,
        "legacy": False,
        "generated_at": generated_at,
        "expires_at": expires_at,
        "issuer": value["issuer"],
        "source": value["source"],
        "target_origin": value["target_origin"],
        "session_binding": value["session_binding"],
    }
    records: dict[str, dict[str, Any]] = {}
    for alias, raw_record in credentials.items():
        if not isinstance(raw_record, dict) or not isinstance(raw_record.get("headers"), dict):
            raise CredentialBundleError(f"credential {alias!r} requires headers object")
        scope = raw_record.get("operation_scope")
        if not isinstance(scope, list) or not all(isinstance(item, str) for item in scope):
            raise CredentialBundleError(f"credential {alias!r} requires operation_scope")
        metadata = dict(bundle_metadata)
        metadata["operation_scope"] = list(scope)
        for field in ("target_origin", "session_binding", "issuer", "source"):
            if field in raw_record:
                if not isinstance(raw_record[field], str) or not raw_record[field]:
                    raise CredentialBundleError(f"credential {alias!r} has invalid {field}")
                metadata[field] = raw_record[field]
        if "expires_at" in raw_record:
            metadata["expires_at"] = _timestamp(
                raw_record["expires_at"], f"credential {alias!r} expires_at", nullable=True
            )
        form_fields = raw_record.get("form_fields", {})
        if not isinstance(form_fields, dict) or any(
            key not in META_AUTH_FORM_FIELDS or not isinstance(val, str) or len(val) > 16384
            for key, val in form_fields.items()
        ):
            raise CredentialBundleError(
                "credential has unsupported or oversized authentication form fields"
            )
        records[str(alias)] = {
            "headers": raw_record["headers"],
            "metadata": metadata,
            "form_fields": dict(form_fields),
        }
    return generation, records, bundle_metadata


def unwrap_credentials(value: Any) -> tuple[str | None, dict[str, Any]]:
    generation, records, _metadata = inspect_credentials(value)
    return generation, {alias: record["headers"] for alias, record in records.items()}


def inspect_cookies(value: Any) -> tuple[str | None, list[dict[str, Any]], dict[str, Any]]:
    if isinstance(value, list):
        return None, [item for item in value if isinstance(item, dict)], {"legacy": True}
    if not isinstance(value, dict) or value.get("schema_version") not in (
        SUPPORTED_CREDENTIAL_SCHEMA_VERSIONS
    ):
        raise CredentialBundleError("cookie bundle must be an array or supported schema object")
    generation = value.get("generation_id")
    cookies = value.get("cookies")
    if not isinstance(generation, str) or not generation:
        raise CredentialBundleError("cookie bundle requires generation_id")
    if not isinstance(cookies, list):
        raise CredentialBundleError("cookie bundle requires cookies array")
    if value["schema_version"] == 1:
        return generation, [item for item in cookies if isinstance(item, dict)], {"legacy": True}
    generated_at = _timestamp(value.get("generated_at"), "generated_at")
    for field in ("source", "target_origin", "session_binding"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise CredentialBundleError(f"cookie bundle requires {field}")
    return (
        generation,
        [item for item in cookies if isinstance(item, dict)],
        {
            "legacy": False,
            "generated_at": generated_at,
            "source": value["source"],
            "target_origin": value["target_origin"],
            "session_binding": value["session_binding"],
        },
    )


def unwrap_cookies(value: Any) -> tuple[str | None, list[dict[str, Any]]]:
    generation, cookies, _metadata = inspect_cookies(value)
    return generation, cookies


def generations_match(auth_generation: str | None, cookie_generation: str | None) -> bool:
    return auth_generation == cookie_generation
