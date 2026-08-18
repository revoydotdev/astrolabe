from __future__ import annotations

import json

import pytest

from astrolabe.credentials import (
    CREDENTIAL_SCHEMA_VERSION,
    CredentialBundleError,
    inspect_cookies,
    inspect_credentials,
    unwrap_credentials,
)


def _bundle(**record_overrides):
    generation = "generation-2"
    record = {
        "headers": {"authorization": "Bearer SECRET"},
        "operation_scope": ["Viewer"],
        "target_origin": "https://api.example.com",
        "session_binding": generation,
        **record_overrides,
    }
    return {
        "schema_version": CREDENTIAL_SCHEMA_VERSION,
        "generation_id": generation,
        "generated_at": "2026-08-14T12:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "issuer": "https://example.com",
        "source": "test-bootstrap",
        "target_origin": "https://example.com",
        "session_binding": generation,
        "credentials": {"Viewer": record},
    }


def test_v2_credential_bundle_exposes_metadata_but_unwraps_headers() -> None:
    generation, records, metadata = inspect_credentials(_bundle())
    assert generation == "generation-2"
    assert records["Viewer"]["metadata"]["operation_scope"] == ["Viewer"]
    assert metadata["source"] == "test-bootstrap"
    assert unwrap_credentials(_bundle())[1] == {"Viewer": {"authorization": "Bearer SECRET"}}


def test_v2_bundle_requires_timezone_and_session_metadata() -> None:
    value = _bundle()
    value["generated_at"] = "2026-08-14T12:00:00"
    with pytest.raises(CredentialBundleError, match="timezone"):
        inspect_credentials(value)
    value = _bundle()
    del value["session_binding"]
    with pytest.raises(CredentialBundleError, match="session_binding"):
        inspect_credentials(value)


def test_v2_cookie_bundle_carries_generation_binding() -> None:
    value = {
        "schema_version": 2,
        "generation_id": "generation-2",
        "generated_at": "2026-08-14T12:00:00Z",
        "source": "test-bootstrap",
        "target_origin": "https://example.com",
        "session_binding": "generation-2",
        "cookies": [{"name": "session", "value": "SECRET"}],
    }
    generation, cookies, metadata = inspect_cookies(value)
    assert generation == metadata["session_binding"] == "generation-2"
    assert cookies[0]["name"] == "session"
    assert "SECRET" not in json.dumps(metadata, default=str)
