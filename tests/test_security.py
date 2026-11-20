from __future__ import annotations

import gzip
import json

import pytest

from astrolabe.operation import (
    Protocol,
    SemanticKind,
    graphql_protocol,
    semantic_kind,
    verification_allowed,
)
from astrolabe.security import (
    CAPTURE_RAW,
    CAPTURE_SHAPE,
    CAPTURE_VALUES,
    REDACTED,
    capture_fidelity,
    host_matches,
    is_first_party,
    normalize_host,
    redact,
    request_metadata,
    retain_raw,
    retain_values,
    safe_text,
    safe_url,
    structural_shape,
    validate_url,
)


def test_recursive_redaction_covers_the_shapes_credentials_actually_arrive_in() -> None:
    """The redaction guarantee, pinned on production shapes.

    A value only survives redaction when it is opaque AND stored under a
    non-credential key, which no credential path in the package does.
    """
    auth_map = {
        "ViewerSatisfiable": {"authorization": "Bearer canary-credential"},
        "SearchJobs": {"cookie": "sessionid=canary-credential", "x-csrf-token": "canary"},
    }
    cookie_jar = [{"name": "sessionid", "value": "canary-credential", "domain": "example.com"}]
    error = {"message": "upstream rejected token=canary-credential", "raw": b"canary-credential"}
    serialized = json.dumps(redact({**auth_map, "cookies": cookie_jar, **error}))
    assert "canary-credential" not in serialized
    # The key survives, so a diagnostic still says which credential shape was involved.
    assert "authorization" in serialized
    assert "<bytes:" in serialized
    assert redact({"authorization": "x"})["authorization"] == REDACTED


def test_no_unwired_credential_wrapper_in_the_package() -> None:
    """A safeguard nothing constructs fires on nothing and reads as a guarantee.

    ``Secret`` was deleted rather than wired: its ``str()`` returns ``<redacted>``, so
    wrapping live credentials would silently corrupt any implicit string use (building
    a Cookie header) in exchange for protecting a leak no credential path produces.
    """
    import astrolabe.security as security

    assert not hasattr(security, "Secret")


@pytest.mark.parametrize(
    ("host", "allowed", "expected"),
    [
        ("example.com", "example.com", True),
        ("API.EXAMPLE.COM.", "example.com", True),
        ("notexample.com", "example.com", False),
        ("example.com.attacker.test", "example.com", False),
        ("xn--bcher-kva.example", "bücher.example", True),
        ("2001:db8::1", "2001:db8::1", True),
    ],
)
def test_host_boundary_normalization(host: str, allowed: str, expected: bool) -> None:
    assert host_matches(host, allowed) is expected


def test_first_party_handles_ports_and_encoded_hosts() -> None:
    assert is_first_party("https://api.example.com:8443/x", "example.com")
    assert not is_first_party("https://example.com.attacker.test/x", "example.com")
    assert normalize_host("BÜCHER.example.") == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/x",
        "https://user@example.com/x",
        "https://example.com/x#fragment",
        "https://attacker.test/x",
        "https://127.0.0.1/x",
        "https://[::1]/x",
        "https://localhost/x",
        "https://example.com/a/../admin",
        "https://example.com/x\nInjected: yes",
        "file:///etc/passwd",
    ],
)
def test_validate_url_rejects_ambiguous_or_unsafe_targets(url: str) -> None:
    with pytest.raises(ValueError):
        validate_url(url, {"example.com"})


def test_validate_and_sanitize_url() -> None:
    assert validate_url("https://API.EXAMPLE.COM:443/a?q=1", {"example.com"}) == (
        "https://api.example.com:443/a?q=1"
    )
    sanitized = safe_url("https://user:pass@example.com/graphql?alias=Feed&variables=CANARY#secret")
    assert "Feed" in sanitized
    assert "CANARY" not in sanitized
    assert "user" not in sanitized


def test_request_metadata_is_structural_and_optionally_keyed() -> None:
    body = json.dumps({"token": "CANARY", "variables": {"ids": [123]}})
    metadata = request_metadata(
        body, "application/json; charset=utf-8", fingerprint_key=b"k", fidelity=CAPTURE_SHAPE
    )
    assert metadata["request_bytes"] == len(body.encode())
    assert metadata["request_media_type"] == "application/json"
    assert metadata["request_fields"] == ["token", "variables"]
    assert metadata["request_shape"]["token"] == "str"
    assert "CANARY" not in json.dumps(metadata)
    assert len(metadata["request_fingerprint"]) == 64


def test_structural_shape_has_explicit_budget_markers() -> None:
    counters: dict[str, int] = {}
    shaped = structural_shape(
        {"a": {"deep": {"value": "CANARY"}}, "b": 1},
        max_depth=1,
        max_nodes=10,
        max_keys=10,
        counters=counters,
    )
    assert shaped["a"]["deep"]["$astrolabe_truncated"]["reason"] == "depth_budget"
    assert counters == {"depth_budget": 1}
    assert "CANARY" not in json.dumps(shaped)


def test_request_metadata_handles_gzip_and_multipart_without_values() -> None:
    compressed = gzip.compress(json.dumps({"field": "CANARY"}).encode())
    gzip_meta = request_metadata(
        compressed,
        "application/json",
        content_encoding="gzip",
        fidelity=CAPTURE_SHAPE,
    )
    assert gzip_meta["request_shape"] == {"field": "str"}
    assert gzip_meta["request_content_encoding"] == "gzip"
    assert "CANARY" not in json.dumps(gzip_meta)

    multipart = (
        b'--boundary\r\nContent-Disposition: form-data; name="upload"; filename="secret.txt"\r\n'
        b"Content-Type: text/plain\r\n\r\nCANARY\r\n--boundary--\r\n"
    )
    multipart_meta = request_metadata(
        multipart, "multipart/form-data; boundary=boundary", fidelity=CAPTURE_SHAPE
    )
    assert multipart_meta["request_shape"] == {"upload": "str"}
    assert "CANARY" not in json.dumps(multipart_meta)


def test_request_metadata_marks_byte_budget_without_decompression_bomb() -> None:
    counters: dict[str, int] = {}
    compressed = gzip.compress(json.dumps({"field": "x" * 10000}).encode())
    metadata = request_metadata(
        compressed,
        "application/json",
        content_encoding="gzip",
        max_body_bytes=100,
        shape_counters=counters,
    )
    assert metadata["request_truncated"] == {"reason": "body_byte_budget"}
    assert counters["body_byte_budget"] == 1


def test_a_gzipped_request_body_is_inflated_exactly_once(monkeypatch) -> None:
    """One inflation per request, on a real gzip body.

    capture.py decodes once and hands the result to request_metadata; before that the
    same bytes were inflated by _decode_bounded, again by decode_payload inside
    request_metadata, and a third time at the call site. The decode is counted, not
    timed, so this cannot pass on a fast box.
    """
    import astrolabe.payloads as payloads
    import astrolabe.security as security

    calls: list[str] = []
    real_bounded = security._decode_bounded
    real_decode = payloads.decode_payload

    def count(label, real):
        def wrapper(*args, **kwargs):
            calls.append(label)
            return real(*args, **kwargs)

        return wrapper

    monkeypatch.setattr(security, "_decode_bounded", count("_decode_bounded", real_bounded))
    monkeypatch.setattr(security, "decode_payload", count("security.decode_payload", real_decode))
    monkeypatch.setattr(payloads, "decode_payload", count("payloads.decode_payload", real_decode))

    body = gzip.compress(json.dumps({"query": "{viewer}", "variables": {"id": "7"}}).encode())

    # What capture.py now does: one decode at the call site, handed to request_metadata.
    calls.clear()
    decoded = payloads.decode_payload(body, media_type="application/json", content_encoding="gzip")
    shared = request_metadata(
        body,
        "application/json",
        content_encoding="gzip",
        decoded_payload=decoded,
        fidelity=CAPTURE_SHAPE,
    )
    assert calls == ["payloads.decode_payload"], f"inflated more than once: {calls}"
    assert shared["request_packaging"] == ["gzip", "json"]
    assert shared["request_shape"]["query"] == "str"
    assert shared["request_fields"] == ["query", "variables"]

    # A caller that decoded nothing is unchanged, and produces identical metadata.
    calls.clear()
    assert (
        request_metadata(body, "application/json", content_encoding="gzip", fidelity=CAPTURE_SHAPE)
        == shared
    )
    assert calls == ["security.decode_payload"]


def test_a_multi_coded_content_encoding_still_counts_against_the_body_budget() -> None:
    """Pinned because the bounded inflate moved: _decode_bounded reads the whole header
    as one coding, so a comma-separated list has always been recorded as over budget,
    even though decode_payload unwraps the list and succeeds."""
    counters: dict[str, int] = {}
    body = gzip.compress(json.dumps({"field": "x"}).encode())
    metadata = request_metadata(
        body,
        "application/json",
        content_encoding="gzip, identity",
        shape_counters=counters,
        fidelity=CAPTURE_SHAPE,
    )
    assert metadata["request_truncated"] == {"reason": "body_byte_budget"}
    assert metadata["request_shape"] == {"field": "str"}
    assert counters["body_byte_budget"] == 1


def test_atomic_write_json_does_not_reparse_its_own_output(monkeypatch, tmp_path) -> None:
    """The dropped self-check was accidental: json.dumps cannot emit bytes json.loads
    rejects, so it only ever doubled the serialization cost of every atomic write.
    What has to survive it is the durability contract, asserted here rather than assumed."""
    import astrolabe.security as security

    real_loads = json.loads
    loads_calls: list[bytes] = []

    def counted_loads(payload, *args, **kwargs):
        loads_calls.append(payload)
        return real_loads(payload, *args, **kwargs)

    monkeypatch.setattr(json, "loads", counted_loads)

    def write(target, value, **kwargs) -> list[bytes]:
        """One atomic write, and every json.loads it caused."""
        before = len(loads_calls)
        security.atomic_write_json(target, value, **kwargs)
        return loads_calls[before:]

    first = {"records": 2, "failures": []}
    path = tmp_path / "meta.json"
    assert write(path, first) == [], "atomic_write_json still round-trips its own payload"
    assert json.loads(path.read_text()) == first
    assert path.read_bytes().endswith(b"\n")

    # Still atomic: one file, no leftover temp, and the mode is still constrained.
    assert oct(path.stat().st_mode & 0o777) == oct(0o644)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["meta.json"]

    secret = tmp_path / "auth.headers.json"
    assert write(secret, {"authorization": "Bearer CANARY"}, mode=0o600) == []
    assert oct(secret.stat().st_mode & 0o777) == oct(0o600)

    # And the last-known-good backup still happens on overwrite.
    assert write(path, {"records": 3}) == []
    assert json.loads(path.read_text()) == {"records": 3}
    assert json.loads((tmp_path / ".meta.json.lkg").read_text()) == first


def test_safe_text_handles_exceptions_and_assignment_secrets() -> None:
    text = safe_text(RuntimeError("token=CANARY authorization Bearer abc.def"))
    assert "CANARY" not in text
    assert "abc.def" not in text


@pytest.mark.parametrize(
    ("query", "declared", "expected"),
    [
        ("query Feed { feed }", None, SemanticKind.QUERY),
        ("mutation Delete { delete }", None, SemanticKind.MUTATION),
        ("subscription New { new }", None, SemanticKind.SUBSCRIPTION),
        ("{ viewer { id } }", None, SemanticKind.QUERY),
        (None, "persisted", SemanticKind.UNKNOWN),
        (None, "query", SemanticKind.QUERY),
        ("query A{x} mutation B{y}", None, SemanticKind.UNKNOWN),
    ],
)
def test_semantic_kind_requires_trusted_evidence(query, declared, expected) -> None:
    assert semantic_kind(query, declared) is expected


def test_protocols_are_orthogonal_to_semantics() -> None:
    assert graphql_protocol(query="query X{x}", persisted_id=None) is Protocol.GRAPHQL_INLINE
    assert graphql_protocol(query=None, persisted_id="a" * 64) is Protocol.GRAPHQL_APQ
    assert graphql_protocol(query=None, persisted_id="123", url="https://x.test/graphql/123/X") is (
        Protocol.GRAPHQL_X_PERSISTED
    )
    assert (
        graphql_protocol(
            query=None, persisted_id="123", media_type="application/x-www-form-urlencoded"
        )
        is Protocol.GRAPHQL_META_DOC_ID
    )
    assert graphql_protocol(query=None, persisted_id="vendor") is Protocol.GRAPHQL_VENDOR_PERSISTED


def test_active_verification_policy_refuses_unknown_batches_and_needs_two_mutation_opts() -> None:
    assert verification_allowed("Feed", [SemanticKind.QUERY]) == (True, SemanticKind.QUERY)
    assert verification_allowed("Mystery", [SemanticKind.UNKNOWN])[0] is False
    assert verification_allowed("batch", [SemanticKind.QUERY, SemanticKind.MUTATION])[0] is False
    assert verification_allowed("Delete", [SemanticKind.MUTATION], {"Delete"})[0] is False
    assert verification_allowed(
        "Delete", [SemanticKind.MUTATION], {"Delete"}, mutation_runtime_enabled=True
    ) == (True, SemanticKind.MUTATION)
    assert (
        verification_allowed(
            "Other", [SemanticKind.MUTATION], {"Delete"}, mutation_runtime_enabled=True
        )[0]
        is False
    )


# --- capture fidelity (replaces the binary developer-mode firewall) ----------


@pytest.fixture
def _clean_fidelity_env(monkeypatch):
    monkeypatch.delenv("ASTROLABE_CAPTURE_FIDELITY", raising=False)
    monkeypatch.delenv("ASTROLABE_DEVELOPER_MODE", raising=False)
    return monkeypatch


def test_default_fidelity_is_shape(_clean_fidelity_env) -> None:
    # The value-free boundary is the library default; only the agent-facing `map`
    # entrypoint opts into `values` (see mapping_mcp._capture_env).
    assert capture_fidelity() == CAPTURE_SHAPE
    assert retain_values() is False
    assert retain_raw() is False


def test_developer_mode_env_still_selects_raw(_clean_fidelity_env) -> None:
    _clean_fidelity_env.setenv("ASTROLABE_DEVELOPER_MODE", "1")
    assert capture_fidelity() == CAPTURE_RAW
    assert retain_raw() is True


def test_explicit_fidelity_overrides_legacy_flag(_clean_fidelity_env) -> None:
    _clean_fidelity_env.setenv("ASTROLABE_DEVELOPER_MODE", "1")
    _clean_fidelity_env.setenv("ASTROLABE_CAPTURE_FIDELITY", "shape")
    assert capture_fidelity() == CAPTURE_SHAPE
    assert retain_values() is False


def test_unknown_fidelity_is_an_error_not_a_silent_fallback(_clean_fidelity_env) -> None:
    _clean_fidelity_env.setenv("ASTROLABE_CAPTURE_FIDELITY", "loud")
    with pytest.raises(ValueError):
        capture_fidelity()


def test_values_fidelity_keeps_data_but_masks_credentials() -> None:
    payload = {
        "data": {"user": {"id": 42, "name": "Ada", "friend_count": 128}},
        "access_token": "SECRETTOKEN",
        "session": {"xs": "SECRETTOKEN"},
        "note": "Authorization: Bearer SECRETTOKEN here",
    }
    shaped = structural_shape(payload, fidelity=CAPTURE_VALUES)
    # Real, non-sensitive data survives so an agent can read what it mapped.
    assert shaped["data"]["user"]["id"] == 42
    assert shaped["data"]["user"]["name"] == "Ada"
    assert shaped["data"]["user"]["friend_count"] == 128
    # Credential-ish keys are pruned to a marker, subtree and all.
    assert shaped["access_token"] == REDACTED
    assert shaped["session"] == REDACTED
    # Inline bearer secrets inside free-text leaves are scrubbed.
    assert "SECRETTOKEN" not in json.dumps(shaped)


def test_shape_fidelity_collapses_every_value_to_a_type_name() -> None:
    shaped = structural_shape({"id": 42, "name": "Ada"}, fidelity=CAPTURE_SHAPE)
    assert shaped == {"id": "int", "name": "str"}


def test_raw_fidelity_keeps_credentials_verbatim() -> None:
    shaped = structural_shape({"access_token": "SECRETTOKEN"}, fidelity=CAPTURE_RAW)
    assert shaped["access_token"] == "SECRETTOKEN"


def test_request_metadata_default_values_retains_data_masks_token() -> None:
    body = json.dumps({"token": "CANARY", "variables": {"ids": [123]}})
    metadata = request_metadata(body, "application/json", fidelity=CAPTURE_VALUES)
    assert metadata["request_shape"]["token"] == REDACTED
    assert metadata["request_shape"]["variables"]["ids"] == [123]
    assert "CANARY" not in json.dumps(metadata)
