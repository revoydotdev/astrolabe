from __future__ import annotations

import hashlib
import json
import shutil
import subprocess

import pytest

from astrolabe.analyze import render
from astrolabe.capture import graphql_entries
from astrolabe.mcp_server import ConfigurationError, Settings, _validate_pack
from astrolabe.mcpgen import build_pack
from astrolabe.persisted import (
    MAX_DOCUMENT_BYTES,
    RECOVERY_INIT_SCRIPT,
    RECOVERY_READ_SCRIPT,
    bind_document,
    graphql_response_success,
)


def test_browser_observer_preserves_digest_and_only_exports_matching_documents():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed to exercise Web Crypto")
    script = (
        """
globalThis.crypto = require('node:crypto').webcrypto;
const original = crypto.subtle.digest;
let originalPromise;
crypto.subtle.digest = function(...args) {
  originalPromise = original.apply(this, args);
  return originalPromise;
};
"""
        + RECOVERY_INIT_SCRIPT
        + """
(async () => {
  const encoder = new TextEncoder();
  const input = encoder.encode('query Feed { items }');
  const promise = crypto.subtle.digest('SHA-256', input);
  const identicalPromise = promise === originalPromise;
  const hash = Buffer.from(await promise).toString('hex');
  const nonDocumentHash = Buffer.from(await crypto.subtle.digest('SHA-256', encoder.encode('credential-secret'))).toString('hex');
  const read = """
        + RECOVERY_READ_SCRIPT
        + """;
  console.log(JSON.stringify({identicalPromise, records: read([hash, nonDocumentHash])}));
})();
"""
    )
    result = subprocess.run(
        [node, "-e", script], capture_output=True, text=True, timeout=10, check=True
    )
    value = json.loads(result.stdout)
    assert value["identicalPromise"] is True
    assert value["records"][0]["document"] == "query Feed { items }"
    assert "document" not in value["records"][1]
    assert "credential-secret" not in result.stdout


def entry(document, name="Feed"):
    return graphql_entries(
        {
            "operationName": name,
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": hashlib.sha256(document.encode()).hexdigest(),
                }
            },
            "variables": {"limit": 1},
        },
        "https://example.com/api/gql/Feed",
        "application/json",
    )[0]


def bind(value, document):
    return bind_document(
        value,
        document,
        source_url="https://example.com/feed?token=secret",
        observed_at="2026-09-08T12:00:00+00:00",
    )


def test_exact_document_binding_and_provenance():
    doc = "query Feed($limit: Int!) { items(limit: $limit) { id } }"
    result = bind(entry(doc), doc)
    assert result["semantic_kind"] == "query"
    assert result["declared_variables"] == ["limit"]
    assert result["query"] == doc
    assert "secret" not in json.dumps(result)
    assert result["request_template"]["document_evidence"]["binding"] == "exact-sha256"


@pytest.mark.parametrize(
    "document,name",
    [
        ("query Feed {", "Feed"),
        ("query Other { x }", "Feed"),
        ("query Feed { x } mutation Write { y }", "Feed"),
        ("query Feed { x }" + " " * MAX_DOCUMENT_BYTES, "Feed"),
    ],
)
def test_unusable_documents_stay_unknown(document, name):
    original = entry(document, name)
    assert bind(original, document) == original
    assert original["semantic_kind"] == "unknown"


def test_mismatch_does_not_promote_and_mutation_name_does_not_mislead():
    doc = "mutation Feed { updateTimestamp }"
    assert bind(entry(doc), doc)["semantic_kind"] == "mutation"
    original = entry("query Feed { items }")
    assert bind(original, doc) == original


def test_response_proof_requires_data_without_errors():
    doc = "query Feed { items }"
    entries = [bind(entry(doc), doc)]
    assert graphql_response_success({"data": {"items": []}}, entries)
    for payload in (
        {"errors": [{}]},
        {"data": None},
        {"data": {}},
        {"data": {"items": []}, "errors": [{"message": "failed"}]},
        [{"data": {"items": []}}],
    ):
        assert not graphql_response_success(payload, entries)


def test_capture_graph_toolpack_roundtrip_and_hash_drift(tmp_path):
    doc = "query Feed($limit: Int!) { items(limit: $limit) { id } }"
    recovered = bind(entry(doc), doc)
    recovered["request_template"]["document_evidence"]["observed_response_success"] = True
    record = {
        "method": "POST",
        "url": "https://example.com/api/gql/Feed",
        "status": 200,
        "resp_ct": "text/plain",
        "response_kind": "graphql",
        "request_media_type": "application/json",
        "graphql": [recovered],
        "resp_shape": {"data": {"items": [{"id": "str"}]}},
    }
    (tmp_path / "capture.jsonl").write_text(json.dumps(record) + "\n")
    meta = {
        "base_domain": "example.com",
        "graphql_endpoints": {"/api/gql/Feed": {}},
        "captured_at": "2026-09-08T12:00:00+00:00",
    }
    (tmp_path / "meta.json").write_text(json.dumps(meta))
    render(str(tmp_path), [record], meta)
    pack = build_pack(str(tmp_path))
    tool = next(t for t in pack["tools"] if t["operation"] == "Feed")
    assert tool["exposed"] is True
    assert tool["query"] == doc
    assert tool["request_url"] == record["url"]
    assert tool["input_schema"]["required"] == ["limit"]
    assert tool["document_evidence"]["sha256"] == recovered["persistedHash"]
    settings = Settings(toolpack_path=tmp_path / "toolpack.json", allow_anonymous=True)
    _validate_pack(pack, settings)
    tool["apq_hash"] = "a" * 64
    with pytest.raises(ConfigurationError, match="invalid recovered document evidence"):
        _validate_pack(pack, settings)
