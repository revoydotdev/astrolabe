from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from astrolabe import schema_recover


def test_load_headers_rejects_injection_and_protected_headers(tmp_path):
    artifact = tmp_path / "headers.json"
    artifact.write_text(json.dumps({"Authorization": "Bearer ok\r\nX-Evil: yes"}))
    with pytest.raises(ValueError, match="unsafe header value"):
        schema_recover.load_headers(str(artifact))

    artifact.write_text(json.dumps({"Host": "attacker.example"}))
    with pytest.raises(ValueError, match="unsafe header name"):
        schema_recover.load_headers(str(artifact))


def test_recover_skips_clairvoyance_without_suggestion_evidence(tmp_path, monkeypatch):
    headers = tmp_path / "headers.json"
    headers.write_text(json.dumps({"Authorization": "Bearer secret"}))
    monkeypatch.setattr(schema_recover, "suggestion_probe", lambda *args: False)
    monkeypatch.setattr(
        schema_recover.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("clairvoyance must remain gated"),
    )
    report = schema_recover.recover(
        endpoint="https://example.com/graphql",
        allowed_host="example.com",
        headers_path=str(headers),
        clairvoyance="/opt/clairvoyance",
        wordlist=str(tmp_path / "names.txt"),
        schema_out=str(tmp_path / "schema.json"),
        concurrency=1,
        timeout=30,
    )
    assert report == {"suggestions": False, "recovered": False}


def test_recover_passes_secret_header_as_literal_argv_and_promotes_valid_json(
    tmp_path, monkeypatch
):
    headers = tmp_path / "headers.json"
    headers.write_text(json.dumps({"Authorization": "Bearer literal;$(id)"}))
    monkeypatch.setattr(schema_recover, "suggestion_probe", lambda *args: True)
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        Path(argv[argv.index("-o") + 1]).write_text(json.dumps({"data": {"__schema": {}}}))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(schema_recover.subprocess, "run", fake_run)
    destination = tmp_path / "schema.json"
    report = schema_recover.recover(
        endpoint="https://example.com/graphql",
        allowed_host="example.com",
        headers_path=str(headers),
        clairvoyance="/opt/clairvoyance",
        wordlist=str(tmp_path / "names.txt"),
        schema_out=str(destination),
        concurrency=2,
        timeout=30,
    )
    assert report == {"suggestions": True, "recovered": True}
    header_index = seen["argv"].index("-H")
    assert seen["argv"][header_index + 1] == "Authorization: Bearer literal;$(id)"
    assert json.loads(destination.read_text()) == {"data": {"__schema": {}}}


def test_recover_rejects_unbounded_concurrency(tmp_path):
    with pytest.raises(ValueError, match="between 1 and 8"):
        schema_recover.recover(
            endpoint="https://example.com/graphql",
            allowed_host="example.com",
            headers_path=str(tmp_path / "unused.json"),
            clairvoyance="clairvoyance",
            wordlist="names.txt",
            schema_out="schema.json",
            concurrency=99,
            timeout=30,
        )
