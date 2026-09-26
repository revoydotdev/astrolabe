"""End-to-end tests for `astrolabe import-har`: a HAR file recorded elsewhere
becomes a chartable capture dir that `astrolabe mcp-gen` can consume, without
ever persisting a header value, cookie value, or response value the fixture
HAR carries.

Driven through the real CLI process (as the operator would run it), not
through internal functions -- the thing being proven is that the wiring from
`import-har` through `analyze`/`contract` to `mcp-gen` actually works end to
end, and that no planted secret survives the trip onto disk anywhere in the
output directory.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import astrolabe

REPO_ROOT = str(Path(astrolabe.__file__).resolve().parent.parent)
FIXTURE_HAR = str(Path(__file__).resolve().parent / "fixtures" / "sample.har.json")

# Secrets planted in tests/fixtures/sample.har.json. None of these strings may
# appear anywhere under the output directory this command produces.
PLANTED_SECRETS = (
    "s3cr3t-bearer-abcdef123456",  # Authorization: Bearer <token>
    "sess_9f8e7d6c5b4a3210",  # Cookie: session=<value>
    "alice.example.pii@example.com",  # a response body VALUE (PII)
    "bob.example.pii@example.com",  # a second response body VALUE (PII)
)


def _run_cli(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-m", "astrolabe.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _grep_tree_for(root: Path, needle: str) -> list[str]:
    hits = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if needle in text:
            hits.append(str(path))
    return hits


def test_import_har_end_to_end(tmp_path) -> None:
    out_dir = tmp_path / "capture"

    result = _run_cli(
        [
            "import-har",
            FIXTURE_HAR,
            "--domain",
            "example.com",
            "--out",
            str(out_dir),
            "--no-contract-store",
            "--json",
        ],
        cwd=str(tmp_path),
    )
    assert result.returncode == 0, result.stderr
    envelope = json.loads(result.stdout.strip().splitlines()[-1])
    assert envelope["ok"] is True
    assert envelope["command"] == "import-har"
    payload = envelope["result"]
    assert payload["entries_total"] == 10
    # 7 first-party API entries kept: 2x search, 2x profile, graphql, 2x config.
    # (analytics is third-party, logo.png is an image, the last entry is malformed.)
    assert payload["entries_kept"] == 7
    assert payload["failures"] == 1

    # ---- capture.jsonl excludes third-party and image traffic ----
    cap_lines = [
        json.loads(line)
        for line in (out_dir / "capture.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert len(cap_lines) == 7
    urls = {rec["url"] for rec in cap_lines}
    assert all("analytics.example-cdn.net" not in u for u in urls)
    assert all("logo.png" not in u for u in urls)
    assert all(rec.get("evidence_source") == "har-import" for rec in cap_lines)

    # ---- no secret value survives anywhere in the output directory ----
    for secret in PLANTED_SECRETS:
        hits = _grep_tree_for(out_dir, secret)
        assert hits == [], f"planted secret {secret!r} leaked into {hits}"

    # header presence is recorded, never the header value
    auth_records = [rec for rec in cap_lines if "req_headers" in rec]
    assert auth_records
    for rec in auth_records:
        assert rec["req_headers"].get("Authorization") == "<present>"

    # ---- meta.json is stamped as imported evidence ----
    meta = json.loads((out_dir / "meta.json").read_text())
    assert meta["evidence_source"] == "har-import"
    assert meta["import"]["format"] == "har"
    assert meta["import"]["entries_total"] == 10
    assert meta["import"]["entries_kept"] == 7
    assert meta["partial"] is False
    assert meta["interactions"][0]["kind"] == "import"

    # ---- contract.json carries the REST endpoints, labelled as imported ----
    contract = json.loads((out_dir / "contract.json").read_text())
    ops = contract["operations"]
    rest_keys = [k for k, op in ops.items() if op.get("transport") == "rest"]
    assert any(k.startswith("POST ") and "search" in k for k in rest_keys)
    assert any(k.startswith("GET ") and "profile" in k for k in rest_keys)
    assert any(k.startswith("GET ") and "config" in k for k in rest_keys)
    for key in rest_keys:
        observed = ops[key]["proof"]["observed"]
        if observed["ok"]:
            assert observed["source"] == "har-import"

    gql_keys = [k for k, op in ops.items() if op.get("transport") == "graphql"]
    assert "Viewer" in gql_keys
    assert ops["Viewer"]["proof"]["observed"]["source"] == "har-import"
    assert ops["Viewer"]["proof"]["observed"]["ok"] is True

    contract_md = (out_dir / "contract.md").read_text()
    assert "imported" in contract_md

    # ---- artifact manifest records the correct provenance ----
    manifest = json.loads((out_dir / "artifact-manifest.json").read_text())
    assert manifest["artifact_type"] == "har-import"

    # ---- mcp-gen consumes this directory exactly like a live capture ----
    gen = _run_cli(["mcp-gen", str(out_dir), "--json"], cwd=str(tmp_path))
    assert gen.returncode == 0, gen.stderr
    gen_envelope = json.loads(gen.stdout.strip().splitlines()[-1])
    assert gen_envelope["ok"] is True

    toolpack = json.loads((out_dir / "toolpack.json").read_text())
    tool_names = {t["name"] for t in toolpack["tools"]}
    transports = {t["name"]: t["transport"] for t in toolpack["tools"]}
    methods = {t["name"]: t.get("method") for t in toolpack["tools"]}
    assert any(transports.get(name) == "graphql" for name in tool_names)
    assert any(transports.get(name) == "rest" and methods.get(name) == "GET" for name in tool_names)

    # No planted secret leaked into the generated toolpack either.
    toolpack_text = (out_dir / "toolpack.json").read_text()
    for secret in PLANTED_SECRETS:
        assert secret not in toolpack_text
