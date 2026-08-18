"""Tests for process-isolated browser surface sharding and artifact merge."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from astrolabe.capture_parallel import build_shards, main, merge_shards


def _option(arguments: list[str], name: str) -> str | None:
    try:
        return arguments[arguments.index(name) + 1]
    except (ValueError, IndexError):
        return None


def _seed_values(arguments: list[str]) -> list[str]:
    return [arguments[index + 1] for index, value in enumerate(arguments[:-1]) if value == "--seed"]


def test_declarative_surfaces_are_partitioned_without_shared_pages(tmp_path: Path) -> None:
    recipe = tmp_path / "recipe.json"
    surfaces = [f"https://example.com/{index}" for index in range(5)]
    recipe.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "surfaces": surfaces,
                "actions": [{"action": "wait", "milliseconds": 1}],
            }
        )
    )
    arguments = [
        "capture.py",
        "--base-domain",
        "example.com",
        "--outdir",
        str(tmp_path / "out"),
        "--run-id",
        "parent",
        "--recipe",
        str(recipe),
        "--max-total-requests",
        "300",
        "--max-origin-requests",
        "150",
        "--max-operation-requests",
        "30",
        "--introspect",
    ]
    shards = build_shards(arguments, 3, tmp_path / "shards")
    assert len(shards) == 3
    assert "--recipe" in shards[0]
    assert "--skip-recipe-surfaces" in shards[0]
    assert "--recipe" not in shards[1]
    assert "--recipe" not in shards[2]
    assert [surface for shard in shards for surface in _seed_values(shard)] == [
        surfaces[0],
        surfaces[1],
        surfaces[3],
        surfaces[2],
        surfaces[4],
    ]
    assert sum(int(_option(shard, "--max-total-requests") or 0) for shard in shards) == 300
    assert sum(int(_option(shard, "--max-origin-requests") or 0) for shard in shards) == 150
    assert sum(int(_option(shard, "--max-operation-requests") or 0) for shard in shards) == 30
    assert sum("--introspect" in shard for shard in shards) == 1
    assert len({_option(shard, "--outdir") for shard in shards}) == 3
    assert len({_option(shard, "--rate-stop-dir") for shard in shards}) == 1


def test_unconstrained_fallback_is_not_imported_for_shard_planning(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    recipe = tmp_path / "recipe.py"
    recipe.write_text(f"open({str(marker)!r}, 'w').write('bad')\nSURFACES=['https://example.com']\n")
    arguments = [
        "capture.py",
        "--outdir",
        str(tmp_path / "out"),
        "--recipe",
        str(recipe),
        "--allow-inprocess-python-recipe",
        "--seed",
        "https://example.com/explicit",
    ]
    shards = build_shards(arguments, 2, tmp_path / "shards")
    assert not marker.exists()
    assert "--skip-recipe-surfaces" not in shards[0]
    assert any("--recipe" in shard for shard in shards)


def _write_shard(path: Path, index: int) -> None:
    path.mkdir(parents=True)
    interaction = f"interaction-{index}"
    meta = {
        "base_domain": "example.com",
        "graphql_endpoints": {"/graphql": {"count": index}},
        "auth_headers": {"authorization": index},
        "events": {"cf": [], "byparr": [], "introspection": None},
        "websockets": {},
        "service_workers": [f"https://example.com/sw-{index}.js"],
        "offline_queues": [],
        "request_budgets": {
            "limits": {
                "total": 10,
                "per_origin": 8,
                "per_operation": 4,
                "rate_limit_reserve": 1,
            },
            "used": {
                "total": index,
                "origins": {"https://example.com": index},
                "operations": {"GET /api": index},
            },
            "truncations": [],
            "truncation_count": 0,
            "rate_limits": {},
        },
        "surfaces": [f"https://example.com/{index}"],
        "records": 1,
        "truncations": {},
        "failures": [],
        "interactions": [{"id": interaction, "kind": "navigation"}],
        "authentication": {
            "public_identifier_names": [],
            "secret_credential_names": ["authorization"],
            "observations": [{"credential_name": "authorization", "interaction_id": interaction}],
        },
        "run_id": f"child-{index}",
        "started_at": f"2026-08-14T00:00:0{index}+00:00",
        "completed_at": f"2026-08-14T00:01:0{index}+00:00",
        "partial": False,
        "proxy_interception": False,
        "tls_verification": "strict",
    }
    (path / "meta.json").write_text(json.dumps(meta))
    (path / "capture.jsonl").write_text(
        json.dumps({"url": "https://example.com/api", "interaction_id": interaction}) + "\n"
    )
    (path / "graphql-names.txt").write_text(f"Query{index}\n")
    (path / "capture.har").write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "test", "version": "1"},
                    "pages": [{"id": "page", "title": str(index)}],
                    "entries": [{"pageref": "page", "request": {"url": "https://example.com"}}],
                }
            }
        )
    )


def test_merge_shards_preserves_lineage_budgets_and_har_pages(tmp_path: Path) -> None:
    shards = [tmp_path / "one", tmp_path / "two"]
    for index, shard in enumerate(shards, 1):
        _write_shard(shard, index)
    out = tmp_path / "merged"
    merged = merge_shards(shards, out, "parent-run")
    assert merged["run_id"] == "parent-run"
    assert merged["records"] == 2
    assert merged["graphql_endpoints"]["/graphql"]["count"] == 3
    assert merged["request_budgets"]["limits"]["total"] == 20
    assert merged["request_budgets"]["used"]["total"] == 3
    assert [item["run_id"] for item in merged["parallel_capture"]["shards"]] == [
        "child-1",
        "child-2",
    ]
    assert all(item["capture_sha256"] for item in merged["parallel_capture"]["shards"])
    assert [item["id"] for item in merged["interactions"]] == [
        "shard-1-interaction-1",
        "shard-2-interaction-2",
    ]
    records = [json.loads(line) for line in (out / "capture.jsonl").read_text().splitlines()]
    assert [item["interaction_id"] for item in records] == [
        "shard-1-interaction-1",
        "shard-2-interaction-2",
    ]
    har = json.loads((out / "capture.har").read_text())
    assert [page["id"] for page in har["log"]["pages"]] == [
        "shard-1-page",
        "shard-2-page",
    ]
    assert [entry["pageref"] for entry in har["log"]["entries"]] == [
        "shard-1-page",
        "shard-2-page",
    ]
    manifest = json.loads((out / "transfer-manifest.json").read_text())
    assert manifest["run_id"] == "parent-run"
    for name, digest in manifest["sha256"].items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest


def test_parallel_controller_runs_real_independent_child_processes(tmp_path: Path) -> None:
    capture = tmp_path / "capture.py"
    capture.write_text(
        "import argparse,json,os\n"
        "p=argparse.ArgumentParser(); p.add_argument('--outdir'); p.add_argument('--run-id'); "
        "p.add_argument('--seed',action='append',default=[]); "
        "p.add_argument('--max-total-requests',type=int,default=10); "
        "p.add_argument('--max-origin-requests',type=int,default=10); "
        "p.add_argument('--max-operation-requests',type=int,default=10); "
        "p.add_argument('--rate-limit-reserve',type=int,default=1); a,_=p.parse_known_args(); "
        "os.makedirs(a.outdir,exist_ok=True); "
        "meta={'base_domain':'example.com','graphql_endpoints':{},'auth_headers':{},"
        "'events':{'cf':[],'byparr':[],'introspection':None},'websockets':{},"
        "'service_workers':[],'offline_queues':[],'request_budgets':{'limits':"
        "{'total':a.max_total_requests,'per_origin':a.max_origin_requests,"
        "'per_operation':a.max_operation_requests,'rate_limit_reserve':a.rate_limit_reserve},"
        "'used':{'total':1,'origins':{},'operations':{}},'truncations':[],"
        "'truncation_count':0,'rate_limits':{}},'surfaces':a.seed,'records':1,"
        "'truncations':{},'failures':[],'interactions':[],'authentication':"
        "{'public_identifier_names':[],'secret_credential_names':[],'observations':[]},"
        "'run_id':a.run_id,'started_at':'2026-08-14T00:00:00+00:00',"
        "'completed_at':'2026-08-14T00:00:01+00:00','partial':False,"
        "'proxy_interception':False,'tls_verification':'strict'}; "
        "open(os.path.join(a.outdir,'meta.json'),'w').write(json.dumps(meta)); "
        "open(os.path.join(a.outdir,'capture.jsonl'),'w').write('{}\\n'); "
        "open(os.path.join(a.outdir,'graphql-names.txt'),'w').write('')\n"
    )
    out = tmp_path / "out"
    result = main(
        [
            "--concurrency",
            "2",
            "--",
            str(capture),
            "--outdir",
            str(out),
            "--run-id",
            "parent",
            "--seed",
            "https://example.com/1",
            "--seed",
            "https://example.com/2",
            "--seed",
            "https://example.com/3",
            "--seed",
            "https://example.com/4",
            "--max-total-requests",
            "100",
            "--max-origin-requests",
            "80",
            "--max-operation-requests",
            "40",
        ]
    )
    assert result == 0
    merged = json.loads((out / "meta.json").read_text())
    assert merged["run_id"] == "parent"
    assert merged["records"] == 2
    assert set(merged["surfaces"]) == {
        "https://example.com/1",
        "https://example.com/2",
        "https://example.com/3",
        "https://example.com/4",
    }
    assert len(list((out / ".capture-shards").glob("shard-*"))) == 2
