#!/usr/bin/env python3
"""Process-isolated, budgeted surface concurrency for capture.py."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from astrolabe.recipe import load_declarative_recipe
    from astrolabe.recipe_runtime import SandboxedRecipe
    from astrolabe.security import atomic_write_json, atomic_write_text
except ImportError:
    from recipe import load_declarative_recipe  # type: ignore[import-not-found,no-redef]
    from recipe_runtime import SandboxedRecipe  # type: ignore[import-not-found,no-redef]
    from security import atomic_write_json, atomic_write_text  # type: ignore[import-not-found,no-redef]


def _option(arguments: list[str], name: str, default: str | None = None) -> str | None:
    try:
        return arguments[arguments.index(name) + 1]
    except (ValueError, IndexError):
        return default


def _remove_option(arguments: list[str], name: str, *, flag: bool = False) -> list[str]:
    result: list[str] = []
    index = 0
    while index < len(arguments):
        if arguments[index] == name:
            index += 1 if flag else 2
            continue
        result.append(arguments[index])
        index += 1
    return result


def _set_option(arguments: list[str], name: str, value: str) -> list[str]:
    return [*_remove_option(arguments, name), name, value]


def _partition(values: list[str], count: int) -> list[list[str]]:
    groups: list[list[str]] = [[] for _ in range(max(1, min(count, len(values))))]
    for index, value in enumerate(values):
        groups[index % len(groups)].append(value)
    return groups


def _recipe_plan(arguments: list[str]) -> tuple[list[str] | None, bool]:
    recipe_path = _option(arguments, "--recipe")
    if not recipe_path:
        return [], False
    if recipe_path.lower().endswith(".json"):
        declarative = load_declarative_recipe(recipe_path)
        return list(declarative.SURFACES), bool(declarative.ACTIONS or declarative.ACTIVE_PROBES)
    if "--allow-inprocess-python-recipe" in arguments:
        # Do not import an unconstrained fallback merely to plan concurrency.
        return None, True
    sandboxed = SandboxedRecipe(
        recipe_path,
        worker_path=str(Path(__file__).with_name("recipe_worker.py")),
    )
    try:
        return list(sandboxed.SURFACES or []), bool(
            sandboxed._has_drive  # noqa: SLF001 - local protocol object
            or sandboxed.ACTIVE_PROBES
        )
    finally:
        sandboxed.close(force=True)


def build_shards(arguments: list[str], concurrency: int, shard_root: Path) -> list[list[str]]:
    """Create child argv sets with disjoint pages and conservative aggregate budgets."""
    recipe_surfaces, has_actions = _recipe_plan(arguments)
    unknown_recipe_surfaces = recipe_surfaces is None
    seeds = [item for item in (_option(arguments, "--seeds", "") or "").split(",") if item]
    index = 0
    while index < len(arguments):
        if arguments[index] == "--seed" and index + 1 < len(arguments):
            seeds.append(arguments[index + 1])
            index += 2
        else:
            index += 1
    all_surfaces = list(dict.fromkeys([*(recipe_surfaces or []), *seeds]))
    action_seed = (
        all_surfaces[0] if has_actions and all_surfaces and not unknown_recipe_surfaces else None
    )
    independent = all_surfaces[1:] if action_seed else all_surfaces
    worker_slots = concurrency - (1 if has_actions else 0)
    groups = _partition(independent, worker_slots) if independent and worker_slots > 0 else []

    base = list(arguments)
    for option in ("--outdir", "--run-id", "--seeds", "--seed", "--rate-stop-dir"):
        base = _remove_option(base, option)
    base = _remove_option(base, "--introspect", flag=True)
    base = _remove_option(base, "--crawl")
    tasks: list[tuple[list[str], bool]] = []
    if has_actions:
        action = list(base)
        if not unknown_recipe_surfaces:
            action.append("--skip-recipe-surfaces")
        if action_seed:
            action += ["--seed", action_seed]
        tasks.append((action, True))
    no_recipe = list(base)
    for option in ("--recipe",):
        no_recipe = _remove_option(no_recipe, option)
    for flag in ("--trusted-recipe", "--allow-inprocess-python-recipe", "--skip-recipe-surfaces"):
        no_recipe = _remove_option(no_recipe, flag, flag=True)
    for group in groups:
        child = list(no_recipe)
        for surface in group:
            child += ["--seed", surface]
        tasks.append((child, False))
    if not tasks:
        tasks.append((base, bool(_option(base, "--recipe"))))

    count = len(tasks)
    total = max(1, int(_option(arguments, "--max-total-requests", "10000") or 10000) // count)
    origin = max(1, int(_option(arguments, "--max-origin-requests", "5000") or 5000) // count)
    operation = max(
        1,
        int(_option(arguments, "--max-operation-requests", "500") or 500) // count,
    )
    run_id = _option(arguments, "--run-id", "capture") or "capture"
    stop_dir = shard_root / "rate-stops"
    stop_dir.mkdir(parents=True, exist_ok=True)
    output: list[list[str]] = []
    for shard_index, (task, _action) in enumerate(tasks, 1):
        shard_dir = shard_root / f"shard-{shard_index}"
        shard_dir.mkdir(parents=True, exist_ok=True)
        task = _set_option(task, "--outdir", str(shard_dir))
        task = _set_option(task, "--run-id", f"{run_id}-shard-{shard_index}")
        task = _set_option(task, "--max-total-requests", str(total))
        task = _set_option(task, "--max-origin-requests", str(origin))
        task = _set_option(task, "--max-operation-requests", str(operation))
        task = _set_option(task, "--rate-stop-dir", str(stop_dir))
        if shard_index == 1 and "--introspect" in arguments:
            task.append("--introspect")
        if shard_index == 1 and (crawl := _option(arguments, "--crawl")):
            task += ["--crawl", crawl]
        output.append(task)
    return output


def _merge_counts(destination: dict[str, int], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, int):
            destination[key] = destination.get(key, 0) + value


def _merge_websockets(destination: dict[str, Any], source: dict[str, Any]) -> None:
    for url, incoming in source.items():
        if url not in destination:
            destination[url] = incoming
            continue
        current = destination[url]
        for field in ("frames", "binary_frames"):
            current[field] = int(current.get(field, 0)) + int(incoming.get(field, 0))
        current["engineio"] = current.get("engineio") or incoming.get("engineio")
        for direction in ("events_sent", "events_received"):
            events = current.setdefault(direction, {})
            for name, event in (incoming.get(direction) or {}).items():
                if name not in events:
                    events[name] = event
                else:
                    events[name]["count"] = int(events[name].get("count", 0)) + int(
                        event.get("count", 0)
                    )
        for direction in ("sent", "received"):
            current.setdefault("non_socketio", {})[direction] = int(
                current.get("non_socketio", {}).get(direction, 0)
            ) + int(incoming.get("non_socketio", {}).get(direction, 0))


def _failure_summary(failures: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "total": len(failures),
        "by_stage": {},
        "by_category": {},
        "by_surface": {},
    }
    for failure in failures:
        for output, field in (("by_stage", "stage"), ("by_category", "category")):
            key = str(failure.get(field) or "unknown")
            summary[output][key] = summary[output].get(key, 0) + 1
        context = failure.get("context")
        if context:
            key = str(context).split("?", 1)[0]
            summary["by_surface"][key] = summary["by_surface"].get(key, 0) + 1
    return summary


def merge_shards(shard_dirs: list[Path], outdir: Path, run_id: str) -> dict[str, Any]:
    outdir.mkdir(parents=True, exist_ok=True)
    merged: dict[str, Any] = {
        "base_domain": None,
        "graphql_endpoints": {},
        "auth_headers": {},
        "events": {"cf": [], "byparr": [], "introspection": None},
        "websockets": {},
        "service_workers": [],
        "offline_queues": [],
        "request_budgets": {
            "limits": {},
            "used": {"total": 0, "origins": {}, "operations": {}},
            "truncations": [],
            "truncation_count": 0,
            "rate_limits": {},
        },
        "surfaces": [],
        "records": 0,
        "truncations": {},
        "failures": [],
        "interactions": [],
        "authentication": {
            "public_identifier_names": [],
            "secret_credential_names": [],
            "observations": [],
        },
        "run_id": run_id,
        "started_at": None,
        "completed_at": None,
        "captured_at": None,
        "partial": False,
        "parallel_capture": {
            "browser_processes": len(shard_dirs),
            "mutable_page_state_shared": False,
            "budget_strategy": "conservative-partition-with-shared-rate-stop",
            "shards": [],
        },
    }
    capture_lines: list[str] = []
    names: set[str] = set()
    har: dict[str, Any] | None = None
    newest_auth: Path | None = None
    for shard_index, shard in enumerate(shard_dirs, 1):
        prefix = f"shard-{shard_index}-"
        try:
            meta = json.loads((shard / "meta.json").read_text())
        except (OSError, json.JSONDecodeError) as exc:
            merged["partial"] = True
            merged["failures"].append(
                {"stage": "parallel-merge", "category": "artifact", "message": str(exc)}
            )
            continue
        domain = meta.get("base_domain")
        merged["parallel_capture"]["shards"].append(
            {
                "run_id": meta.get("run_id"),
                "records": meta.get("records", 0),
                "meta_sha256": hashlib.sha256((shard / "meta.json").read_bytes()).hexdigest(),
                "capture_sha256": (
                    hashlib.sha256((shard / "capture.jsonl").read_bytes()).hexdigest()
                    if (shard / "capture.jsonl").exists()
                    else None
                ),
            }
        )
        if merged["base_domain"] not in {None, domain}:
            raise ValueError("capture shards disagree on base domain")
        merged["base_domain"] = domain
        merged["partial"] = bool(merged["partial"] or meta.get("partial"))
        merged["proxy_interception"] = meta.get("proxy_interception")
        merged["tls_verification"] = meta.get("tls_verification")
        for endpoint, evidence in (meta.get("graphql_endpoints") or {}).items():
            current = merged["graphql_endpoints"].setdefault(endpoint, {})
            current.update({k: v for k, v in evidence.items() if k != "count"})
            current["count"] = int(current.get("count", 0)) + int(evidence.get("count", 0))
        _merge_counts(merged["auth_headers"], meta.get("auth_headers") or {})
        for kind in ("cf", "byparr"):
            merged["events"][kind].extend((meta.get("events") or {}).get(kind) or [])
        merged["events"]["introspection"] = merged["events"]["introspection"] or (
            meta.get("events") or {}
        ).get("introspection")
        _merge_websockets(merged["websockets"], meta.get("websockets") or {})
        merged["service_workers"] = sorted(
            set(merged["service_workers"]) | set(meta.get("service_workers") or [])
        )
        merged["offline_queues"].extend(meta.get("offline_queues") or [])
        budgets = meta.get("request_budgets") or {}
        limits = budgets.get("limits") or {}
        merged_limits = merged["request_budgets"]["limits"]
        for field in ("total", "per_origin", "per_operation"):
            merged_limits[field] = int(merged_limits.get(field, 0)) + int(limits.get(field, 0))
        merged_limits["rate_limit_reserve"] = max(
            int(merged_limits.get("rate_limit_reserve", 0)),
            int(limits.get("rate_limit_reserve", 0)),
        )
        used = budgets.get("used") or {}
        merged["request_budgets"]["used"]["total"] += int(used.get("total", 0))
        _merge_counts(merged["request_budgets"]["used"]["origins"], used.get("origins") or {})
        _merge_counts(merged["request_budgets"]["used"]["operations"], used.get("operations") or {})
        merged["request_budgets"]["truncations"].extend(budgets.get("truncations") or [])
        merged["request_budgets"]["truncation_count"] += int(budgets.get("truncation_count", 0))
        merged["request_budgets"]["rate_limits"].update(budgets.get("rate_limits") or {})
        merged["surfaces"] = list(
            dict.fromkeys([*merged["surfaces"], *(meta.get("surfaces") or [])])
        )
        merged["records"] += int(meta.get("records", 0))
        _merge_counts(merged["truncations"], meta.get("truncations") or {})
        for failure in meta.get("failures") or []:
            item = dict(failure)
            if item.get("interaction_id"):
                item["interaction_id"] = prefix + str(item["interaction_id"])
            merged["failures"].append(item)
        for interaction in meta.get("interactions") or []:
            item = dict(interaction)
            item["id"] = prefix + str(item.get("id"))
            merged["interactions"].append(item)
        authentication = meta.get("authentication") or {}
        for field in ("public_identifier_names", "secret_credential_names"):
            merged["authentication"][field] = sorted(
                set(merged["authentication"][field]) | set(authentication.get(field) or [])
            )
        for observation in authentication.get("observations") or []:
            item = dict(observation)
            if item.get("interaction_id"):
                item["interaction_id"] = prefix + str(item["interaction_id"])
            merged["authentication"]["observations"].append(item)
        started = meta.get("started_at")
        completed = meta.get("completed_at")
        if started and (not merged["started_at"] or started < merged["started_at"]):
            merged["started_at"] = started
        if completed and (not merged["completed_at"] or completed > merged["completed_at"]):
            merged["completed_at"] = completed

        try:
            for line in (shard / "capture.jsonl").read_text().splitlines():
                record = json.loads(line)
                if record.get("interaction_id"):
                    record["interaction_id"] = prefix + str(record["interaction_id"])
                capture_lines.append(json.dumps(record, separators=(",", ":")))
        except (OSError, json.JSONDecodeError) as exc:
            merged["partial"] = True
            merged["failures"].append(
                {"stage": "parallel-merge", "category": "capture-jsonl", "message": str(exc)}
            )
        try:
            names.update((shard / "graphql-names.txt").read_text().splitlines())
        except OSError:
            merged["partial"] = True
        har_path = shard / "capture.har"
        if har_path.exists():
            incoming_har = json.loads(har_path.read_text())
            incoming_pages = list(incoming_har.get("log", {}).get("pages", []))
            incoming_entries = list(incoming_har.get("log", {}).get("entries", []))
            if har is None:
                har = incoming_har
                har["log"]["entries"] = []
                har["log"]["pages"] = []
            page_map = {
                str(page.get("id")): prefix + str(page.get("id")) for page in incoming_pages
            }
            for page in incoming_pages:
                page = dict(page)
                page["id"] = page_map[str(page.get("id"))]
                har["log"]["pages"].append(page)
            for entry in incoming_entries:
                entry = dict(entry)
                if entry.get("pageref") in page_map:
                    entry["pageref"] = page_map[entry["pageref"]]
                har["log"]["entries"].append(entry)
        auth_path = shard / "auth.headers.json"
        if auth_path.exists() and (
            newest_auth is None or auth_path.stat().st_mtime > newest_auth.stat().st_mtime
        ):
            newest_auth = auth_path

    merged["completed_at"] = merged["completed_at"] or datetime.now(UTC).isoformat()
    merged["captured_at"] = merged["completed_at"]
    merged["failure_summary"] = _failure_summary(merged["failures"])
    atomic_write_text(
        outdir / "capture.jsonl", "\n".join(capture_lines) + ("\n" if capture_lines else "")
    )
    atomic_write_text(
        outdir / "graphql-names.txt", "\n".join(sorted(name for name in names if name))
    )
    atomic_write_json(outdir / "meta.json", merged)
    if har is not None:
        atomic_write_json(outdir / "capture.har", har, mode=0o600)
    if newest_auth is not None:
        shutil.copy2(newest_auth, outdir / "auth.headers.json")
        os.chmod(outdir / "auth.headers.json", 0o600)
    checksums = {}
    for name in ("capture.jsonl", "meta.json", "graphql-names.txt"):
        checksums[name] = hashlib.sha256((outdir / name).read_bytes()).hexdigest()
    atomic_write_json(outdir / "transfer-manifest.json", {"run_id": run_id, "sha256": checksums})
    return merged


_children: set[subprocess.Popen[str]] = set()
_children_lock = threading.Lock()


def _stop_children(_signum: int, _frame: Any) -> None:
    with _children_lock:
        children = list(_children)
    for process in children:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


def _run_child(arguments: list[str], cwd: Path) -> tuple[int, str]:
    process = subprocess.Popen(
        [sys.executable, *arguments],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    with _children_lock:
        _children.add(process)
    try:
        output, _ = process.communicate()
        return process.returncode or 0, output or ""
    finally:
        with _children_lock:
            _children.discard(process)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--concurrency", type=int, required=True)
    parser.add_argument("child", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not 2 <= args.concurrency <= 8:
        raise SystemExit("--concurrency must be between 2 and 8")
    child = list(args.child)
    if child and child[0] == "--":
        child = child[1:]
    if not child or Path(child[0]).name != "capture.py":
        raise SystemExit("parallel capture requires capture.py child argv")
    outdir = Path(_option(child, "--outdir") or ".").resolve()
    run_id = _option(child, "--run-id") or f"parallel-{os.getpid()}"
    shard_root = outdir / ".capture-shards"
    shard_root.mkdir(parents=True, exist_ok=True)
    shards = build_shards(child, args.concurrency, shard_root)
    signal.signal(signal.SIGTERM, _stop_children)
    signal.signal(signal.SIGINT, _stop_children)
    results: list[tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=min(args.concurrency, len(shards))) as pool:
        futures = [pool.submit(_run_child, shard, outdir) for shard in shards]
        for future in as_completed(futures):
            results.append(future.result())
    shard_dirs = [Path(_option(shard, "--outdir") or "") for shard in shards]
    meta = merge_shards(shard_dirs, outdir, run_id)
    if any(code != 0 for code, _output in results):
        meta["partial"] = True
        meta["failures"].append(
            {"stage": "parallel-capture", "category": "worker", "message": "a shard failed"}
        )
        meta["failure_summary"] = _failure_summary(meta["failures"])
        atomic_write_json(outdir / "meta.json", meta)
        checksums = {
            name: hashlib.sha256((outdir / name).read_bytes()).hexdigest()
            for name in ("capture.jsonl", "meta.json", "graphql-names.txt")
        }
        atomic_write_json(
            outdir / "transfer-manifest.json", {"run_id": run_id, "sha256": checksums}
        )
    for _code, output in results:
        if output:
            print(output[-2000:], end="" if output.endswith("\n") else "\n")
    print(
        json.dumps(
            {
                "parallel_shards": len(shards),
                "records": meta.get("records", 0),
                "partial": meta.get("partial", False),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
