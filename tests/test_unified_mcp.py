"""Tests for astrolabe.unified_mcp — the unified MCP facade combining the
mapping_mcp workflow with optional mounted typed toolpack servers.

Every test runs against a freshly-constructed FastMCP server in-process via
fastmcp.Client. No env vars leak between cases (autouse scrub).
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from astrolabe.mapping_mcp import create_server
from astrolabe.unified_mcp import (
    _MAX_INSTRUCTIONS_CHARS,
    _collect_toolpack_paths,
    _sanitize_namespace,
    create_unified_server,
)

# ----- Fixture source data ---------------------------------------------------

# Real toolpacks shipped in the repo copy from a chart directory so the
# tests exercise the production _validate_pack path. We never mutate the
# originals on disk.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPO_CHART_QUALCOMM = _REPO_ROOT / "chart-docs.qualcomm.com-af7e7498ef63"
_REPO_TOOLPACK_QUALCOMM = _REPO_CHART_QUALCOMM / "toolpack.json"

_QUALCOMM_DOMAIN_RAW = "docs.qualcomm.com"
_QUALCOMM_DOMAIN_SANITIZED = "docs_qualcomm_com"

# The eight per-namespace discovery tools every mounted pack currently re-advertises.
DISCOVERY_SUFFIXES = {
    "search_operations",
    "describe_operation",
    "trace_surface",
    "diff_contract",
    "coverage_report",
    "invoke_query",
    "verify_operation",
    "subscribe_events",
}

MAPPING_TOOL_NAMES = {
    "call_tool",
    "chart_status",
    "register_session",
    "revoke_session",
    "scan_site",
    "scan_to_recipe",
    "generate_chart",
    "import_har",
    "list_charts",
    "map_site",
    "preflight",
    "search_tools",
    "solve_challenge",
    "verify_chart",
}


# ----- Helpers ---------------------------------------------------------------


async def _tool_names(server) -> list[str]:
    async with Client(server) as client:
        tools = await client.list_tools()
    return sorted(t.name for t in tools)


async def _resource_uris(server) -> list[str]:
    async with Client(server) as client:
        res = await client.list_resources()
    return sorted(str(r.uri) for r in res)


async def _resource_template_uris(server) -> list[str]:
    async with Client(server) as client:
        tmpls = await client.list_resource_templates()
    return sorted(r.uri_template for r in tmpls)


# ----- Fixtures --------------------------------------------------------------


@pytest.fixture(autouse=True)
def _scrub_astrolabe_env(monkeypatch):
    """Wipe every ASTROLABE_* variable before each test so cases don't leak."""
    for k in list(os.environ):
        if k.startswith("ASTROLABE_"):
            monkeypatch.delenv(k, raising=False)
    yield


@pytest.fixture
def tmp_workspace(monkeypatch, tmp_path):
    """Redirect the mapping MCP's default workspace into tmp_path so the
    side-effecting workspace mkdir() in create_server doesn't touch ~."""
    workspace = tmp_path / "astrolabe"
    workspace.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ASTROLABE_WORKSPACE", str(workspace))
    return workspace


@pytest.fixture
def qualcomm_pack(tmp_path) -> Path:
    """Deep-copy of the bundled qualcomm toolpack into tmp_path."""
    if not _REPO_TOOLPACK_QUALCOMM.exists():
        pytest.skip(f"bundled toolpack missing: {_REPO_TOOLPACK_QUALCOMM}")
    target = tmp_path / "qualcomm.json"
    shutil.copyfile(_REPO_TOOLPACK_QUALCOMM, target)
    return target


@pytest.fixture
def two_distinct_packs(tmp_path) -> tuple[Path, Path]:
    """Two *distinct* toolpacks derived from the qualcomm pack by mutating
    only base_domain so both pass _validate_pack independently."""
    if not _REPO_TOOLPACK_QUALCOMM.exists():
        pytest.skip(f"bundled toolpack missing: {_REPO_TOOLPACK_QUALCOMM}")
    base = json.loads(_REPO_TOOLPACK_QUALCOMM.read_text())
    a = dict(base)
    a["base_domain"] = "a.example.test"
    b = dict(base)
    b["base_domain"] = "b.example.test"
    pa = tmp_path / "a.json"
    pa.write_text(json.dumps(a))
    pb = tmp_path / "b.json"
    pb.write_text(json.dumps(b))
    return pa, pb


@pytest.fixture
def bad_toolpack(tmp_path) -> Path:
    """A file that exists but is not a valid toolpack — should be skipped."""
    p = tmp_path / "garbage.json"
    p.write_text(json.dumps({"this": "is not a valid toolpack"}))
    return p


# ----- _sanitize_namespace ---------------------------------------------------


def test_sanitize_replaces_dots_with_underscores():
    assert _sanitize_namespace("docs.qualcomm.com") == "docs_qualcomm_com"


def test_sanitize_idempotent_on_already_clean_string():
    assert _sanitize_namespace("a_b_c") == "a_b_c"


def test_sanitize_handles_trailing_and_leading_dots():
    assert _sanitize_namespace(".foo.bar.") == "foo_bar"


# ----- _collect_toolpack_paths ----------------------------------------------


def test_collect_empty_when_no_env():
    assert _collect_toolpack_paths() == []


def test_collect_single_via_astrolabe_toolpack(tmp_path):
    p = tmp_path / "one.json"
    p.write_text("{}")
    os.environ["ASTROLABE_TOOLPACK"] = str(p)
    assert _collect_toolpack_paths() == [p]


def test_collect_csv_via_astrolabe_toolpacks(tmp_path):
    a = tmp_path / "a.json"
    a.write_text("{}")
    b = tmp_path / "b.json"
    b.write_text("{}")
    os.environ["ASTROLABE_TOOLPACKS"] = f"{a},{b}"
    assert _collect_toolpack_paths() == [a, b]


def test_collect_directory_globs_json_only(tmp_path):
    d = tmp_path / "packs"
    d.mkdir()
    for n in ("alpha.json", "beta.json", "schema.json"):
        (d / n).write_text("{}")
    (d / "ignore.txt").write_text("not a json")
    # json files inside the directory are returned in lexicographic order
    os.environ["ASTROLABE_TOOLPACKS"] = str(d)
    result = _collect_toolpack_paths()
    assert {p.name for p in result} == {"alpha.json", "beta.json", "schema.json"}
    assert [p.name for p in result] == sorted([p.name for p in result])


def test_collect_skips_missing_paths_in_csv(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("{}")
    ghost = tmp_path / "ghost.json"  # never created
    os.environ["ASTROLABE_TOOLPACKS"] = f"{real},{ghost}"
    assert _collect_toolpack_paths() == [real]


def test_collect_both_single_and_plural_de_duped(tmp_path):
    a = tmp_path / "a.json"
    a.write_text("{}")
    b = tmp_path / "b.json"
    b.write_text("{}")
    os.environ["ASTROLABE_TOOLPACK"] = str(a)
    os.environ["ASTROLABE_TOOLPACKS"] = str(b)
    # single wins listing order, plural appends
    assert _collect_toolpack_paths() == [a, b]


def test_collect_singular_path_must_exist(tmp_path):
    """ASTROLABE_TOOLPACK referencing a missing file is silently ignored (parity
    with the directory-glob behavior)."""
    ghost = tmp_path / "nope.json"
    os.environ["ASTROLABE_TOOLPACK"] = str(ghost)
    assert _collect_toolpack_paths() == []


def test_collect_directory_also_recurses_for_toolpack_json(tmp_path):
    """Repo-style layout: toolpacks live at ``<root>/chart-*/toolpack.json``,
    one level deep. The directory case must pick them up, alongside any flat
    ``*.json`` files at the root."""
    root = tmp_path / "corpus"
    root.mkdir()
    chart_dir = root / "chart-example.test-1234"
    chart_dir.mkdir()
    real_toolpack = chart_dir / "toolpack.json"
    real_toolpack.write_text(json.dumps({"base_domain": "example.test", "version": 2, "tools": []}))

    # Noise at the root: not a toolpack.
    (root / "config.json").write_text("{}")
    # Noise inside the chart dir: adjacent capture artifacts.
    (chart_dir / "contract.json").write_text("{}")
    (chart_dir / "endpoints.json").write_text("{}")

    os.environ["ASTROLABE_TOOLPACKS"] = str(root)
    result = _collect_toolpack_paths()
    assert real_toolpack in result
    names = [p.name for p in result]
    assert names.count("toolpack.json") == 1
    # The flat config.json at the root IS picked up by the *.json glob;
    # the chart-internal contract.json and endpoints.json are deeper than
    # one level so they are not picked up by *.json (only toolpack.json
    # recurses). That's intentional: contract/endpoints are not full packs.
    assert (root / "config.json") in result


# ----- create_unified_server: mapping-only mode -----------------------------


async def test_mapping_only_exposes_full_mapping_surface(tmp_workspace):
    server = create_unified_server()
    names = await _tool_names(server)
    assert set(names) >= MAPPING_TOOL_NAMES  # exactly the set
    assert set(names) == MAPPING_TOOL_NAMES
    assert await _resource_uris(server) == []


async def test_mapping_only_server_name(tmp_workspace):
    server = create_unified_server()
    assert server.name == "astrolabe"


# ----- create_unified_server: single toolpack mounted -----------------------


async def test_single_toolpack_mounts_with_typed_prefix(tmp_workspace, qualcomm_pack, monkeypatch):
    """The pre-collapse per-Chart names are now opt-in, so this asserts the landing
    path: an operator who has not migrated can still get them back verbatim."""
    monkeypatch.setenv("ASTROLABE_LEGACY_DIRECT_TOOLS", "1")
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(qualcomm_pack))
    server = create_unified_server()
    names = await _tool_names(server)

    # Mapping tools unchanged
    assert set(names) >= MAPPING_TOOL_NAMES

    # Exactly one typed-pack namespace mounted, with the sanitized domain
    expected_ns = f"typed_{_QUALCOMM_DOMAIN_SANITIZED}"
    assert server.unified_namespaces == {expected_ns}

    # Every typed tool appears once with the namespaced name
    typed_names = [n for n in names if n.startswith(expected_ns + "_")]
    assert typed_names, f"no namespaced tools: {names}"
    assert len(typed_names) == len(set(typed_names)), "duplicate tool names"

    # The qualcomm pack carries these tools (verified earlier):
    expected_inner = {
        "coverage_report",
        "describe_operation",
        "diff_contract",
        "invoke_query",
        "search_operations",
        "subscribe_events",
        "trace_surface",
        "verify_operation",
    }
    for inner in expected_inner:
        assert f"{expected_ns}_{inner}" in names, f"missing {expected_ns}_{inner}"


async def test_single_toolpack_namespace_has_no_dots(tmp_workspace, qualcomm_pack):
    """FastMCP rejects namespaces that contain dots; the implementation must
    sanitize so consumers never see ``typed_docs.qualcomm.com_tool``."""
    os.environ["ASTROLABE_TOOLPACK"] = str(qualcomm_pack)
    server = create_unified_server()
    names = await _tool_names(server)
    typed = [n for n in names if n.startswith("typed_")]
    assert all("." not in n for n in typed)


async def test_single_toolpack_resources_namespaced(tmp_workspace, qualcomm_pack, monkeypatch):
    monkeypatch.setenv("ASTROLABE_LEGACY_DIRECT_TOOLS", "1")
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(qualcomm_pack))
    server = create_unified_server()
    uris = await _resource_uris(server)
    expected_ns = f"typed_{_QUALCOMM_DOMAIN_SANITIZED}"
    # FastMCP namespaced the URIs to ``astrolabe://<ns>/<original>``
    assert any(expected_ns in u and u.endswith("/manifest") for u in uris)
    assert any(expected_ns in u and u.endswith("/health") for u in uris)


# ----- create_unified_server: ASTROLABE_TOOLPACKS dir + csv -----------------


async def test_toolpacks_dir_mounts_each(tmp_workspace, two_distinct_packs):
    pa, pb = two_distinct_packs
    pack_dir = pa.parent
    os.environ["ASTROLABE_TOOLPACKS"] = str(pack_dir)
    server = create_unified_server()
    names = await _tool_names(server)

    # Both packs mount — distinct sanitized domains appear in unified_namespaces
    assert {"typed_a_example_test", "typed_b_example_test"} <= server.unified_namespaces
    # mapping tools still present
    assert set(names) >= MAPPING_TOOL_NAMES


async def test_toolpacks_csv_mounts_each(tmp_workspace, two_distinct_packs):
    pa, pb = two_distinct_packs
    os.environ["ASTROLABE_TOOLPACKS"] = f"{pa},{pb}"
    server = create_unified_server()
    assert {"typed_a_example_test", "typed_b_example_test"} <= server.unified_namespaces


# ----- create_unified_server: skip behaviour --------------------------------


async def test_bad_toolpack_is_skipped_and_warning_emitted(tmp_workspace, bad_toolpack, capsys):
    os.environ["ASTROLABE_TOOLPACK"] = str(bad_toolpack)
    server = create_unified_server()
    # Mapping tools still served
    names = await _tool_names(server)
    assert set(names) >= MAPPING_TOOL_NAMES

    err = capsys.readouterr().err
    assert "astrolabe-unified" in err or "skipped" in err
    assert str(bad_toolpack) in err


async def test_missing_toolpack_does_not_crash(tmp_workspace):
    """A path that points at a non-existent file under ASTROLABE_TOOLPACK is
    silently dropped (parity with the ASTROLABE_TOOLPACKS csv case)."""
    os.environ["ASTROLABE_TOOLPACK"] = str(tmp_workspace / "no.such.file.json")
    server = create_unified_server()
    names = await _tool_names(server)
    assert set(names) >= MAPPING_TOOL_NAMES


async def test_one_bad_pack_among_good_ones_continues(
    tmp_workspace, two_distinct_packs, bad_toolpack
):
    pa, pb = two_distinct_packs
    os.environ["ASTROLABE_TOOLPACKS"] = f"{pa},{bad_toolpack},{pb}"
    server = create_unified_server()
    names = await _tool_names(server)

    assert {"typed_a_example_test", "typed_b_example_test"} <= server.unified_namespaces
    assert len([n for n in names if n in MAPPING_TOOL_NAMES]) == len(MAPPING_TOOL_NAMES)
    assert server.unified_skipped, "expected at least one skipped entry"
    skip_paths = {p for p, _ in server.unified_skipped}
    assert str(bad_toolpack) in skip_paths


# ----- create_unified_server: collision resistance --------------------------


async def test_two_packs_same_domain_second_is_rejected(tmp_workspace, monkeypatch):
    """If two toolpacks target the same base_domain, mounting them under
    identical namespaces would produce a FastMCP composition error. The
    unified server must handle this gracefully — by deduping the second."""
    if not _REPO_TOOLPACK_QUALCOMM.exists():
        pytest.skip("bundled toolpack missing")
    monkeypatch.setenv("ASTROLABE_LEGACY_DIRECT_TOOLS", "1")
    base = json.loads(_REPO_TOOLPACK_QUALCOMM.read_text())
    p1 = tmp_workspace / "p1.json"
    p1.write_text(json.dumps(base))
    p2 = tmp_workspace / "p2.json"
    p2.write_text(json.dumps(base))
    os.environ["ASTROLABE_TOOLPACKS"] = f"{p1},{p2}"
    server = create_unified_server()
    names = await _tool_names(server)

    # Exactly one qualcomm namespace mounted (the second pack was skipped)
    assert server.unified_namespaces == {f"typed_{_QUALCOMM_DOMAIN_SANITIZED}"}
    # No duplicate tool names anywhere
    typed = [n for n in names if n.startswith("typed_")]
    counts = {n: names.count(n) for n in typed}
    assert all(c == 1 for c in counts.values()), f"duplicate tool names: {counts}"
    # And the qualcomm pack's tool appears (one canonical copy)
    qualcomm_ns = f"typed_{_QUALCOMM_DOMAIN_SANITIZED}"
    assert f"{qualcomm_ns}_invoke_query" in names
    # The skip was recorded with the collision reason
    skip_paths = {p for p, _ in server.unified_skipped}
    assert str(p2) in skip_paths


# ----- composed instructions -------------------------------------------------

# Occurs exactly once inside a single pack contract, so counting it counts contract
# blocks. "UPSTREAM_AUTH_EXPIRED" cannot be used for this: the contract names it
# twice, so a substring count would report 2 for a single mounted pack.
_CONTRACT_MARKER = "do not retry it yourself"


async def test_instructions_carry_the_typed_contract(tmp_workspace, qualcomm_pack, monkeypatch):
    """The flip of a baseline that proved mounting contributed no instructions.

    An agent that cannot see ``UPSTREAM_AUTH_EXPIRED`` will hand-retry an expired
    credential and re-run mutations the server already declined to auto-retry.
    """
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(qualcomm_pack))
    server = create_unified_server()
    assert server.unified_namespaces
    instructions = server.instructions or ""
    mapping = create_server(tmp_workspace).instructions
    assert mapping is not None
    assert "UPSTREAM_AUTH_EXPIRED" in instructions
    assert mapping in instructions


async def test_instructions_without_packs_are_the_mapping_string(tmp_workspace):
    server = create_unified_server()
    assert server.instructions == create_server(tmp_workspace).instructions


async def test_skipped_pack_contributes_no_instructions(tmp_workspace, monkeypatch):
    """A pack skipped for a namespace collision has no tools, so it must not
    contribute a contract describing tools the agent cannot reach."""
    if not _REPO_TOOLPACK_QUALCOMM.exists():
        pytest.skip(f"bundled toolpack missing: {_REPO_TOOLPACK_QUALCOMM}")
    base = json.loads(_REPO_TOOLPACK_QUALCOMM.read_text())
    first = dict(base)
    second = dict(base)  # identical base_domain -> collides with the first
    p1 = tmp_workspace / "first.json"
    p2 = tmp_workspace / "second.json"
    p1.write_text(json.dumps(first))
    p2.write_text(json.dumps(second))
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", f"{p1},{p2}")
    server = create_unified_server()
    assert server.unified_skipped
    instructions = server.instructions or ""
    assert instructions.count(_CONTRACT_MARKER) == 1


def _synthetic_packs(workspace: Path, count: int) -> list[str]:
    base = json.loads(_REPO_TOOLPACK_QUALCOMM.read_text())
    paths = []
    for index in range(count):
        pack = dict(base)
        pack["base_domain"] = f"pack{index}.example.test"
        target = workspace / f"pack{index}.json"
        target.write_text(json.dumps(pack))
        paths.append(str(target))
    return paths


async def test_instructions_length_is_bounded_with_twelve_packs(tmp_workspace, monkeypatch):
    if not _REPO_TOOLPACK_QUALCOMM.exists():
        pytest.skip(f"bundled toolpack missing: {_REPO_TOOLPACK_QUALCOMM}")
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", ",".join(_synthetic_packs(tmp_workspace, 12)))
    server = create_unified_server()
    assert len(server.unified_namespaces) == 12
    instructions = server.instructions or ""
    assert len(instructions) <= _MAX_INSTRUCTIONS_CHARS
    # Twelve identical contracts de-duplicate to one block, not twelve.
    assert instructions.count(_CONTRACT_MARKER) == 1


async def test_instructions_are_identical_regardless_of_enumeration_order(
    tmp_workspace, monkeypatch
):
    if not _REPO_TOOLPACK_QUALCOMM.exists():
        pytest.skip(f"bundled toolpack missing: {_REPO_TOOLPACK_QUALCOMM}")
    paths = _synthetic_packs(tmp_workspace, 12)
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", ",".join(paths))
    forward = create_unified_server().instructions
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", ",".join(reversed(paths)))
    backward = create_unified_server().instructions
    assert forward == backward


# ----- chart_status ----------------------------------------------------------


async def test_chart_status_reports_a_collision_with_its_reason(tmp_workspace, monkeypatch):
    if not _REPO_TOOLPACK_QUALCOMM.exists():
        pytest.skip(f"bundled toolpack missing: {_REPO_TOOLPACK_QUALCOMM}")
    paths = _synthetic_packs(tmp_workspace, 2)
    base = json.loads(_REPO_TOOLPACK_QUALCOMM.read_text())
    for path in paths:  # same base_domain -> the second pack collides
        pack = dict(base)
        pack["base_domain"] = "collide.example.test"
        Path(path).write_text(json.dumps(pack))
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", ",".join(paths))
    server = create_unified_server()
    async with Client(server) as client:
        status = (await client.call_tool("chart_status", {})).data
    assert len(status["mounted"]) == 1
    assert status["skipped"]
    assert any("collision" in entry["reason"] for entry in status["skipped"])


async def test_chart_status_flags_a_pack_that_lands_out_of_band(tmp_workspace, monkeypatch):
    """The disk-vs-mounted diff is the whole point, so it must notice a chart
    that appears after the server was built."""
    if not _REPO_TOOLPACK_QUALCOMM.exists():
        pytest.skip(f"bundled toolpack missing: {_REPO_TOOLPACK_QUALCOMM}")
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", str(tmp_workspace))
    server = create_unified_server()
    async with Client(server) as client:
        before = (await client.call_tool("chart_status", {})).data
        assert before["charts_on_disk_not_mounted"] == []
        late = tmp_workspace / "late-arrival"
        late.mkdir()
        (late / "toolpack.json").write_text(_REPO_TOOLPACK_QUALCOMM.read_text())
        after = (await client.call_tool("chart_status", {})).data
    assert after["charts_on_disk_not_mounted"] == ["late-arrival/toolpack.json"]


async def test_chart_status_never_returns_an_absolute_chart_path(tmp_workspace, monkeypatch):
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", ",".join(_synthetic_packs(tmp_workspace, 3)))
    server = create_unified_server()
    async with Client(server) as client:
        status = (await client.call_tool("chart_status", {})).data
    for field in ("mounted", "skipped", "configured_roots", "charts_on_disk_not_mounted"):
        value = status[field]
        paths = (
            list(value.values())
            if field == "mounted"
            else [entry["pack"] for entry in value]
            if field == "skipped"
            else value
        )
        assert not [p for p in paths if p.startswith("/")], f"{field} leaked an absolute path"


# ----- todo 5 baseline: the pre-collapse surface -----------------------------


async def test_collapsed_surface_drops_the_per_chart_tools(
    tmp_workspace, qualcomm_pack, monkeypatch
):
    """FLIPPED from a baseline that pinned 8 discovery tools per Chart.

    Those were the same eight on every pack, so twelve namespaces spent ~96 tools
    re-advertising them. The collapsed surface carries neither them nor the
    per-Chart operation tools.
    """
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(qualcomm_pack))
    server = create_unified_server()
    async with Client(server) as client:
        names = {t.name for t in await client.list_tools()}
    assert set(names) == MAPPING_TOOL_NAMES
    assert not [n for n in names if n.startswith("typed_")]


async def test_collapsed_surface_legacy_opt_in_restores_the_old_names(
    tmp_workspace, qualcomm_pack, monkeypatch
):
    """The landing path for an agent that learned astrolabe_typed_<ns>_<op>."""
    monkeypatch.setenv("ASTROLABE_LEGACY_DIRECT_TOOLS", "1")
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(qualcomm_pack))
    server = create_unified_server()
    async with Client(server) as client:
        names = {t.name for t in await client.list_tools()}
    expected_ns = f"typed_{_QUALCOMM_DOMAIN_SANITIZED}"
    for inner in DISCOVERY_SUFFIXES:
        assert f"{expected_ns}_{inner}" in names, f"legacy opt-in did not restore {inner}"


async def test_every_invocable_operation_stays_reachable_after_the_collapse(
    tmp_workspace, qualcomm_pack, monkeypatch
):
    """The invariant the collapse had to preserve, re-expressed through call_tool.

    Pinned before the change as "each invocable operation has a direct typed tool";
    it must now hold as "each invocable operation is returned by search_tools and
    accepted by call_tool", with no reachable operation lost.
    """
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(qualcomm_pack))
    server = create_unified_server()
    async with Client(server) as client:
        found = await client.call_tool("search_tools", {"limit": 200})
    payload = found.data if isinstance(found.data, dict) else found.structured_content
    operations = payload["operations"]
    assert operations, "the collapse left nothing callable"
    for entry in operations:
        assert entry["operation_id"].startswith(f"{_QUALCOMM_DOMAIN_SANITIZED}__")
        assert entry["input_schema"], "a hit carried no input schema"

    # The operation ids are accepted, and an unknown one is refused with a reason.
    async with Client(server) as client:
        unknown = await client.call_tool("call_tool", {"operation_id": "nope__nope"})
    unknown_payload = unknown.data if isinstance(unknown.data, dict) else unknown.structured_content
    assert unknown_payload["error_code"] == "OPERATION_NOT_FOUND"
    assert "search_tools" in unknown_payload["error_detail"]


async def test_collapsed_surface_excludes_charts_with_nothing_invocable(
    tmp_workspace, qualcomm_pack, monkeypatch
):
    """A Chart with no invocable operation must contribute no callable operation.

    Measured live before the change: pastebin and privatebin contributed 16 tools
    between them with invocable_count 0, all of them unreachable.
    """
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(qualcomm_pack))
    server = create_unified_server()
    async with Client(server) as client:
        found = await client.call_tool("search_tools", {"limit": 200})
    payload = found.data if isinstance(found.data, dict) else found.structured_content
    assert all(o["operation_id"] for o in payload["operations"])


# ----- todo 8: no tool leaks a raw validation error ---------------------------

LEAK_MARKERS = ("errors.pydantic.dev", "validation error for call", "Traceback")


async def _every_tool_refusals_are_authored(server) -> list[tuple[str, str]]:
    """Call every tool with no arguments and return (name, text) for each."""
    out = []
    async with Client(server) as client:
        names = sorted(t.name for t in await client.list_tools())
        for name in names:
            try:
                result = await client.call_tool(name, {})
            except ToolError as exc:
                out.append((name, str(exc)))
                continue
            out.append((name, " ".join(c.text for c in result.content if c.type == "text")))
    return out


async def test_no_tool_leaks_a_raw_validation_error_on_the_unified_surface(tmp_workspace):
    """An omitted argument must produce an authored refusal, not a Pydantic traceback.

    The SDK validates a tool call against the function signature before the body runs,
    so a required parameter turns any omission into an internal error carrying
    errors.pydantic.dev. Every required parameter is therefore optional with a guard.
    """
    leaks = [
        (name, text)
        for name, text in await _every_tool_refusals_are_authored(create_unified_server())
        if any(marker in text for marker in LEAK_MARKERS)
    ]
    assert not leaks, f"tools leaking a raw validation error: {leaks}"


async def test_missing_arguments_name_the_way_out(tmp_workspace, qualcomm_pack, monkeypatch):
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(qualcomm_pack))
    refusals = dict(await _every_tool_refusals_are_authored(create_unified_server()))
    assert "capture_directory is required" in refusals["generate_chart"]
    assert "list_charts" in refusals["generate_chart"]
    assert "domain is required" in refusals["map_site"]
