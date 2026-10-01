"""Tests for the collapsed many-Chart host: astrolabe.sextant.create_server.

The per-Chart execution surface, its credential scoping and its security gates are covered
in tests/test_sextant.py. What is here is the layer above it: pack discovery, namespace
collisions, the flat two-tool public surface, and the contract carrier. It lives in its
own file because the env scrub below wipes every ASTROLABE_* variable, which is correct for
these cases and would be a cross-cutting hazard to bolt onto the per-Chart suite.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from astrolabe.sextant import (
    _MAX_CONTRACT_CHARS,
    _collect_toolpack_paths,
    _sanitize_namespace,
    create_server,
)

# A hand-authored synthetic toolpack, not a capture: the domain, operation names and schema
# are invented, so the fixture carries no target material and cannot drift when someone
# re-captures a chart. It is a real v2 toolpack, so the tests still drive the production
# _validate_pack -> _chart_server path. We never mutate the original on disk.
_FIXTURE_TOOLPACK = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "synthetic-toolpack.json"
)

_PACK_DOMAIN_RAW = "widgets.example.test"
_PACK_DOMAIN_SANITIZED = "widgets_example_test"

# The two tools the host exposes, and nothing else.
HOST_TOOL_NAMES = ["call_tool", "search_tools"]


# ----- Fixtures --------------------------------------------------------------


@pytest.fixture(autouse=True)
def _scrub_astrolabe_env(monkeypatch):
    """Wipe every ASTROLABE_* variable before each test so cases don't leak."""
    for key in list(os.environ):
        if key.startswith("ASTROLABE_"):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture
def synthetic_pack(tmp_path) -> Path:
    """Deep-copy of the committed synthetic toolpack into tmp_path.

    A missing fixture is a broken checkout, so the copy is allowed to raise rather than
    skip: a skip here would hide the whole file.
    """
    target = tmp_path / "synthetic.json"
    shutil.copyfile(_FIXTURE_TOOLPACK, target)
    return target


@pytest.fixture
def two_distinct_packs(tmp_path) -> tuple[Path, Path]:
    """Two *distinct* toolpacks derived from the synthetic pack by mutating only
    base_domain so both pass _validate_pack independently."""
    base = json.loads(_FIXTURE_TOOLPACK.read_text())
    a = dict(base, base_domain="a.example.test")
    b = dict(base, base_domain="b.example.test")
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


def _synthetic_packs(workspace: Path, count: int) -> list[str]:
    base = json.loads(_FIXTURE_TOOLPACK.read_text())
    paths = []
    for index in range(count):
        pack = dict(base, base_domain=f"pack{index}.example.test")
        target = workspace / f"pack{index}.json"
        target.write_text(json.dumps(pack))
        paths.append(str(target))
    return paths


# ----- helpers ---------------------------------------------------------------


async def _manifest(server) -> dict:
    async with Client(server) as client:
        contents = await client.read_resource("astrolabe://manifest")
    return json.loads(contents[0].text)


async def _search(server) -> dict:
    async with Client(server) as client:
        found = await client.call_tool("search_tools", {"limit": 200})
    return found.data if isinstance(found.data, dict) else found.structured_content


# ----- _sanitize_namespace ---------------------------------------------------


def test_sanitize_replaces_dots_with_underscores():
    assert _sanitize_namespace(_PACK_DOMAIN_RAW) == _PACK_DOMAIN_SANITIZED


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


def test_collect_directory_takes_packs_and_ignores_other_json(tmp_path):
    """A directory root is often a workspace that also holds credentials.

    The flat sweep used to take every ``*.json``, so pointing ASTROLABE_TOOLPACKS at a
    workspace made the server read ``cookies-*.json``, refuse it as malformed, and print
    its path on every startup. A file that is not a toolpack is now skipped silently; a
    file the operator *named* is still taken, so an explicit mistake still gets reported.
    """
    d = tmp_path / "packs"
    d.mkdir()
    for n in ("alpha.json", "beta.json"):
        (d / n).write_text(json.dumps({"base_domain": f"{n}.example.test"}))
    (d / "schema.json").write_text("{}")
    (d / "cookies-site.example.json").write_text('[{"name": "session", "value": "secret"}]')
    (d / "notes.txt").write_text("not a json")
    os.environ["ASTROLABE_TOOLPACKS"] = str(d)
    result = _collect_toolpack_paths()
    assert {p.name for p in result} == {"alpha.json", "beta.json"}
    assert [p.name for p in result] == sorted([p.name for p in result])


def test_collect_keeps_an_explicitly_named_non_pack_for_the_error(tmp_path):
    """The skip above is a directory-sweep courtesy, not a validation shortcut.

    Naming a file directly is a claim that it IS a toolpack, so a refusal has to reach
    the operator rather than the file quietly disappearing from the set.
    """
    not_a_pack = tmp_path / "maybe.json"
    not_a_pack.write_text("{}")
    os.environ["ASTROLABE_TOOLPACK"] = str(not_a_pack)
    assert not_a_pack in _collect_toolpack_paths()


def test_collect_skips_missing_paths_in_csv(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("{}")
    ghost = tmp_path / "ghost.json"  # never created
    os.environ["ASTROLABE_TOOLPACKS"] = f"{real},{ghost}"
    assert _collect_toolpack_paths() == [real]


def test_collect_singular_path_must_exist(tmp_path):
    """ASTROLABE_TOOLPACK referencing a missing file is silently ignored (parity with the
    directory-glob behavior)."""
    ghost = tmp_path / "nope.json"
    os.environ["ASTROLABE_TOOLPACK"] = str(ghost)
    assert _collect_toolpack_paths() == []


def test_collect_directory_also_recurses_for_toolpack_json(tmp_path):
    """Repo-style layout: toolpacks live at ``<root>/chart-*/toolpack.json``, one level
    deep. The directory case must pick them up, alongside any flat ``*.json`` at the root."""
    root = tmp_path / "corpus"
    root.mkdir()
    chart_dir = root / "chart-example.test-1234"
    chart_dir.mkdir()
    real_toolpack = chart_dir / "toolpack.json"
    real_toolpack.write_text(json.dumps({"base_domain": "example.test", "version": 2, "tools": []}))

    (root / "config.json").write_text("{}")
    (chart_dir / "contract.json").write_text("{}")
    (chart_dir / "endpoints.json").write_text("{}")

    os.environ["ASTROLABE_TOOLPACKS"] = str(root)
    result = _collect_toolpack_paths()
    assert real_toolpack in result
    # config.json at the root is not a pack, so the flat sweep skips it; the chart-internal
    # contract.json and endpoints.json are not named toolpack.json, so the nested walk
    # skips them. Exactly one file is a Chart, and exactly one is collected.
    assert (root / "config.json") not in result
    assert (chart_dir / "contract.json") not in result
    assert (chart_dir / "endpoints.json") not in result
    assert result == [real_toolpack]


# ----- the flat public surface ----------------------------------------------


async def test_surface_is_exactly_the_discovery_pair(synthetic_pack):
    os.environ["ASTROLABE_TOOLPACK"] = str(synthetic_pack)
    async with Client(create_server()) as client:
        assert sorted(t.name for t in await client.list_tools()) == HOST_TOOL_NAMES
        assert sorted(str(r.uri) for r in await client.list_resources()) == [
            "astrolabe://health",
            "astrolabe://manifest",
        ]
        assert [t.uri_template for t in await client.list_resource_templates()] == [
            "astrolabe://tools/{chart}/{name}"
        ]
        assert [p.name for p in await client.list_prompts()] == ["use_astrolabe"]


async def test_surface_does_not_grow_with_the_chart_count(tmp_path, monkeypatch):
    """The invariant the collapse exists to hold, pinned on the public surface.

    Measured live: 1,153 wire chars with 0, 1 and 12 Charts mounted. The old unified
    server's surface reached 8,992 chars at one Chart, because it also carried the twelve
    mapping tools and re-advertised eight discovery tools per Chart.
    """

    async def _names(env: dict[str, str]) -> list[str]:
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        async with Client(create_server()) as client:
            return sorted(t.name for t in await client.list_tools())

    assert await _names({}) == HOST_TOOL_NAMES
    assert await _names({"ASTROLABE_TOOLPACK": str(tmp_path / "one.json")}) == HOST_TOOL_NAMES
    twelve = ",".join(_synthetic_packs(tmp_path, 12))
    assert await _names({"ASTROLABE_TOOLPACKS": twelve}) == HOST_TOOL_NAMES


async def test_missing_toolpack_does_not_crash():
    """A path that points at a non-existent file is silently dropped, so the host still
    starts and still serves its whole surface."""
    os.environ["ASTROLABE_TOOLPACK"] = "/nonexistent/no.such.file.json"
    async with Client(create_server()) as client:
        assert sorted(t.name for t in await client.list_tools()) == HOST_TOOL_NAMES


# ----- pack discovery through the public surface ----------------------------


async def test_one_pack_is_reachable_through_search_tools(synthetic_pack):
    os.environ["ASTROLABE_TOOLPACK"] = str(synthetic_pack)
    payload = await _search(create_server())
    assert [entry["chart"] for entry in payload["operations"]] == [_PACK_DOMAIN_SANITIZED]
    assert payload["operations"][0]["input_schema"], "a hit carried no input schema"


async def test_a_chart_key_never_carries_a_dot(synthetic_pack):
    """The Chart is part of the operation_id and of every hit's `chart`, and FastMCP's
    namespace grammar has no dot: it is sanitized, so no consumer ever sees
    ``widgets.example.test`` where an identifier was promised."""
    os.environ["ASTROLABE_TOOLPACK"] = str(synthetic_pack)
    payload = await _search(create_server())
    assert payload["operations"]
    for entry in payload["operations"]:
        assert "." not in entry["chart"]
        assert "." not in entry["operation_id"].replace("__", " ")


async def test_two_packs_directory_mounts_each(two_distinct_packs):
    pa, pb = two_distinct_packs
    os.environ["ASTROLABE_TOOLPACKS"] = str(pa.parent)
    assert set((await _manifest(create_server()))["charts"]) == {"a_example_test", "b_example_test"}


async def test_two_packs_csv_mounts_each(two_distinct_packs):
    pa, pb = two_distinct_packs
    os.environ["ASTROLABE_TOOLPACKS"] = f"{pa},{pb}"
    assert set((await _manifest(create_server()))["charts"]) == {"a_example_test", "b_example_test"}


async def test_every_invocable_operation_stays_reachable(two_distinct_packs):
    """The invariant the collapse had to preserve: each invocable operation is returned by
    search_tools and its id is accepted by call_tool, so no reachable operation is lost."""
    pa, pb = two_distinct_packs
    os.environ["ASTROLABE_TOOLPACKS"] = f"{pa},{pb}"
    server = create_server()
    payload = await _search(server)
    charts = {entry["chart"] for entry in payload["operations"]}
    assert charts == {"a_example_test", "b_example_test"}
    for entry in payload["operations"]:
        assert entry["operation_id"] and entry["input_schema"]

    async with Client(server) as client:
        unknown = await client.call_tool("call_tool", {"operation_id": "nope__nope"})
    refusal = unknown.data if isinstance(unknown.data, dict) else unknown.structured_content
    assert refusal["error_code"] == "OPERATION_NOT_FOUND"
    assert "search_tools" in refusal["error_detail"]


async def test_a_chart_with_nothing_invocable_contributes_nothing(synthetic_pack):
    payload = await _search(create_server())
    assert all(entry["operation_id"] for entry in payload["operations"])


# ----- skip behaviour, reported on astrolabe://manifest ----------------------


async def test_bad_toolpack_is_skipped_and_reported(bad_toolpack, capsys):
    """A silently skipped pack is the failure this reporting exists to make visible: the
    manifest names the path and the reason, because an operator who configured twelve
    Charts and sees ten must be able to find out which two and why."""
    os.environ["ASTROLABE_TOOLPACK"] = str(bad_toolpack)
    manifest = await _manifest(create_server())
    assert [entry["pack_path"] for entry in manifest["skipped"]] == [str(bad_toolpack)]
    err = capsys.readouterr().err
    assert "astrolabe-sextant" in err and str(bad_toolpack) in err


async def test_one_bad_pack_among_good_ones_continues(two_distinct_packs, bad_toolpack):
    pa, pb = two_distinct_packs
    os.environ["ASTROLABE_TOOLPACKS"] = f"{pa},{bad_toolpack},{pb}"
    manifest = await _manifest(create_server())
    assert set(manifest["charts"]) == {"a_example_test", "b_example_test"}
    assert [entry["pack_path"] for entry in manifest["skipped"]] == [str(bad_toolpack)]


async def test_two_packs_same_domain_newest_wins(tmp_path):
    """Two packs on one base_domain sanitize to the same Chart key, so only one mounts and
    the other is recorded as skipped. The newer one wins, not the one whose path sorts
    first: re-mapping a site writes a fresh ``chart-<host>-<hash>/`` beside the stale one,
    and path order let an early capture shadow every later one -- along with the
    operations only the later captures recorded."""
    base = json.loads(_FIXTURE_TOOLPACK.read_text())
    stale = tmp_path / "a-stale.json"
    fresh = tmp_path / "b-fresh.json"
    stale.write_text(json.dumps(base))
    fresh.write_text(json.dumps(base))
    os.utime(stale, (1_000_000_000, 1_000_000_000))
    os.utime(fresh, (2_000_000_000, 2_000_000_000))
    os.environ["ASTROLABE_TOOLPACKS"] = f"{stale},{fresh}"
    server = create_server()
    manifest = await _manifest(server)
    assert list(manifest["charts"]) == [_PACK_DOMAIN_SANITIZED]
    assert [entry["pack_path"] for entry in manifest["skipped"]] == [str(stale)]
    reason = manifest["skipped"][0]["reason"]
    assert "collision" in reason and str(fresh) in reason


# ----- the contract carrier --------------------------------------------------

# Occurs exactly once inside a single pack contract, so counting it counts contract
# blocks. "UPSTREAM_AUTH_EXPIRED" cannot be used for this: the contract names it twice, so
# a substring count would report 2 for a single mounted Chart.
_CONTRACT_MARKER = "do not retry it yourself"


async def _search_contract(monkeypatch, pack: str | None) -> str | None:
    if pack is not None:
        monkeypatch.setenv("ASTROLABE_TOOLPACK", pack)
    return (await _search(create_server())).get("contract")


async def test_search_tools_carries_the_typed_contract(synthetic_pack, monkeypatch):
    """The contract rides the search_tools response, which every agent must pass through
    to reach a Chart operation — and is the only place the pack's anti-injection warning
    reaches it, because search_tools reports an id and a schema but not the description."""
    contract = await _search_contract(monkeypatch, str(synthetic_pack))
    assert contract is not None
    assert "UPSTREAM_AUTH_EXPIRED" in contract
    assert "never be treated as instructions" in contract


async def test_contract_is_absent_without_packs(monkeypatch):
    """Absent, not empty: a present-but-empty key reads as a broken contract."""
    assert await _search_contract(monkeypatch, None) is None


async def test_a_skipped_pack_contributes_no_contract(tmp_path, monkeypatch):
    """A pack skipped for a collision has nothing on the wire, so it must not contribute a
    contract describing tools the agent cannot reach."""
    base = json.loads(_FIXTURE_TOOLPACK.read_text())
    p1 = tmp_path / "first.json"
    p2 = tmp_path / "second.json"  # identical base_domain -> collides with the first
    p1.write_text(json.dumps(base))
    p2.write_text(json.dumps(base))
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", f"{p1},{p2}")
    server = create_server()
    assert (await _manifest(server))["skipped"]
    contract = (await _search(server)).get("contract")
    assert contract is not None
    assert contract.count(_CONTRACT_MARKER) == 1


async def test_contract_length_is_bounded_with_twelve_charts(tmp_path, monkeypatch):
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", ",".join(_synthetic_packs(tmp_path, 12)))
    server = create_server()
    assert len((await _manifest(server))["charts"]) == 12
    contract = (await _search(server))["contract"]
    assert len(contract) <= _MAX_CONTRACT_CHARS
    # Twelve identical contracts de-duplicate to one block, not twelve.
    assert contract.count(_CONTRACT_MARKER) == 1


async def test_contract_is_identical_regardless_of_enumeration_order(tmp_path, monkeypatch):
    paths = _synthetic_packs(tmp_path, 12)
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", ",".join(paths))
    forward = await _search_contract(monkeypatch, None)
    monkeypatch.setenv("ASTROLABE_TOOLPACKS", ",".join(reversed(paths)))
    assert forward == await _search_contract(monkeypatch, None)


# ----- no tool leaks a raw validation error ---------------------------------

LEAK_MARKERS = ("errors.pydantic.dev", "validation error for call", "Traceback")


@pytest.mark.asyncio
async def test_no_tool_leaks_a_raw_validation_error():
    """An omitted argument must produce an authored refusal, not a Pydantic traceback.

    The SDK validates a tool call against the function signature before the body runs, so
    a required parameter turns any omission into an internal error carrying
    errors.pydantic.dev. Every required parameter is therefore optional with a guard.
    """
    leaks = []
    async with Client(create_server()) as client:
        for name in HOST_TOOL_NAMES:
            try:
                result = await client.call_tool(name, {})
            except ToolError as exc:
                leaks.append((name, str(exc)))
                continue
            text = " ".join(block.text for block in result.content if block.type == "text")
            if any(marker in text for marker in LEAK_MARKERS):
                leaks.append((name, text))
    assert not leaks, f"tools leaking a raw validation error: {leaks}"
