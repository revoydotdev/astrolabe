"""Frozen characterization of the MCP surface exposed on the current SDK line.

These tests record what the three servers expose *today*, before the
`mcp` 1.x->2.x / `fastmcp` 3.x->4.x migration. The risk that motivates them is
not an import failing loudly -- it is an SDK that upgrades cleanly while quietly
renaming a tool, dropping a response key, or downgrading an authored refusal to a
Pydantic traceback. Asserting the import would pass through every one of those.

Each test therefore pins an exact literal rather than a shape, so any change
fails here and has to be a deliberate, reviewed edit to this file in the same
commit that changed the surface.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from astrolabe.mapping_mcp import create_server
from astrolabe.unified_mcp import create_unified_server

MAPPING_INSTRUCTIONS = (
    "Map authorized sites using exported cookie files, an operator-allowed running "
    "browser (cdp_endpoint), or the native browser/Byparr pipeline. Credentials remain "
    "local. Pages whose API only fires after user input need `actions` (declarative "
    "search/click/press/select/wait_for steps). If a Cloudflare challenge blocks "
    "capture, call solve_challenge and pass its cookies_file and user_agent to "
    "map_site. Browser decryption and CDP attach require operator opt-in. "
    "verify_chart re-executes reads to earn active proof. Unknown operations and "
    "writes are not exposed by generated Charts. Use the generated Chart MCP server "
    "to invoke its read operations."
)

# Frozen at 799d802, the last commit of the SDK migration, and grown twice since by
# deliberate surface changes: ``chart_status`` (todo 4) and ``register_session``
# (todo 10). The migration itself changed nothing here, and that is what this file
# exists to prove.
#
# This is the MAPPING server's surface. The unified server adds search_tools and
# call_tool on top; neither is a mapping tool, so neither belongs in this list.
MAPPING_TOOL_NAMES = [
    "chart_status",
    "generate_chart",
    "import_har",
    "list_charts",
    "map_site",
    "preflight",
    "register_session",
    "revoke_session",
    "scan_site",
    "scan_to_recipe",
    "solve_challenge",
    "verify_chart",
]

# The unified server's frozen surface: the mapping tools plus the collapsed pair that
# replaced the per-Chart tools in todo 5.
UNIFIED_TOOL_NAMES = sorted([*MAPPING_TOOL_NAMES, "call_tool", "search_tools"])

LIST_CHARTS_KEYS = [
    "agree",
    "charts",
    "code_root",
    "runtime_module_path",
    "toolpack_root",
    "workspace",
]

# The operator gate is checked before the profile name, so this argument pair
# refuses on the gate. Both orderings are worth pinning: a migration that
# reorders validation would otherwise change which message an agent sees.
REFUSALS = [
    (
        {"domain": "example.com", "browser": "vivaldi", "cookies_file": "public.json"},
        # Reworded by todo 11: `session` joined the mutual-exclusion set, so the
        # refusal must now name all four sources rather than three. The refusal is
        # still authored and unchanged in kind.
        "choose at most one of cookies_file, browser, cdp_endpoint, or session",
    ),
    (
        {"domain": "example.com", "crawl": 11},
        "crawl must be an integer between zero and ten",
    ),
    (
        {"domain": "example.com", "browser": "vivaldi", "profile": "../Default"},
        "native browser import is disabled for this domain; operator opt-in required "
        "(ASTROLABE_BROWSER_AUTH_DOMAINS)",
    ),
]

# The committed synthetic pack (tests/fixtures/synthetic-toolpack.json), not a generated
# chart-* pack. Still a real v2 pack, so the freeze drives the production
# _validate_pack -> mount -> namespaced-name path; only the pack's identity changed.
_FIXTURE_TOOLPACK = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "synthetic-toolpack.json"
)

# The eight per-namespace discovery tools every mounted pack re-advertises, carrying the
# sanitized namespace the unified server derives from the pack's base_domain. They come
# from the typed server, not the pack's own tool list, so they hold for any pack -- which
# is what makes them the regression signal, independent of what the fixture declares.
#
# Literals, not `_DISCOVERY_SUFFIXES` and not `_sanitize_namespace(...)`: deriving either
# would move both sides of the comparison, and a rename in astrolabe/ would stay green.
TYPED_DISCOVERY_TOOL_NAMES = [
    "typed_widgets_example_test_coverage_report",
    "typed_widgets_example_test_describe_operation",
    "typed_widgets_example_test_diff_contract",
    "typed_widgets_example_test_invoke_query",
    "typed_widgets_example_test_search_operations",
    "typed_widgets_example_test_subscribe_events",
    "typed_widgets_example_test_trace_surface",
    "typed_widgets_example_test_verify_operation",
]

# The pack-derived half of the derived surface: the operations the mounted fixture
# declares and exposes. This part is fixture-dependent by nature and is only as stable as
# the fixture is; it is pinned so an operation added to, or renamed in, the fixture has to
# be a deliberate edit here too.
TYPED_PACK_OPERATION_NAMES = [
    "typed_widgets_example_test_listWidgets",
]

# The complete derived typed surface, exactly as list_tools reports it and sorted the same
# way, so a name appearing, disappearing or moving still fails the equality.
TYPED_TOOL_NAMES = sorted([*TYPED_DISCOVERY_TOOL_NAMES, *TYPED_PACK_OPERATION_NAMES])


@pytest.fixture(autouse=True)
def _no_toolpack_env(monkeypatch):
    monkeypatch.delenv("ASTROLABE_TOOLPACK", raising=False)
    monkeypatch.delenv("ASTROLABE_TOOLPACKS", raising=False)


@pytest.fixture
def synthetic_pack(tmp_path) -> Path:
    """Copy of the committed synthetic toolpack into tmp_path.

    A missing committed fixture is a broken checkout, so the read is allowed to raise
    rather than skip: a skip here hides every typed-name assertion in this file.
    """
    target = tmp_path / "synthetic.json"
    target.write_bytes(_FIXTURE_TOOLPACK.read_bytes())
    return target


async def test_mapping_server_tool_names_are_frozen(tmp_path):
    async with Client(create_server(tmp_path)) as client:
        assert sorted(t.name for t in await client.list_tools()) == MAPPING_TOOL_NAMES


async def test_unified_server_without_toolpacks_is_the_mapping_surface(tmp_path):
    async with Client(create_unified_server()) as client:
        assert sorted(t.name for t in await client.list_tools()) == UNIFIED_TOOL_NAMES


async def test_typed_pack_discovery_tools_are_frozen(synthetic_pack, monkeypatch):
    """The eight per-pack fixed names, asserted on their own and by literal.

    These are the part of the legacy surface that holds for any pack, so they are pinned
    separately from the derived-surface equality below: a fixture edit that renames or adds
    an operation cannot move them, and a rename of e.g. describe_operation in astrolabe/
    fails here even if every list in this file is updated to match.
    """
    monkeypatch.setenv("ASTROLABE_LEGACY_DIRECT_TOOLS", "1")
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(synthetic_pack))
    async with Client(create_unified_server()) as client:
        names = set(t.name for t in await client.list_tools())
    missing = [n for n in TYPED_DISCOVERY_TOOL_NAMES if n not in names]
    assert not missing, f"legacy opt-in dropped the fixed discovery tools: {missing}"


async def test_typed_pack_tool_names_are_frozen(synthetic_pack, monkeypatch):
    """Removed from the default surface by todo 5; pinned on the legacy opt-in, which
    exists precisely so an agent that learned these names can keep using them."""
    monkeypatch.setenv("ASTROLABE_LEGACY_DIRECT_TOOLS", "1")
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(synthetic_pack))
    async with Client(create_unified_server()) as client:
        names = sorted(t.name for t in await client.list_tools())
    assert [n for n in names if n.startswith("typed_")] == TYPED_TOOL_NAMES


async def test_list_charts_response_keys_are_frozen(tmp_path):
    async with Client(create_server(tmp_path)) as client:
        result = await client.call_tool("list_charts", {})
    assert sorted(result.data) == LIST_CHARTS_KEYS


async def test_mapping_server_instructions_are_frozen(tmp_path):
    assert create_server(tmp_path).instructions == MAPPING_INSTRUCTIONS


@pytest.mark.parametrize(("arguments", "message"), REFUSALS)
async def test_authored_refusal_messages_are_frozen(tmp_path, arguments, message):
    (tmp_path / "public.json").write_text("[]")
    async with Client(create_server(tmp_path)) as client:
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("map_site", arguments)
    assert str(excinfo.value) == message
