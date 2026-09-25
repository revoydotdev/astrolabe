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

_REPO_TOOLPACK = (
    Path(__file__).resolve().parents[1] / "chart-docs.qualcomm.com-af7e7498ef63/toolpack.json"
)

TYPED_TOOL_NAMES = [
    "typed_docs_qualcomm_com_coverage_report",
    "typed_docs_qualcomm_com_describe_operation",
    "typed_docs_qualcomm_com_diff_contract",
    "typed_docs_qualcomm_com_getBundlePublicresourceGetCollectionSecuritybulletin",
    "typed_docs_qualcomm_com_getSearchProductNavigationPDC20903",
    "typed_docs_qualcomm_com_invoke_query",
    "typed_docs_qualcomm_com_search_operations",
    "typed_docs_qualcomm_com_subscribe_events",
    "typed_docs_qualcomm_com_trace_surface",
    "typed_docs_qualcomm_com_verify_operation",
]


@pytest.fixture(autouse=True)
def _no_toolpack_env(monkeypatch):
    monkeypatch.delenv("ASTROLABE_TOOLPACK", raising=False)
    monkeypatch.delenv("ASTROLABE_TOOLPACKS", raising=False)


@pytest.fixture
def qualcomm_pack(tmp_path) -> Path:
    if not _REPO_TOOLPACK.exists():
        pytest.skip(f"bundled toolpack missing: {_REPO_TOOLPACK}")
    target = tmp_path / "qualcomm.json"
    target.write_bytes(_REPO_TOOLPACK.read_bytes())
    return target


async def test_mapping_server_tool_names_are_frozen(tmp_path):
    async with Client(create_server(tmp_path)) as client:
        assert sorted(t.name for t in await client.list_tools()) == MAPPING_TOOL_NAMES


async def test_unified_server_without_toolpacks_is_the_mapping_surface(tmp_path):
    async with Client(create_unified_server()) as client:
        assert sorted(t.name for t in await client.list_tools()) == UNIFIED_TOOL_NAMES


async def test_typed_pack_tool_names_are_frozen(qualcomm_pack, monkeypatch):
    """Removed from the default surface by todo 5; pinned on the legacy opt-in, which
    exists precisely so an agent that learned these names can keep using them."""
    monkeypatch.setenv("ASTROLABE_LEGACY_DIRECT_TOOLS", "1")
    monkeypatch.setenv("ASTROLABE_TOOLPACK", str(qualcomm_pack))
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
