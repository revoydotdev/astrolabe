"""Documentation drift probes.

These exist because a doc that is narrower than the code is a security claim that
misleads its reader, and a doc that is wider is worse. Every assertion here
compares prose against the enforcement site: the live MCP servers for the tool
table, the writing module for every artifact filename the security document
attributed to a command, and an exact literal for the block that must not move.

Each test is written to go red when the thing it names changes, including the
reverse direction -- a new tool, a new artifact written -- so it reports drift
rather than only confirming a snapshot someone remembered to update.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastmcp import Client

from astrolabe.mapping_mcp import create_server
from astrolabe.unified_mcp import create_unified_server

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
SECURITY_DOC = ROOT / "docs" / "relay-and-browser-auth.md"

MAPPING_TABLE_ANCHOR = "`astrolabe-mapping-mcp` exposes exactly these twelve tools:"
UNIFIED_TABLE_ANCHOR = (
    "`astrolabe-unified-mcp` serves those same twelve plus the discovery pair that\n"
    "replaced per-Chart tool mounting."
)
PROOF_SECTION_HEADING = "## Native Instagram dogfood"

# relay.py:471-479 is pinned byte-for-byte, and the reason matters more than the
# test. For `graphql-x-persisted` the code accepts two compiler-output shapes
# where the security document names one, and the comment above the block records
# the permissiveness as deliberate: X's web client is itself Relay-based, so both
# shapes are compiler metadata of identical trust. Tightening the code to match
# the doc, or widening the doc to bless the looseness, is a cross-protocol
# evidence-substitution decision that is not an implementer's to make. Pin the
# block so a well-meaning edit has to be a deliberate, reviewed act in the same
# commit that reopens the decision.
RELAY_VALID_EVIDENCE_BLOCK = """def valid_evidence(tool: dict[str, Any]) -> bool:
    evidence = (tool.get("request_template") or {}).get("relay_evidence")
    if not isinstance(evidence, dict):
        return False
    # Each protocol trusts a set of compiler-output shapes. X's web client is itself
    # Relay-based, so an X persisted id resolves either from a webpack queryId module
    # or from a genuine Relay `Request` object in the same bundles; both are compiler
    # metadata with identical trust. Meta ships only the Relay form. The binding is
    # still gated by exact id-and-name agreement below, so the source set guards
    # provenance, not the match itself.
    trusted_sources = {
        "graphql-meta-doc-id": {"relay-compiler-ast"},
        "graphql-x-persisted": {"relay-compiler-ast", "x-persisted-registry"},
    }.get(str(tool.get("protocol")))
"""


def _table_after(text: str, anchor: str) -> list[list[str]]:
    """The first markdown table at or after `anchor`, as rows of cells."""
    tail = text[text.index(anchor) + len(anchor) :].splitlines()
    rows: list[list[str]] = []
    for line in tail[1:]:
        if line.startswith("|"):
            rows.append([cell.strip() for cell in line.strip().strip("|").split("|")])
            continue
        if rows and not line.strip():
            break
    return rows


def _documented_tools(text: str, anchor: str) -> set[str]:
    """Tool names the table claims, refusing a cell that lists more than one.

    A `` `a`, `b` `` cell is how the previous table hid half its surface from any
    name-based comparison, so it fails here rather than parsing to one name.
    """
    tools: set[str] = set()
    for cells in _table_after(text, anchor)[1:]:  # the first row is the header
        if all(set(cell) <= {"-", ":"} for cell in cells):
            continue
        cell = cells[0]
        found = re.findall(r"`([a-z_]+)`", cell)
        assert len(found) == 1, f"tool cell must name exactly one tool, got {cell!r}"
        tools.add(found[0])
    assert tools, f"no tool table found after {anchor!r}"
    return tools


async def _live(create) -> set[str]:
    async with Client(create()) as client:
        return {tool.name for tool in await client.list_tools()}


@pytest.mark.asyncio
async def test_readme_tool_table_matches_the_live_mapping_server(tmp_path):
    """The mapping table is the operator's only map of the surface.

    A tool added, removed or renamed on the server breaks this, which is the
    point: the alternative is a table that quietly stops being true.
    """
    assert _documented_tools(README, MAPPING_TABLE_ANCHOR) == await _live(
        lambda: create_server(tmp_path)
    )


@pytest.mark.asyncio
async def test_readme_discovery_pair_matches_the_live_unified_server(tmp_path):
    """`astrolabe-unified-mcp` is the mapping surface plus the collapsed pair.

    Deriving the extras from the live difference rather than from a second
    hand-kept list means a tool that appears on only one of the two servers is
    caught by the first test, and the second only has to know about the pair.
    """
    mapping = await _live(lambda: create_server(tmp_path))
    unified = await _live(create_unified_server)
    assert _documented_tools(README, UNIFIED_TABLE_ANCHOR) == unified - mapping


def _artifacts_written_by(module: str) -> set[str]:
    """Filenames the module hands to `atomic_write_json`."""
    source = (ROOT / "astrolabe" / module).read_text(encoding="utf-8")
    return set(re.findall(r'atomic_write_json\(\s*f?"\{[^"]*}/([^"]+)"', source))


def _proof_table() -> dict[str, set[str]]:
    section = SECURITY_DOC.read_text(encoding="utf-8")
    section = section[section.index(PROOF_SECTION_HEADING) :]
    writers: dict[str, set[str]] = {}
    for cells in _table_after(section, "beside the chart. None of them contains"):
        if not cells or not re.fullmatch(r"`[\w.-]+`", cells[0]):
            continue
        writers.setdefault(cells[1], set()).add(cells[0].strip("`"))
    assert writers, "no artifact table found in the proof section"
    return writers


def test_every_documented_proof_artifact_is_written_by_the_named_command():
    """The claim the audit found: the doc named a file nothing writes.

    `astrolabe contract --execute` writes exactly these; the set is compared for
    equality, so a new artifact forces the document to say who writes it and a
    stale one fails here.
    """
    contract = _proof_table()["`astrolabe contract --execute`"]
    assert contract == _artifacts_written_by("contract_verify.py")

    mcp_server = (ROOT / "astrolabe" / "mcp_server.py").read_text(encoding="utf-8")
    for name in _proof_table()["the Chart MCP server (`astrolabe-mcp`)"]:
        assert f'"{name}"' in mcp_server, f"the Chart MCP server does not write {name}"


def test_proof_section_names_no_artifact_outside_its_table():
    """Prose cannot smuggle in a filename the table does not account for.

    The original defect lived in a sentence, not a table, so a table alone would
    not have caught it.
    """
    text = SECURITY_DOC.read_text(encoding="utf-8")
    section = text[text.index(PROOF_SECTION_HEADING) :]
    named = set(re.findall(r"`([\w.-]+\.jsonl?)`", section))
    accounted = {name for names in _proof_table().values() for name in names}
    assert named <= accounted, f"named in prose but not attributed to a writer: {named - accounted}"


def test_relay_valid_evidence_block_is_unchanged():
    """See RELAY_VALID_EVIDENCE_BLOCK above: this is an undelegatable decision."""
    source = (ROOT / "astrolabe" / "relay.py").read_text(encoding="utf-8")
    assert RELAY_VALID_EVIDENCE_BLOCK in source, (
        "relay.py's valid_evidence source set changed. That reopens the "
        "cross-protocol evidence-substitution decision recorded above; it is not "
        "a docs fix."
    )
