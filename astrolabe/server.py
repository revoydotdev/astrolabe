"""The single astrolabe MCP server.

One entrypoint, one tool surface: the capture/mapping tools and the Chart
execution tools behind ``search_tools``/``call_tool`` are mounted onto the same
:class:`FastMCP` instance. An agent that can map a site can also invoke what it
mapped, without a second server, a second config stanza, or a second set of
credentials.

What this deliberately does *not* collapse:

* the query-only invocation guard (``sextant.py``) still refuses anything whose
  operation type is not a query;
* the mutation gate still refuses writes;
* credentials never enter tool-visible state, and no tool accepts an egress
  policy argument.

Those are enforced where they were enforced before. What changed is packaging:
the execution surface no longer lives behind a separate process boundary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from .mapping_mcp import MAPPING_INSTRUCTIONS
from .mapping_mcp import create_server as create_mapping_server

EXECUTION_INSTRUCTIONS = (
    "This server also carries the execution surface for mounted Charts: "
    "search_tools finds read operations across every Chart and call_tool invokes "
    "one. Only query operations classified from trusted evidence are executable; "
    "unknown, persisted and write operations are inventory-only."
)


def create_server(
    workspace: Path | None = None,
    *,
    toolpack_root: Path | None = None,
    auth: Any | None = None,
) -> FastMCP:
    """Capture and execution on one surface.

    ``workspace`` and ``toolpack_root`` configure the mapping half; the execution
    half reads its Charts from ``ASTROLABE_TOOLPACK``/``ASTROLABE_TOOLPACKS`` as
    before, because that is operator config rather than a tool argument.
    """
    server = create_mapping_server(
        workspace,
        toolpack_root=toolpack_root,
        instructions=f"{MAPPING_INSTRUCTIONS} {EXECUTION_INSTRUCTIONS}",
    )
    from .sextant import create_server as create_execution_server

    server.mount(create_execution_server(auth=auth))
    return server


def main() -> None:
    create_server().run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
