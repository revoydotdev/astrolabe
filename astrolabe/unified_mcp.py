"""Unified MCP facade: full mapping workflow + optional typed toolpack(s).

Always exposes the Astrolabe mapping & capture workflow (browser/Byparr/Chart
tools) so a toolpack-less start still has full recon capability. When an
operator points at one or more generated typed toolpacks, those packs are
mounted on top with a per-domain namespace so their tool names never collide
with the mapping surface.

Mounting strategy
-----------------

``mapping_mcp.create_server()`` and ``mcp_server.create_server()`` each return
an isolated ``FastMCP`` instance. ``FastMCP.mount(server, namespace=...)``
composes them into the parent server at runtime: tools and resources from the
mounted server appear on the parent with ``namespace_`` prepended to their
names / URIs, and requests to those namespaced objects are forwarded
transparently to the mounted server.

Because typed toolpacks already carry a unique ``base_domain`` per pack, the
namespace ``typed_<sanitized_domain>__`` is collision-free in practice. The
sanitizer strips the ``astrolabe-`` prefix the typed server puts on its name
and replaces dots (which break FastMCP's namespace grammar) with underscores.

Configuration
-------------

``ASTROLABE_TOOLPACK``      : single toolpack JSON file path (preferred)
``ASTROLABE_TOOLPACKS``     : CSV of paths, or a directory. A directory picks
                              up every ``*.json`` in its top level (flat
                              layout) plus every ``toolpack.json`` anywhere
                              below it (nested ``chart-<host>/toolpack.json``
                              layout). Both lists are deduplicated and
                              sorted.
``ASTROLABE_WORKSPACE``     : inherited by the mapping layer (defaults to
                              ``$XDG_DATA_HOME/astrolabe``)

When no toolpack is configured the unified server is functionally identical
to ``astrolabe-mapping-mcp``.

Failures
--------

A toolpack that fails to construct (bad JSON, missing fields, version drift)
is logged to stderr with its path and reason, and skipped. The operator can
keep working with the rest of the surface. A second pack targeting the same
domain is also skipped (logged) to avoid FastMCP's namespace collision.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Protocol, cast

from fastmcp import FastMCP
from mcp.types import ToolAnnotations


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _sanitize_namespace(server_name: str) -> str:
    """Strip ``astrolabe-`` prefix and replace dots with underscores.

    FastMCP namespaces must not contain dots; the typed server's auto-derived
    name (``astrolabe-docs.qualcomm.com``) needs sanitizing before it can be
    used as a namespace token.
    """
    raw = server_name
    if raw.startswith("astrolabe-"):
        raw = raw[len("astrolabe-") :]
    return raw.replace(".", "_").strip("_")


def _expand_user_p(p: Path) -> Path:
    """``Path.expanduser`` only if the string started with ``~`` (avoid surprising
    side effects on empty strings or random ``.`` segments)."""
    return p.expanduser() if str(p).startswith("~") else p


def _toolpack_env() -> tuple[str | None, list[str]]:
    """``(single, multi)`` path tokens from the two operator knobs.

    Kept as one parser because a knob added here and not there is exactly the
    drift that produced the import-path bug this module now refuses to start on.
    """
    single = os.environ.get("ASTROLABE_TOOLPACK")
    multi = os.environ.get("ASTROLABE_TOOLPACKS")
    return (
        single.strip() if single and single.strip() else None,
        [token.strip() for token in multi.split(",") if token.strip()] if multi else [],
    )


def _configured_roots() -> list[Path]:
    """Every configured directory root, in precedence order and de-duplicated.

    A single-file ``ASTROLABE_TOOLPACK`` names one pack rather than a tree, so it
    is not a root.
    """
    single, multi = _toolpack_env()
    roots: list[Path] = []
    for token in ([single] if single else []) + multi:
        candidate = _expand_user_p(Path(token))
        if not candidate.is_dir():
            continue
        resolved = candidate.resolve()
        if resolved not in roots:
            roots.append(resolved)
    return roots


def _configured_toolpack_root() -> Path | None:
    """The first configured directory root, which is the authoritative tree."""
    roots = _configured_roots()
    return roots[0] if roots else None


def _collect_toolpack_paths() -> list[Path]:
    """Resolve the operator's toolpack selection into an ordered list of paths.

    Order:
      1. ``ASTROLABE_TOOLPACK`` (single, preferred)
      2. ``ASTROLABE_TOOLPACKS`` either CSV of paths or a directory. The
         directory case picks up:
           * every ``*.json`` at the directory's top level (flat layout)
           * every ``toolpack.json`` anywhere below the directory (nested
             layout such as ``chart-<host>/toolpack.json``)
         Both lists are sorted and deduplicated so a flat toolpack at the
         root doesn't also surface from the recursive walk.

    Missing files are silently dropped (parity across both forms).
    Returns only paths that actually exist on disk.
    """
    out: list[Path] = []
    single, multi = _toolpack_env()

    if single:
        p = _expand_user_p(Path(single))
        if p.exists():
            out.append(p)

    for token in multi:
        p = _expand_user_p(Path(token))
        if p.is_dir():
            flat = sorted(child for child in p.glob("*.json") if child.is_file())
            nested = sorted(p.rglob("toolpack.json"))
            seen: set[Path] = set()
            for candidate in flat + nested:
                if candidate in seen:
                    continue
                seen.add(candidate)
                out.append(candidate)
        elif p.is_file():
            out.append(p)
        # else: silently drop missing/unreadable paths.

    return out


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


def _foreign_checkout(toolpack_root: Path | None) -> tuple[Path, Path] | None:
    """Report the knob naming a *different astrolabe source checkout* than the running one.

    A toolpack root is a data location, so it may legitimately be an XDG data dir
    or a temp dir that contains no astrolabe package at all. Only a root that
    actually carries a second ``astrolabe`` package is the import-drift hazard —
    Charts generated by one checkout served by code imported from another. Refusing
    outright would take away that legitimate layout, so this reports instead.
    """
    if toolpack_root is None:
        return None
    from .mapping_mcp import code_root

    running = code_root()
    if toolpack_root == running:
        return None
    if (toolpack_root / "astrolabe" / "__init__.py").is_file():
        return toolpack_root, running
    return None


class _Observable(Protocol):
    """The observability attributes this module guarantees on the server it returns.

    Declared rather than silenced so the contract is checked instead of ignored.
    """

    unified_namespaces: set[str]
    unified_skipped: list[tuple[str, str]]


_MAX_INSTRUCTIONS_CHARS = 4096

# The eight tools every typed pack re-advertises. They are the same on every pack, so
# a workspace pays for them once per chart; the collapsed surface drops them entirely.
_DISCOVERY_SUFFIXES = frozenset(
    {
        "search_operations",
        "describe_operation",
        "trace_surface",
        "diff_contract",
        "coverage_report",
        "invoke_query",
        "verify_operation",
        "subscribe_events",
    }
)


def _legacy_direct_tools() -> bool:
    """Whether to keep the old per-chart tools mounted alongside the collapsed surface.

    Off by default. The collapse removes ``astrolabe_typed_<ns>_<op>`` names, which is
    breaking for an agent that learned them, so the operator can keep the old names
    until it has migrated.
    """
    return os.environ.get("ASTROLABE_LEGACY_DIRECT_TOOLS") == "1"


def _envelope(result: Any) -> dict[str, Any]:
    """Decode a dispatched tool result's JSON envelope."""
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            try:
                value = json.loads(text)
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
    return {"ok": False, "error_code": "BAD_RESULT", "error_detail": "tool returned no envelope"}


def _compose_instructions(mapping: str | None, contracts: list[str]) -> str | None:
    """Fold every mounted pack's operational contract into the parent's instructions.

    ``mount()`` does not propagate a mounted server's instructions, so without this
    an agent connecting to the unified server never learns the typed packs'
    ``UPSTREAM_AUTH_EXPIRED`` contract and will re-run failed mutations by hand.

    Only *mounted* packs contribute. A pack skipped for a namespace collision has no
    tools on the wire, so its contract would describe behaviour the agent cannot
    reach. Distinct bodies are sorted so the result is byte-identical across restarts
    that enumerate the same packs in a different filesystem order, which keeps the
    prompt cache warm.

    Every pack currently ships the same contract, so de-duplication normally
    collapses the whole set to one block. The length cap is a backstop for packs
    that genuinely differ, and it cuts on a paragraph boundary rather than mid
    sentence.
    """
    parts = [part for part in (mapping, *sorted(set(contracts))) if part]
    if not parts:
        return None
    composed = "\n\n".join(parts)
    if len(composed) <= _MAX_INSTRUCTIONS_CHARS:
        return composed
    return composed[:_MAX_INSTRUCTIONS_CHARS].rsplit("\n\n", 1)[0].rstrip() + (
        "\n\n[per-pack contracts truncated]"
    )


def _build_typed_server(toolpack_path: Path) -> FastMCP:
    """Construct a typed toolpack FastMCP for ``toolpack_path``, honoring
    every ``ASTROLABE_*`` env knob the operator may have set.

    ``Settings.from_env()`` is the canonical constructor; we temporarily
    inject ``ASTROLABE_TOOLPACK`` for the duration of the call so
    ``from_env`` stays the single source of env semantics (timeout, auth,
    allow-mutations, etc.) and we don't fork the production path.
    """
    from .mcp_server import create_server as create_typed_server

    previous = os.environ.get("ASTROLABE_TOOLPACK")
    os.environ["ASTROLABE_TOOLPACK"] = str(toolpack_path)
    try:
        return create_typed_server()
    finally:
        if previous is None:
            os.environ.pop("ASTROLABE_TOOLPACK", None)
        else:
            os.environ["ASTROLABE_TOOLPACK"] = previous


def create_unified_server() -> FastMCP:
    """Build the unified server (mapping workflow + zero-or-more typed toolpacks).

    Always returns a FastMCP with the mapping tools attached. Failures in
    individual toolpacks are logged to stderr and skipped — the operator
    should never lose access to the mapping surface because of a single bad
    pack.

    The returned server carries two public attributes for observability:

    * ``server.unified_namespaces`` (``set[str]``): every typed-pack namespace
      that was mounted, e.g. ``{"docs_qualcomm_com"}`` for a single qualcomm
      pack. Each mounted pack's tools appear on the wire as
      ``typed_<namespace>_<tool>``.
    * ``server.unified_skipped`` (``list[tuple[str, str]]``): tuples of
      ``(pack_path, reason)`` for every pack that was tried and rejected, so
      callers can surface a richer error in their own UI.
    """
    from .mapping_mcp import create_server as create_mapping_server

    toolpack_root = _configured_toolpack_root()
    drift = _foreign_checkout(toolpack_root)
    if drift is not None:
        foreign, running = drift
        print(
            json.dumps(
                {
                    "error": {
                        "category": "configuration",
                        "message": (
                            f"ASTROLABE_TOOLPACKS names a different astrolabe checkout: "
                            f"toolpack_root={foreign} but this server imported astrolabe "
                            f"from code_root={running}. Charts from that checkout may not "
                            "match the running code."
                        ),
                        "toolpack_root": str(foreign),
                        "code_root": str(running),
                    }
                }
            ),
            file=sys.stderr,
            flush=True,
        )

    mounted_namespaces: set[str] = set()
    mounted_packs: dict[str, str] = {}
    mounted = 0
    skipped: list[tuple[str, str]] = []
    contracts: list[str] = []
    # Threaded in rather than read back off a public attribute at call time: the
    # mount and skip outcomes do not exist until after the mapping server is built,
    # so a closure is what lets chart_status observe them.
    server = create_mapping_server(
        toolpack_root=toolpack_root,
        mount_provenance=lambda: {
            "mounted": dict(mounted_packs),
            "skipped": [{"pack_path": p, "reason": r} for p, r in skipped],
            "configured_roots": _configured_roots(),
        },
    )

    packs: list[tuple[str, FastMCP, str]] = []
    legacy = _legacy_direct_tools()

    for pack_path in _collect_toolpack_paths():
        try:
            typed = _build_typed_server(pack_path)
        except Exception as exc:  # noqa: BLE001 — operator-facing skip log
            skipped.append((str(pack_path), f"construct: {type(exc).__name__}: {exc}"))
            continue

        namespace_token = _sanitize_namespace(typed.name or "")
        if not namespace_token:
            skipped.append((str(pack_path), "construct: empty namespace after sanitize"))
            continue

        if namespace_token in mounted_namespaces:
            skipped.append(
                (str(pack_path), f"collision: namespace '{namespace_token}' already mounted")
            )
            continue

        try:
            if legacy:
                server.mount(typed, namespace=f"typed_{namespace_token}")
        except Exception as exc:  # noqa: BLE001 — surface without crashing server
            skipped.append((str(pack_path), f"mount: {type(exc).__name__}: {exc}"))
            continue

        mounted_namespaces.add(namespace_token)
        mounted_packs[f"typed_{namespace_token}"] = str(pack_path)
        packs.append((namespace_token, typed, str(pack_path)))
        mounted += 1
        if typed.instructions:
            contracts.append(typed.instructions)

    index: dict[str, dict[str, Any]] | None = None

    async def _load_index() -> dict[str, dict[str, Any]]:
        """Cross-pack map of operation_id -> how to reach it, built once on first use.

        Each pack is asked for its own inventory, which already carries input_schema,
        so the argument contract has a single source of truth rather than a second
        copy maintained here.
        """
        nonlocal index
        if index is not None:
            return index
        by_namespace = {namespace: typed for namespace, typed, _ in packs}
        built: dict[str, dict[str, Any]] = {}
        for namespace, typed in by_namespace.items():
            try:
                listing = await typed.get_tool("search_operations")
                if listing is None:
                    continue
                found = await listing.run({})
            except Exception:  # noqa: BLE001 — a pack that cannot list is simply empty
                continue
            for item in _envelope(found).get("operations") or []:
                if not item.get("invocable"):
                    continue
                name = str(item.get("name") or item.get("id") or "")
                if not name or name in _DISCOVERY_SUFFIXES:
                    continue
                # The Chart is part of the id. Two Charts can expose the same operation
                # name, and disambiguating in the id beats mounting two servers to keep
                # them apart.
                built[f"{namespace}__{name}"] = {"namespace": namespace, "tool": name, "item": item}
        # Sorted so enumeration order is identical across restarts, which keeps the
        # prompt cache warm and makes a diff of two runs meaningful.
        index = dict(sorted(built.items()))
        return index

    async def _dispatch(typed: FastMCP, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = await typed.get_tool(name)
        if tool is None:
            return _refusal("OPERATION_NOT_FOUND", f"tool {name!r} is not registered")
        return _envelope(await tool.run(arguments))

    def _refusal(code: str, detail: str, *, next_action: str | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ok": False,
            "error_code": code,
            "error_detail": detail,
            "retryable": False,
        }
        if next_action is not None:
            out["next_action"] = next_action
        return out

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def search_tools(query: str = "", limit: int = 25) -> dict[str, Any]:
        """Find callable operations across every mounted Chart.

        Returns each hit's operation_id, Chart, protocol, proof tier and input_schema,
        so an operation can be called with call_tool without reading anything else.
        Only operations a Chart actually exposes appear here.
        """
        if len(query) > 200:
            return _refusal("BAD_ARGUMENTS", "query must be at most 200 characters")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            return _refusal("BAD_ARGUMENTS", "limit must be an integer between 1 and 200")
        needle = query.casefold().strip()
        hits = []
        for operation_id, record in (await _load_index()).items():
            item = record["item"]
            # The Chart is searchable, not just carried: without it an agent cannot
            # scope a search to one site among twelve.
            haystack = " ".join(
                [operation_id.replace("__", " ")]
                + [str(item.get(key) or "") for key in ("id", "name", "alias", "operation")]
            ).casefold()
            if needle and needle not in haystack:
                continue
            hits.append(
                {
                    "operation_id": operation_id,
                    "chart": record["namespace"],
                    "name": item.get("name"),
                    "alias": item.get("alias"),
                    "transport": item.get("transport"),
                    "protocol": item.get("protocol"),
                    "proof_tier": item.get("proof_tier"),
                    "input_schema": item.get("input_schema")
                    or {"type": "object", "properties": {}},
                }
            )
        return {
            "ok": True,
            "count": len(hits),
            "operations": hits[:limit],
            "truncated": len(hits) > limit,
        }

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=True, idempotent_hint=False, open_world_hint=True
        ),
    )
    async def call_tool(
        operation_id: str | None = None, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Invoke one operation by the operation_id search_tools returned.

        Reaches the same execution path the per-Chart tool did, including that Chart's
        own credential scoping and host validation.
        """
        if not operation_id:
            return _refusal(
                "BAD_ARGUMENTS",
                "operation_id is required",
                next_action="call search_tools to list callable operation ids",
            )
        record = (await _load_index()).get(operation_id)
        if record is None:
            return _refusal(
                "OPERATION_NOT_FOUND",
                f"unknown operation_id {operation_id!r}; run search_tools to list callable operations",
            )
        typed = next(typed for namespace, typed, _ in packs if namespace == record["namespace"])
        return await _dispatch(typed, record["tool"], dict(arguments or {}))

    server.instructions = _compose_instructions(server.instructions, contracts)

    if skipped:
        # Single concise line; tooling can grep. Avoids spamming the wire if
        # many packs are configured.
        print(
            f"astrolabe-unified: mounted {mounted} toolpack(s); skipped {len(skipped)}: "
            + ", ".join(f"{p} ({reason})" for p, reason in skipped),
            file=sys.stderr,
            flush=True,
        )

    observable = cast(_Observable, server)
    observable.unified_namespaces = {f"typed_{n}" for n in mounted_namespaces}
    observable.unified_skipped = skipped
    return server


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """Console-script entry: serve the unified MCP over stdio."""
    server = create_unified_server()
    server.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
