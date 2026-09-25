"""Native MCP facade for Astrolabe's browser/Byparr capture and Chart workflow."""

from __future__ import annotations

import asyncio
import functools
import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from .browser import validate_cdp_endpoint
from .recipe import parse_declarative_recipe
from .security import normalize_host, safe_text, validate_url

CATEGORIES = frozenset(
    {
        "configuration",
        "safety_refusal",
        "partial_capture",
        "authentication",
        "generation",
        "validation",
        "upstream",
        "usage",
        "interrupted",
    }
)
MAX_ERROR_CHARS = 600


def runtime_module_path() -> Path:
    """Where the running interpreter actually imported ``astrolabe`` from.

    Derived from ``astrolabe.__file__`` rather than from this module's ``__file__``:
    the drift this exists to expose is *import-path* drift, where a config string
    and the code that runs disagree. Reading the config string would pass while
    the import came from a different checkout.
    """
    import astrolabe

    return Path(astrolabe.__file__).resolve()


def code_root() -> Path:
    """The source tree the running interpreter imported ``astrolabe`` from."""
    return runtime_module_path().parents[1]


def default_workspace() -> Path:
    """Charts, logs, and staged credentials live in a data directory, not the CWD."""
    configured = os.environ.get("ASTROLABE_WORKSPACE")
    if configured:
        return Path(configured)
    data_home = os.environ.get("XDG_DATA_HOME") or os.path.join(Path.home(), ".local", "share")
    return Path(data_home) / "astrolabe"


def _operator_list(value: frozenset[str] | None, variable: str) -> list[str]:
    if value is not None:
        return list(value)
    return [item.strip() for item in os.environ.get(variable, "").split(",") if item.strip()]


def _refusals(tool):
    """Surface validation failures to the caller instead of a masked generic error.

    Unexpected exceptions stay masked because they may carry paths or upstream text;
    every ValueError raised here is authored by astrolabe and safe to show.
    """

    @functools.wraps(tool)
    async def wrapped(*args, **kwargs):
        try:
            return await tool(*args, **kwargs)
        except ValueError as exc:
            raise ToolError(safe_text(exc)[:MAX_ERROR_CHARS]) from exc

    return wrapped


def create_server(
    workspace: Path | None = None,
    *,
    browser_auth_domains: frozenset[str] | None = None,
    cdp_endpoints: frozenset[str] | None = None,
    toolpack_root: Path | None = None,
) -> FastMCP:
    root = (workspace or default_workspace()).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    toolpacks = Path(toolpack_root).resolve() if toolpack_root is not None else None
    # Operator configuration, never a tool argument. Empty means disabled.
    browser_domains = frozenset(
        normalize_host(d)
        for d in _operator_list(browser_auth_domains, "ASTROLABE_BROWSER_AUTH_DOMAINS")
    )
    attachable = frozenset(
        validate_cdp_endpoint(endpoint)
        for endpoint in _operator_list(cdp_endpoints, "ASTROLABE_CDP_ENDPOINTS")
    )
    server = FastMCP(
        "astrolabe",
        mask_error_details=True,
        instructions=(
            "Map authorized sites using exported cookie files, an operator-allowed running "
            "browser (cdp_endpoint), or the native browser/Byparr pipeline. Credentials remain "
            "local. Pages whose API only fires after user input need `actions` (declarative "
            "search/click/press/select/wait_for steps). If a Cloudflare challenge blocks "
            "capture, call solve_challenge and pass its cookies_file and user_agent to "
            "map_site. Browser decryption and CDP attach require operator opt-in. "
            "verify_chart re-executes reads to earn active proof. Unknown operations and "
            "writes are not exposed by generated Charts. Use the generated Chart MCP server "
            "to invoke its read operations."
        ),
    )
    browser_lock = asyncio.Lock()

    def directory(value: str) -> Path:
        path = (root / value).resolve()
        if not path.is_relative_to(root) or path == root:
            raise ValueError("capture directory must be inside the configured workspace")
        return path

    def credential(value: str) -> Path:
        path = root / value
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise ValueError("cookie file does not exist in the workspace") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("cookies must be a private regular file")
        if not path.resolve().is_relative_to(root):
            raise ValueError("cookie file must be inside the configured workspace")
        return path.resolve()

    def private_json(folder: str, name: str, value) -> Path:
        target_dir = root / ".astrolabe" / folder
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = target_dir / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            json.dump(value, handle)
        return path

    def recipe_for(actions: list[dict] | None) -> Path | None:
        if not actions:
            return None
        # Validated here with the same parser capture uses, so a bad step is refused
        # with its reason before any browser starts.
        parse_declarative_recipe({"schema_version": 1, "actions": actions})
        return private_json(
            "recipes", f"{uuid4().hex}.json", {"schema_version": 1, "actions": actions}
        )

    def seed_urls(host: str, seeds: list[str] | None) -> list[str]:
        urls = seeds or [f"https://{host}/"]
        if len(urls) > 5:
            raise ValueError("at most five seed URLs")
        for url in urls:
            validate_url(url, {host}, schemes=("https",), resolve=False)
            if "," in url:
                raise ValueError("seed URL cannot contain a comma")
        return urls

    async def run(arguments: list[str], timeout: int, label: str) -> dict:
        logs = root / ".astrolabe" / "logs"
        logs.mkdir(mode=0o700, parents=True, exist_ok=True)
        log_path = logs / f"{label}-{uuid4().hex[:12]}.log"
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as log_handle:
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "astrolabe.cli",
                *arguments,
                "--json",
                cwd=root,
                stdout=asyncio.subprocess.PIPE,
                stderr=log_handle,
                # Source checkouts work even before installing the console entry point.
                env={
                    **os.environ,
                    "PYTHONPATH": os.pathsep.join(
                        filter(
                            None,
                            [
                                str(Path(__file__).resolve().parent.parent),
                                os.environ.get("PYTHONPATH"),
                            ],
                        )
                    ),
                },
            )
            try:
                output, _ = await asyncio.wait_for(process.communicate(), timeout)
            except TimeoutError:
                return {
                    "ok": False,
                    "category": "timeout",
                    "message": f"{label} exceeded {timeout}s",
                    "log": str(log_path.relative_to(root)),
                }
            finally:
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), 15)
                    except TimeoutError:
                        process.kill()
                        await process.wait()
        result: dict = {
            "ok": process.returncode == 0,
            "exit_code": process.returncode,
            "log": str(log_path.relative_to(root)),
        }
        try:
            envelope = json.loads(output.strip().splitlines()[-1])
        except (ValueError, AttributeError, IndexError):
            envelope = {}
        if not isinstance(envelope, dict):
            envelope = {}
        if process.returncode:
            error = envelope.get("error")
            category = error.get("category") if isinstance(error, dict) else None
            if isinstance(error, dict) and category in CATEGORIES:
                result["category"] = category
                # The CLI already passes messages through safe_text; re-apply at this
                # boundary so a credential-shaped value can never cross into MCP.
                message = error.get("message")
                if isinstance(message, str) and message:
                    result["message"] = safe_text(message)[:MAX_ERROR_CHARS]
        elif isinstance(envelope.get("result"), dict):
            result["result"] = envelope["result"]
        return result

    def generation_arguments(path: Path, include_mutations: bool, read_pattern: str | None):
        arguments = ["mcp-gen", str(path)]
        if include_mutations:
            arguments.append("--include-mutations")
        if read_pattern:
            if len(read_pattern) > 200:
                raise ValueError("read_pattern must be at most 200 characters")
            try:
                re.compile(read_pattern)
            except re.error as exc:
                raise ValueError(f"read_pattern is not a valid regex: {exc}") from exc
            arguments += ["--read-pattern", read_pattern]
        return arguments

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def list_charts() -> dict:
        """List generated Chart paths without reading credentials or captures."""
        module_path = runtime_module_path()
        code = module_path.parents[1]
        return {
            "workspace": str(root),
            "toolpack_root": str(toolpacks) if toolpacks is not None else None,
            "code_root": str(code),
            "runtime_module_path": str(module_path),
            "agree": toolpacks is None or toolpacks == code,
            "charts": [
                {"directory": str(path.parent.relative_to(root)), "toolpack": str(path)}
                for path in sorted(root.glob("*/toolpack.json"))[:200]
                if path.resolve().is_relative_to(root)
            ],
        }

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
    async def preflight() -> dict:
        """Check this installation's local capture services and egress readiness."""
        return await run(["preflight", "--local"], 180, "preflight")

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    @_refusals
    async def generate_chart(
        capture_directory: str,
        include_mutations: bool = False,
        read_pattern: str | None = None,
    ) -> dict:
        """Generate a Chart; writes need this opt-in and a separate runtime opt-in.

        read_pattern is a regex of REST paths the operator asserts are reads even
        though their method is not (e.g. a POST-based search), so they become tools.
        """
        path = directory(capture_directory)
        result = await run(
            generation_arguments(path, include_mutations, read_pattern), 180, "mcp-gen"
        )
        if result["ok"]:
            result["toolpack"] = str(path / "toolpack.json")
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, openWorldHint=True))
    @_refusals
    async def solve_challenge(url: str, timeout_seconds: int = 60) -> dict:
        """Solve an anti-bot challenge with Byparr and stage its cookies privately.

        Returns a workspace cookies_file and the user_agent that solved it; pass both
        to map_site, since clearance cookies only work under the solving agent.
        Cookie values are never returned.
        """
        host = normalize_host(urlsplit(url).hostname or "")
        validate_url(url, {host}, schemes=("https",), resolve=False)
        if not 10 <= timeout_seconds <= 180:
            raise ValueError("timeout_seconds must be between 10 and 180")
        cookies_dir = root / ".astrolabe" / "cookies"
        cookies_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = cookies_dir / f"{host}-{uuid4().hex[:12]}.json"
        async with browser_lock:
            result = await run(
                [
                    "challenge",
                    url,
                    "--domain",
                    host,
                    "--out",
                    str(target),
                    "--local",
                    "--timeout",
                    str(timeout_seconds),
                ],
                timeout_seconds + 60,
                "challenge",
            )
        solved = result.pop("result", None) or {}
        if result["ok"]:
            result.update(
                {
                    "cookies_file": str(target.relative_to(root)),
                    "cookie_names": solved.get("cookie_names") or [],
                    "user_agent": solved.get("user_agent"),
                }
            )
        return result

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            openWorldHint=True,
        )
    )
    @_refusals
    async def map_site(
        domain: str,
        cookies_file: str | None = None,
        seeds: list[str] | None = None,
        actions: list[dict] | None = None,
        recover_persisted: bool = False,
        browser: str | None = None,
        profile: str = "Default",
        cdp_endpoint: str | None = None,
        user_agent: str | None = None,
        crawl: int = 0,
        block_assets: bool = True,
        max_requests: int = 100,
        timeout_seconds: int = 300,
        include_mutations: bool = False,
        read_pattern: str | None = None,
    ) -> dict:
        """Capture with a browser, drive optional page actions, and generate a Chart.

        Session sources (choose at most one; omit all for anonymous capture):
        cookies_file (private Playwright JSON in the workspace, e.g. from
        solve_challenge), browser (decrypt this domain's local Linux browser cookies;
        operator opt-in), or cdp_endpoint (attach to a running loopback Chromium and
        reuse its session; operator opt-in).

        actions run in order on the last seed page after it loads, each followed by a
        wait for API traffic to settle. Steps: {"action": "search", "selector",
        "value", "submit": bool}, {"action": "click", "selector"}, {"action": "press",
        "selector", "key": Enter|Tab|Escape|ArrowDown|ArrowUp|Space}, {"action":
        "select", "selector", "value"}, {"action": "wait_for", "selector"},
        {"action": "wait", "milliseconds"}, {"action": "scroll", "pixels"}. State-changing
        steps require "safe_annotation" explaining why they are read-only; selector
        steps accept "optional": true (skip when absent, e.g. a disclaimer modal) and
        "timeout_ms" (<=15000). At most five same-site seeds, 50 actions, ten crawled
        links, and max_requests (1-500) first-party requests.
        """
        host = normalize_host(domain)
        sources = [item for item in (cookies_file, browser, cdp_endpoint) if item is not None]
        if len(sources) > 1:
            raise ValueError("choose at most one of cookies_file, browser, or cdp_endpoint")
        if browser is not None:
            if host not in browser_domains:
                raise ValueError(
                    "native browser import is disabled for this domain; operator opt-in "
                    "required (ASTROLABE_BROWSER_AUTH_DOMAINS)"
                )
            from .browser_cookies import BROWSERS

            if browser not in BROWSERS:
                raise ValueError(f"browser must be one of {sorted(BROWSERS)}")
            if not profile or profile in {".", ".."} or "/" in profile or "\\" in profile:
                raise ValueError("invalid browser profile name")
            if actions:
                raise ValueError(
                    "native browser import cannot run actions; use cdp_endpoint or a "
                    "cookies_file for interactive capture"
                )
        if cdp_endpoint is not None:
            validate_cdp_endpoint(cdp_endpoint)
            if cdp_endpoint not in attachable:
                raise ValueError(
                    "attaching to this browser is disabled; operator opt-in required "
                    "(ASTROLABE_CDP_ENDPOINTS)"
                )
            if user_agent:
                raise ValueError("user_agent cannot apply to an attached browser")
        if user_agent is not None and not 1 <= len(user_agent) <= 400:
            raise ValueError("user_agent must be 1-400 characters")
        if isinstance(crawl, bool) or not isinstance(crawl, int) or not 0 <= crawl <= 10:
            raise ValueError("crawl must be an integer between zero and ten")
        if isinstance(max_requests, bool) or not 1 <= max_requests <= 500:
            raise ValueError("max_requests must be between 1 and 500")
        if not 60 <= timeout_seconds <= 900:
            raise ValueError("timeout_seconds must be between 60 and 900")
        urls = seed_urls(host, seeds)
        credentials = credential(cookies_file) if cookies_file is not None else None
        destination = directory(f"chart-{host}-{uuid4().hex[:12]}")
        generation = generation_arguments(destination, include_mutations, read_pattern)
        recipe = recipe_for(actions)
        args = [
            "map",
            host,
            "--local",
            "--no-burp",
            "--seeds",
            ",".join(urls),
            "--max-total-requests",
            str(max_requests),
            "--max-origin-requests",
            str(max_requests),
            "--max-operation-requests",
            str(max(1, min(max_requests, max(20, max_requests // 5)))),
            "--timeout",
            str(timeout_seconds),
            "--out",
            str(destination),
        ]
        if crawl:
            args += ["--crawl", str(crawl)]
        if block_assets:
            args.append("--block-assets")
        if recipe is not None:
            args += ["--recipe", str(recipe)]
        if user_agent:
            args += ["--user-agent", user_agent]
        if browser is not None:
            args += ["--browser", browser, "--profile", profile]
        elif cdp_endpoint is not None:
            args += ["--cdp-endpoint", cdp_endpoint]
        elif credentials is not None:
            args += ["--cookies-file", str(credentials)]
        else:
            args.append("--no-auth")
        if recover_persisted:
            args.append("--recover-persisted")
        try:
            async with browser_lock:
                result = await run(args, timeout_seconds + 120, "map")
        finally:
            if recipe is not None:
                recipe.unlink(missing_ok=True)
        result.pop("result", None)
        result["capture_directory"] = str(destination)
        if not result["ok"] and Path(f"{destination}.partial").is_dir():
            result["partial_directory"] = f"{destination}.partial"
        if result["ok"]:
            result["chart"] = generated = await run(generation, 180, "mcp-gen")
            generated.pop("result", None)
            result["ok"] = generated["ok"]
            if generated["ok"]:
                result["toolpack"] = str(destination / "toolpack.json")
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, openWorldHint=False))
    @_refusals
    async def import_har(
        har_file: str,
        domain: str,
        include_mutations: bool = False,
        read_pattern: str | None = None,
    ) -> dict:
        """Chart traffic recorded elsewhere (e.g. DevTools "Save all as HAR").

        har_file must be inside the workspace. Only first-party API shapes are kept;
        values never enter the Chart, and its proof is labelled imported, not observed.
        """
        host = normalize_host(domain)
        source = (root / har_file).resolve()
        if not source.is_relative_to(root) or not source.is_file():
            raise ValueError("har_file must be an existing file inside the workspace")
        destination = directory(f"chart-{host}-{uuid4().hex[:12]}")
        generation = generation_arguments(destination, include_mutations, read_pattern)
        result = await run(
            ["import-har", str(source), "--domain", host, "--out", str(destination)],
            300,
            "import-har",
        )
        imported = result.pop("result", None) or {}
        result["capture_directory"] = str(destination)
        if result["ok"]:
            result["entries_kept"] = imported.get("entries_kept")
            result["entries_total"] = imported.get("entries_total")
            result["chart"] = generated = await run(generation, 180, "mcp-gen")
            generated.pop("result", None)
            result["ok"] = generated["ok"]
            if generated["ok"]:
                result["toolpack"] = str(destination / "toolpack.json")
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, openWorldHint=True))
    @_refusals
    async def verify_chart(
        capture_directory: str,
        seeds: list[str] | None = None,
        actions: list[dict] | None = None,
        cookies_file: str | None = None,
        browser: str | None = None,
        profile: str = "Default",
        timeout_seconds: int = 300,
        read_pattern: str | None = None,
    ) -> dict:
        """Re-execute a Chart's read operations in a warm browser and regenerate it.

        Seeds (and optional actions, same vocabulary as map_site) warm the pages that
        fire the reads; each observed GraphQL query or contract-typed REST read is
        replayed once and its response validated against the contract. Writes are
        never replayed. Proven operations become verified-active in contract.json.
        """
        path = directory(capture_directory)
        try:
            host = normalize_host(json.loads((path / "endpoints.json").read_text())["base_domain"])
        except (OSError, ValueError, KeyError) as exc:
            raise ValueError("capture directory has no endpoints.json base_domain") from exc
        if cookies_file is not None and browser is not None:
            raise ValueError("choose at most one of cookies_file or browser")
        if browser is not None and host not in browser_domains:
            raise ValueError(
                "native browser import is disabled for this domain; operator opt-in required"
            )
        if not 60 <= timeout_seconds <= 900:
            raise ValueError("timeout_seconds must be between 60 and 900")
        urls = seed_urls(host, seeds)
        credentials = credential(cookies_file) if cookies_file is not None else None
        generation = generation_arguments(path, False, read_pattern)
        recipe = recipe_for(actions)
        args = [
            "contract",
            str(path),
            "--execute",
            "--local",
            "--seeds",
            ",".join(urls),
            "--timeout",
            str(timeout_seconds),
        ]
        if recipe is not None:
            args += ["--recipe", str(recipe)]
        if browser is not None:
            args += ["--browser", browser, "--profile", profile]
        elif credentials is not None:
            args += ["--cookies-file", str(credentials)]
        else:
            args.append("--no-auth")
        try:
            async with browser_lock:
                result = await run(args, timeout_seconds + 120, "verify")
        finally:
            if recipe is not None:
                recipe.unlink(missing_ok=True)
        result.pop("result", None)
        if result["ok"]:
            try:
                contract = json.loads((path / "contract.json").read_text())
                result["verified_active"] = sorted(
                    key
                    for key, operation in (contract.get("operations") or {}).items()
                    if operation.get("status") == "verified-active"
                )
            except (OSError, ValueError):
                result["verified_active"] = []
            result["chart"] = generated = await run(generation, 180, "mcp-gen")
            generated.pop("result", None)
            result["ok"] = generated["ok"]
            if generated["ok"]:
                result["toolpack"] = str(path / "toolpack.json")
        return result

    return server


def main() -> None:
    create_server().run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
