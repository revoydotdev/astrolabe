"""Native MCP facade for Astrolabe's browser/Byparr capture and Chart workflow."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import stat
import sys
from uuid import uuid4

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .security import normalize_host, validate_url


def create_server(
    workspace: Path | None = None, *, browser_auth_domains: frozenset[str] | None = None
) -> FastMCP:
    root = (workspace or Path(os.environ.get("ASTROLABE_WORKSPACE", os.getcwd()))).resolve()
    # Operator configuration, never a tool argument. Empty means disabled.
    browser_domains = frozenset(
        normalize_host(d)
        for d in (
            browser_auth_domains
            if browser_auth_domains is not None
            else filter(None, os.environ.get("ASTROLABE_BROWSER_AUTH_DOMAINS", "").split(","))
        )
    )
    server = FastMCP(
        "astrolabe",
        mask_error_details=True,
        instructions=(
            "Map authorized sites using exported cookie files and the native browser/Byparr pipeline. "
            "Credentials remain local. Browser decryption requires operator domain opt-in and an explicit browser argument. "
            "Recovered persisted operations require exact document or compiler metadata evidence; "
            "unknown operations and writes are not exposed by generated Charts. "
            "Use the generated Chart MCP server to verify and invoke its read operations."
        ),
    )
    lock = asyncio.Lock()

    def directory(value: str) -> Path:
        path = (root / value).resolve()
        if not path.is_relative_to(root) or path == root:
            raise ValueError("capture directory must be inside the configured workspace")
        return path

    def credential(value: str) -> Path:
        path = root / value
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("cookies must be a private regular file")
        if not path.resolve().is_relative_to(root):
            raise ValueError("cookie file must be inside the configured workspace")
        return path.resolve()

    async def run(arguments: list[str], timeout: int) -> dict:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "astrolabe.cli",
            *arguments,
            "--json",
            cwd=root,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            # Source checkouts work even before installing the console entry point.
            env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parent.parent)},
        )
        try:
            output, _ = await asyncio.wait_for(process.communicate(), timeout)
            result = {"ok": process.returncode == 0, "exit_code": process.returncode}
            if process.returncode:
                # Forward only a controlled category, never credential-bearing diagnostics.
                try:
                    diagnostic = json.loads(output.strip().splitlines()[-1])
                    category = (diagnostic.get("error") or {}).get("category") or diagnostic.get(
                        "category"
                    )
                    if category in {
                        "configuration",
                        "safety_refusal",
                        "partial_capture",
                        "authentication",
                        "generation",
                        "validation",
                        "upstream",
                    }:
                        result["category"] = category
                except (ValueError, AttributeError, IndexError):
                    pass
            return result
        except TimeoutError:
            return {"ok": False, "category": "timeout"}
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 15)
                except TimeoutError:
                    process.kill()
                    await process.wait()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def list_charts() -> dict:
        """List generated Chart paths without reading credentials or captures."""
        return {
            "workspace": str(root),
            "charts": [
                {"directory": str(path.parent.relative_to(root)), "toolpack": str(path)}
                for path in sorted(root.glob("*/toolpack.json"))[:200]
                if path.resolve().is_relative_to(root)
            ],
        }

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
    async def preflight() -> dict:
        """Check this installation's local capture services and egress readiness."""
        async with lock:
            return await run(["preflight", "--local"], 180)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    async def generate_chart(capture_directory: str, include_mutations: bool = False) -> dict:
        """Generate a Chart; writes need this opt-in and a separate runtime opt-in."""
        path = directory(capture_directory)
        arguments = ["mcp-gen", str(path)]
        if include_mutations:
            arguments.append("--include-mutations")
        async with lock:
            result = await run(arguments, 180)
        if result["ok"]:
            result["toolpack"] = str(path / "toolpack.json")
        return result

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            openWorldHint=True,
        )
    )
    async def map_site(
        domain: str,
        cookies_file: str | None = None,
        seeds: list[str] | None = None,
        recover_persisted: bool = False,
        browser: str | None = None,
        profile: str = "Default",
        crawl: int = 0,
        block_assets: bool = False,
        include_mutations: bool = False,
    ) -> dict:
        """Capture with native browser/Byparr, recover APQ evidence, and generate a Chart.

        Cookie files are private Playwright JSON exports inside ASTROLABE_WORKSPACE.
        Alternatively explicitly select browser to decrypt only this domain's local
        Linux browser cookies. Omit both sources for anonymous capture. At most five same-site seed URLs,
        100 requests, one browser, and up to ten same-site links; normal page loading
        may trigger site telemetry. Generated mutations remain runtime-gated and are
        never executed by mapping. No all-host cookie export or arbitrary scripts.
        """
        host = normalize_host(domain)
        if browser is not None:
            if host not in browser_domains:
                raise ValueError(
                    "native browser import is disabled for this domain; operator opt-in required"
                )
            from .browser_cookies import BROWSERS

            if browser not in BROWSERS or cookies_file is not None:
                raise ValueError("choose a supported browser or a cookie file")
            if not profile or profile in {".", ".."} or "/" in profile or "\\" in profile:
                raise ValueError("invalid browser profile name")
        urls = seeds or [f"https://{host}/"]
        if len(urls) > 5:
            raise ValueError("at most five seed URLs")
        if isinstance(crawl, bool) or not isinstance(crawl, int) or not 0 <= crawl <= 10:
            raise ValueError("crawl must be an integer between zero and ten")
        for url in urls:
            validate_url(url, {host}, schemes=("https",), resolve=False)
            if "," in url:
                raise ValueError("seed URL cannot contain a comma")
        destination = directory(f"chart-{host}-{uuid4().hex[:12]}")
        args = [
            "map",
            host,
            "--local",
            "--no-burp",
            "--seeds",
            ",".join(urls),
            "--max-total-requests",
            "100",
            "--max-origin-requests",
            "100",
            "--max-operation-requests",
            "20",
            "--timeout",
            "300",
            "--out",
            str(destination),
        ]
        if crawl:
            args += ["--crawl", str(crawl)]
        if block_assets:
            args.append("--block-assets")
        if browser is not None:
            args += ["--browser", browser, "--profile", profile]
        elif cookies_file is not None:
            args += ["--cookies-file", str(credential(cookies_file))]
        else:
            args.append("--no-auth")
        if recover_persisted:
            args.append("--recover-persisted")
        async with lock:
            result = await run(args, 420)
            result["capture_directory"] = str(destination)
            if result["ok"]:
                generation_args = ["mcp-gen", str(destination)]
                if include_mutations:
                    generation_args.append("--include-mutations")
                result["chart"] = generated = await run(generation_args, 180)
                result["ok"] = generated["ok"]
                if generated["ok"]:
                    result["toolpack"] = str(destination / "toolpack.json")
        return result

    return server


def main() -> None:
    create_server().run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
