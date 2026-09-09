from __future__ import annotations

import json

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from astrolabe.mapping_mcp import create_server


@pytest.mark.asyncio
async def test_native_map_uses_export_and_recovery_without_exposing_secrets(tmp_path, monkeypatch):
    calls = []

    class Process:
        returncode = 0

        async def communicate(self):
            return b'{"ok":true}', b""

    async def subprocess(*args, **kwargs):
        calls.append((args, kwargs))
        return Process()

    monkeypatch.setattr("astrolabe.mapping_mcp.asyncio.create_subprocess_exec", subprocess)
    cookies = tmp_path / "cookies.json"
    cookies.write_text('[{"value":"credential-secret"}]')
    cookies.chmod(0o600)
    async with Client(create_server(tmp_path)) as client:
        result = await client.call_tool(
            "map_site",
            {
                "domain": "example.com",
                "cookies_file": "cookies.json",
                "seeds": ["https://example.com/feed"],
                "recover_persisted": True,
            },
        )
    assert result.data["ok"] is True
    capture, generation = [args for args, _ in calls]
    assert capture[2] == "astrolabe.cli"
    assert "--recover-persisted" in capture
    assert "--cookies-file" in capture
    assert "--browser" not in capture
    assert capture[capture.index("--max-total-requests") + 1] == "100"
    assert generation[3] == "mcp-gen"
    assert "credential-secret" not in json.dumps(result.data)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "arguments",
    [
        {"domain": "example.com", "seeds": ["https://other.com/"]},
        {"domain": "example.com", "seeds": ["http://example.com/"]},
        {"domain": "example.com", "seeds": ["https://example.com/"] * 6},
        {"domain": "example.com", "seeds": ["https://example.com/a,https://other.com/"]},
        {"domain": "example.com", "cookies_file": "public.json"},
        {"domain": "example.com", "cookies_file": "link.json"},
        {"domain": "example.com", "browser": "unknown"},
        {"domain": "example.com", "browser": "vivaldi", "profile": "../Default"},
        {"domain": "example.com", "browser": "vivaldi", "cookies_file": "public.json"},
        {"domain": "example.com", "crawl": -1},
        {"domain": "example.com", "crawl": 11},
    ],
)
async def test_invalid_map_inputs_fail_before_subprocess(tmp_path, monkeypatch, arguments):
    async def forbidden(*args, **kwargs):
        pytest.fail("invalid input reached subprocess")

    monkeypatch.setattr("astrolabe.mapping_mcp.asyncio.create_subprocess_exec", forbidden)
    (tmp_path / "public.json").write_text("[]")
    (tmp_path / "public.json").chmod(0o644)
    (tmp_path / "link.json").symlink_to(tmp_path / "public.json")
    async with Client(create_server(tmp_path)) as client:
        with pytest.raises(ToolError):
            await client.call_tool("map_site", arguments)


@pytest.mark.asyncio
async def test_generation_failure_does_not_claim_chart_success(tmp_path, monkeypatch):
    calls = []

    class Process:
        def __init__(self, code):
            self.returncode = code

        async def communicate(self):
            return b'{"category":"generation","error":"credential-secret"}', b""

    async def subprocess(*args, **kwargs):
        calls.append(args)
        return Process(0 if len(calls) == 1 else 8)

    monkeypatch.setattr("astrolabe.mapping_mcp.asyncio.create_subprocess_exec", subprocess)
    async with Client(create_server(tmp_path)) as client:
        result = await client.call_tool("map_site", {"domain": "example.com"})
    assert result.data["ok"] is False
    assert "toolpack" not in result.data
    assert "credential-secret" not in json.dumps(result.data)
    assert "--no-auth" in calls[0]


@pytest.mark.asyncio
async def test_chart_path_cannot_escape_workspace(tmp_path):
    async with Client(create_server(tmp_path)) as client:
        with pytest.raises(ToolError):
            await client.call_tool("generate_chart", {"capture_directory": "../elsewhere"})


@pytest.mark.asyncio
async def test_native_browser_import_is_forwarded_to_capture(tmp_path, monkeypatch):
    calls = []

    class Process:
        returncode = 0

        async def communicate(self):
            return b'{"ok":true}', b""

    async def subprocess(*args, **kwargs):
        calls.append(args)
        return Process()

    monkeypatch.setattr("astrolabe.mapping_mcp.asyncio.create_subprocess_exec", subprocess)
    async with Client(create_server(tmp_path, browser_auth_domains=frozenset({"x.com"}))) as client:
        result = await client.call_tool(
            "map_site",
            {
                "domain": "x.com",
                "browser": "vivaldi",
                "profile": "Profile 1",
                "crawl": 4,
                "block_assets": True,
                "include_mutations": True,
            },
        )
    assert result.data["ok"] is True
    capture = calls[0]
    assert capture[capture.index("--browser") + 1] == "vivaldi"
    assert capture[capture.index("--profile") + 1] == "Profile 1"
    assert "--cookies-file" not in capture
    assert "--no-auth" not in capture
    assert "--recover-persisted" not in capture
    assert capture[capture.index("--crawl") + 1] == "4"
    assert "--block-assets" in capture
    assert "--include-mutations" in calls[1]


@pytest.mark.asyncio
async def test_generate_chart_mutations_require_explicit_opt_in(tmp_path, monkeypatch):
    calls = []

    class Process:
        returncode = 0

        async def communicate(self):
            return b"{}", b""

    async def subprocess(*args, **kwargs):
        calls.append(args)
        return Process()

    monkeypatch.setattr("astrolabe.mapping_mcp.asyncio.create_subprocess_exec", subprocess)
    (tmp_path / "capture").mkdir()
    async with Client(create_server(tmp_path)) as client:
        await client.call_tool("generate_chart", {"capture_directory": "capture"})
        await client.call_tool(
            "generate_chart", {"capture_directory": "capture", "include_mutations": True}
        )
    assert "--include-mutations" not in calls[0]
    assert "--include-mutations" in calls[1]


@pytest.mark.asyncio
async def test_browser_import_disabled_by_default_and_exact_domain_only(tmp_path, monkeypatch):
    monkeypatch.delenv("ASTROLABE_BROWSER_AUTH_DOMAINS", raising=False)

    async def forbidden(*args, **kwargs):
        pytest.fail("unauthorized browser import reached subprocess")

    monkeypatch.setattr("astrolabe.mapping_mcp.asyncio.create_subprocess_exec", forbidden)
    for allowed, domain in [(None, "x.com"), (frozenset({"x.com"}), "api.x.com")]:
        async with Client(create_server(tmp_path, browser_auth_domains=allowed)) as client:
            with pytest.raises(ToolError):
                await client.call_tool("map_site", {"domain": domain, "browser": "vivaldi"})
