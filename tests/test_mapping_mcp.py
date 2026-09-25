from __future__ import annotations

import json
import stat
from pathlib import Path

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


def _recording_subprocess(calls, envelopes=None, on_call=None):
    envelopes = list(envelopes or [])

    class Process:
        def __init__(self, envelope):
            self.envelope = envelope
            self.returncode = 0 if envelope.get("ok", True) else 3

        async def communicate(self):
            return json.dumps(self.envelope).encode(), b""

    async def subprocess(*args, **kwargs):
        calls.append((args, kwargs))
        if on_call:
            on_call(args, kwargs)
        return Process(envelopes.pop(0) if envelopes else {"ok": True})

    return subprocess


@pytest.mark.asyncio
async def test_refusal_reasons_reach_the_caller(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "astrolabe.mapping_mcp.asyncio.create_subprocess_exec",
        _recording_subprocess([]),
    )
    async with Client(create_server(tmp_path, cdp_endpoints=frozenset())) as client:
        with pytest.raises(ToolError, match="ASTROLABE_CDP_ENDPOINTS"):
            await client.call_tool(
                "map_site", {"domain": "example.com", "cdp_endpoint": "http://127.0.0.1:9222"}
            )
        with pytest.raises(ToolError, match="ASTROLABE_BROWSER_AUTH_DOMAINS"):
            await client.call_tool("map_site", {"domain": "example.com", "browser": "chrome"})
        with pytest.raises(ToolError, match="action 0 key must be one of"):
            await client.call_tool(
                "map_site",
                {
                    "domain": "example.com",
                    "actions": [
                        {"action": "press", "selector": "#q", "key": "F5", "safe_annotation": "x"}
                    ],
                },
            )


@pytest.mark.asyncio
async def test_actions_become_a_private_recipe_removed_after_capture(tmp_path, monkeypatch):
    calls, seen = [], {}

    def inspect(args, _kwargs):
        if "--recipe" in args:
            recipe = Path(args[args.index("--recipe") + 1])
            seen["mode"] = recipe.stat().st_mode & 0o777
            seen["recipe"] = json.loads(recipe.read_text())
            seen["path"] = recipe

    monkeypatch.setattr(
        "astrolabe.mapping_mcp.asyncio.create_subprocess_exec",
        _recording_subprocess(calls, on_call=inspect),
    )
    actions = [
        {
            "action": "search",
            "selector": "#name",
            "value": "synthetic",
            "submit": True,
            "safe_annotation": "read-only name search",
        },
        {
            "action": "click",
            "selector": "#acknowledge",
            "optional": True,
            "safe_annotation": "acknowledge disclaimer",
        },
    ]
    async with Client(create_server(tmp_path)) as client:
        result = await client.call_tool(
            "map_site",
            {
                "domain": "example.com",
                "seeds": ["https://example.com/search"],
                "actions": actions,
                "max_requests": 250,
            },
        )
    assert result.data["ok"] is True
    capture = calls[0][0]
    assert seen["mode"] == 0o600
    assert seen["recipe"] == {"schema_version": 1, "actions": actions}
    assert not seen["path"].exists()
    assert capture[capture.index("--max-total-requests") + 1] == "250"
    assert capture[capture.index("--max-operation-requests") + 1] == "50"
    assert "--block-assets" in capture
    assert "--no-auth" in capture


@pytest.mark.asyncio
async def test_cli_failure_message_and_log_are_returned(tmp_path, monkeypatch):
    calls = []
    envelope = {
        "ok": False,
        "error": {
            "category": "configuration",
            "code": 3,
            "message": "local playwright backend selected but chromium is not available",
        },
    }
    monkeypatch.setattr(
        "astrolabe.mapping_mcp.asyncio.create_subprocess_exec",
        _recording_subprocess(calls, [envelope]),
    )
    async with Client(create_server(tmp_path)) as client:
        result = await client.call_tool("map_site", {"domain": "example.com"})
    assert result.data["ok"] is False
    assert result.data["category"] == "configuration"
    assert "chromium is not available" in result.data["message"]
    log = tmp_path / result.data["log"]
    assert log.is_file() and log.stat().st_mode & 0o777 == 0o600
    assert calls[0][1]["stderr"] is not None


@pytest.mark.asyncio
async def test_operator_allowed_cdp_endpoint_is_forwarded(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "astrolabe.mapping_mcp.asyncio.create_subprocess_exec", _recording_subprocess(calls)
    )
    server = create_server(tmp_path, cdp_endpoints=frozenset({"http://127.0.0.1:9222"}))
    async with Client(server) as client:
        await client.call_tool(
            "map_site", {"domain": "example.com", "cdp_endpoint": "http://127.0.0.1:9222"}
        )
    capture = calls[0][0]
    assert capture[capture.index("--cdp-endpoint") + 1] == "http://127.0.0.1:9222"
    assert "--no-auth" not in capture and "--cookies-file" not in capture


def test_non_loopback_operator_cdp_endpoint_is_rejected_at_startup(tmp_path):
    with pytest.raises(ValueError):
        create_server(tmp_path, cdp_endpoints=frozenset({"http://192.168.1.5:9222"}))


@pytest.mark.asyncio
async def test_solve_challenge_returns_cookie_file_and_agent_not_values(tmp_path, monkeypatch):
    calls = []
    envelope = {
        "ok": True,
        "result": {"cookie_names": ["__cf_bm"], "user_agent": "Solver/1.0", "status": 200},
    }
    monkeypatch.setattr(
        "astrolabe.mapping_mcp.asyncio.create_subprocess_exec",
        _recording_subprocess(calls, [envelope]),
    )
    async with Client(create_server(tmp_path)) as client:
        result = await client.call_tool("solve_challenge", {"url": "https://example.com/app"})
    arguments = calls[0][0]
    assert arguments[3] == "challenge"
    assert arguments[arguments.index("--domain") + 1] == "example.com"
    out = Path(arguments[arguments.index("--out") + 1])
    assert out.is_relative_to(tmp_path)
    assert result.data["cookies_file"] == str(out.relative_to(tmp_path))
    assert result.data["user_agent"] == "Solver/1.0"
    assert result.data["cookie_names"] == ["__cf_bm"]


@pytest.mark.asyncio
async def test_verify_chart_defaults_to_anonymous_and_regenerates(tmp_path, monkeypatch):
    calls = []
    chart = tmp_path / "chart-example.com-1"
    chart.mkdir()
    (chart / "endpoints.json").write_text('{"base_domain": "example.com"}')
    (chart / "contract.json").write_text(
        '{"operations": {"GET /api/a": {"status": "verified-active"},'
        ' "POST /api/b": {"status": "verified-observed"}}}'
    )
    monkeypatch.setattr(
        "astrolabe.mapping_mcp.asyncio.create_subprocess_exec", _recording_subprocess(calls)
    )
    async with Client(create_server(tmp_path)) as client:
        result = await client.call_tool(
            "verify_chart",
            {"capture_directory": chart.name, "seeds": ["https://example.com/a"]},
        )
    verify, generation = calls[0][0], calls[1][0]
    assert verify[3:6] == ("contract", str(chart), "--execute")
    assert "--no-auth" in verify
    assert verify[verify.index("--seeds") + 1] == "https://example.com/a"
    assert generation[3] == "mcp-gen"
    assert result.data["verified_active"] == ["GET /api/a"]


@pytest.mark.asyncio
async def test_import_har_runs_the_real_pipeline_into_a_chart(tmp_path):
    """No subprocess double: the MCP tool drives the real CLI on the HAR fixture."""
    fixture = Path(__file__).parent / "fixtures" / "sample.har.json"
    (tmp_path / "capture.har").write_text(fixture.read_text())
    async with Client(create_server(tmp_path)) as client:
        with pytest.raises(ToolError, match="inside the workspace"):
            await client.call_tool("import_har", {"har_file": "../x.har", "domain": "example.com"})
        result = await client.call_tool(
            "import_har",
            {
                "har_file": "capture.har",
                "domain": json.loads(fixture.read_text())["log"]["entries"][0]["request"][
                    "url"
                ].split("/")[2],
            },
        )
    assert result.data["ok"] is True, result.data
    chart = Path(result.data["capture_directory"])
    contract = json.loads((chart / "contract.json").read_text())
    sources = {op["proof"]["observed"].get("source") for op in contract["operations"].values()}
    assert sources == {"har-import"}
    assert (chart / "toolpack.json").is_file()


@pytest.mark.asyncio
async def test_chart_status_without_provenance_is_honest(tmp_path):
    """The mapping server can run without the unified facade's mount data. It must
    report the empty case rather than omit the keys."""
    async with Client(create_server(tmp_path)) as client:
        status = (await client.call_tool("chart_status", {})).data
    assert status["mounted"] == {}
    assert status["skipped"] == []
    assert status["charts_on_disk_not_mounted"] == []
    assert status["code_root"] and status["runtime_module_path"]


# ----- register_session: the agent-held credential trust boundary ------------

_SESSION_COOKIE_VALUE = "SUPER_SECRET_COOKIE_VALUE_9f3a2b"
_SESSION_HEADER_VALUE = "Bearer SUPER_SECRET_HEADER_VALUE_7c2d1e"
_SESSION_COOKIE = {
    "name": "sid",
    "value": _SESSION_COOKIE_VALUE,
    "domain": "example.com",
    "path": "/",
}


def _session_payload(**overrides) -> dict:
    payload = {
        "domain": "example.com",
        "cookies": [dict(_SESSION_COOKIE)],
        "headers": {"authorization": _SESSION_HEADER_VALUE},
    }
    payload.update(overrides)
    return payload


async def _register(server, **overrides) -> dict:
    async with Client(server) as client:
        result = await client.call_tool("register_session", _session_payload(**overrides))
    data = result.data
    return data if isinstance(data, dict) else json.loads(result.content[0].text)


@pytest.mark.asyncio
async def test_register_session_returns_names_and_never_a_value(tmp_path):
    server = create_server(tmp_path, session_domains=frozenset({"example.com"}))
    response = await _register(server)
    assert response["cookie_names"] == ["sid"]
    assert response["header_names"] == ["authorization"]
    # The guarantee, stated explicitly: scan the serialized response for every value
    # that was submitted. redact() is not relied on here, because it matches on key
    # names and would blank cookie_names, a field the contract requires.
    serialized = json.dumps(response)
    assert _SESSION_COOKIE_VALUE not in serialized
    assert _SESSION_HEADER_VALUE not in serialized
    # Also per-value, so a value nested inside a list or dict cannot hide from the
    # serialized scan above.
    for value in response.values():
        assert _SESSION_COOKIE_VALUE not in json.dumps(value)
        assert _SESSION_HEADER_VALUE not in json.dumps(value)


@pytest.mark.asyncio
async def test_register_session_handle_is_unguessable_and_not_derivable(tmp_path):
    server = create_server(tmp_path, session_domains=frozenset({"example.com"}))
    first = await _register(server)
    second = await _register(server)
    handle = first["handle"]
    assert len(handle) >= 22, "handle is too short to be unguessable"
    assert handle.replace("-", "").replace("_", "").isalnum(), "handle is not URL-safe"
    assert first["handle"] != second["handle"]
    assert handle != "example.com"
    assert "example" not in handle and "com" not in handle


@pytest.mark.asyncio
async def test_register_session_stores_a_private_file(tmp_path):
    server = create_server(tmp_path, session_domains=frozenset({"example.com"}))
    response = await _register(server)
    stored = tmp_path / ".astrolabe" / "sessions" / f"{response['handle']}.json"
    assert stored.is_file()
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600
    assert stat.S_IMODE(stored.parent.stat().st_mode) == 0o700
    # The file must actually hold the value: a store that silently dropped it would
    # look identical from the response alone.
    assert _SESSION_COOKIE_VALUE in stored.read_text()


@pytest.mark.asyncio
async def test_register_session_refuses_a_domain_without_the_operator_gate(tmp_path):
    server = create_server(tmp_path)  # gate empty by default
    with pytest.raises(ToolError) as excinfo:
        await _register(server)
    assert "ASTROLABE_SESSION_DOMAINS" in str(excinfo.value)


@pytest.mark.asyncio
async def test_register_session_gate_is_exact_match_not_a_suffix(tmp_path):
    server = create_server(tmp_path, session_domains=frozenset({"example.com"}))
    for lookalike in ("notexample.com", "example.com.evil.test", "sub.example.com"):
        with pytest.raises(ToolError) as excinfo:
            await _register(server, domain=lookalike)
        assert "ASTROLABE_SESSION_DOMAINS" in str(excinfo.value)


@pytest.mark.asyncio
async def test_register_session_refuses_denied_header_and_cookie_names(tmp_path):
    server = create_server(tmp_path, session_domains=frozenset({"example.com"}))
    for denied in ("Host", "Cookie", "Transfer-Encoding"):
        with pytest.raises(ToolError) as excinfo:
            await _register(server, headers={denied: "x"}, cookies=[])
        assert denied in str(excinfo.value) or "not accepted" in str(excinfo.value)
        assert _SESSION_HEADER_VALUE not in str(excinfo.value)


@pytest.mark.asyncio
async def test_register_session_refuses_an_empty_session(tmp_path):
    server = create_server(tmp_path, session_domains=frozenset({"example.com"}))
    with pytest.raises(ToolError, match="at least one of cookies or headers"):
        await _register(server, cookies=[], headers={})


@pytest.mark.asyncio
async def test_register_session_refuses_an_oversized_value(tmp_path):
    server = create_server(tmp_path, session_domains=frozenset({"example.com"}))
    huge = "v" * 9000
    with pytest.raises(ToolError, match="exceeds the maximum length"):
        await _register(server, cookies=[], headers={"x-big": huge})
    assert huge not in str(server)


@pytest.mark.asyncio
async def test_register_session_label_is_length_and_charset_constrained(tmp_path):
    """A label is agent-supplied free text that gets stored, so it is constrained."""
    server = create_server(tmp_path, session_domains=frozenset({"example.com"}))
    with pytest.raises(ToolError, match="label must be"):
        await _register(server, label="<script>alert(1)</script>")
    with pytest.raises(ToolError, match="label must be"):
        await _register(server, label="x" * 65)
    assert (await _register(server, label="checkout run 1"))["ok"] is True
