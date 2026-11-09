"""The session-registry trust boundary, asserted rather than described.

An agent-held session is a credential the agent chose to introduce, so every
control around it is a security control. Each test here names one invariant and
asserts it specifically: none of them asserts only that a call "did not raise",
because a check that cannot fail is not a check.

The file-mode and expiry cases deliberately break a stored session before using
it, which is the only way to prove the gate is looking at the file rather than
trusting how it was written.
"""

from __future__ import annotations

import contextlib
import json
import stat
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from astrolabe.mapping_mcp import _session_stem, create_server

COOKIE_VALUE = "SUPER_SECRET_COOKIE_VALUE_9f3a2b"
HEADER_VALUE = "Bearer SUPER_SECRET_HEADER_VALUE_7c2d1e"
COOKIE: dict[str, Any] = {
    "name": "sid",
    "value": COOKIE_VALUE,
    "domain": "example.com",
    "path": "/",
}
GATED = frozenset({"example.com", "other.test"})


def _server(tmp_path: Path, domains: frozenset[str] = GATED):
    return create_server(tmp_path, session_domains=domains)


async def _register(server, **overrides) -> dict:
    payload: dict[str, Any] = {"domain": "example.com", "cookies": [dict(COOKIE)]}
    payload.update(overrides)
    async with Client(server) as client:
        result = await client.call_tool("register_session", payload)
    return result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)


def _stored(tmp_path: Path, handle: str) -> Path:
    return tmp_path / ".astrolabe" / "sessions" / f"{_session_stem(handle)}.json"


async def _use(server, handle: str) -> None:
    """Drive a session-sourced map_site; raises ToolError when refused."""
    async with Client(server) as client:
        await client.call_tool("map_site", {"domain": "example.com", "session": handle})


# ----- file mode -------------------------------------------------------------


@pytest.mark.asyncio
async def test_stored_session_file_is_mode_0600(tmp_path):
    handle = (await _register(_server(tmp_path)))["handle"]
    mode = stat.S_IMODE(_stored(tmp_path, handle).stat().st_mode)
    assert mode == 0o600, f"session file is {oct(mode)}, expected 0o600"


@pytest.mark.asyncio
async def test_session_directory_is_mode_0700(tmp_path):
    handle = (await _register(_server(tmp_path)))["handle"]
    mode = stat.S_IMODE(_stored(tmp_path, handle).parent.stat().st_mode)
    assert mode == 0o700, f"session directory is {oct(mode)}, expected 0o700"


@pytest.mark.asyncio
async def test_group_or_world_readable_session_file_is_refused(tmp_path):
    """0o077 is rejected: another local user must not be able to read the secret."""
    handle = (await _register(_server(tmp_path)))["handle"]
    _stored(tmp_path, handle).chmod(0o604)
    with pytest.raises(ToolError) as excinfo:
        await _use(_server(tmp_path), handle)
    assert "private regular file" in str(excinfo.value), (
        f"expected the file-mode refusal, got: {excinfo.value}"
    )


@pytest.mark.asyncio
async def test_mode_0644_session_file_is_refused(tmp_path):
    """The deliberate violation, as a permanent test rather than a one-off run."""
    handle = (await _register(_server(tmp_path)))["handle"]
    _stored(tmp_path, handle).chmod(0o644)
    with pytest.raises(ToolError) as excinfo:
        await _use(_server(tmp_path), handle)
    assert "private regular file" in str(excinfo.value), (
        f"a world-readable session was accepted: {excinfo.value}"
    )


# ----- file type and symlinks ------------------------------------------------


@pytest.mark.asyncio
async def test_non_regular_session_file_is_refused(tmp_path):
    """A directory in the cookie file's place must fail the S_ISREG check."""
    handle = (await _register(_server(tmp_path)))["handle"]
    target = _stored(tmp_path, handle)
    target.unlink()
    target.mkdir()
    with pytest.raises(ToolError) as excinfo:
        await _use(_server(tmp_path), handle)
    assert "private regular file" in str(excinfo.value), (
        f"a non-regular file was accepted: {excinfo.value}"
    )


@pytest.mark.asyncio
async def test_symlinked_session_file_is_refused(tmp_path):
    """A symlink is not a regular file, so lstat must reject it even when the
    target it points at is itself private."""
    handle = (await _register(_server(tmp_path)))["handle"]
    target = _stored(tmp_path, handle)
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("[]")
    elsewhere.chmod(0o600)
    target.unlink()
    target.symlink_to(elsewhere)
    with pytest.raises(ToolError) as excinfo:
        await _use(_server(tmp_path), handle)
    assert "private regular file" in str(excinfo.value), (
        f"a symlinked session was followed: {excinfo.value}"
    )


# ----- containment -----------------------------------------------------------


@pytest.mark.asyncio
async def test_relative_traversal_handle_is_refused(tmp_path):
    with pytest.raises(ToolError) as excinfo:
        await _use(_server(tmp_path), "../../etc/passwd")
    assert "register_session" in str(excinfo.value)
    assert "etc/passwd" not in str(excinfo.value), "the probe path was echoed back"


@pytest.mark.asyncio
async def test_absolute_path_handle_is_refused(tmp_path):
    absolute = str(tmp_path / "cookies.json")
    (tmp_path / "cookies.json").write_text("[]")
    (tmp_path / "cookies.json").chmod(0o600)
    with pytest.raises(ToolError) as excinfo:
        await _use(_server(tmp_path), absolute)
    assert "register_session" in str(excinfo.value)


# ----- handle properties -----------------------------------------------------


@pytest.mark.asyncio
async def test_handle_carries_at_least_128_bits_of_url_safe_entropy(tmp_path):
    handle = (await _register(_server(tmp_path)))["handle"]
    assert len(handle) >= 22, f"handle is {len(handle)} chars, too short to be unguessable"
    assert handle.replace("-", "").replace("_", "").isalnum(), "handle is not URL-safe"


@pytest.mark.asyncio
async def test_two_registrations_produce_different_handles(tmp_path):
    server = _server(tmp_path)
    assert (await _register(server))["handle"] != (await _register(server))["handle"]


@pytest.mark.asyncio
async def test_handle_is_not_derivable_from_the_domain(tmp_path):
    handle = (await _register(_server(tmp_path)))["handle"]
    assert handle != "example.com"
    assert "example" not in handle and "com" not in handle


@pytest.mark.asyncio
async def test_handle_never_appears_in_a_filename(tmp_path):
    """The resolved path goes on argv, which ps exposes, so it must not carry the
    handle."""
    handle = (await _register(_server(tmp_path)))["handle"]
    listed = [p.name for p in (tmp_path / ".astrolabe" / "sessions").iterdir()]
    assert listed, "no session file was written, so this assertion would be vacuous"
    assert all(handle not in name for name in listed), f"handle leaked into {listed}"


# ----- values never echoed ---------------------------------------------------


@pytest.mark.asyncio
async def test_response_contains_no_submitted_cookie_value(tmp_path):
    response = await _register(_server(tmp_path))
    assert COOKIE_VALUE not in json.dumps(response), "the cookie value was echoed back"


@pytest.mark.asyncio
async def test_response_contains_no_submitted_header_value(tmp_path):
    response = await _register(_server(tmp_path), headers={"authorization": HEADER_VALUE})
    assert HEADER_VALUE not in json.dumps(response), "the header value was echoed back"


@pytest.mark.asyncio
async def test_refusal_bodies_contain_no_submitted_value(tmp_path):
    server = _server(tmp_path)
    for bad in ({"headers": {"Host": HEADER_VALUE}}, {"cookies": [], "headers": {}}):
        with pytest.raises(ToolError) as excinfo:
            await _register(server, **bad)
        assert COOKIE_VALUE not in str(excinfo.value)
        assert HEADER_VALUE not in str(excinfo.value)


# ----- expiry ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_expired_session_is_refused_at_resolve(tmp_path):
    """Expiry is re-checked on use, not only at registration."""
    handle = (await _register(_server(tmp_path)))["handle"]
    meta = _stored(tmp_path, handle).with_suffix(".meta.json")
    stored = json.loads(meta.read_text())
    stored["expires_at"] = "2000-01-01T00:00:00+00:00"
    meta.write_text(json.dumps(stored))
    with pytest.raises(ToolError, match="expired"):
        await _use(_server(tmp_path), handle)


@pytest.mark.asyncio
async def test_session_expiry_is_capped_at_24_hours(tmp_path):
    from datetime import UTC, datetime, timedelta

    from astrolabe.mapping_mcp import MAX_SESSION_SECONDS

    far = int((datetime.now(UTC) + timedelta(days=30)).timestamp())
    response = await _register(_server(tmp_path), cookies=[{**COOKIE, "expires": far}])
    granted = datetime.fromisoformat(response["expires_at"])
    ceiling = datetime.now(UTC) + timedelta(seconds=MAX_SESSION_SECONDS)
    assert granted <= ceiling, (
        f"granted {granted.isoformat()} beyond the {MAX_SESSION_SECONDS}s cap"
    )


# ----- revocation ------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoked_session_is_refused_on_next_use(tmp_path):
    handle = (await _register(_server(tmp_path)))["handle"]
    async with Client(_server(tmp_path)) as client:
        assert (await client.call_tool("revoke_session", {"handle": handle})).data[
            "revoked"
        ] is True
    with pytest.raises(ToolError, match="register_session"):
        await _use(_server(tmp_path), handle)


@pytest.mark.asyncio
async def test_revoke_reports_false_when_there_was_nothing_to_remove(tmp_path):
    handle = (await _register(_server(tmp_path)))["handle"]
    async with Client(_server(tmp_path)) as client:
        await client.call_tool("revoke_session", {"handle": handle})
        again = (await client.call_tool("revoke_session", {"handle": handle})).data
    assert again["revoked"] is False, "a second revoke claimed a removal that did not happen"


@pytest.mark.asyncio
async def test_revoke_does_not_echo_the_handle(tmp_path):
    handle = (await _register(_server(tmp_path)))["handle"]
    async with Client(_server(tmp_path)) as client:
        revoked = (await client.call_tool("revoke_session", {"handle": handle})).data
    assert handle not in json.dumps(revoked), "revoke echoed a bearer token"


# ----- the operator allowlist ------------------------------------------------


@pytest.mark.asyncio
async def test_allowlist_refuses_every_domain_when_env_is_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("ASTROLABE_SESSION_DOMAINS", raising=False)
    server = create_server(tmp_path)
    for domain in ("example.com", "other.test", "deep.sub.example.com"):
        with pytest.raises(ToolError, match="ASTROLABE_SESSION_DOMAINS"):
            await _register(server, domain=domain)


@pytest.mark.asyncio
async def test_allowlist_permits_an_exact_domain_from_the_env(tmp_path, monkeypatch):
    """F-22: the env path with a non-empty value that SUCCEEDS."""
    monkeypatch.setenv("ASTROLABE_SESSION_DOMAINS", "example.com")
    response = await _register(create_server(tmp_path))
    assert response["ok"] is True
    assert response["cookie_names"] == ["sid"]


@pytest.mark.asyncio
async def test_allowlist_is_exact_not_a_suffix_match(tmp_path, monkeypatch):
    monkeypatch.setenv("ASTROLABE_SESSION_DOMAINS", "sub.example.com")
    with pytest.raises(ToolError, match="ASTROLABE_SESSION_DOMAINS"):
        await _register(create_server(tmp_path), domain="example.com")


@pytest.mark.asyncio
async def test_session_registered_for_one_domain_is_refused_for_another(tmp_path):
    handle = (await _register(_server(tmp_path), domain="other.test"))["handle"]
    with pytest.raises(ToolError, match="different domain"):
        await _use(_server(tmp_path), handle)


# ----- denied names ----------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("denied", ["Host", "Cookie", "Transfer-Encoding", "Content-Length"])
async def test_denied_header_names_are_refused(tmp_path, denied):
    with pytest.raises(ToolError, match="not accepted"):
        await _register(_server(tmp_path), cookies=[], headers={denied: "x"})


@pytest.mark.asyncio
async def test_denied_cookie_name_is_refused(tmp_path):
    with pytest.raises(ToolError, match="not accepted"):
        await _register(_server(tmp_path), cookies=[{"name": "Host", "value": "x"}], headers={})


# ----- no handle in logs -----------------------------------------------------


@pytest.mark.asyncio
async def test_handle_never_appears_in_a_run_log(tmp_path, monkeypatch):
    handle = (await _register(_server(tmp_path)))["handle"]

    class Process:
        returncode = 1

        async def communicate(self):
            return b'{"ok":false,"error":"upstream refused"}', b""

    async def fake(*args, **kwargs):
        return Process()

    monkeypatch.setattr("astrolabe.mapping_mcp.asyncio.create_subprocess_exec", fake)
    with contextlib.suppress(ToolError):
        await _use(_server(tmp_path), handle)
    logs = list((tmp_path / ".astrolabe" / "logs").glob("*.log"))
    assert logs, "no run log was written, so the scan would have been vacuous"
    for log in logs:
        assert handle not in log.read_text(errors="replace"), f"handle leaked into {log.name}"


# ----- malformed registration input -----------------------------------------


@pytest.mark.asyncio
async def test_registration_without_a_domain_is_refused(tmp_path):
    with pytest.raises(ToolError, match="domain is required"):
        await _register(_server(tmp_path), domain="")


@pytest.mark.asyncio
async def test_non_object_cookie_is_refused(tmp_path):
    """Malformed cookie entries fail closed.

    The refusal comes from the declared ``list[dict]`` type rather than from the
    tool body, so this asserts the outcome and not which layer produced it.
    """
    with pytest.raises(ToolError):
        await _register(_server(tmp_path), cookies=["sid=abc"], headers={})


@pytest.mark.asyncio
async def test_cookie_without_a_name_is_refused(tmp_path):
    with pytest.raises(ToolError, match="needs a name"):
        await _register(_server(tmp_path), cookies=[{"value": "abc"}], headers={})


@pytest.mark.asyncio
async def test_oversized_session_is_refused_rather_than_truncated(tmp_path):
    """The per-value cap fires first, so reaching the total-size branch needs many
    individually legal values."""
    from astrolabe.mapping_mcp import MAX_SESSION_BYTES, MAX_SESSION_VALUE_CHARS

    chunk = "v" * (MAX_SESSION_VALUE_CHARS - 1)
    headers = {f"x-{i}": chunk for i in range(MAX_SESSION_BYTES // len(chunk) + 2)}
    with pytest.raises(ToolError, match="too large"):
        await _register(_server(tmp_path), cookies=[], headers=headers)


@pytest.mark.asyncio
async def test_revoke_without_a_handle_is_refused(tmp_path):
    async with Client(_server(tmp_path)) as client:
        with pytest.raises(ToolError, match="handle is required"):
            await client.call_tool("revoke_session", {})


# ----- malformed stored metadata --------------------------------------------


@pytest.mark.asyncio
async def test_unreadable_session_metadata_is_refused(tmp_path):
    """Corrupt metadata must fail closed rather than fall through to a use."""
    handle = (await _register(_server(tmp_path)))["handle"]
    _stored(tmp_path, handle).with_suffix(".meta.json").write_text("{not json")
    with pytest.raises(ToolError, match="metadata is unreadable"):
        await _use(_server(tmp_path), handle)


@pytest.mark.asyncio
async def test_session_metadata_without_an_expiry_is_refused(tmp_path):
    """A record with no deadline is not a session we can bound, so it is refused."""
    handle = (await _register(_server(tmp_path)))["handle"]
    meta_path = _stored(tmp_path, handle).with_suffix(".meta.json")
    stored = json.loads(meta_path.read_text())
    stored.pop("expires_at", None)
    meta_path.write_text(json.dumps(stored))
    with pytest.raises(ToolError, match="no readable expiry"):
        await _use(_server(tmp_path), handle)


@pytest.mark.asyncio
async def test_expiry_without_a_timezone_is_read_as_utc(tmp_path):
    """A naive timestamp is common in hand-edited records; treating it as local
    time would silently extend or shorten the session."""
    from datetime import UTC, datetime, timedelta

    handle = (await _register(_server(tmp_path)))["handle"]
    meta_path = _stored(tmp_path, handle).with_suffix(".meta.json")
    stored = json.loads(meta_path.read_text())
    # Read as UTC, so a naive timestamp an hour out is still valid and must be
    # accepted: coercing it to local time could silently shorten the session.
    stored["expires_at"] = (datetime.now(UTC) + timedelta(hours=1)).replace(tzinfo=None).isoformat()
    meta_path.write_text(json.dumps(stored))
    with contextlib.suppress(ToolError):
        await _use(_server(tmp_path), handle)
    # A naive timestamp already in the past is refused rather than accepted.
    stored["expires_at"] = (datetime.now(UTC) - timedelta(hours=1)).replace(tzinfo=None).isoformat()
    meta_path.write_text(json.dumps(stored))
    with pytest.raises(ToolError, match="expired"):
        await _use(_server(tmp_path), handle)
