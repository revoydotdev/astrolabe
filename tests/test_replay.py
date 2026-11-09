"""Tests for astrolabe.replay — the browserless curl_cffi replay tier.

curl_cffi IS an installed project dependency (unlike cloakbrowser), so this module
imports cleanly. No test here makes a real network call: `replay.requests.Session`
is monkeypatched with a fake that records what would have been sent.
"""

from __future__ import annotations

import json

import pytest

from astrolabe import replay

# ---- dget / dset -----------------------------------------------------------


def test_dget_walks_nested_dict_path():
    obj = {"data": {"search": {"paging": {"total": 42}}}}
    assert replay.dget(obj, "data.search.paging.total") == 42


def test_dget_walks_through_list_index():
    obj = {"data": {"items": [{"id": "a"}, {"id": "b"}]}}
    assert replay.dget(obj, "data.items.1.id") == "b"


def test_dget_missing_key_returns_none():
    obj = {"data": {"search": {}}}
    assert replay.dget(obj, "data.search.paging.total") is None


def test_dget_non_int_list_index_returns_none():
    obj = {"items": [1, 2, 3]}
    assert replay.dget(obj, "items.notanindex") is None


def test_dget_through_scalar_returns_none():
    obj = {"a": 5}
    assert replay.dget(obj, "a.b") is None


def test_dset_creates_intermediate_dicts():
    obj: dict = {}
    replay.dset(obj, "a.b.c", "value")
    assert obj == {"a": {"b": {"c": "value"}}}


def test_dset_overwrites_existing_leaf():
    obj = {"a": {"b": {"c": "old"}}}
    replay.dset(obj, "a.b.c", "new")
    assert obj["a"]["b"]["c"] == "new"


def test_dset_single_component_path():
    obj: dict = {}
    replay.dset(obj, "x", 1)
    assert obj == {"x": 1}


# ---- fakes for main() end-to-end request-construction tests ---------------


class _FakeCookieJar:
    def __init__(self):
        self.calls = []

    def set(self, name, value, domain=None, path="/"):
        self.calls.append({"name": name, "value": value, "domain": domain, "path": path})


class _FakeResponse:
    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers

    def json(self):
        if self._json_data is None:
            raise ValueError("no json body")
        return self._json_data


class _FakeSession:
    """Records every constructor + .post() call so tests can assert on the
    exact URL/headers/body astrolabe.replay would have sent, without curl_cffi
    ever touching the network."""

    instances: list[_FakeSession] = []

    def __init__(self, impersonate=None):
        self.impersonate = impersonate
        self.cookies = _FakeCookieJar()
        self.post_calls = []
        _FakeSession.instances.append(self)

    def post(self, url, headers=None, data=None, timeout=None):
        self.post_calls.append({"url": url, "headers": headers, "data": data, "timeout": timeout})
        return _FakeResponse(200, {"data": {"ok": True}})


@pytest.fixture(autouse=True)
def _reset_fake_session_registry():
    _FakeSession.instances.clear()
    yield
    _FakeSession.instances.clear()


@pytest.fixture
def fake_session(monkeypatch):
    monkeypatch.setattr(replay.requests, "Session", _FakeSession)
    return _FakeSession


def _write(path, obj):
    path.write_text(json.dumps(obj))
    return str(path)


def _run_replay(monkeypatch, tmp_path, op, auth_map, cookies=None, extra_argv=None):
    cookies_path = _write(tmp_path / "cookies.json", cookies if cookies is not None else [])
    auth_path = _write(tmp_path / "auth.map.json", auth_map)
    op_path = _write(tmp_path / "op.json", op)
    argv = [
        "replay.py",
        "--cookies",
        cookies_path,
        "--auth",
        auth_path,
        "--op-file",
        op_path,
        "--outdir",
        str(tmp_path),
    ] + (extra_argv or [])
    monkeypatch.setattr("sys.argv", argv)
    replay.main()
    return json.loads((tmp_path / "replay.json").read_text())


# ---- endpoint handling ------------------------------------------------------


def test_missing_endpoint_raises_clear_systemexit(monkeypatch, tmp_path, fake_session):
    op = {"alias": "someOp", "query": "query{x}"}
    auth_map = {"someOp": {"authorization": "Bearer abc"}}
    with pytest.raises(SystemExit, match="endpoint"):
        _run_replay(monkeypatch, tmp_path, op, auth_map)
    assert _FakeSession.instances == []  # never even got to opening a session


def test_endpoint_used_verbatim_when_no_alias_param(monkeypatch, tmp_path, fake_session):
    op = {
        "alias": "someOp",
        "endpoint": "https://example.com/api/graphql",
        "query": "query{x}",
    }
    auth_map = {"someOp": {"authorization": "Bearer abc"}}
    _run_replay(monkeypatch, tmp_path, op, auth_map)
    call = _FakeSession.instances[0].post_calls[0]
    assert call["url"] == "https://example.com/api/graphql"


def test_alias_param_appended_when_requested_and_no_existing_query(
    monkeypatch, tmp_path, fake_session
):
    op = {
        "alias": "userJobSearch",
        "endpoint": "https://www.example.com/api/graphql/v1",
        "query": "query{x}",
        "alias_param": True,
    }
    auth_map = {"userJobSearch": {"authorization": "Bearer abc"}}
    _run_replay(monkeypatch, tmp_path, op, auth_map)
    call = _FakeSession.instances[0].post_calls[0]
    assert call["url"] == "https://www.example.com/api/graphql/v1?alias=userJobSearch"


def test_alias_param_not_appended_when_endpoint_already_has_query(
    monkeypatch, tmp_path, fake_session
):
    op = {
        "alias": "someOp",
        "endpoint": "https://example.com/api/graphql?ver=2",
        "query": "query{x}",
        "alias_param": True,
    }
    auth_map = {"someOp": {"authorization": "Bearer abc"}}
    _run_replay(monkeypatch, tmp_path, op, auth_map)
    call = _FakeSession.instances[0].post_calls[0]
    assert call["url"] == "https://example.com/api/graphql?ver=2"


def test_alias_param_not_appended_when_not_requested(monkeypatch, tmp_path, fake_session):
    op = {
        "alias": "someOp",
        "endpoint": "https://example.com/api/graphql",
        "query": "query{x}",
    }
    auth_map = {"someOp": {"authorization": "Bearer abc"}}
    _run_replay(monkeypatch, tmp_path, op, auth_map)
    call = _FakeSession.instances[0].post_calls[0]
    assert call["url"] == "https://example.com/api/graphql"


# ---- header forwarding -------------------------------------------------


def test_auth_headers_forwarded_verbatim_from_auth_map(monkeypatch, tmp_path, fake_session):
    op = {"alias": "someOp", "endpoint": "https://example.com/api/graphql", "query": "q"}
    auth_map = {
        "someOp": {
            "authorization": "Bearer abc",
            "x-shopify-storefront-access-token": "tok-123",
            "x-tenant-id": "t1",
        }
    }
    _run_replay(monkeypatch, tmp_path, op, auth_map)
    headers = _FakeSession.instances[0].post_calls[0]["headers"]
    assert headers["authorization"] == "Bearer abc"
    assert headers["x-shopify-storefront-access-token"] == "tok-123"
    assert headers["x-tenant-id"] == "t1"


def test_hop_by_hop_headers_stripped_from_auth_map(monkeypatch, tmp_path, fake_session):
    op = {"alias": "someOp", "endpoint": "https://example.com/api/graphql", "query": "q"}
    auth_map = {
        "someOp": {
            "authorization": "Bearer abc",
            "content-length": "999",
            "Connection": "keep-alive",
            "host": "example.com",
        }
    }
    _run_replay(monkeypatch, tmp_path, op, auth_map)
    headers = _FakeSession.instances[0].post_calls[0]["headers"]
    assert "content-length" not in headers
    assert "Connection" not in headers
    assert "host" not in headers
    assert headers["authorization"] == "Bearer abc"


def test_generic_defaults_fill_in_when_not_supplied(monkeypatch, tmp_path, fake_session):
    op = {"alias": "someOp", "endpoint": "https://example.com/api/graphql", "query": "q"}
    auth_map = {"someOp": {"authorization": "Bearer abc"}}
    _run_replay(monkeypatch, tmp_path, op, auth_map)
    headers = _FakeSession.instances[0].post_calls[0]["headers"]
    assert headers["x-requested-with"] == "XMLHttpRequest"
    assert headers["content-type"] == "application/json"


def test_generic_defaults_do_not_override_harvested_values(monkeypatch, tmp_path, fake_session):
    op = {"alias": "someOp", "endpoint": "https://example.com/api/graphql", "query": "q"}
    auth_map = {
        "someOp": {"authorization": "Bearer abc", "content-type": "application/json; charset=x"}
    }
    _run_replay(monkeypatch, tmp_path, op, auth_map)
    headers = _FakeSession.instances[0].post_calls[0]["headers"]
    assert headers["content-type"] == "application/json; charset=x"


def test_no_hardcoded_default_endpoint():
    """No hardcoded single-site default GraphQL endpoint must live in the
    source; op-file 'endpoint' is required, not defaulted. `op.get("endpoint")`
    must never carry a second (default-value) argument."""
    import inspect
    import re

    src = inspect.getsource(replay)
    assert re.search(r'op\.get\(\s*"endpoint"\s*,', src) is None


# ---- alias resolution / auth-map fallback ----------------------------------


def test_no_scoped_auth_raises_clear_error(monkeypatch, tmp_path, fake_session):
    op = {"alias": "someOp", "endpoint": "https://example.com/api/graphql", "query": "q"}
    with pytest.raises(SystemExit, match="no scoped bearer"):
        _run_replay(monkeypatch, tmp_path, op, {})


def test_never_falls_back_to_first_auth_entry(monkeypatch, tmp_path, fake_session):
    op = {"alias": "missingAlias", "endpoint": "https://example.com/api/graphql", "query": "q"}
    auth_map = {"otherAlias": {"authorization": "Bearer fallback"}}
    with pytest.raises(SystemExit, match="NO_CREDENTIAL_FOR_OPERATION"):
        _run_replay(monkeypatch, tmp_path, op, auth_map)
    assert _FakeSession.instances == []


def test_versioned_auth_and_cookie_generations_must_match(monkeypatch, tmp_path, fake_session):
    op = {"alias": "someOp", "endpoint": "https://example.com/graphql", "query": "q"}
    auth = {
        "schema_version": 1,
        "generation_id": "auth-generation",
        "credentials": {"someOp": {"authorization": "Bearer abc"}},
    }
    cookies = {
        "schema_version": 1,
        "generation_id": "cookie-generation",
        "cookies": [],
    }
    with pytest.raises(SystemExit, match="AUTH_GENERATION_MISMATCH"):
        _run_replay(monkeypatch, tmp_path, op, auth, cookies)
    assert _FakeSession.instances == []


def test_versioned_auth_and_cookie_generation_executes_when_coherent(
    monkeypatch, tmp_path, fake_session
):
    op = {"alias": "someOp", "endpoint": "https://example.com/graphql", "query": "q"}
    auth = {
        "schema_version": 1,
        "generation_id": "generation-1",
        "credentials": {"someOp": {"authorization": "Bearer abc"}},
    }
    cookies = {"schema_version": 1, "generation_id": "generation-1", "cookies": []}
    result = _run_replay(monkeypatch, tmp_path, op, auth, cookies)
    assert result["ok"] == 1


# ---- output shape ------------------------------------------------------


def test_replay_json_written_with_expected_summary_fields(monkeypatch, tmp_path, fake_session):
    op = {"alias": "someOp", "endpoint": "https://example.com/api/graphql", "query": "q"}
    auth_map = {"someOp": {"authorization": "Bearer abc"}}
    out = _run_replay(monkeypatch, tmp_path, op, auth_map, extra_argv=["--repeat", "2"])
    assert out["op"] == "someOp"
    assert out["count"] == 2
    assert out["ok"] == 2
    assert len(out["results"]) == 2


def test_vary_sweeps_variable_across_calls(monkeypatch, tmp_path, fake_session):
    op = {
        "alias": "someOp",
        "endpoint": "https://example.com/api/graphql",
        "query": "q",
        "variables": {"filter": {"page": 1}},
    }
    auth_map = {"someOp": {"authorization": "Bearer abc"}}
    _run_replay(monkeypatch, tmp_path, op, auth_map, extra_argv=["--vary", "filter.page=1,2,3"])
    bodies = [json.loads(c["data"]) for c in _FakeSession.instances[0].post_calls]
    assert [b["variables"]["filter"]["page"] for b in bodies] == ["1", "2", "3"]


# ---- retry policy -------------------------------------------------------


class _StatusSession:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.post_calls = []
        self.cookies = _FakeCookieJar()

    def post(self, url, headers=None, data=None, timeout=None):
        self.post_calls.append({"url": url, "headers": headers, "data": data})
        status = self.statuses.pop(0) if self.statuses else 200
        headers = {"retry-after": "3"} if status == 429 else None
        return _FakeResponse(status, {"data": {"ok": True}}, headers)


def _install(monkeypatch, statuses):
    session = _StatusSession(statuses)
    monkeypatch.setattr(replay.requests, "Session", lambda impersonate=None: session)
    monkeypatch.setattr(replay.time, "sleep", lambda seconds: None)
    return session


def _op():
    return {"alias": "someOp", "endpoint": "https://example.com/api/graphql", "query": "q"}


def test_rate_limited_origin_is_retried_rather_than_recorded_as_a_failed_sample(
    monkeypatch, tmp_path, fake_session
):
    session = _install(monkeypatch, [429, 200])
    out = _run_replay(
        monkeypatch,
        tmp_path,
        _op(),
        {"someOp": {"authorization": "Bearer abc"}},
    )
    assert out["ok"] == 1
    assert len(session.post_calls) == 2
    assert out["results"][0]["status"] == 200
    assert out["results"][0]["attempts"] == 2


def test_permanent_verdict_is_not_retried(monkeypatch, tmp_path, fake_session):
    session = _install(monkeypatch, [403, 200])
    out = _run_replay(
        monkeypatch,
        tmp_path,
        _op(),
        {"someOp": {"authorization": "Bearer abc"}},
    )
    assert len(session.post_calls) == 1
    assert out["results"][0]["status"] == 403
    assert out["results"][0]["attempts"] == 1


def test_retry_budget_is_bounded_and_the_last_status_is_reported(
    monkeypatch, tmp_path, fake_session
):
    session = _install(monkeypatch, [429, 429, 429, 200])
    out = _run_replay(
        monkeypatch,
        tmp_path,
        _op(),
        {"someOp": {"authorization": "Bearer abc"}},
        extra_argv=["--retries", "2"],
    )
    assert len(session.post_calls) == 3
    assert out["results"][0]["status"] == 429
    assert out["results"][0]["attempts"] == 3


def test_retries_zero_makes_exactly_one_attempt(monkeypatch, tmp_path, fake_session):
    session = _install(monkeypatch, [429, 200])
    _run_replay(
        monkeypatch,
        tmp_path,
        _op(),
        {"someOp": {"authorization": "Bearer abc"}},
        extra_argv=["--retries", "0"],
    )
    assert len(session.post_calls) == 1


def test_replay_waits_the_origins_retry_after(monkeypatch, tmp_path, fake_session):
    session = _StatusSession([429, 200])
    monkeypatch.setattr(replay.requests, "Session", lambda impersonate=None: session)
    slept = []
    monkeypatch.setattr(replay.time, "sleep", lambda seconds: slept.append(seconds))
    _run_replay(
        monkeypatch,
        tmp_path,
        _op(),
        {"someOp": {"authorization": "Bearer abc"}},
    )
    assert slept == [3.0]
