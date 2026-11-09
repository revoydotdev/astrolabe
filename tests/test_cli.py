"""Tests for astrolabe.cli — argument parsing, profile wiring, and the
ssh/put/get/run_capture/preflight command-construction layer.

Nothing here invokes real ssh/scp or a browser: `cli.run` (the module-level
subprocess.run wrapper) is monkeypatched wherever a command would otherwise
shell out remotely. Local profiles execute literal argv values directly to
exercise run_capture_argv()'s actual timeout/SIGTERM handling.
"""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

import pytest

import astrolabe
from astrolabe import cli
from astrolabe import profile as prof


class _FakeCompleted:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Isolate every test from this machine's real env/config so profile
    resolution is deterministic (mirrors tests/test_profile.py)."""
    for k in list(os.environ):
        if k.startswith("ASTROLABE_"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    yield


# ---- argument parsing --------------------------------------------------


def test_all_subcommands_registered():
    p = cli.build_parser()
    sub_actions = [a for a in p._subparsers._group_actions if a.dest == "cmd"]
    choices = set(sub_actions[0].choices)
    assert choices == {
        "preflight",
        "map",
        "replay",
        "mcp-gen",
        "scan",
        "contract",
        "recipe",
        "import-openapi",
        "challenge",
        "import-har",
        "inspect-artifact",
        "migrate-artifact",
        "check",
    }


@pytest.mark.parametrize(
    "subcmd,extra",
    [
        ("preflight", []),
        ("map", ["example.com"]),
        ("scan", ["https://example.com"]),
        ("contract", ["/tmp/some-capture-dir"]),
        (
            "replay",
            [
                "example.com",
                "--op",
                "op.json",
                "--cookies-file",
                "cookies.json",
                "--auth-file",
                "auth.map.json",
            ],
        ),
    ],
)
def test_host_and_local_default_to_none_not_hardcoded_host(subcmd, extra):
    """--host/--local must default to None (meaning "unset, fall through to
    profile resolution") — NOT the old hardcoded "capture-host" / False. A
    store_true default of False here would silently defeat the whole
    layered-resolution design (see _resolve())."""
    p = cli.build_parser()
    a = p.parse_args([subcmd, *extra])
    assert a.host is None
    assert a.local is None


def test_preflight_json_flag_defaults_false():
    p = cli.build_parser()
    a = p.parse_args(["preflight"])
    assert a.json is False


def test_scan_parses_discovery_policy_and_static_mining_controls():
    args = cli.build_parser().parse_args(
        [
            "scan",
            "https://example.com/catalog",
            "--max-total-requests",
            "60",
            "--max-static-resources",
            "12",
            "--allowed-static-host",
            "assets.example.net",
            "--delay-ms",
            "800",
            "--working-hours-utc",
            "9-17",
            "--account-risk",
            "sensitive",
            "--authorized-path",
            "/catalog",
            "--prohibited-path",
            "/account",
            "--prohibited-action",
            "checkout",
            "--operator-seed",
            "https://example.com/catalog?page=2",
        ]
    )
    assert args.max_total_requests == 60
    assert args.max_static_resources == 12
    assert args.allowed_static_host == ["assets.example.net"]
    assert args.delay_ms == 800
    assert args.working_hours_utc == "9-17"
    assert args.account_risk == "sensitive"
    assert args.authorized_path == ["/catalog"]
    assert args.prohibited_path == ["/account"]
    assert args.prohibited_action == ["checkout"]
    assert args.operator_seed == ["https://example.com/catalog?page=2"]


def test_map_parses_full_domain_and_flags():
    p = cli.build_parser()
    a = p.parse_args(
        ["map", "example.com", "--host", "myhost", "--local", "--no-auth", "--crawl", "3"]
    )
    assert a.domain == "example.com"
    assert a.host == "myhost"
    assert a.local is True
    assert a.no_auth is True
    assert a.crawl == 3
    assert a.func is cli.cmd_map


def test_replay_requires_op():
    p = cli.build_parser()
    with pytest.raises(SystemExit):
        p.parse_args(["replay", "example.com"])  # missing required --op


def test_replay_local_flag_true_when_passed():
    """replay now exposes --local like map/scan/contract, so LOCAL-mode
    pipelines don't have every transfer shell out to a remote scp target that
    happens to be this machine."""
    p = cli.build_parser()
    a = p.parse_args(
        [
            "replay",
            "example.com",
            "--op",
            "op.json",
            "--cookies-file",
            "cookies.json",
            "--auth-file",
            "auth.map.json",
            "--local",
        ]
    )
    assert a.local is True


def test_replay_local_flag_defaults_to_none_not_false():
    """A store_true default of False here would silently override the
    profile's own autodetection of "am I the pipeline host" -- see _resolve()
    and profile.resolve_profile()'s `local` precedence."""
    p = cli.build_parser()
    a = p.parse_args(
        [
            "replay",
            "example.com",
            "--op",
            "op.json",
            "--cookies-file",
            "cookies.json",
            "--auth-file",
            "auth.map.json",
        ]
    )
    assert a.local is None


def test_contract_execute_flag_and_defaults():
    p = cli.build_parser()
    a = p.parse_args(["contract", "/tmp/cap", "--execute", "--domain", "example.com"])
    assert a.execute is True
    assert a.domain == "example.com"
    assert a.host is None
    assert a.local is None


# ---- profile wiring (_resolve) ------------------------------------------


def test_resolve_with_no_overrides_matches_legacy_defaults():
    a = types.SimpleNamespace(host=None, local=None)
    hp = cli._resolve(a)
    assert hp.host == "capture-host"
    assert hp.cloak_py == "~/.local/share/pipx/venvs/cloakbrowser/bin/python"
    assert hp.clairvoyance == "~/astrolabe-tools/venv/bin/clairvoyance"
    assert hp.byparr == "http://127.0.0.1:8191/v1"


def test_resolve_threads_explicit_host_and_local_from_argv():
    a = types.SimpleNamespace(host="custom-host", local=True)
    hp = cli._resolve(a)
    assert hp.host == "custom-host"
    assert hp.local is True


def test_resolve_missing_local_attr_falls_through():
    """Commands without a --local flag (replay) still resolve via getattr's
    default of None rather than raising AttributeError."""
    a = types.SimpleNamespace(host=None)
    hp = cli._resolve(a)
    assert isinstance(hp, prof.HostProfile)


def test_resolve_returns_a_host_profile_instance():
    a = types.SimpleNamespace(host=None, local=None)
    hp = cli._resolve(a)
    assert isinstance(hp, prof.HostProfile)


# ---- command construction: argv execution / put / get --------------------


def test_ssh_argv_default_timeout_comes_from_profile(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: calls.append((cmd, kw)) or _FakeCompleted())
    hp = prof.resolve_profile(host="remote-box", local=False, ssh_timeout=77, config_path=None)
    cli.ssh_argv(hp, ["echo", "hi"])
    assert calls[0][1] == {"timeout": 77}


def test_ssh_argv_local_does_not_interpret_shell_metacharacters(tmp_path):
    hp = prof.resolve_profile(host="local", config_path=None)
    marker = tmp_path / "must-not-exist"
    hostile = f"literal; touch {marker}"
    result = cli.ssh_argv(
        hp,
        [sys.executable, "-c", "import sys;print(sys.argv[1])", hostile],
        timeout=5,
    )
    assert result.stdout.strip() == hostile
    assert not marker.exists()


def test_ssh_argv_remote_quotes_every_argument_once(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: calls.append((cmd, kw)) or _FakeCompleted())
    hp = prof.resolve_profile(host="remote-box", local=False, config_path=None)
    cli.ssh_argv(hp, ["tool", "value;touch /tmp/nope", "$(id)"], cwd="/dev/shm/astrolabe-x")
    remote_command = calls[0][0][2]
    assert remote_command == (
        "cd /dev/shm/astrolabe-x && exec tool 'value;touch /tmp/nope' '$(id)'"
    )


def test_deployed_helpers_import_flat():
    """Every helper staged onto the capture host must import as a top-level module.

    Regression: graphql_doc.py carried `from .operation import SemanticKind`, which
    only resolves inside the package. Deployed flat into /dev/shm it raised
    ImportError and took down every `astrolabe map` run at the capture step."""
    import ast as _ast

    unguarded = []
    for helper in sorted(set(cli.CAPTURE_HELPERS) | set(cli.CONTRACT_HELPERS)):
        source = Path(cli.HERE, helper).read_text()
        tree = _ast.parse(source)
        relative = [n for n in _ast.walk(tree) if isinstance(n, _ast.ImportFrom) and n.level]
        # A relative import is only allowed when a try/except ImportError also offers
        # the flat form (the pattern capture.py already uses).
        if relative and not _relative_import_has_flat_fallback(tree):
            unguarded.append((helper, [n.lineno for n in relative]))
    assert not unguarded, f"deployed helpers with unguarded relative imports: {unguarded}"


def _relative_import_has_flat_fallback(tree) -> bool:
    import ast as _ast

    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Try):
            continue
        handles_import_error = any(
            isinstance(h.type, _ast.Name) and h.type.id == "ImportError" for h in node.handlers
        )
        relative_in_body = any(
            isinstance(n, _ast.ImportFrom) and n.level
            for n in _ast.walk(_ast.Module(node.body, []))
        )
        flat_in_handler = any(
            isinstance(n, _ast.ImportFrom) and not n.level
            for h in node.handlers
            for n in _ast.walk(_ast.Module(h.body, []))
        )
        if handles_import_error and relative_in_body and flat_in_handler:
            return True
    return False


def test_site_recipe_stem_does_not_collide_with_a_deployed_helper():
    """The site recipe and astrolabe's helpers share one staging dir on the capture
    host. Naming the recipe `recipe.py` clobbered the helper of the same name."""
    staged = {f"{cli.SITE_RECIPE_STEM}.py", f"{cli.SITE_RECIPE_STEM}.json"}
    assert not staged & (set(cli.CAPTURE_HELPERS) | set(cli.CONTRACT_HELPERS))


def test_ssh_argv_remote_defers_tilde_arguments_to_the_remote_home(monkeypatch):
    """A `~/` path passed as an *argument* must stay expandable on the far side.

    Regression: only argv[0] got the "$HOME" treatment, so the clairvoyance
    probe (`test -x ~/astrolabe-tools/.../clairvoyance`) shipped a literal tilde and
    always reported the engine absent."""
    calls = []
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: calls.append((cmd, kw)) or _FakeCompleted())
    hp = prof.resolve_profile(host="remote-box", local=False, config_path=None)
    cli.ssh_argv(hp, ["test", "-x", "~/astrolabe-tools/venv/bin/clairvoyance"])
    assert calls[0][0][2] == 'test -x "$HOME"/astrolabe-tools/venv/bin/clairvoyance'


def test_ssh_argv_local_expands_tilde_arguments(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: calls.append((cmd, kw)) or _FakeCompleted())
    monkeypatch.setenv("HOME", str(tmp_path))
    hp = prof.resolve_profile(host="local", config_path=None)
    cli.ssh_argv(hp, ["test", "-x", "~/astrolabe-tools/bin/x", "not~/a~/path"])
    assert calls[0][0] == ["test", "-x", f"{tmp_path}/astrolabe-tools/bin/x", "not~/a~/path"]


def test_ssh_argv_fails_closed_on_nonzero_result(monkeypatch):
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: _FakeCompleted(stderr="denied", returncode=9))
    hp = prof.resolve_profile(host="remote-box", local=False, config_path=None)
    with pytest.raises(cli.CommandExecutionError, match="exit 9"):
        cli.ssh_argv(hp, ["false"])


def test_put_local_copies_via_cp(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: calls.append((cmd, kw)) or _FakeCompleted())
    hp = prof.resolve_profile(host="local", config_path=None)
    src = tmp_path / "capture.py"
    src.write_text("# helper")
    dst = str(tmp_path / "deployed" / "capture.py")
    cli.put(hp, str(src), dst)
    assert calls == [(["cp", str(src), dst], {})]
    assert os.path.isdir(tmp_path / "deployed")  # makedirs side effect for the local path


def test_put_remote_uses_scp(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: calls.append((cmd, kw)) or _FakeCompleted())
    hp = prof.resolve_profile(host="remote-box", local=False, config_path=None)
    src = tmp_path / "capture.py"
    src.write_text("# helper")
    cli.put(hp, str(src), "/dev/shm/astrolabe-x/capture.py")
    assert calls == [
        (["scp", "-q", "--", str(src), "remote-box:/dev/shm/astrolabe-x/capture.py"], {})
    ]


def test_get_remote_uses_scp(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: calls.append((cmd, kw)) or _FakeCompleted())
    hp = prof.resolve_profile(host="remote-box", local=False, config_path=None)
    cli.get(hp, "/dev/shm/astrolabe-x/out.json", "/local/out.json")
    assert calls == [
        (["scp", "-q", "--", "remote-box:/dev/shm/astrolabe-x/out.json", "/local/out.json"], {})
    ]


def test_get_local_fails_closed_when_source_absent(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: calls.append((cmd, kw)) or _FakeCompleted())
    hp = prof.resolve_profile(host="local", config_path=None)
    missing_src = str(tmp_path / "does-not-exist.json")
    with pytest.raises(FileNotFoundError, match="required remote artifact"):
        cli.get(hp, missing_src, str(tmp_path / "out.json"))
    assert calls == []


def test_transfer_rejects_remote_path_outside_staging(monkeypatch, tmp_path):
    src = tmp_path / "capture.py"
    src.write_text("# helper")
    hp = prof.resolve_profile(host="remote-box", local=False, config_path=None)
    with pytest.raises(ValueError, match="outside"):
        cli.put(hp, str(src), "/tmp/user-controlled.py")


def test_transfer_failure_is_fatal(monkeypatch, tmp_path):
    src = tmp_path / "capture.py"
    src.write_text("# helper")
    monkeypatch.setattr(
        cli, "run", lambda cmd, **kw: _FakeCompleted(stderr="scp failed", returncode=1)
    )
    hp = prof.resolve_profile(host="remote-box", local=False, config_path=None)
    with pytest.raises(cli.CommandExecutionError, match="upload"):
        cli.put(hp, str(src), "/dev/shm/astrolabe-x/capture.py")


def test_transfer_manifest_binds_run_id_and_checksums(tmp_path):
    for name, content in {
        "capture.jsonl": "{}\n",
        "meta.json": "{}",
        "graphql-names.txt": "Query\n",
    }.items():
        (tmp_path / name).write_text(content)
    checksums = {
        name: cli._sha256_file(str(tmp_path / name))
        for name in ("capture.jsonl", "meta.json", "graphql-names.txt")
    }
    (tmp_path / "transfer-manifest.json").write_text(
        json.dumps({"run_id": "expected-run", "sha256": checksums})
    )
    assert cli._verify_transfer_manifest(str(tmp_path), "expected-run")["sha256"] == checksums


@pytest.mark.parametrize("failure", ["run-id", "checksum"])
def test_transfer_manifest_rejects_stale_or_corrupt_artifacts(tmp_path, failure):
    for name in ("capture.jsonl", "meta.json", "graphql-names.txt"):
        (tmp_path / name).write_text("original")
    checksums = {
        name: cli._sha256_file(str(tmp_path / name))
        for name in ("capture.jsonl", "meta.json", "graphql-names.txt")
    }
    (tmp_path / "transfer-manifest.json").write_text(
        json.dumps({"run_id": "old-run" if failure == "run-id" else "new-run", "sha256": checksums})
    )
    if failure == "checksum":
        (tmp_path / "meta.json").write_text("truncated")
    with pytest.raises(cli.PartialCaptureError):
        cli._verify_transfer_manifest(str(tmp_path), "new-run")


def test_target_slug_is_bounded_and_collision_resistant():
    first = cli._target_slug("a" * 253)
    second = cli._target_slug("a" * 252 + "b")
    assert len(first) <= 77
    assert first != second


def test_directory_promotion_replaces_artifact_set_atomically(tmp_path):
    destination = tmp_path / "result"
    destination.mkdir()
    (destination / "stale.json").write_text("old")
    staging = tmp_path / ".astrolabe-stage-new"
    staging.mkdir()
    (staging / "current.json").write_text("new")
    cli._promote_staging_directory(str(staging), str(destination))
    assert (destination / "current.json").read_text() == "new"
    assert not (destination / "stale.json").exists()
    assert not list(tmp_path.glob(".astrolabe-backup-*"))


def test_directory_promotion_restores_prior_output_if_swap_fails(tmp_path, monkeypatch):
    destination = tmp_path / "result"
    destination.mkdir()
    (destination / "prior.json").write_text("known-good")
    staging = tmp_path / ".astrolabe-stage-new"
    staging.mkdir()
    (staging / "current.json").write_text("new")
    real_replace = cli.os.replace
    calls = 0

    def fail_second_replace(source, target):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated promotion failure")
        return real_replace(source, target)

    monkeypatch.setattr(cli.os, "replace", fail_second_replace)
    with pytest.raises(OSError, match="simulated"):
        cli._promote_staging_directory(str(staging), str(destination))
    assert (destination / "prior.json").read_text() == "known-good"
    assert (staging / "current.json").read_text() == "new"


def test_cleanup_failure_makes_otherwise_successful_command_fail():
    @cli._guaranteed_cleanup
    def operation():
        cli._register_cleanup(lambda: (_ for _ in ()).throw(OSError("cleanup denied")))
        return "would-have-succeeded"

    with pytest.raises(cli.CommandExecutionError, match="cleanup denied"):
        operation()


def test_cleanup_failure_does_not_replace_primary_error():
    @cli._guaranteed_cleanup
    def operation():
        cli._register_cleanup(lambda: (_ for _ in ()).throw(OSError("cleanup denied")))
        raise cli.PartialCaptureError("capture failed")

    with pytest.raises(cli.PartialCaptureError, match="capture failed") as raised:
        operation()
    assert any("cleanup denied" in note for note in getattr(raised.value, "__notes__", []))


# ---- command construction: run_capture_argv (real local subprocess) --------


def test_run_capture_argv_local_returns_stdout_on_success():
    hp = prof.resolve_profile(host="local", config_path=None)
    r = cli.run_capture_argv(hp, ["echo", "hello-from-capture"], timeout=5)
    assert "hello-from-capture" in r.stdout
    assert r.returncode == 0


def test_run_capture_argv_local_sigterm_on_timeout_then_flushes():
    hp = prof.resolve_profile(host="local", config_path=None)
    # sleeps far longer than the 1s timeout; run_capture_argv must SIGTERM the
    # process group and return within `grace` rather than hanging.
    code = (
        "import signal,time;"
        "signal.signal(signal.SIGTERM,lambda *_:(print('caught-term',flush=True),exit(0)));"
        "time.sleep(30)"
    )
    r = cli.run_capture_argv(hp, [sys.executable, "-c", code], timeout=1, grace=5)
    assert "exceeded 1s" in r.stdout
    assert "SIGTERM" in r.stdout


def test_run_capture_argv_remote_delegates_to_ssh_argv(monkeypatch):
    seen = {}

    def fake_ssh_argv(hp, argv, cwd=None, timeout=None, check=True):
        seen["hp"] = hp
        seen["argv"] = argv
        seen["cwd"] = cwd
        seen["timeout"] = timeout
        seen["check"] = check
        return _FakeCompleted(stdout="remote-ok")

    monkeypatch.setattr(cli, "ssh_argv", fake_ssh_argv)
    hp = prof.resolve_profile(host="remote-box", local=False, config_path=None)
    r = cli.run_capture_argv(hp, ["some-capture-cmd"], timeout=99, cwd="/dev/shm/astrolabe-x")
    assert r.stdout == "remote-ok"
    assert seen == {
        "hp": hp,
        "argv": ["some-capture-cmd"],
        "cwd": "/dev/shm/astrolabe-x",
        "timeout": 99,
        "check": False,
    }


def test_run_capture_argv_preserves_literal_arguments():
    hp = prof.resolve_profile(host="local", config_path=None)
    result = cli.run_capture_argv(
        hp,
        [sys.executable, "-c", "import sys;print(sys.argv[1])", "a;$(id)"],
        timeout=5,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "a;$(id)"


def test_python_recipe_sandbox_capability_fails_closed(monkeypatch):
    hp = prof.resolve_profile(host="remote-box", local=False, config_path=None)
    monkeypatch.setattr(
        cli,
        "ssh_argv",
        lambda *_args, **_kwargs: _FakeCompleted(stderr="bwrap missing", returncode=127),
    )
    with pytest.raises(cli.ConfigurationError, match="bubblewrap"):
        cli._require_recipe_sandbox(hp)


def test_python_recipe_sandbox_capability_uses_literal_argv(monkeypatch):
    hp = prof.resolve_profile(host="remote-box", local=False, config_path=None)
    seen = {}

    def fake_ssh(profile, argv, **kwargs):
        seen.update(profile=profile, argv=argv, kwargs=kwargs)
        return _FakeCompleted(stdout="bubblewrap 0.11")

    monkeypatch.setattr(cli, "ssh_argv", fake_ssh)
    cli._require_recipe_sandbox(hp)
    assert seen == {
        "profile": hp,
        "argv": ["bwrap", "--version"],
        "kwargs": {"timeout": 15, "check": False},
    }


def test_anonymous_capture_concurrency_uses_process_orchestrator() -> None:
    args = types.SimpleNamespace(
        browser_concurrency=3,
        max_total_requests=300,
        max_origin_requests=150,
        max_operation_requests=30,
        rate_limit_reserve=3,
        no_auth=True,
        allow_auth_concurrency=False,
    )
    original = ["cloak-python", "capture.py", "--base-domain", "example.com"]
    assert cli._capture_concurrency_argv(original, args) == [
        "cloak-python",
        "capture_parallel.py",
        "--concurrency",
        "3",
        "--",
        "capture.py",
        "--base-domain",
        "example.com",
    ]


def test_authenticated_capture_concurrency_requires_target_acknowledgement() -> None:
    args = types.SimpleNamespace(
        browser_concurrency=2,
        max_total_requests=100,
        max_origin_requests=100,
        max_operation_requests=20,
        rate_limit_reserve=2,
        no_auth=False,
        allow_auth_concurrency=False,
    )
    with pytest.raises(cli.SafetyRefusalError, match="allow-auth-concurrency"):
        cli._capture_concurrency_argv(["python", "capture.py"], args)


def test_capture_concurrency_refuses_a_budget_too_small_for_each_shard() -> None:
    args = types.SimpleNamespace(
        browser_concurrency=4,
        max_total_requests=3,
        max_origin_requests=20,
        max_operation_requests=20,
        rate_limit_reserve=1,
        no_auth=True,
        allow_auth_concurrency=False,
    )
    with pytest.raises(cli.ConfigurationError, match="at least browser concurrency"):
        cli._capture_concurrency_argv(["python", "capture.py"], args)


def test_parallel_capture_reserve_covers_inflight_shards() -> None:
    args = types.SimpleNamespace(
        browser_concurrency=3,
        max_total_requests=30,
        max_origin_requests=30,
        max_operation_requests=30,
        rate_limit_reserve=2,
        no_auth=True,
        allow_auth_concurrency=False,
    )
    with pytest.raises(cli.ConfigurationError, match="reserve"):
        cli._capture_concurrency_argv(["python", "capture.py"], args)


# ---- preflight() / cmd_preflight: fully offline via monkeypatched run ----


def _fake_engine_run(cmd, **kw):
    joined = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
    if "cloakbrowser" in joined:
        return _FakeCompleted(stdout="9.9.9\n")
    if "clairvoyance" in joined:
        return _FakeCompleted(stdout="yes\n")
    if "curl" in joined and "health" in joined:
        return _FakeCompleted(stdout="working\n")
    if "ipify" in joined:
        return _FakeCompleted(stdout="203.0.113.9\n")
    if "glob" in joined:  # burp discovery heredoc
        return _FakeCompleted(stdout="\n")
    if "import graphql,jsonschema" in joined or "import curl_cffi" in joined:
        return _FakeCompleted()
    if "--version" in joined or "--help" in joined:
        return _FakeCompleted()
    return _FakeCompleted(stdout="", returncode=1)


def test_preflight_all_engines_present_offline(monkeypatch):
    monkeypatch.setattr(cli, "run", _fake_engine_run)
    hp = prof.resolve_profile(host="local", config_path=None)
    info = cli.preflight(hp, verbose=False)
    assert info["cloakbrowser"] == "9.9.9"
    assert info["clairvoyance"] is True
    assert info["byparr"] == hp.byparr
    assert info["egress_match"] is True
    assert info["engines"]["cloakbrowser"] == {
        "present": True,
        "detail": "9.9.9",
        "status": "ready",
    }
    assert info["host_status"] == "reachable"
    assert info["egress_status"] == "match"


def test_preflight_missing_engines_offline(monkeypatch):
    monkeypatch.setattr(cli, "run", lambda cmd, **kw: _FakeCompleted(stdout="", returncode=1))
    hp = prof.resolve_profile(host="local", config_path=None)
    info = cli.preflight(hp, verbose=False)
    assert info["cloakbrowser"] is None
    assert info["clairvoyance"] is False
    assert info["byparr"] is None


def test_cmd_preflight_json_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run", _fake_engine_run)
    cli.main(["preflight", "--host", "local", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["command"] == "preflight"
    assert payload["result"]["host"] == "local"
    assert payload["result"]["cloakbrowser"] == "9.9.9"
    assert "engines" in payload["result"]


def test_cmd_preflight_default_prints_table_not_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run", _fake_engine_run)
    p = cli.build_parser()
    a = p.parse_args(["preflight", "--host", "local"])
    cli.cmd_preflight(a)
    out = capsys.readouterr().out
    assert "preflight" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_every_subcommand_accepts_json_mode():
    parser = cli.build_parser()
    commands = {
        "preflight": [],
        "map": ["example.com"],
        "replay": [
            "example.com",
            "--op",
            "op.json",
            "--cookies-file",
            "cookies.json",
            "--auth-file",
            "auth.map.json",
        ],
        "mcp-gen": ["capture"],
        "import-openapi": ["openapi.json"],
        "import-har": ["capture.har", "--domain", "example.com"],
        "scan": ["https://example.com"],
        "contract": ["capture"],
        "recipe": ["recipe.py"],
        "inspect-artifact": ["artifact-manifest.json"],
        "migrate-artifact": ["graph.json"],
        "check": [],
    }
    for command, arguments in commands.items():
        assert parser.parse_args([command, *arguments, "--json"]).json is True


def test_machine_error_uses_stable_exit_code_and_single_json_envelope(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "preflight",
        lambda *args, **kwargs: (_ for _ in ()).throw(cli.ConfigurationError("missing engine")),
    )
    with pytest.raises(SystemExit) as raised:
        cli.main(["preflight", "--host", "local", "--json"])
    assert raised.value.code == cli.ExitCode.CONFIGURATION
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "command": "preflight",
        "error": {"category": "configuration", "code": 3, "message": "missing engine"},
        "ok": False,
    }


def test_machine_usage_error_is_json_and_exit_two(capsys):
    with pytest.raises(SystemExit) as raised:
        cli.main(["preflight", "--json", "--not-a-real-option"])
    assert raised.value.code == cli.ExitCode.USAGE
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"]["category"] == "usage"
    assert payload["error"]["code"] == 2


def test_exit_code_contract_is_stable():
    assert {name: int(code) for name, code in cli.ExitCode.__members__.items()} == {
        "SUCCESS": 0,
        "USAGE": 2,
        "CONFIGURATION": 3,
        "SAFETY_REFUSAL": 4,
        "PARTIAL_CAPTURE": 5,
        "AUTHENTICATION": 6,
        "DRIFT": 7,
        "GENERATION": 8,
        "VALIDATION": 9,
        "UPSTREAM": 10,
        "INTERRUPTED": 130,
    }


# ---- mcp-gen: --overrides / --noise-pattern (Task 1) ----------------------


def test_mcpgen_parses_overrides_and_noise_pattern():
    p = cli.build_parser()
    a = p.parse_args(["mcp-gen", "capdir", "--overrides", "surfaces", "--noise-pattern", "foo.*"])
    assert a.overrides == "surfaces"
    assert a.noise_pattern == "foo.*"
    assert a.include_mutations is False


def test_mcpgen_overrides_and_noise_pattern_default_none():
    p = cli.build_parser()
    a = p.parse_args(["mcp-gen", "capdir"])
    assert a.overrides is None
    assert a.noise_pattern is None


def test_cmd_mcpgen_threads_overrides_and_noise_pattern_into_argv(monkeypatch):
    captured = {}

    def fake_main():
        captured["argv"] = list(sys.argv)

    monkeypatch.setattr(cli.mg, "main", fake_main)
    p = cli.build_parser()
    a = p.parse_args(
        [
            "mcp-gen",
            "capdir",
            "--overrides",
            "surfaces",
            "--noise-pattern",
            "foo.*",
            "--include-mutations",
        ]
    )
    cli.cmd_mcpgen(a)
    assert captured["argv"] == [
        "mcpgen",
        "capdir",
        "--include-mutations",
        "--overrides",
        "surfaces",
        "--noise-pattern",
        "foo.*",
    ]


def test_cmd_mcpgen_omits_flags_when_not_supplied(monkeypatch):
    captured = {}

    def fake_main():
        captured["argv"] = list(sys.argv)

    monkeypatch.setattr(cli.mg, "main", fake_main)
    p = cli.build_parser()
    a = p.parse_args(["mcp-gen", "capdir"])
    cli.cmd_mcpgen(a)
    assert captured["argv"] == ["mcpgen", "capdir"]


# ---- recipe subcommand (Task 6) --------------------------------------------


def test_recipe_subcommand_parses():
    p = cli.build_parser()
    a = p.parse_args(["recipe", "surfaces/foo.recipe.py"])
    assert a.recipe_file == "surfaces/foo.recipe.py"
    assert a.func is cli.cmd_recipe


def test_cmd_recipe_missing_module_raises_clear_systemexit(monkeypatch):
    # Force ImportError deterministically regardless of whether astrolabe/recipe.py
    # actually exists on disk yet (it's owned by a concurrent workstream and may
    # land mid-session -- and once ANY test module does `from astrolabe import
    # recipe`, the `astrolabe` package object keeps a `recipe` attribute for the
    # rest of the process, which `from . import recipe` would happily reuse
    # even with the sys.modules entry poisoned). Clearing both the sys.modules
    # cache AND the package attribute forces a real ImportError either way.
    monkeypatch.setitem(sys.modules, "astrolabe.recipe", None)
    monkeypatch.delattr(astrolabe, "recipe", raising=False)
    p = cli.build_parser()
    a = p.parse_args(["recipe", "surfaces/foo.recipe.py"])
    with pytest.raises(cli.GenerationError, match="astrolabe.recipe"):
        cli.cmd_recipe(a)


def test_cmd_recipe_delegates_to_module_main(monkeypatch):
    captured = {}
    fake_mod = types.ModuleType("astrolabe.recipe")

    def fake_main():
        captured["argv"] = list(sys.argv)

    fake_mod.main = fake_main
    monkeypatch.setitem(sys.modules, "astrolabe.recipe", fake_mod)
    monkeypatch.setattr(astrolabe, "recipe", fake_mod, raising=False)
    p = cli.build_parser()
    a = p.parse_args(["recipe", "surfaces/foo.recipe.py"])
    cli.cmd_recipe(a)
    assert captured["argv"] == ["recipe", "surfaces/foo.recipe.py"]


# ---- cmd_replay: put()/get() routing, bring-your-own cookies + auth bundle ----


@pytest.fixture
def _replay_env(monkeypatch, tmp_path):
    """Fully offline cmd_replay harness: preflight, argv execution, put, get,
    and run are all monkeypatched so no network/ssh/browser is touched.
    Cookies and the scoped-auth credential bundle are bring-your-own (no
    CloakBrowser mint step); this fixture writes both as pre-made fixture
    files and returns their paths alongside op_path/out_dir and a dict of
    what put()/get()/ssh()/run() were invoked with."""
    monkeypatch.setattr(cli, "preflight", lambda hp: {"egress_match": True})
    state = {"put": [], "get": [], "ssh": [], "run": []}

    def fake_put(hp, src, dst):
        state["put"].append((src, dst))
        return _FakeCompleted()

    def fake_get(hp, src, dst):
        state["get"].append((src, dst))
        if src.endswith("/replay.json"):
            Path(dst).write_text(json.dumps({"op": "someOp", "results": []}))
        return _FakeCompleted()

    def fake_ssh_argv(hp, argv, cwd=None, timeout=None, check=True):
        state["ssh"].append(list(argv))
        return _FakeCompleted(stdout="")

    def fake_run(cmd, **kw):
        state["run"].append(cmd)
        return _FakeCompleted()

    monkeypatch.setattr(cli, "put", fake_put)
    monkeypatch.setattr(cli, "get", fake_get)
    monkeypatch.setattr(cli, "ssh_argv", fake_ssh_argv)
    monkeypatch.setattr(cli, "run", fake_run)

    op_path = tmp_path / "op.json"
    op_path.write_text(
        json.dumps({"alias": "someOp", "query": "query{x}", "endpoint": "https://example.com/api"})
    )
    cookies_path = tmp_path / "cookies.json"
    cookies_path.write_text(
        json.dumps(
            [
                {
                    "name": "session",
                    "value": "v",
                    "domain": "example.com",
                    "path": "/",
                    "expires": -1,
                    "httpOnly": False,
                    "secure": True,
                    "sameSite": "Lax",
                }
            ]
        )
    )
    auth_path = tmp_path / "auth.map.json"
    auth_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generation_id": "fixture-generation",
                "credentials": {"someOp": {"authorization": "Bearer abc"}},
            }
        )
    )
    state["op_path"] = op_path
    state["cookies_path"] = cookies_path
    state["auth_path"] = auth_path
    state["out_dir"] = tmp_path / "out"
    return state


def _replay_args(state, extra=()):
    p = cli.build_parser()
    return p.parse_args(
        [
            "replay",
            "example.com",
            "--op",
            str(state["op_path"]),
            "--cookies-file",
            str(state["cookies_path"]),
            "--auth-file",
            str(state["auth_path"]),
            "--out",
            str(state["out_dir"]),
            "--local",
            *extra,
        ]
    )


def test_cmd_replay_routes_every_transfer_through_put_and_get(_replay_env):
    a = _replay_args(_replay_env)
    cli.cmd_replay(a)

    put_dsts = [dst for _src, dst in _replay_env["put"]]
    assert any(dst.endswith("/replay.py") for dst in put_dsts)
    assert any(dst.endswith("/cookies.json") for dst in put_dsts)
    assert any(dst.endswith("/auth.map.json") for dst in put_dsts)
    assert any(dst.endswith("/op.json") for dst in put_dsts)

    get_srcs = [src for src, _dst in _replay_env["get"]]
    assert any(src.endswith("/replay.json") for src in get_srcs)


def test_cmd_replay_local_flag_resolves_local_profile(_replay_env, monkeypatch):
    seen = {}
    orig_resolve = cli._resolve

    def spy_resolve(a):
        hp = orig_resolve(a)
        seen["hp"] = hp
        return hp

    monkeypatch.setattr(cli, "_resolve", spy_resolve)
    a = _replay_args(_replay_env)
    cli.cmd_replay(a)
    assert seen["hp"].local is True


def test_cmd_replay_requires_cookies_file(_replay_env):
    p = cli.build_parser()
    with pytest.raises(SystemExit):
        p.parse_args(
            [
                "replay",
                "example.com",
                "--op",
                str(_replay_env["op_path"]),
                "--auth-file",
                str(_replay_env["auth_path"]),
            ]
        )


def test_cmd_replay_requires_auth_file(_replay_env):
    p = cli.build_parser()
    with pytest.raises(SystemExit):
        p.parse_args(
            [
                "replay",
                "example.com",
                "--op",
                str(_replay_env["op_path"]),
                "--cookies-file",
                str(_replay_env["cookies_path"]),
            ]
        )


@pytest.mark.parametrize(
    "extra",
    [
        ["--host", "remote.invalid"],
        ["--local", "--no-auth"],
        ["--local", "--cookies-file", "cookies.json"],
        ["--local", "--recipe", "actions.json"],
        ["--local", "--openapi"],
    ],
)
def test_native_browser_import_rejects_unsafe_combinations_before_preflight(extra, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unsafe native import reached preflight")

    monkeypatch.setattr(cli, "preflight", forbidden)
    args = cli.build_parser().parse_args(["map", "example.com", "--browser", "vivaldi", *extra])
    with pytest.raises(cli.SafetyRefusalError):
        cli.cmd_map(args)


def test_native_decryption_and_recovery_are_not_parser_defaults():
    args = cli.build_parser().parse_args(["map", "example.com"])
    assert args.browser is None
    assert args.recover_persisted is False


# ---- cmd_contract: native browser import mirrors cmd_map's for --execute ----


def test_contract_browser_requires_execute():
    p = cli.build_parser()
    a = p.parse_args(["contract", "/tmp/cap", "--browser", "vivaldi", "--local"])
    with pytest.raises(cli.ConfigurationError, match="no effect without --execute"):
        cli.cmd_contract(a)


def test_contract_browser_and_cookies_file_are_mutually_exclusive(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("mutually-exclusive auth sources reached preflight")

    monkeypatch.setattr(cli, "preflight", forbidden)
    p = cli.build_parser()
    a = p.parse_args(
        [
            "contract",
            str(tmp_path),
            "--execute",
            "--domain",
            "example.com",
            "--browser",
            "vivaldi",
            "--cookies-file",
            "cookies.json",
            "--local",
        ]
    )
    with pytest.raises(cli.ConfigurationError, match="choose --browser or --cookies-file"):
        cli.cmd_contract(a)


def test_contract_browser_refused_on_non_local_host(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("non-local native import reached preflight")

    monkeypatch.setattr(cli, "preflight", forbidden)
    p = cli.build_parser()
    a = p.parse_args(
        [
            "contract",
            str(tmp_path),
            "--execute",
            "--domain",
            "example.com",
            "--browser",
            "vivaldi",
            "--host",
            "remote.invalid",
        ]
    )
    with pytest.raises(cli.SafetyRefusalError):
        cli.cmd_contract(a)


@pytest.fixture
def _contract_browser_env(monkeypatch, tmp_path):
    """Stops cmd_contract right after cookie staging (the first remote ssh
    call) so the test never needs a real capture dir, contract.json, or
    warm-browser round trip -- only that native import stages cookies the
    same way --cookies-file already does."""
    monkeypatch.setattr(cli, "preflight", lambda hp: {"egress_match": True})

    import astrolabe.browser_cookies as bc

    calls: dict = {"export_cookies": None, "writes": []}
    secret_value = "s3cr3t-session-token"

    def fake_export_cookies(browser, domain, profile):
        calls["export_cookies"] = (browser, domain, profile)
        return [
            {
                "name": "session",
                "value": secret_value,
                "domain": domain,
                "path": "/",
                "expires": -1,
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax",
            }
        ]

    monkeypatch.setattr(bc, "export_cookies", fake_export_cookies)

    orig_write = cli.atomic_write_json

    def spy_write(path, value, *, mode=0o644, **kw):
        calls["writes"].append((str(path), mode))
        return orig_write(path, value, mode=mode, **kw)

    monkeypatch.setattr(cli, "atomic_write_json", spy_write)

    class _StagingStoppedError(Exception):
        pass

    def fake_ssh_argv(hp, argv, cwd=None, timeout=None, check=True):
        raise _StagingStoppedError()

    monkeypatch.setattr(cli, "ssh_argv", fake_ssh_argv)

    cap = tmp_path / "cap"
    cap.mkdir()
    calls["cap"] = cap
    calls["secret_value"] = secret_value
    calls["stop_exc"] = _StagingStoppedError
    return calls


def test_contract_browser_happy_path_stages_cookies_like_cookies_file(
    _contract_browser_env, capsys
):
    env = _contract_browser_env
    p = cli.build_parser()
    a = p.parse_args(
        [
            "contract",
            str(env["cap"]),
            "--execute",
            "--domain",
            "example.com",
            "--browser",
            "vivaldi",
            "--local",
        ]
    )
    with pytest.raises(env["stop_exc"]):
        cli.cmd_contract(a)

    assert env["export_cookies"] == ("vivaldi", "example.com", "Default")

    cookie_writes = [(path, mode) for path, mode in env["writes"] if path.endswith("_cookies.json")]
    assert cookie_writes, "cookies were never staged through atomic_write_json"
    assert all(mode == 0o600 for _path, mode in cookie_writes)

    out = capsys.readouterr().out
    assert env["secret_value"] not in out
    assert "[cookies] 1 domain-scoped cookies from vivaldi" in out


@pytest.mark.parametrize(
    "extra",
    [
        ["--local", "--no-auth"],
        ["--local", "--cookies-file", "cookies.json"],
        ["--local", "--browser", "chrome"],
        ["--local", "--openapi"],
        ["--local", "--browser-concurrency", "2"],
        ["--host", "remote-capture"],
    ],
)
def test_attached_browser_rejects_unsafe_combinations_before_preflight(extra, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unsafe attached capture reached preflight")

    monkeypatch.setattr(cli, "preflight", forbidden)
    monkeypatch.setattr(
        cli, "_resolve", lambda a: types.SimpleNamespace(local="--local" in extra, host="h")
    )
    args = cli.build_parser().parse_args(
        ["map", "example.com", "--cdp-endpoint", "http://127.0.0.1:9222", *extra]
    )
    with pytest.raises((cli.SafetyRefusalError, cli.ConfigurationError)):
        cli.cmd_map(args)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://10.0.0.5:9222",
        "https://127.0.0.1:9222",
        "http://127.0.0.1",
        "ws://user:pw@localhost:1",
    ],
)
def test_attached_browser_accepts_only_loopback_devtools_endpoints(endpoint, monkeypatch):
    monkeypatch.setattr(cli, "preflight", lambda *a, **k: pytest.fail("reached preflight"))
    args = cli.build_parser().parse_args(
        ["map", "example.com", "--local", "--cdp-endpoint", endpoint]
    )
    with pytest.raises(ValueError):
        cli.cmd_map(args)


def test_contract_execute_no_auth_cannot_combine_with_credentials(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "preflight", lambda *a, **k: pytest.fail("reached preflight"))
    args = cli.build_parser().parse_args(
        ["contract", str(tmp_path), "--execute", "--local", "--no-auth", "--cookies-file", "c.json"]
    )
    with pytest.raises(cli.ConfigurationError):
        cli.cmd_contract(args)
