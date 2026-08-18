"""Tests for astrolabe.profile — resolved host/engine topology config.

Every test isolates itself from the real machine: no reliance on this box's
actual $HOME, CWD, or ASTROLABE_* env vars, since the whole point of the module
is that resolution is deterministic and layered.
"""

from __future__ import annotations

import dataclasses
import os
import textwrap

import pytest

from astrolabe import profile as prof

# The literal values that were hardcoded at module scope in astrolabe/cli.py
# before this module existed. Backward compatibility means: no config file,
# no env vars -> resolve_profile() must reproduce these EXACTLY.
LEGACY_HOST = "capture-host"
LEGACY_CLOAK_PY = "~/.local/share/pipx/venvs/cloakbrowser/bin/python"
LEGACY_CLAIR = "~/astrolabe-tools/venv/bin/clairvoyance"
LEGACY_BYPARR = "http://127.0.0.1:8191/v1"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Strip every ASTROLABE_* env var so tests never inherit the real shell's
    state, and give ASTROLABE_PROFILE an explicit empty override where a test
    wants "no config file" guaranteed regardless of the real $HOME/$CWD."""
    for k in list(os.environ):
        if k.startswith("ASTROLABE_"):
            monkeypatch.delenv(k, raising=False)
    yield


# ---- backward compatibility: no config, no env == old hardcoded values ----


def test_defaults_match_legacy_hardcoded_values_with_no_overrides():
    """The core backward-compat guarantee: an author with no astrolabe.toml and
    no env vars gets an IDENTICAL profile to the old hardcoded constants."""
    p = prof.resolve_profile(config_path=None)
    assert p.host == LEGACY_HOST
    assert p.cloak_py == LEGACY_CLOAK_PY
    assert p.clairvoyance == LEGACY_CLAIR
    assert p.byparr == LEGACY_BYPARR


def test_defaults_dict_matches_legacy_values():
    assert prof.DEFAULTS["host"] == LEGACY_HOST
    assert prof.DEFAULTS["cloak_py"] == LEGACY_CLOAK_PY
    assert prof.DEFAULTS["clairvoyance"] == LEGACY_CLAIR
    assert prof.DEFAULTS["byparr"] == LEGACY_BYPARR


# ---- resolution order: CLI override > env > config > default --------------


def test_cli_override_wins_over_everything(tmp_path, monkeypatch):
    cfg = tmp_path / "astrolabe.toml"
    cfg.write_text('[profile]\nhost = "from-config"\n')
    monkeypatch.setenv("ASTROLABE_HOST", "from-env")
    p = prof.resolve_profile(host="from-cli", config_path=str(cfg))
    assert p.host == "from-cli"


def test_env_wins_over_config_and_default(tmp_path, monkeypatch):
    cfg = tmp_path / "astrolabe.toml"
    cfg.write_text('[profile]\nhost = "from-config"\n')
    monkeypatch.setenv("ASTROLABE_HOST", "from-env")
    p = prof.resolve_profile(config_path=str(cfg))
    assert p.host == "from-env"


def test_config_wins_over_default(tmp_path):
    cfg = tmp_path / "astrolabe.toml"
    cfg.write_text('[profile]\nhost = "from-config"\ncloak_py = "/opt/cloak/python"\n')
    p = prof.resolve_profile(config_path=str(cfg))
    assert p.host == "from-config"
    assert p.cloak_py == "/opt/cloak/python"
    # fields not present in the config file still fall back to defaults
    assert p.clairvoyance == LEGACY_CLAIR


def test_missing_config_file_is_not_an_error(tmp_path):
    missing = tmp_path / "does-not-exist.toml"
    p = prof.resolve_profile(config_path=str(missing))
    assert p.host == LEGACY_HOST


def test_config_file_without_profile_table_accepted(tmp_path):
    cfg = tmp_path / "astrolabe.toml"
    cfg.write_text('host = "flat-config"\n')  # no [profile] header
    p = prof.resolve_profile(config_path=str(cfg))
    assert p.host == "flat-config"


def test_int_fields_resolve_from_env_as_int(monkeypatch):
    monkeypatch.setenv("ASTROLABE_SSH_TIMEOUT", "300")
    p = prof.resolve_profile(config_path=None)
    assert p.ssh_timeout == 300
    assert isinstance(p.ssh_timeout, int)


def test_int_fields_resolve_from_config_as_int(tmp_path):
    cfg = tmp_path / "astrolabe.toml"
    cfg.write_text("[profile]\nssh_timeout = 42\ngrace_s = 7\n")
    p = prof.resolve_profile(config_path=str(cfg))
    assert p.ssh_timeout == 42
    assert p.grace_s == 7


# ---- config file search order ----------------------------------------------


def test_find_config_file_prefers_astrolabe_profile_env(tmp_path, monkeypatch):
    explicit = tmp_path / "explicit.toml"
    explicit.write_text('[profile]\nhost = "x"\n')
    cwd_file = tmp_path / "astrolabe.toml"
    cwd_file.write_text('[profile]\nhost = "y"\n')
    monkeypatch.setenv("ASTROLABE_PROFILE", str(explicit))
    monkeypatch.chdir(tmp_path)
    found = prof.find_config_file()
    assert found == str(explicit)


def test_find_config_file_falls_back_to_cwd(tmp_path, monkeypatch):
    cwd_file = tmp_path / "astrolabe.toml"
    cwd_file.write_text('[profile]\nhost = "y"\n')
    monkeypatch.chdir(tmp_path)
    found = prof.find_config_file()
    assert found == str(cwd_file)


def test_find_config_file_returns_none_when_nothing_exists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(tmp_path / "home")))
    found = prof.find_config_file()
    assert found is None


# ---- local-vs-remote resolution --------------------------------------------


def test_explicit_local_true_overrides_autodetect():
    p = prof.resolve_profile(
        host="some-unresolvable-host-xyz.invalid", local=True, config_path=None
    )
    assert p.local is True


def test_explicit_local_false_overrides_host_local_literal():
    p = prof.resolve_profile(host="local", local=False, config_path=None)
    assert p.local is False


def test_host_local_literal_is_local():
    p = prof.resolve_profile(host="local", config_path=None)
    assert p.local is True


def test_unresolvable_host_fails_closed_as_remote():
    p = prof.resolve_profile(host="definitely-not-a-real-host.invalid.example", config_path=None)
    assert p.local is False


def test_autodetect_local_helper_loopback():
    assert prof.autodetect_local("localhost") is True


def test_autodetect_local_helper_unresolvable():
    assert prof.autodetect_local("this-host-does-not-exist.invalid.example") is False


def test_local_never_evaluated_at_import_time():
    """Regression guard for the old `LOCAL = _detect_local()` import-time DNS
    side effect. Importing the module must not require network access or
    resolve any hostname; only resolve_profile() may do that, lazily."""
    import importlib

    import astrolabe.profile as reloaded

    importlib.reload(reloaded)
    assert not hasattr(reloaded, "LOCAL")
    assert not hasattr(reloaded, "HOST")


# ---- engine probing ---------------------------------------------------------


class _FakeCompleted:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def test_probe_reports_present_engines_via_injected_runner():
    p = prof.resolve_profile(config_path=None)

    def fake_runner(argv, timeout):
        joined = " ".join(argv)
        if "cloakbrowser" in joined:
            return _FakeCompleted("1.2.3\n")
        if argv[:2] == ["test", "-x"]:
            return _FakeCompleted()
        if "curl" in argv:
            return _FakeCompleted("working\n")
        return _FakeCompleted("")

    results = prof.probe(p, runner=fake_runner)
    assert results["cloakbrowser"] == {
        "present": True,
        "detail": "1.2.3",
        "status": "ready",
    }
    assert results["clairvoyance"] == {
        "present": True,
        "detail": None,
        "status": "ready",
    }
    assert results["byparr"]["present"] is True


def test_probe_reports_absent_engines():
    p = prof.resolve_profile(config_path=None)

    def fake_runner(argv, timeout):
        return _FakeCompleted("", returncode=1)

    results = prof.probe(p, runner=fake_runner)
    assert results["cloakbrowser"] == {
        "present": False,
        "detail": None,
        "status": "unavailable",
    }
    assert results["clairvoyance"] == {
        "present": False,
        "detail": None,
        "status": "unavailable",
    }
    assert results["byparr"] == {
        "present": False,
        "detail": None,
        "status": "unavailable",
    }


def test_probe_distinguishes_unreachable_and_timeout():
    p = prof.resolve_profile(config_path=None)
    calls = 0

    def fake_runner(argv, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise prof.subprocess.TimeoutExpired(argv, timeout)
        return _FakeCompleted("", returncode=255)

    results = prof.probe(p, runner=fake_runner)
    assert results["cloakbrowser"]["status"] == "timeout"
    assert results["clairvoyance"]["status"] == "unreachable"


def test_probe_passes_expected_commands_and_timeouts():
    p = prof.resolve_profile(config_path=None)
    seen = []

    def fake_runner(argv, timeout):
        seen.append((argv, timeout))
        return _FakeCompleted("")

    prof.probe(p, runner=fake_runner)
    cmds = [c for c, _t in seen]
    assert any(any("cloakbrowser" in arg for arg in c) for c in cmds)
    assert any(p.clairvoyance in c for c in cmds)
    assert any("curl" in c and any("/health" in arg for arg in c) for c in cmds)


def test_validate_true_when_all_engines_present():
    p = prof.resolve_profile(config_path=None)

    def fake_runner(cmd, timeout):
        return _FakeCompleted("1.0.0\nyes\nworking\n")

    assert prof.validate(p, runner=fake_runner) is True


def test_validate_ignores_absent_optional_engine():
    p = prof.resolve_profile(config_path=None)

    def fake_runner(argv, timeout):
        if "curl" in argv:
            return _FakeCompleted("", returncode=1)  # optional byparr down
        return _FakeCompleted("1.0.0\nyes\n")

    assert prof.validate(p, runner=fake_runner) is True


def test_validate_false_when_required_capture_dependencies_absent():
    p = prof.resolve_profile(config_path=None)

    def fake_runner(argv, timeout):
        if "import graphql,jsonschema" in argv:
            return _FakeCompleted("", returncode=1)
        return _FakeCompleted("1.0.0\n")

    assert prof.validate(p, runner=fake_runner) is False


def test_probe_default_runner_is_used_when_none_supplied(monkeypatch):
    """probe()/validate() must work standalone (no injected runner) by
    falling back to a bare local/ssh runner derived from profile.local."""
    p = prof.resolve_profile(host="local", config_path=None)
    calls = []

    def fake_subprocess_run(args, **kwargs):
        calls.append(args)
        return _FakeCompleted("")

    monkeypatch.setattr(prof.subprocess, "run", fake_subprocess_run)
    prof.probe(p)
    assert calls  # the default runner actually invoked subprocess.run
    assert calls[0][0].endswith("/cloakbrowser/bin/python")


def test_resolve_rejects_shell_metacharacters_in_host():
    with pytest.raises(ValueError, match="unsafe"):
        prof.resolve_profile(host="box;touch-pwned", config_path=None)


def test_select_backend_reports_capability_reason():
    caps = {"cloakbrowser": {"present": True}, "tls_http": {"present": False}}
    assert prof.select_backend({"requires_ui": True}, caps)["backend"] == "ui-drive"
    assert prof.select_backend({"tls_matched": True}, caps) == {
        "backend": "inventory-only",
        "reason": "TLS-matched HTTP is unavailable",
    }


# ---- HostProfile is immutable / a plain data object ------------------------


def test_host_profile_is_frozen():
    p = prof.resolve_profile(config_path=None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.host = "mutated"  # type: ignore[misc]


def test_resolve_profile_toml_with_various_types(tmp_path):
    cfg = tmp_path / "astrolabe.toml"
    cfg.write_text(
        textwrap.dedent(
            """
            [profile]
            host = "toml-host"
            byparr = "http://127.0.0.1:9999/v1"
            ssh_timeout = 55
            """
        )
    )
    p = prof.resolve_profile(config_path=str(cfg))
    assert p.host == "toml-host"
    assert p.byparr == "http://127.0.0.1:9999/v1"
    assert p.ssh_timeout == 55
