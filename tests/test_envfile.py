"""Operator ``.env`` handling: parsing, precedence, masking and file mode."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from astrolabe import envfile


def test_parse_ignores_comments_blanks_and_bad_lines():
    text = """
# a comment
   
NOT_ASSIGNED
KEY=value
export EXPORTED=yes
QUOTED="with spaces"
SINGLE='single'
"""
    assert envfile.parse_env_text(text) == {
        "KEY": "value",
        "EXPORTED": "yes",
        "QUOTED": "with spaces",
        "SINGLE": "single",
    }


def test_value_is_taken_literally_without_shell_expansion():
    """A credential is not a shell expression; expanding it silently corrupts it."""
    assert envfile.parse_env_text("PASS=$HOME/secret")["PASS"] == "$HOME/secret"


def test_file_is_a_default_and_the_environment_wins(tmp_path):
    path = tmp_path / ".env"
    path.write_text("ONLY_FILE=1\nBOTH=file\n", encoding="utf-8")
    resolved = envfile.resolve(str(path), env={"BOTH": "env"})
    assert resolved["ONLY_FILE"] == "1"
    assert resolved["BOTH"] == "env"


def test_find_env_file_prefers_explicit_then_variable_then_cwd(tmp_path, monkeypatch):
    explicit = tmp_path / "explicit.env"
    explicit.write_text("A=1\n", encoding="utf-8")
    configured = tmp_path / "configured.env"
    configured.write_text("A=2\n", encoding="utf-8")
    monkeypatch.setenv(envfile.ENV_FILE_VAR, str(configured))
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("A=3\n", encoding="utf-8")
    assert envfile.find_env_file(str(explicit)) == explicit
    assert envfile.find_env_file() == configured


def test_find_env_file_falls_back_to_cwd_and_returns_none_when_absent(tmp_path, monkeypatch):
    monkeypatch.delenv(envfile.ENV_FILE_VAR, raising=False)
    monkeypatch.chdir(tmp_path)
    assert envfile.find_env_file() is None
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    assert envfile.find_env_file() == Path(".env")


def test_missing_file_is_empty_config_not_an_error(tmp_path):
    assert envfile.load_env_file(tmp_path / "nope.env") == {}


@pytest.mark.parametrize(
    "name",
    ["PASSWORD", "API_TOKEN", "COOKIE_JAR", "AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY", "HTTP_AUTH"],
)
def test_sensitive_names_are_recognised(name):
    assert envfile.is_secret(name)


@pytest.mark.parametrize("name", ["USER", "GATEWAY", "STATE", "FULL_NAME"])
def test_non_sensitive_names_are_not_masked(name):
    assert not envfile.is_secret(name)


def test_redacted_masks_secrets_and_leaves_the_rest_readable():
    shown = envfile.redacted({"PASSWORD": "hunter2", "STATE": "virginia"})
    assert shown == {"PASSWORD": "<set>", "STATE": "virginia"}


def test_relevant_limits_output_to_operator_config():
    environment = {
        "PATH": "/usr/bin",
        "ASTROLABE_BROWSER": "auto",
        "BASTILLE_RESPROXY_USER": "u",
        "HOME": "/home/x",
    }
    assert set(envfile.relevant(environment)) == {
        "ASTROLABE_BROWSER",
        "BASTILLE_RESPROXY_USER",
    }


def test_permissions_warning_flags_a_world_readable_file(tmp_path):
    path = tmp_path / ".env"
    path.write_text("PASSWORD=x\n", encoding="utf-8")
    os.chmod(path, 0o644)
    assert "chmod 600" in (envfile.permissions_warning(path) or "")
    os.chmod(path, 0o600)
    assert envfile.permissions_warning(path) is None
