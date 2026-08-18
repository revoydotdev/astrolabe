"""astrolabe.profile — host/engine topology as a resolved, testable config object.

Replaces cli.py's old module-level hardcoded HOST/CLOAK_PY/CLAIR/BYPARR
constants and its import-time DNS-based LOCAL auto-detection (`_detect_local()`
ran at import, so it fired even for commands/tests that never touched the
network). Local-vs-remote is now a property resolved once, lazily, when a
profile is *built* — never at import time.

Resolution order (first hit wins), per field:
  1. an explicit CLI-flag-equivalent override passed to resolve_profile()
  2. an environment variable (ASTROLABE_HOST, ASTROLABE_CLOAK_PY, ASTROLABE_CLAIRVOYANCE,
     ASTROLABE_BYPARR, ASTROLABE_BURP_GLOB, ASTROLABE_SSH_TIMEOUT, ASTROLABE_GRACE_S)
  3. a config file (TOML, see find_config_file() for search order)
  4. built-in defaults (DEFAULTS below) -- these are exactly the values that
     used to be hardcoded directly into astrolabe/cli.py, so a machine with no
     config file and no env vars resolves to IDENTICAL behavior to before
     this module existed.

Config file search order (first path that exists wins; missing at every
location is NOT an error -- resolution just falls through to env/defaults):
  1. $ASTROLABE_PROFILE (explicit path, expanded)
  2. ./astrolabe.toml (current working directory)
  3. ~/.config/astrolabe/profile.toml

The file may contain either a top-level `[profile]` table or the fields at
the top level directly; both are accepted so a minimal file can skip the
table header.

local-vs-remote (HostProfile.local) is resolved in this order, at build time:
  1. explicit `local=True/False` passed to resolve_profile() (--local CLI flag)
  2. the resolved `host` field being the literal string "local"
  3. autodetect_local(host): does `host` resolve to a loopback/link-local address
     on this machine? DNS failure is remote/unreachable and never implies local.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import tomllib
from collections.abc import Callable
from dataclasses import dataclass

# Built-in defaults -- the exact values that were previously hardcoded at
# module scope in cli.py. Do not change these without also treating it as a
# behavior change for anyone with no astrolabe.toml / env vars set.
DEFAULTS: dict[str, object] = {
    "host": "capture-host",
    "cloak_py": "~/.local/share/pipx/venvs/cloakbrowser/bin/python",
    "clairvoyance": "~/astrolabe-tools/venv/bin/clairvoyance",
    "byparr": "http://127.0.0.1:8191/v1",
    "burp_config_glob": "~/.config/burpsuite/*.json",
    "ssh_timeout": 120,
    "grace_s": 45,
    "http_py": "python3",
    "node": "node",
    "har_to_openapi": "har-to-openapi",
}

ENV_VARS: dict[str, str] = {
    "host": "ASTROLABE_HOST",
    "cloak_py": "ASTROLABE_CLOAK_PY",
    "clairvoyance": "ASTROLABE_CLAIRVOYANCE",
    "byparr": "ASTROLABE_BYPARR",
    "burp_config_glob": "ASTROLABE_BURP_GLOB",
    "ssh_timeout": "ASTROLABE_SSH_TIMEOUT",
    "grace_s": "ASTROLABE_GRACE_S",
    "http_py": "ASTROLABE_HTTP_PY",
    "node": "ASTROLABE_NODE",
    "har_to_openapi": "ASTROLABE_HAR_TO_OPENAPI",
}

_INT_FIELDS = frozenset({"ssh_timeout", "grace_s"})


@dataclass(frozen=True)
class HostProfile:
    """A fully-resolved capture-host topology. Immutable once built by
    resolve_profile() -- callers thread the same instance through argv execution,
    transfers, and preflight instead of reading module globals."""

    host: str
    cloak_py: str
    clairvoyance: str
    byparr: str
    burp_config_glob: str
    ssh_timeout: int
    grace_s: int
    local: bool
    http_py: str = "python3"
    node: str = "node"
    har_to_openapi: str = "har-to-openapi"


def autodetect_local(host: str) -> bool:
    """True when `host` either does not resolve at all, or resolves to a
    loopback/link-local address on THIS machine -- i.e. the configured
    pipeline host IS this machine. DNS failure is fail-closed: callers must use
    an explicit local profile or --local."""
    if host == "local":
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for _fam, _ty, _pr, _cn, sockaddr in infos:
        ip = str(sockaddr[0])
        if ip.startswith(("127.", "::1", "169.254.")):
            return True
    return False


def find_config_file() -> str | None:
    """Search order: $ASTROLABE_PROFILE -> ./astrolabe.toml -> ~/.config/astrolabe/profile.toml.
    Returns the first existing path, or None (absence is not an error)."""
    candidates = []
    env_path = os.environ.get("ASTROLABE_PROFILE")
    if env_path:
        candidates.append(os.path.expanduser(env_path))
    candidates.append(os.path.join(os.getcwd(), "astrolabe.toml"))
    candidates.append(os.path.expanduser("~/.config/astrolabe/profile.toml"))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _load_config_file(path: str | None) -> dict:
    if not path:
        return {}
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return {}  # an explicit-but-missing config_path is not an error either
    table = data.get("profile", data)
    return table if isinstance(table, dict) else {}


def resolve_profile(
    *,
    host: str | None = None,
    local: bool | None = None,
    cloak_py: str | None = None,
    clairvoyance: str | None = None,
    byparr: str | None = None,
    burp_config_glob: str | None = None,
    ssh_timeout: int | None = None,
    grace_s: int | None = None,
    http_py: str | None = None,
    node: str | None = None,
    har_to_openapi: str | None = None,
    config_path: str | None = "__search__",
) -> HostProfile:
    """Resolve a HostProfile from the layered precedence documented in the
    module docstring. Every keyword defaults to None, meaning "not supplied
    at this layer -- fall through". `config_path`:
      - "__search__" (default): use find_config_file()'s normal search order
      - an explicit path: load exactly that file (missing is still not an error)
      - None: skip the config-file layer entirely (env/defaults only)
    """
    resolved_config_path = find_config_file() if config_path == "__search__" else config_path
    cfg = _load_config_file(resolved_config_path)

    overrides = {
        "host": host,
        "cloak_py": cloak_py,
        "clairvoyance": clairvoyance,
        "byparr": byparr,
        "burp_config_glob": burp_config_glob,
        "ssh_timeout": ssh_timeout,
        "grace_s": grace_s,
        "http_py": http_py,
        "node": node,
        "har_to_openapi": har_to_openapi,
    }

    resolved: dict[str, object] = {}
    for key, default in DEFAULTS.items():
        if overrides.get(key) is not None:
            resolved[key] = overrides[key]
            continue
        env_name = ENV_VARS[key]
        env_val = os.environ.get(env_name)
        if env_val:
            resolved[key] = env_val
            continue
        if key in cfg and cfg[key] is not None:
            resolved[key] = cfg[key]
            continue
        resolved[key] = default
    for key in _INT_FIELDS:
        resolved[key] = int(str(resolved[key]))

    if local is not None:
        resolved_local = bool(local)
    elif resolved["host"] == "local":
        resolved_local = True
    else:
        resolved_local = autodetect_local(str(resolved["host"]))

    host_value = str(resolved["host"])
    if host_value != "local" and not re.fullmatch(
        r"(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+", host_value
    ):
        raise ValueError("profile host contains unsafe or unsupported characters")
    for key in ("cloak_py", "clairvoyance", "http_py", "node", "har_to_openapi"):
        if any(character in str(resolved[key]) for character in "\x00\r\n"):
            raise ValueError(f"profile {key} contains forbidden control characters")

    return HostProfile(
        host=host_value,
        cloak_py=str(resolved["cloak_py"]),
        clairvoyance=str(resolved["clairvoyance"]),
        byparr=str(resolved["byparr"]),
        burp_config_glob=str(resolved["burp_config_glob"]),
        ssh_timeout=int(str(resolved["ssh_timeout"])),
        grace_s=int(str(resolved["grace_s"])),
        local=resolved_local,
        http_py=str(resolved["http_py"]),
        node=str(resolved["node"]),
        har_to_openapi=str(resolved["har_to_openapi"]),
    )


# ---- engine validation -------------------------------------------------

Runner = Callable[[list[str], int], "subprocess.CompletedProcess[str]"]


def _default_runner(profile: HostProfile) -> Runner:
    """A minimal standalone argv runner (direct locally, quoted once remotely)
    so probe()/validate() work without any caller-supplied runner. cli.py
    normally injects its own argv runner so probing goes through the exact same
    execution path (and timeouts/retries) as the rest of the pipeline."""

    def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
        if profile.local:
            local_argv = list(argv)
            local_argv[0] = os.path.expanduser(local_argv[0])
            return subprocess.run(local_argv, capture_output=True, text=True, timeout=timeout)
        import shlex

        if argv[0].startswith("~/"):
            command = " ".join(
                ['"$HOME"/' + shlex.quote(argv[0][2:]), *(shlex.quote(v) for v in argv[1:])]
            )
        else:
            command = shlex.join(argv)
        return subprocess.run(
            ["ssh", profile.host, command], capture_output=True, text=True, timeout=timeout
        )

    return _run


def probe(profile: HostProfile, runner: Runner | None = None) -> dict[str, dict]:
    """Check each engine (cloakbrowser, clairvoyance, byparr) and return a
    structured {engine: {"present": bool, "detail": str|None}} result.

    `runner(argv, timeout) -> CompletedProcess`-like object exposing `.stdout`
    is the injected command executor. Defaults to a bare local/ssh runner
    derived from `profile.local` (see _default_runner) when not supplied --
    callers that already have an argv helper (e.g. cli.py) should inject it
    so probing shares the same execution path as everything else."""
    run = runner or _default_runner(profile)

    results: dict[str, dict] = {}

    def execute(argv: list[str], timeout: int):
        try:
            result = run(argv, timeout)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(argv, 124, "", "timeout"), "timeout"
        except FileNotFoundError:
            return subprocess.CompletedProcess(argv, 127, "", "missing executable"), "missing"
        except OSError:
            return subprocess.CompletedProcess(argv, 255, "", "host unreachable"), "unreachable"
        code = getattr(result, "returncode", 1)
        if code == 255:
            return result, "unreachable"
        if code == 127:
            return result, "missing"
        if code == 126:
            return result, "incompatible"
        return result, "unavailable"

    def state(default: str, present: bool) -> str:
        return "ready" if present else default

    r, r_state = execute(
        [profile.cloak_py, "-c", "import cloakbrowser as c;print(c.__version__)"],
        profile.ssh_timeout,
    )
    version = (getattr(r, "stdout", "") or "").strip()
    results["cloakbrowser"] = {
        "present": bool(version),
        "detail": version or None,
        "status": state(r_state, bool(version)),
    }

    r, r_state = execute(["test", "-x", profile.clairvoyance], profile.ssh_timeout)
    present = getattr(r, "returncode", 1) == 0
    results["clairvoyance"] = {
        "present": present,
        "detail": None,
        "status": state(r_state, present),
    }

    r, r_state = execute(["curl", "-fsS", "-m", "30", profile.byparr.replace("/v1", "/health")], 40)
    healthy = "working" in (getattr(r, "stdout", "") or "").lower()
    results["byparr"] = {
        "present": healthy,
        "detail": profile.byparr if healthy else None,
        "status": state(r_state, healthy),
    }

    for name, interpreter, statement in (
        ("capture_dependencies", profile.cloak_py, "import graphql,jsonschema"),
        ("tls_http", profile.http_py, "import curl_cffi"),
    ):
        r, r_state = execute([interpreter, "-c", statement], profile.ssh_timeout)
        present = getattr(r, "returncode", 1) == 0
        results[name] = {
            "present": present,
            "detail": interpreter,
            "status": state(r_state, present),
        }
    node_result, node_state = execute([profile.node, "--version"], profile.ssh_timeout)
    converter_result, converter_state = execute(
        [profile.har_to_openapi, "--help"], profile.ssh_timeout
    )
    openapi_present = (
        getattr(node_result, "returncode", 1) == 0
        and getattr(converter_result, "returncode", 1) == 0
    )
    results["openapi"] = {
        "present": openapi_present,
        "detail": profile.har_to_openapi,
        "status": (
            "ready"
            if openapi_present
            else next(
                (
                    candidate
                    for candidate in (node_state, converter_state)
                    if candidate in {"unreachable", "timeout", "missing", "incompatible"}
                ),
                "unavailable",
            )
        ),
    }

    return results


def validate(profile: HostProfile, runner: Runner | None = None) -> bool:
    """True when the mandatory capture engine and its dependencies are present.

    Optional engines are selected per operation; their absence must not make
    an otherwise valid host unusable for every workflow.
    """
    results = probe(profile, runner)
    return all(results[name]["present"] for name in ("cloakbrowser", "capture_dependencies"))


def select_backend(operation: dict, capabilities: dict[str, dict]) -> dict[str, str]:
    """Choose an execution backend with an explicit machine-readable reason."""
    if operation.get("executable") is False or operation.get("semantic_kind") == "unknown":
        return {"backend": "inventory-only", "reason": "operation is not safely executable"}
    if operation.get("requires_ui"):
        if capabilities.get("cloakbrowser", {}).get("present"):
            return {"backend": "ui-drive", "reason": "operation requires browser interaction"}
        return {"backend": "inventory-only", "reason": "browser capability is unavailable"}
    if operation.get("requires_warm_browser"):
        if capabilities.get("cloakbrowser", {}).get("present"):
            return {
                "backend": "warm-browser",
                "reason": "operation requires live browser session state",
            }
        return {"backend": "inventory-only", "reason": "browser capability is unavailable"}
    if operation.get("tls_matched"):
        if capabilities.get("tls_http", {}).get("present"):
            return {"backend": "tls-matched-http", "reason": "target requires browser TLS mimicry"}
        return {"backend": "inventory-only", "reason": "TLS-matched HTTP is unavailable"}
    return {"backend": "direct-http", "reason": "exact HTTP adapter is available"}
