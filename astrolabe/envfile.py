"""Local ``.env`` support for operator credentials and sensitive fetch config.

An operator keeps residential-proxy credentials, the byparr URL and the VPN
egress command in a gitignored ``.env`` instead of exporting them per shell.
This module is the only reader of that file.

Two rules keep it from becoming a way for an agent to widen its own envelope:

* **It is operator config, not tool input.** Nothing here is reachable from a
  tool argument; the fetch command reads it, the MCP surfaces never do.
* **It never mutates ``os.environ``.** Resolved values are returned as a dict
  and passed to the code that needs them, so a value loaded for one command
  cannot leak into another module's ambient environment.

Secrets are marked by name, not by heuristics on the value. ``redacted()`` is
what the ``astrolabe env`` command prints, so a value never reaches a terminal
or a log by default.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_FILE_VAR = "ASTROLABE_ENV_FILE"
DEFAULT_ENV_FILE = ".env"

# A key is treated as sensitive when any of these appear in its upper-cased
# name. Deliberately name-based: a password that happens to be "hunter2" is
# still a password, and a non-secret named FOO must not be masked by accident.
SECRET_MARKERS = (
    "PASS",
    "SECRET",
    "TOKEN",
    "COOKIE",
    "CREDENTIAL",
    "AUTH",
    "_KEY",
    "APIKEY",
    "PRIVATE",
)


def is_secret(name: str) -> bool:
    """Whether a config key must be redacted in output."""
    upper = name.upper()
    return any(marker in upper for marker in SECRET_MARKERS)


def find_env_file(explicit: str | None = None) -> Path | None:
    """Resolve which ``.env`` to read: explicit argument, then the env var,
    then ``./.env``. Returns ``None`` when none of them exists."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    configured = os.environ.get(ENV_FILE_VAR)
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.append(Path(DEFAULT_ENV_FILE))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def parse_env_text(text: str) -> dict[str, str]:
    """Parse ``KEY=VALUE`` lines. Comments, blanks and a leading ``export`` are
    ignored; surrounding quotes are stripped. No shell expansion: a value is
    taken literally, which is the only predictable thing to do with a credential."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        if not key:
            continue
        values[key] = value.strip().strip("'\"")
    return values


def load_env_file(path: Path) -> dict[str, str]:
    """Read one ``.env`` file. A missing or unreadable file yields ``{}``."""
    try:
        return parse_env_text(path.read_text(encoding="utf-8"))
    except OSError:
        return {}


def resolve(explicit: str | None = None, *, env: dict[str, str] | None = None) -> dict[str, str]:
    """Resolve operator config: the file first, then ``os.environ`` wins.

    An exported variable is a deliberate per-shell override, so it takes
    precedence over the file every time.
    """
    environment = dict(os.environ if env is None else env)
    path = find_env_file(explicit)
    if path is None:
        return environment
    merged = load_env_file(path)
    merged.update(environment)
    return merged


def permissions_warning(path: Path) -> str | None:
    """Warn when the file holding credentials is readable by other users.

    A warning, not a refusal: the operator may be inside a single-user
    container where the mode says nothing useful. Silence would be worse.
    """
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return None
    if mode & 0o077:
        return (
            f"{path} is readable by group/other (mode {oct(mode & 0o777)}); "
            f"chmod 600 it if it holds credentials"
        )
    return None


def relevant(environment: dict[str, str]) -> dict[str, str]:
    """The subset of an environment that belongs to astrolabe's operator config.

    ``astrolabe env`` must not dump a shell's whole environment: most of it is
    unrelated, and the point is to show what the tool will actually read.
    """
    prefixes = ("ASTROLABE_", "BASTILLE_", "CLOAKBROWSER_", "BYPARR_", "CFFETCH_")
    return {name: value for name, value in sorted(environment.items()) if name.startswith(prefixes)}


def redacted(values: dict[str, str]) -> dict[str, str]:
    """Copy of ``values`` with sensitive entries masked for display."""
    return {
        name: "<set>" if is_secret(name) and value else value
        for name, value in sorted(values.items())
    }
