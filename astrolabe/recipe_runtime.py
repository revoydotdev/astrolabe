"""Controller for network/filesystem-isolated Python recipe execution."""

from __future__ import annotations

import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


class RecipeSandboxError(RuntimeError):
    """Raised when a Python recipe cannot be safely isolated or controlled."""


_CALLS = frozenset(
    {
        "goto",
        "wait_for_timeout",
        "evaluate",
        "eval_on_selector_all",
        "click",
        "fill",
        "press",
        "hover",
        "type",
        "locator",
        "query_selector_all",
        "query_selector",
        "get_attribute",
        "title",
        "select_option",
        "check",
        "is_visible",
        "count",
        "inner_text",
        "scroll_into_view_if_needed",
        "wheel",
        # Waiting for an element to exist is a read: it drives nothing and changes
        # nothing. Without it a recipe can only sleep a fixed interval, which loses
        # the race against any SPA that hydrates its controls after first paint —
        # the controls then read as absent and the surface is silently unmapped.
        "wait_for_selector",
    }
)
_GETS = frozenset({"url", "first", "mouse", "keyboard"})
_SCRIPT_NETWORK = re.compile(r"\b(?:fetch|xmlhttprequest|websocket|eventsource|sendbeacon)\b", re.I)
_SCRIPT_SECRET = re.compile(r"localstorage|sessionstorage|document\s*\.\s*cookie", re.I)
_SCRIPT_URL = re.compile(r"(?:https?|wss?)://[^\s'\"`<>]+", re.I)


def _mount(command: list[str], source: Path, destination: str | None = None) -> None:
    if not source.exists():
        return
    command.extend(["--ro-bind", str(source), destination or str(source)])


def sandbox_command(recipe: Path, worker: Path, bwrap: str | None = None) -> list[str]:
    """Build the minimal bubblewrap profile used for an escape-hatch recipe."""
    executable = Path(sys.executable).resolve()
    bwrap = bwrap or shutil.which("bwrap")
    if not bwrap:
        raise RecipeSandboxError("bubblewrap is required for Python recipes; use declarative JSON")
    command = [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "PYTHONHASHSEED",
        "0",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/sandbox",
        "--chdir",
        "/tmp",
    ]
    mounted: set[Path] = set()
    for candidate in (
        Path("/usr"),
        Path("/lib"),
        Path("/lib64"),
        Path(sys.base_prefix).resolve(),
        executable.parent.parent,
    ):
        if candidate not in mounted:
            _mount(command, candidate)
            mounted.add(candidate)
    _mount(command, worker.resolve(strict=True), "/sandbox/worker.py")
    _mount(command, recipe.resolve(strict=True), "/sandbox/recipe.py")
    command.extend([str(executable), "-I", "-S", "/sandbox/worker.py", "/sandbox/recipe.py"])
    return command


class SandboxedRecipe:
    declarative = False
    sandboxed = True
    SURFACES: list[str]
    ACTIVE_PROBES: list[dict[str, Any]]
    SESS_HEADERS: dict[str, str]
    SESS_HEADER_HARVEST: dict[str, str]
    AUTH_HEADERS: list[str]
    AUTH_HEADER_PATTERN: str | None

    def __init__(
        self,
        path: str,
        *,
        worker_path: str | None = None,
        startup_timeout: float = 10.0,
    ) -> None:
        recipe = Path(path)
        worker = Path(worker_path) if worker_path else Path(__file__).with_name("recipe_worker.py")
        command = sandbox_command(recipe, worker)
        try:
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            raise RecipeSandboxError(f"cannot start recipe sandbox: {exc}") from exc
        self._closed = False
        try:
            ready = self._read(startup_timeout)
            if ready.get("kind") != "ready" or not isinstance(ready.get("metadata"), dict):
                raise RecipeSandboxError(self._message(ready))
            metadata = ready["metadata"]
            for name in (
                "SURFACES",
                "ACTIVE_PROBES",
                "SESS_HEADERS",
                "SESS_HEADER_HARVEST",
                "AUTH_HEADERS",
                "AUTH_HEADER_PATTERN",
            ):
                setattr(self, name, metadata.get(name))
            self._has_drive = metadata.get("has_drive") is True
            if not self._has_drive:
                self.close()
        except BaseException:
            self.close(force=True)
            raise

    def _message(self, value: dict[str, Any]) -> str:
        return f"recipe sandbox failed ({value.get('error_type', 'protocol')}): {value.get('error', value)}"

    def _read(self, timeout: float) -> dict[str, Any]:
        stdout = self._process.stdout
        if stdout is None:
            raise RecipeSandboxError("recipe sandbox has no output channel")
        selector = selectors.DefaultSelector()
        selector.register(stdout, selectors.EVENT_READ)
        try:
            if not selector.select(timeout):
                raise RecipeSandboxError("recipe sandbox timed out")
            line = stdout.readline()
        finally:
            selector.close()
        if not line:
            stderr = self._process.stderr.read(1000) if self._process.stderr else ""
            raise RecipeSandboxError(f"recipe sandbox exited without a response: {stderr}")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RecipeSandboxError("recipe sandbox emitted invalid protocol data") from exc
        if not isinstance(value, dict):
            raise RecipeSandboxError("recipe sandbox emitted a non-object protocol message")
        return value

    def _send(self, value: dict[str, Any]) -> None:
        if self._process.stdin is None:
            raise RecipeSandboxError("recipe sandbox has no input channel")
        self._process.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        self._process.stdin.flush()

    @staticmethod
    def _encode_result(value: Any, objects: dict[str, Any]) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, (list, tuple)):
            return [SandboxedRecipe._encode_result(item, objects) for item in value[:1000]]
        if isinstance(value, dict):
            return {
                str(key)[:200]: SandboxedRecipe._encode_result(item, objects)
                for key, item in list(value.items())[:1000]
            }
        object_id = f"object-{len(objects)}"
        objects[object_id] = value
        return {"$remote": object_id}

    @staticmethod
    def _validate_script(
        attribute: str,
        args: list[Any],
        validate_navigation: Callable[[str], str],
    ) -> None:
        if attribute not in {"evaluate", "eval_on_selector_all"} or not args:
            return
        script_index = 0 if attribute == "evaluate" else 1
        if len(args) <= script_index or not isinstance(args[script_index], str):
            raise RecipeSandboxError("recipe browser script must be a literal string")
        script = args[script_index]
        if _SCRIPT_SECRET.search(script):
            raise RecipeSandboxError("recipe browser script may not read browser credential stores")
        if not _SCRIPT_NETWORK.search(script):
            return
        candidates = _SCRIPT_URL.findall(script)
        for value in args[script_index + 1 :]:
            if isinstance(value, str) and value.startswith(
                ("http://", "https://", "ws://", "wss://")
            ):
                candidates.append(value)
        if not candidates:
            raise RecipeSandboxError(
                "network-capable recipe JavaScript requires an explicit approved URL"
            )
        for candidate in candidates:
            validate_navigation(candidate)

    def drive(
        self,
        page: Any,
        log: Callable[[str], None],
        *,
        validate_navigation: Callable[[str], str],
        interaction: Callable[[str, str], None] | None = None,
        timeout: float = 180.0,
        max_commands: int = 500,
    ) -> None:
        if not self._has_drive:
            return
        objects = {"page": page}
        self._send({"kind": "drive"})
        deadline = time.monotonic() + timeout
        commands = 0
        try:
            while True:
                message = self._read(max(0.01, deadline - time.monotonic()))
                kind = message.get("kind")
                if kind == "done":
                    return
                if kind == "fatal":
                    raise RecipeSandboxError(self._message(message))
                if kind == "log":
                    log(f"[recipe-sandbox] {str(message.get('message') or '')[:1000]}")
                    self._send({"ok": True, "result": None})
                    continue
                commands += 1
                if commands > max_commands:
                    raise RecipeSandboxError("recipe exceeded its browser-command budget")
                object_id = message.get("object")
                attribute = message.get("attribute")
                target = objects.get(str(object_id))
                if target is None:
                    raise RecipeSandboxError("recipe referenced an unknown browser object")
                try:
                    if kind == "get":
                        if attribute not in _GETS:
                            raise RecipeSandboxError(
                                f"recipe property {attribute!r} is not allowed"
                            )
                        result = getattr(target, str(attribute))
                    elif kind == "call":
                        if attribute not in _CALLS:
                            raise RecipeSandboxError(f"recipe method {attribute!r} is not allowed")
                        args = message.get("args") or []
                        kwargs = message.get("kwargs") or {}
                        if not isinstance(args, list) or not isinstance(kwargs, dict):
                            raise RecipeSandboxError("recipe call arguments are malformed")
                        if attribute == "goto":
                            if not args or not isinstance(args[0], str):
                                raise RecipeSandboxError("recipe goto requires a URL")
                            args[0] = validate_navigation(args[0])
                        self._validate_script(str(attribute), args, validate_navigation)
                        if interaction is not None:
                            causal_kind = {
                                "goto": "navigation",
                                "click": "click",
                                "check": "click",
                                "select_option": "click",
                                "press": "input",
                                "fill": "input",
                                "type": "input",
                                "wheel": "scroll",
                                "evaluate": "probe",
                            }.get(str(attribute))
                            if causal_kind:
                                interaction(
                                    causal_kind,
                                    f"isolated Python recipe {attribute}",
                                )
                        result = getattr(target, str(attribute))(*args, **kwargs)
                    else:
                        raise RecipeSandboxError("recipe sent an unsupported protocol command")
                    self._send({"ok": True, "result": self._encode_result(result, objects)})
                except BaseException as exc:
                    self._send({"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:500]}"})
        finally:
            self.close(force=True)

    def close(self, *, force: bool = False) -> None:
        if self._closed:
            return
        self._closed = True
        if not force and self._process.poll() is None:
            try:
                self._send({"kind": "close"})
                self._process.wait(timeout=2)
            except (OSError, subprocess.SubprocessError):
                force = True
        if force and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)
        for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
            if stream is not None:
                stream.close()

    def __del__(self) -> None:
        try:
            self.close(force=True)
        except Exception:
            pass
