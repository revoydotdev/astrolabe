#!/usr/bin/env python3
"""Isolated Python-recipe worker.

This process has no browser object of its own. It imports a reviewed recipe inside a
bubblewrap sandbox, reports only the bounded recipe interface as JSON, and proxies drive()
calls over a line-delimited RPC channel. The parent owns and validates every browser action.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import os
import resource
import sys
from pathlib import Path
from typing import Any

_PROPERTIES = frozenset({"url", "first", "mouse", "keyboard"})


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    if hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))


class Channel:
    def __init__(self) -> None:
        self.output = os.fdopen(os.dup(sys.stdout.fileno()), "w", encoding="utf-8", buffering=1)

    def send(self, value: dict[str, Any]) -> dict[str, Any]:
        self.output.write(json.dumps(value, separators=(",", ":")) + "\n")
        line = sys.stdin.readline()
        if not line:
            raise RuntimeError("recipe controller disconnected")
        response = json.loads(line)
        if not response.get("ok"):
            raise RuntimeError(str(response.get("error") or "browser action failed"))
        return response


class RemoteObject:
    def __init__(self, channel: Channel, object_id: str):
        object.__setattr__(self, "_channel", channel)
        object.__setattr__(self, "_object_id", object_id)

    def _decode(self, value: Any) -> Any:
        if isinstance(value, dict) and set(value) == {"$remote"}:
            return RemoteObject(self._channel, str(value["$remote"]))
        if isinstance(value, list):
            return [self._decode(item) for item in value]
        if isinstance(value, dict):
            return {key: self._decode(item) for key, item in value.items()}
        return value

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or name in {"context", "request", "browser"}:
            raise AttributeError(f"recipe access to {name!r} is not allowed")
        if name in _PROPERTIES:
            response = self._channel.send(
                {"kind": "get", "object": self._object_id, "attribute": name}
            )
            return self._decode(response.get("result"))

        def call(*args: Any, **kwargs: Any) -> Any:
            response = self._channel.send(
                {
                    "kind": "call",
                    "object": self._object_id,
                    "attribute": name,
                    "args": args,
                    "kwargs": kwargs,
                }
            )
            return self._decode(response.get("result"))

        return call


def _metadata(module: Any) -> dict[str, Any]:
    pattern = getattr(module, "AUTH_HEADER_PATTERN", None)
    if pattern is not None and not isinstance(pattern, str):
        pattern = getattr(pattern, "pattern", None)
    value = {
        "SURFACES": getattr(module, "SURFACES", []),
        "ACTIVE_PROBES": getattr(module, "ACTIVE_PROBES", []),
        "SESS_HEADERS": getattr(module, "SESS_HEADERS", {}),
        "SESS_HEADER_HARVEST": getattr(module, "SESS_HEADER_HARVEST", {}),
        "AUTH_HEADERS": getattr(module, "AUTH_HEADERS", []),
        "AUTH_HEADER_PATTERN": pattern,
        "has_drive": callable(getattr(module, "drive", None)),
    }
    # Round-trip here so arbitrary recipe objects can never reach the controller.
    return json.loads(json.dumps(value))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("recipe")
    args = parser.parse_args(argv)
    _limits()
    channel = Channel()
    null = open(os.devnull, "w", encoding="utf-8")
    try:
        recipe_path = Path(args.recipe).resolve(strict=True)
        spec = importlib.util.spec_from_file_location("isolated_astrolabe_recipe", recipe_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load recipe module")
        module = importlib.util.module_from_spec(spec)
        with contextlib.redirect_stdout(null), contextlib.redirect_stderr(null):
            spec.loader.exec_module(module)
        channel.output.write(
            json.dumps({"kind": "ready", "metadata": _metadata(module)}, separators=(",", ":"))
            + "\n"
        )
        command = json.loads(sys.stdin.readline())
        if command.get("kind") == "close":
            return 0
        if command.get("kind") != "drive" or not callable(getattr(module, "drive", None)):
            raise RuntimeError("invalid recipe worker command")

        def log(message: Any) -> None:
            channel.send({"kind": "log", "message": str(message)[:1000]})

        page = RemoteObject(channel, "page")
        with contextlib.redirect_stdout(null), contextlib.redirect_stderr(null):
            module.drive(page, log)
        channel.output.write('{"kind":"done"}\n')
        return 0
    except BaseException as exc:
        channel.output.write(
            json.dumps(
                {"kind": "fatal", "error_type": type(exc).__name__, "error": str(exc)[:1000]},
                separators=(",", ":"),
            )
            + "\n"
        )
        return 1
    finally:
        null.close()


if __name__ == "__main__":
    raise SystemExit(main())
