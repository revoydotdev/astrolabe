"""Bounded, first-party GraphQL suggestion probe and schema recovery.

This helper runs on the capture host. Secret header values remain in tmpfs and
are passed to clairvoyance as argv values, never interpolated into a shell.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import urllib.parse as up
from typing import Any

import h11

try:
    from astrolabe.security import resolve_public_addresses, validate_url
except ImportError:  # standalone deployment on the capture host
    from security import (  # type: ignore[import-not-found,no-redef]
        resolve_public_addresses,
        validate_url,
    )

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_PROTECTED = frozenset({"host", "content-length", "transfer-encoding", "connection"})
_MAX_RESPONSE_BYTES = 1_048_576


def load_headers(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("auth header artifact must be an object")
    result: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name)
        if name.startswith("_"):
            continue
        if not _HEADER_NAME.fullmatch(name) or name.lower() in _PROTECTED:
            raise ValueError("auth artifact contains an unsafe header name")
        text = str(raw_value)
        if "\r" in text or "\n" in text:
            raise ValueError("auth artifact contains an unsafe header value")
        result[name] = text
    return result


def _request_once(url: str, address: str, headers: dict[str, str]) -> tuple[int, bytes]:
    parsed = up.urlsplit(url)
    port = parsed.port or 443
    host = parsed.hostname or ""
    target = up.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    body = json.dumps({"query": "query{search{zzznotafieldzzz}}"}).encode()
    request_headers = [
        ("host", parsed.netloc),
        ("content-type", "application/json"),
        ("accept", "application/json"),
        ("content-length", str(len(body))),
        ("connection", "close"),
        *((name, value) for name, value in headers.items()),
    ]
    connection = h11.Connection(h11.CLIENT)
    raw_socket = socket.create_connection((address, port), timeout=25)
    try:
        with ssl.create_default_context().wrap_socket(raw_socket, server_hostname=host) as stream:
            stream.settimeout(25)
            stream.sendall(
                connection.send(h11.Request(method="POST", target=target, headers=request_headers))
                + connection.send(h11.Data(data=body))
                + connection.send(h11.EndOfMessage())
            )
            status = 0
            chunks: list[bytes] = []
            size = 0
            while True:
                event = connection.next_event()
                if event is h11.NEED_DATA:
                    data = stream.recv(65_536)
                    connection.receive_data(data)
                    if not data:
                        break
                    continue
                if isinstance(event, h11.Response):
                    status = event.status_code
                elif isinstance(event, h11.Data):
                    size += len(event.data)
                    if size > _MAX_RESPONSE_BYTES:
                        raise ValueError("suggestion probe response exceeds byte budget")
                    chunks.append(event.data)
                elif isinstance(event, (h11.EndOfMessage, h11.ConnectionClosed)):
                    break
            return status, b"".join(chunks)
    finally:
        raw_socket.close()


def suggestion_probe(endpoint: str, allowed_host: str, headers: dict[str, str]) -> bool:
    url = validate_url(endpoint, {allowed_host}, resolve=True)
    parsed = up.urlsplit(url)
    last_error: Exception | None = None
    for address in resolve_public_addresses(parsed.hostname or "", parsed.port or 443):
        try:
            _status, body = _request_once(url, address, headers)
            return b"did you mean" in body.lower()
        except (OSError, ssl.SSLError, h11.ProtocolError) as exc:
            last_error = exc
    if last_error:
        raise RuntimeError("all pinned suggestion-probe connections failed") from last_error
    return False


def recover(
    *,
    endpoint: str,
    allowed_host: str,
    headers_path: str,
    clairvoyance: str,
    wordlist: str,
    schema_out: str,
    concurrency: int,
    timeout: int,
) -> dict[str, Any]:
    if concurrency < 1 or concurrency > 8:
        raise ValueError("schema concurrency must be between 1 and 8")
    headers = load_headers(headers_path)
    if not suggestion_probe(endpoint, allowed_host, headers):
        return {"suggestions": False, "recovered": False}
    directory = os.path.dirname(os.path.abspath(schema_out)) or "."
    descriptor, staged = tempfile.mkstemp(prefix=".schema-", suffix=".json", dir=directory)
    os.close(descriptor)
    os.unlink(staged)
    try:
        argv = [
            os.path.expanduser(clairvoyance),
            endpoint,
            "-o",
            staged,
            "-w",
            wordlist,
            "-c",
            str(concurrency),
            "-p",
            "slow",
        ]
        for name, value in headers.items():
            argv += ["-H", f"{name}: {value}"]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(f"clairvoyance failed with exit {result.returncode}")
        with open(staged, encoding="utf-8") as handle:
            schema = json.load(handle)
        if not isinstance(schema, dict):
            raise ValueError("clairvoyance schema must be a JSON object")
        os.replace(staged, schema_out)
        return {"suggestions": True, "recovered": True}
    finally:
        if os.path.exists(staged):
            os.unlink(staged)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--allowed-host", required=True)
    parser.add_argument("--headers", required=True)
    parser.add_argument("--clairvoyance", required=True)
    parser.add_argument("--wordlist", required=True)
    parser.add_argument("--schema-out", required=True)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    report = recover(
        endpoint=args.endpoint,
        allowed_host=args.allowed_host,
        headers_path=args.headers,
        clairvoyance=args.clairvoyance,
        wordlist=args.wordlist,
        schema_out=args.schema_out,
        concurrency=args.concurrency,
        timeout=args.timeout,
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
