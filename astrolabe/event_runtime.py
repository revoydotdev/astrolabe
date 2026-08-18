"""Pinned, bounded, cancelable WebSocket/socket.io and SSE subscriptions."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

import h11
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from .security import resolve_public_addresses, validate_url


class EventAdapterError(RuntimeError):
    """A typed event transport failure safe to return through MCP."""


def validate_event_channel(
    channel: dict[str, Any], allowed_hosts: set[str], *, allow_insecure: bool = False
) -> None:
    protocol = channel.get("protocol")
    url = channel.get("url")
    schemes = {
        "sse": ("https", "http") if allow_insecure else ("https",),
        "websocket": ("wss", "ws") if allow_insecure else ("wss",),
        "socketio": ("wss", "ws") if allow_insecure else ("wss",),
    }.get(str(protocol))
    if schemes is None or not isinstance(url, str):
        raise EventAdapterError("unsupported event channel protocol or URL")
    validate_url(url, allowed_hosts, schemes=schemes)


async def subscribe_channel(
    channel: dict[str, Any],
    headers: dict[str, str],
    *,
    max_events: int,
    timeout_seconds: float,
    max_bytes: int,
    max_queue: int,
    reconnects: int,
    last_event_id: str | None = None,
) -> dict[str, Any]:
    protocol = channel["protocol"]
    if protocol == "sse":
        return await _subscribe_sse(
            channel,
            headers,
            max_events=max_events,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
            reconnects=reconnects,
            last_event_id=last_event_id,
        )
    return await _subscribe_websocket(
        channel,
        headers,
        max_events=max_events,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
        max_queue=max_queue,
        reconnects=reconnects,
    )


async def _connected_socket(url: str) -> socket.socket:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise EventAdapterError("event URL has no host")
    port = parsed.port or (443 if parsed.scheme in {"https", "wss"} else 80)
    addresses = resolve_public_addresses(parsed.hostname, port)
    last_error: OSError | None = None
    for address in addresses:
        try:
            sock = await asyncio.to_thread(socket.create_connection, (address, port), 5.0)
            sock.setblocking(False)
            return sock
        except OSError as exc:
            last_error = exc
    raise EventAdapterError(f"could not connect to approved address: {last_error}")


def _decode_event_payload(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _socketio_event(payload: str) -> dict[str, Any] | None:
    if not payload.startswith("42"):
        return None
    value = payload[2:]
    namespace = None
    if value.startswith("/"):
        comma = value.find(",")
        if comma < 0:
            return None
        namespace, value = value[:comma], value[comma + 1 :]
    while value and value[0].isdigit():
        value = value[1:]
    try:
        packet = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(packet, list) or not packet or not isinstance(packet[0], str):
        return None
    return {"event": packet[0], "args": packet[1:], "namespace": namespace}


async def _subscribe_websocket(
    channel: dict[str, Any],
    headers: dict[str, str],
    *,
    max_events: int,
    timeout_seconds: float,
    max_bytes: int,
    max_queue: int,
    reconnects: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    events: list[dict[str, Any]] = []
    attempts = 0
    while len(events) < max_events and attempts <= reconnects:
        attempts += 1
        sock = await _connected_socket(channel["url"])
        try:
            async with connect(
                channel["url"],
                sock=sock,
                additional_headers=headers,
                origin=channel.get("origin"),
                subprotocols=channel.get("subprotocols") or None,
                open_timeout=min(10.0, timeout_seconds),
                close_timeout=2.0,
                max_size=max_bytes,
                max_queue=max_queue,
            ) as websocket:
                if channel["protocol"] == "socketio":
                    namespace = channel.get("namespace") or "/"
                    if not channel.get("read_only_setup_attested"):
                        raise EventAdapterError(
                            "socket.io namespace setup is not attested read-only"
                        )
                    await websocket.send("40" + (f"{namespace}," if namespace != "/" else ""))
                while len(events) < max_events:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return {
                            "ok": True,
                            "events": events,
                            "truncated": True,
                            "truncation_reason": "timeout",
                            "reconnects": attempts - 1,
                        }
                    message = await asyncio.wait_for(websocket.recv(), timeout=remaining)
                    if isinstance(message, bytes):
                        events.append(
                            {
                                "event": "binary",
                                "data_base64": base64.b64encode(message).decode(),
                                "byte_length": len(message),
                            }
                        )
                        continue
                    if channel["protocol"] == "socketio" and message == "2":
                        await websocket.send("3")
                        continue
                    parsed = (
                        _socketio_event(message)
                        if channel["protocol"] == "socketio"
                        else {"event": "message", "data": _decode_event_payload(message)}
                    )
                    if parsed is None:
                        continue
                    allowed_events = set(channel.get("received_events") or [])
                    if allowed_events and parsed.get("event") not in allowed_events:
                        continue
                    events.append(parsed)
        except asyncio.CancelledError:
            raise
        except (OSError, TimeoutError, EventAdapterError, WebSocketException):
            if attempts > reconnects or time.monotonic() >= deadline:
                raise
    return {
        "ok": True,
        "events": events,
        "truncated": len(events) >= max_events,
        "truncation_reason": "event-budget" if len(events) >= max_events else None,
        "reconnects": attempts - 1,
    }


class _SSEParser:
    def __init__(self) -> None:
        self.buffer = ""
        self.fields: dict[str, list[str]] = {}
        self.retry_ms: int | None = None

    def feed(self, data: bytes) -> list[dict[str, Any]]:
        self.buffer += data.decode("utf-8", errors="replace")
        events: list[dict[str, Any]] = []
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            line = line.rstrip("\r")
            if not line:
                if self.fields.get("data"):
                    raw_data = "\n".join(self.fields["data"])
                    event_ids = self.fields.get("id") or []
                    events.append(
                        {
                            "event": (self.fields.get("event") or ["message"])[-1],
                            "id": event_ids[-1] if event_ids else None,
                            "data": _decode_event_payload(raw_data),
                        }
                    )
                self.fields = {}
                continue
            if line.startswith(":"):
                continue
            field, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
            if field == "retry" and value.isdigit():
                self.retry_ms = min(int(value), 60_000)
            elif field in {"event", "data", "id"}:
                self.fields.setdefault(field, []).append(value)
        return events


async def _open_pinned_http(url: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    parsed = urlparse(url)
    sock = await _connected_socket(url)
    context = ssl.create_default_context() if parsed.scheme == "https" else None
    return await asyncio.open_connection(
        sock=sock,
        ssl=context,
        server_hostname=parsed.hostname if context else None,
    )


async def _subscribe_sse(
    channel: dict[str, Any],
    headers: dict[str, str],
    *,
    max_events: int,
    timeout_seconds: float,
    max_bytes: int,
    reconnects: int,
    last_event_id: str | None,
) -> dict[str, Any]:
    if last_event_id and not channel.get("resume_understood"):
        raise EventAdapterError("Last-Event-ID semantics are not attested for this channel")
    deadline = time.monotonic() + timeout_seconds
    events: list[dict[str, Any]] = []
    total_bytes = 0
    attempts = 0
    parser = _SSEParser()
    while len(events) < max_events and attempts <= reconnects:
        attempts += 1
        reader, writer = await _open_pinned_http(channel["url"])
        connection = h11.Connection(h11.CLIENT)
        parsed_url = urlparse(channel["url"])
        target = parsed_url.path or "/"
        if parsed_url.query:
            target += "?" + parsed_url.query
        request_headers = [
            (b"host", parsed_url.netloc.encode()),
            (b"accept", b"text/event-stream"),
            (b"cache-control", b"no-cache"),
        ]
        request_headers.extend(
            (str(name).encode(), str(value).encode()) for name, value in headers.items()
        )
        if last_event_id:
            request_headers.append((b"last-event-id", last_event_id.encode()))
        writer.write(
            connection.send(
                h11.Request(method=b"GET", target=target.encode(), headers=request_headers)
            )
            + connection.send(h11.EndOfMessage())
        )
        await writer.drain()
        try:
            response_seen = False
            while len(events) < max_events:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                data = await asyncio.wait_for(reader.read(65_536), timeout=remaining)
                if not data:
                    break
                total_bytes += len(data)
                if total_bytes > max_bytes:
                    raise EventAdapterError("SSE byte budget exceeded")
                connection.receive_data(data)
                while True:
                    event = connection.next_event()
                    if event is h11.NEED_DATA:
                        break
                    if isinstance(event, h11.Response):
                        response_seen = True
                        if event.status_code != 200:
                            raise EventAdapterError(
                                f"SSE upstream returned HTTP {event.status_code}"
                            )
                        response_headers = {
                            name.decode().lower(): value.decode() for name, value in event.headers
                        }
                        if "text/event-stream" not in response_headers.get("content-type", ""):
                            raise EventAdapterError("SSE upstream returned the wrong media type")
                    elif isinstance(event, h11.Data):
                        events.extend(parser.feed(event.data))
                        if channel.get("resume_understood") and events and events[-1].get("id"):
                            last_event_id = str(events[-1]["id"])
                    elif isinstance(event, h11.EndOfMessage):
                        break
                if isinstance(event, h11.EndOfMessage):
                    break
            if not response_seen:
                raise EventAdapterError("SSE upstream closed before response headers")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        if len(events) < max_events and attempts <= reconnects:
            delay = min((parser.retry_ms or 250) / 1000, max(0.0, deadline - time.monotonic()))
            await asyncio.sleep(delay)
    return {
        "ok": True,
        "events": events[:max_events],
        "truncated": len(events) >= max_events or time.monotonic() >= deadline,
        "truncation_reason": (
            "event-budget"
            if len(events) >= max_events
            else "timeout"
            if time.monotonic() >= deadline
            else None
        ),
        "reconnects": attempts - 1,
        "last_event_id": last_event_id,
    }
