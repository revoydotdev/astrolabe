from __future__ import annotations

import asyncio

import h11
import pytest

import astrolabe.event_runtime as events
from astrolabe.event_runtime import EventAdapterError, _SSEParser, subscribe_channel


def test_sse_parser_handles_chunking_multiline_data_ids_and_retry() -> None:
    parser = _SSEParser()
    assert parser.feed(b'event: price\nid: 7\ndata: {"n":') == []
    parsed = parser.feed(b"1}\ndata: tail\nretry: 1500\n\n")

    assert parsed == [{"event": "price", "id": "7", "data": '{"n":1}\ntail'}]
    assert parser.retry_ms == 1500


def test_socketio_parser_preserves_namespace_event_and_heterogeneous_args() -> None:
    assert events._socketio_event('42/market,17["price",7,{"currency":"USD"}]') == {
        "event": "price",
        "args": [7, {"currency": "USD"}],
        "namespace": "/market",
    }


@pytest.mark.asyncio
async def test_socketio_subscription_is_bounded_handles_heartbeat_and_closes(monkeypatch) -> None:
    sent: list[str] = []
    closed = False

    class Socket:
        pass

    class WebSocket:
        messages = iter(["2", '42/market,["price",{"n":1}]'])

        async def send(self, value: str) -> None:
            sent.append(value)

        async def recv(self) -> str:
            return next(self.messages)

    class Connection:
        async def __aenter__(self):
            return WebSocket()

        async def __aexit__(self, *_args):
            nonlocal closed
            closed = True

    async def connected(_url: str):
        return Socket()

    monkeypatch.setattr(events, "_connected_socket", connected)
    monkeypatch.setattr(events, "connect", lambda *_args, **_kwargs: Connection())
    result = await subscribe_channel(
        {
            "protocol": "socketio",
            "url": "wss://example.com/socket.io/?EIO=4&transport=websocket",
            "namespace": "/market",
            "received_events": ["price"],
            "read_only_setup_attested": True,
        },
        {},
        max_events=1,
        timeout_seconds=1,
        max_bytes=1000,
        max_queue=2,
        reconnects=0,
    )

    assert result["events"] == [{"event": "price", "args": [{"n": 1}], "namespace": "/market"}]
    assert sent == ["40/market,", "3"]
    assert closed is True


@pytest.mark.asyncio
async def test_websocket_subscription_cancellation_closes_transport(monkeypatch) -> None:
    entered = asyncio.Event()
    closed = asyncio.Event()

    class WebSocket:
        async def recv(self) -> str:
            entered.set()
            await asyncio.Future()
            raise AssertionError("unreachable")

    class Connection:
        async def __aenter__(self):
            return WebSocket()

        async def __aexit__(self, *_args):
            closed.set()

    async def connected(_url: str):
        return object()

    monkeypatch.setattr(events, "_connected_socket", connected)
    monkeypatch.setattr(events, "connect", lambda *_args, **_kwargs: Connection())
    task = asyncio.create_task(
        subscribe_channel(
            {"protocol": "websocket", "url": "wss://example.com/events"},
            {},
            max_events=1,
            timeout_seconds=30,
            max_bytes=1000,
            max_queue=2,
            reconnects=0,
        )
    )
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert closed.is_set()


class _Writer:
    def __init__(self) -> None:
        self.data = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


@pytest.mark.asyncio
async def test_sse_subscription_uses_h11_and_returns_bounded_events(monkeypatch) -> None:
    server = h11.Connection(h11.SERVER)
    response = server.send(
        h11.Response(
            status_code=200,
            headers=[(b"content-type", b"text/event-stream")],
        )
    )
    response += server.send(h11.Data(data=b'event: update\nid: 9\ndata: {"ok":true}\n\n'))
    reader = asyncio.StreamReader()
    reader.feed_data(response)
    writer = _Writer()

    async def opened(_url: str):
        return reader, writer

    monkeypatch.setattr(events, "_open_pinned_http", opened)
    result = await subscribe_channel(
        {
            "protocol": "sse",
            "url": "https://example.com/events",
            "resume_understood": True,
        },
        {"authorization": "Bearer runtime-only"},
        max_events=1,
        timeout_seconds=1,
        max_bytes=1000,
        max_queue=2,
        reconnects=0,
    )

    assert result["events"] == [{"event": "update", "id": "9", "data": {"ok": True}}]
    assert b"authorization: Bearer runtime-only" in writer.data
    assert writer.closed is True


@pytest.mark.asyncio
async def test_sse_resume_requires_explicit_semantic_attestation() -> None:
    with pytest.raises(EventAdapterError, match="Last-Event-ID"):
        await subscribe_channel(
            {"protocol": "sse", "url": "https://example.com/events"},
            {},
            max_events=1,
            timeout_seconds=1,
            max_bytes=1000,
            max_queue=2,
            reconnects=0,
            last_event_id="9",
        )
