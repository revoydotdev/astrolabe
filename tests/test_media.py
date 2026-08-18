from __future__ import annotations

import pytest

from astrolabe.media import MediaKind, classify_media, is_api_media


@pytest.mark.parametrize(
    ("content_type", "resource_type", "prefix", "expected"),
    [
        ("application/json; charset=utf-8", "fetch", None, MediaKind.JSON_API),
        ("application/problem+json", "xhr", None, MediaKind.JSON_API),
        ("text/html", "xhr", None, MediaKind.HTML),
        ("", "document", None, MediaKind.HTML),
        ("text/event-stream", "fetch", None, MediaKind.STREAM),
        ("application/javascript", "script", None, MediaKind.JAVASCRIPT),
        ("application/octet-stream", "fetch", None, MediaKind.BINARY),
        ("", "fetch", b'  {"ok":true}', MediaKind.JSON_API),
        ("", "fetch", b"<!doctype html><title>x", MediaKind.HTML),
        ("", "fetch", b"\x89PNG\r\n\x1a\n", MediaKind.BINARY),
    ],
)
def test_media_classification(content_type, resource_type, prefix, expected) -> None:
    assert classify_media(content_type, resource_type, prefix=prefix) is expected


def test_graphql_evidence_overrides_generic_json() -> None:
    assert classify_media("application/json", "fetch", graphql=True) is MediaKind.GRAPHQL
    assert is_api_media(MediaKind.GRAPHQL)
    assert not is_api_media(MediaKind.HTML)
