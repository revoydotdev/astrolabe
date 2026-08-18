"""Value-free request/response media classification shared across the pipeline."""
from __future__ import annotations

from enum import StrEnum


class MediaKind(StrEnum):
    JSON_API = "json-api"
    GRAPHQL = "graphql"
    HTML = "html"
    JAVASCRIPT = "javascript-static"
    TEXT = "text"
    BINARY = "binary"
    STREAM = "stream"
    UNKNOWN = "unknown"


def classify_media(
    content_type: str | None,
    resource_type: str | None = None,
    *,
    prefix: bytes | None = None,
    graphql: bool = False,
) -> MediaKind:
    if graphql:
        return MediaKind.GRAPHQL
    media_type = str(content_type or "").split(";", 1)[0].strip().lower()
    resource = str(resource_type or "").lower()
    if media_type == "text/event-stream":
        return MediaKind.STREAM
    if media_type in {"text/html", "application/xhtml+xml"} or resource == "document":
        return MediaKind.HTML
    if media_type in {"application/javascript", "text/javascript"} or resource in {
        "script",
        "stylesheet",
        "font",
        "image",
    }:
        return MediaKind.JAVASCRIPT
    if media_type.endswith("+json") or media_type in {
        "application/json",
        "application/problem+json",
        "application/graphql-response+json",
    }:
        return MediaKind.JSON_API
    if media_type.startswith("text/"):
        return MediaKind.TEXT
    if media_type.startswith(("image/", "audio/", "video/")) or media_type in {
        "application/octet-stream",
        "application/pdf",
        "application/zip",
    }:
        return MediaKind.BINARY
    if prefix:
        sample = prefix.lstrip()[:16].lower()
        if sample.startswith((b"{", b"[")):
            return MediaKind.JSON_API
        if sample.startswith((b"<!doctype html", b"<html")):
            return MediaKind.HTML
        if prefix.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"%PDF-")):
            return MediaKind.BINARY
    return MediaKind.UNKNOWN


def is_api_media(kind: str | MediaKind) -> bool:
    return str(kind) in {MediaKind.JSON_API.value, MediaKind.GRAPHQL.value}
