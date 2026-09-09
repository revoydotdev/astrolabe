"""Bounded, non-executing decoding of common reversible API payload packaging.

Decoding is transport evidence, never proof that an operation is safe to execute.
HTTP clients normally remove Brotli/Zstd content encoding before this layer.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import io
import json
import lzma
import re
import urllib.parse
import zipfile
import zlib
from dataclasses import dataclass
from typing import Any


class PackagingError(ValueError):
    """An unsupported, malformed, or over-budget payload; never includes values."""


@dataclass(frozen=True)
class DecodedPayload:
    value: Any
    layers: tuple[str, ...]


def _inflate(raw: bytes, mode: int, limit: int) -> bytes:
    decoder = zlib.decompressobj(mode)
    value = decoder.decompress(raw, limit + 1)
    if len(value) > limit or not decoder.eof or decoder.unused_data:
        raise PackagingError("compressed payload is incomplete, concatenated, or over budget")
    return value


def decode_payload(
    raw: bytes,
    *,
    media_type: str = "",
    content_encoding: str = "",
    max_bytes: int = 2_000_000,
    max_layers: int = 8,
) -> DecodedPayload:
    """Decode complete structured values with bounded bytes, depth, and expansion.

    Never evaluate JavaScript, extract archives to disk, recurse into object fields,
    or infer encryption keys. A string is unwrapped only when it ultimately yields
    an object/list; ordinary JSON scalar strings retain their original meaning.
    """
    if len(raw) > max_bytes or max_bytes <= 0 or max_layers <= 0:
        raise PackagingError("payload exceeds decoding budget")
    layers: list[str] = []
    cumulative = 0
    scalar: Any = None
    have_scalar = False
    explicit = [e.strip().lower() for e in content_encoding.split(",") if e.strip()]
    while len(layers) < max_layers:
        cumulative += len(raw)
        if len(raw) > max_bytes or cumulative > max_bytes * 4:
            raise PackagingError("payload exceeds decoding budget")
        encoding = explicit.pop() if explicit else ""
        try:
            if encoding == "identity":
                continue
            if raw.startswith(b"\x1f\x8b") or encoding in {"gzip", "x-gzip"}:
                raw = _inflate(raw, 16 + zlib.MAX_WBITS, max_bytes)
                layers.append("gzip")
                continue
            if encoding == "deflate" or (
                len(raw) >= 2 and raw[0] & 15 == 8 and (raw[0] * 256 + raw[1]) % 31 == 0
            ):
                try:
                    raw = _inflate(raw, zlib.MAX_WBITS, max_bytes)
                except zlib.error:
                    if encoding != "deflate":
                        raise
                    raw = _inflate(raw, -zlib.MAX_WBITS, max_bytes)
                layers.append("deflate")
                continue
            if encoding:
                raise PackagingError("unsupported content encoding")
            if raw.startswith(b"BZh"):
                bz = bz2.BZ2Decompressor()
                raw = bz.decompress(raw, max_length=max_bytes + 1)
                if not bz.eof or bz.unused_data or len(raw) > max_bytes:
                    raise PackagingError("bzip2 payload exceeds budget or is incomplete")
                layers.append("bzip2")
                continue
            if raw.startswith(b"\xfd7zXZ\x00"):
                xz = lzma.LZMADecompressor(memlimit=32 * 1024 * 1024)
                raw = xz.decompress(raw, max_length=max_bytes + 1)
                if not xz.eof or xz.unused_data or len(raw) > max_bytes:
                    raise PackagingError("xz payload exceeds budget or is incomplete")
                layers.append("xz")
                continue
            if raw.startswith(b"PK\x03\x04"):
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    entries = archive.infolist()
                    if len(entries) != 1 or entries[0].is_dir() or entries[0].flag_bits & 1:
                        raise PackagingError("archive must contain one unencrypted payload")
                    if entries[0].file_size > max_bytes:
                        raise PackagingError("archive exceeds byte budget")
                    with archive.open(entries[0]) as member:
                        raw = member.read(max_bytes + 1)
                layers.append("zip-single-entry")
                continue
            text = raw.decode("utf-8-sig").strip()
            try:
                value = json.loads(text)
            except (ValueError, RecursionError):
                value = None
            else:
                if isinstance(value, str):
                    if not have_scalar:
                        scalar, have_scalar = value, True
                    raw = value.encode("utf-8")
                    layers.append("json-string")
                    continue
                if have_scalar and not isinstance(value, (dict, list)):
                    return DecodedPayload(scalar, ())
                return DecodedPayload(value, tuple([*layers, "json"]))
            # Strip only known anti-XSSI guards, never arbitrary executable prefixes.
            guard = next(
                (
                    p
                    for p in (")]}'", "for(;;);", "for (;;);", "while(1);", "while (1);")
                    if text.startswith(p)
                ),
                None,
            )
            if guard:
                raw = text[len(guard) :].lstrip(",\r\n ").encode()
                layers.append("xssi-guard")
                continue
            callback = re.fullmatch(
                r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*\((.*)\)\s*;?", text, re.S
            )
            if callback:
                raw = callback.group(1).encode()
                layers.append("jsonp")
                continue
            if media_type.lower().startswith("multipart/mixed"):
                match = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', media_type, re.I)
                if not match or len(match.group(1) or match.group(2)) > 200:
                    raise PackagingError("multipart boundary missing or invalid")
                boundary = ("--" + (match.group(1) or match.group(2))).encode()
                parts = raw.split(boundary)
                if len(parts) > 66 or not parts[-1].strip().startswith(b"--"):
                    raise PackagingError("multipart stream is incomplete or over budget")
                values = []
                for part in parts[1:-1]:
                    _, separator, body = part.lstrip(b"\r\n").partition(b"\r\n\r\n")
                    if not separator:
                        raise PackagingError("multipart part lacks header boundary")
                    values.append(json.loads(body.strip()))
                if not values:
                    raise PackagingError("multipart stream has no JSON parts")
                # Preserve incremental parts. Do not manufacture a merged GraphQL result.
                return DecodedPayload(values, tuple([*layers, "multipart-json"]))
            lines = text.splitlines()
            if 1 < len(lines) <= 256:
                try:
                    values = [json.loads(line) for line in lines if line.strip()]
                    if all(isinstance(v, (dict, list)) for v in values):
                        return DecodedPayload(values, tuple([*layers, "ndjson"]))
                except (ValueError, RecursionError):
                    pass
            if re.match(r"^(?:%7[bB]|%5[bB]|%22)", text):
                raw = urllib.parse.unquote_to_bytes(text)
                layers.append("percent-encoding")
                continue
            if len(text) >= 4 and len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
                raw = bytes.fromhex(text)
                layers.append("hex")
                continue
            if len(text) >= 4 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", text):
                raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
                layers.append("base64")
                continue
            raise PackagingError("unsupported payload packaging")
        except PackagingError:
            if have_scalar:
                return DecodedPayload(scalar, ())
            raise
        except (
            ValueError,
            OSError,
            EOFError,
            zlib.error,
            lzma.LZMAError,
            binascii.Error,
            zipfile.BadZipFile,
            RecursionError,
        ) as exc:
            if have_scalar:
                return DecodedPayload(scalar, ())
            raise PackagingError("malformed or unsupported packaged payload") from exc
    if have_scalar:
        return DecodedPayload(scalar, ())
    raise PackagingError("payload exceeds layer budget")
