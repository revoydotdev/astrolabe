"""Shared security boundaries for capture and execution.

This module deliberately has no third-party dependencies so the standalone browser
helpers can import it on a capture host.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import tempfile
import urllib.parse as up
import zlib

try:
    from .payloads import decode_payload, PackagingError
except ImportError:  # flat capture-host deployment
    from payloads import decode_payload, PackagingError  # type: ignore[import-not-found,no-redef]
from collections.abc import Mapping
from typing import Any

REDACTED = "<redacted>"
_SENSITIVE_KEY = re.compile(
    r"authorization|cookie|token|secret|password|passwd|api[-_]?key|csrf|session|credential",
    re.I,
)
_CANARY_VALUE = re.compile(
    r"(?i)(?:bearer\s+)?[a-z0-9_=-]*(?:token|secret|password|passwd|session|credential)"
    r"[a-z0-9_=-]*",
)


class Secret(str):
    """A secret value whose display forms are always redacted.

    ``reveal`` is intentionally explicit; ordinary formatting, repr, and str never
    expose the underlying value.
    """

    _secret_value: str

    def __new__(cls, value: str) -> Secret:
        obj = super().__new__(cls, REDACTED)
        obj._secret_value = value
        return obj

    def __repr__(self) -> str:
        return REDACTED

    def reveal(self) -> str:
        return self._secret_value


def redact(value: Any, *, key: str | None = None, depth: int = 0) -> Any:
    """Recursively remove likely credentials before diagnostic serialization."""
    if depth > 12:
        return "<truncated>"
    if key and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, Secret):
        return REDACTED
    if isinstance(value, Mapping):
        return {str(k): redact(v, key=str(k), depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact(v, depth=depth + 1) for v in value]
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, str):
        # Values in error strings have no field name. Redact common credential
        # assignments and bearer tokens while preserving useful diagnostics.
        value = re.sub(r"(?i)bearer\s+[a-z0-9._~+/=-]+", "Bearer <redacted>", value)
        value = re.sub(
            r"(?i)((?:token|secret|password|passwd|api[-_]?key|session|credential)\s*[=:]\s*)"
            r"[^\s,;]+",
            r"\1<redacted>",
            value,
        )
        return value
    return value


def safe_text(value: Any) -> str:
    if isinstance(value, BaseException):
        value = str(value) or type(value).__name__
    cleaned = redact(value)
    return (
        cleaned
        if isinstance(cleaned, str)
        else json.dumps(cleaned, sort_keys=True, default=lambda item: type(item).__name__)
    )


def atomic_write_bytes(
    path: str | os.PathLike[str],
    data: bytes,
    *,
    mode: int = 0o644,
    retain_last_known_good: bool = True,
) -> None:
    """Standalone-safe durable replacement used by remote capture helpers."""
    target = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(target))
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{os.path.basename(target)}.", dir=directory)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if retain_last_known_good and os.path.isfile(target):
            backup = os.path.join(directory, f".{os.path.basename(target)}.lkg")
            with open(target, "rb") as source, open(backup, "wb") as output:
                output.write(source.read())
                output.flush()
                os.fsync(output.fileno())
            os.chmod(backup, mode)
        os.replace(temporary, target)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def atomic_write_json(path: str | os.PathLike[str], value: Any, *, mode: int = 0o644) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    json.loads(payload)
    atomic_write_bytes(path, payload, mode=mode)


def atomic_write_text(path: str | os.PathLike[str], value: str, *, mode: int = 0o644) -> None:
    atomic_write_bytes(path, value.encode(), mode=mode)


def normalize_host(host: str) -> str:
    """Return a canonical ASCII hostname, handling IP literals and IDNA."""
    candidate = host.strip().rstrip(".").lower()
    if not candidate or any(c in candidate for c in "\x00/\\@?#"):
        raise ValueError("invalid host")
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass
    labels = candidate.split(".")
    if any(not label for label in labels):
        raise ValueError("invalid host")
    try:
        encoded = ".".join(label.encode("idna").decode("ascii") for label in labels)
    except UnicodeError as exc:
        raise ValueError("malformed IDNA host") from exc
    if len(encoded) > 253 or any(len(label) > 63 for label in encoded.split(".")):
        raise ValueError("invalid host length")
    return encoded


def host_matches(host: str, allowed_host: str, *, allow_subdomains: bool = True) -> bool:
    """Canonical exact-host/domain-boundary predicate."""
    try:
        actual = normalize_host(host)
        allowed = normalize_host(allowed_host)
    except (TypeError, ValueError):
        return False
    return actual == allowed or (allow_subdomains and actual.endswith("." + allowed))


def is_first_party(url: str, allowed_host: str, *, allow_subdomains: bool = True) -> bool:
    try:
        parsed = up.urlsplit(url)
        host = parsed.hostname
        return bool(host and host_matches(host, allowed_host, allow_subdomains=allow_subdomains))
    except ValueError:
        return False


def safe_url(url: str, *, preserve_keys: frozenset[str] = frozenset({"alias"})) -> str:
    """Strip URL credentials, fragments, and query values before persistence/logging."""
    try:
        parsed = up.urlsplit(url)
        host = normalize_host(parsed.hostname or "")
        netloc = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            netloc += f":{parsed.port}"
        query = up.urlencode(
            [
                (key, value if key in preserve_keys else "<present>")
                for key, value in up.parse_qsl(parsed.query, keep_blank_values=True)
            ]
        )
        return up.urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", query, ""))
    except (TypeError, ValueError):
        return "<invalid-url>"


def _blocked_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    return not ip.is_global


def resolve_public_addresses(host: str, port: int) -> tuple[str, ...]:
    """Resolve once and fail unless every answer is globally routable."""
    canonical = normalize_host(host)
    answers = socket.getaddrinfo(canonical, port, type=socket.SOCK_STREAM)
    addresses = tuple(sorted({str(item[4][0]) for item in answers}))
    if not addresses or any(_blocked_address(address) for address in addresses):
        raise ValueError("DNS resolved to a private or special-use address")
    return addresses


def validate_url(
    url: str,
    allowed_hosts: set[str] | frozenset[str],
    *,
    allow_subdomains: bool = True,
    schemes: tuple[str, ...] = ("https",),
    resolve: bool = False,
) -> str:
    """Validate a request target before attaching credentials.

    Returns a normalized URL. When ``resolve`` is true, every current DNS answer
    must be globally routable; callers still disable redirects so each new target
    is independently revalidated.
    """
    if not isinstance(url, str) or "\r" in url or "\n" in url:
        raise ValueError("invalid URL")
    try:
        parsed = up.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("malformed URL") from exc
    if parsed.scheme.lower() not in schemes:
        raise ValueError(f"scheme must be one of {schemes}")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must have a host and no userinfo")
    if parsed.fragment:
        raise ValueError("request URL must not contain a fragment")
    host = normalize_host(parsed.hostname)
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("localhost destination denied")
    if not any(
        host_matches(host, allowed, allow_subdomains=allow_subdomains) for allowed in allowed_hosts
    ):
        raise ValueError("destination is outside the allowed origin set")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid port")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and _blocked_address(str(literal)):
        raise ValueError("private or special-use destination denied")
    if resolve:
        resolve_public_addresses(host, port or 443)
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = parsed.path or "/"
    # Preserve encoded path semantics but reject browser/shell ambiguity.
    if "\\" in path or any(seg == ".." for seg in up.unquote(path).split("/")):
        raise ValueError("path traversal denied")
    return up.urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def structural_shape(
    value: Any,
    *,
    max_depth: int = 8,
    max_nodes: int = 1000,
    max_keys: int = 200,
    max_array_samples: int = 8,
    counters: dict[str, int] | None = None,
) -> Any:
    """Return a value-free shape with explicit, counted budget truncation markers."""
    counts = counters if counters is not None else {}
    nodes = 0

    def truncated(reason: str, omitted: int | None = None) -> dict[str, Any]:
        counts[reason] = counts.get(reason, 0) + 1
        detail: dict[str, Any] = {"reason": reason}
        if omitted is not None:
            detail["omitted"] = max(omitted, 0)
        return {"$astrolabe_truncated": detail}

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes:
            return truncated("node_budget")
        if depth > max_depth:
            return truncated("depth_budget")
        if isinstance(item, Mapping):
            keys = list(item)
            shaped = {str(key): visit(item[key], depth + 1) for key in keys[:max_keys]}
            if len(keys) > max_keys:
                shaped["$astrolabe_truncated"] = {
                    "reason": "key_budget",
                    "omitted": len(keys) - max_keys,
                }
                counts["key_budget"] = counts.get("key_budget", 0) + 1
            return shaped
        if isinstance(item, (list, tuple)):
            if not item:
                return []
            samples = []
            signatures: set[str] = set()
            for member in item:
                candidate = visit(member, depth + 1)
                signature = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
                if signature in signatures:
                    continue
                signatures.add(signature)
                samples.append(candidate)
                if len(samples) >= max_array_samples:
                    if len(signatures) < len(item):
                        samples.append(
                            truncated("array_sample_budget", len(item) - len(signatures))
                        )
                    break
            return samples
        if item is None:
            return "null"
        return type(item).__name__

    return visit(value, 0)


def _decode_bounded(raw: bytes, content_encoding: str, max_body_bytes: int) -> tuple[bytes, bool]:
    encoding = content_encoding.lower().strip()
    if not encoding or encoding == "identity":
        return raw[:max_body_bytes], len(raw) > max_body_bytes
    if encoding in {"gzip", "x-gzip"}:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decoded = decoder.decompress(raw, max_body_bytes + 1)
        return decoded[:max_body_bytes], len(decoded) > max_body_bytes or not decoder.eof
    if encoding == "deflate":
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(raw, max_body_bytes + 1)
        return decoded[:max_body_bytes], len(decoded) > max_body_bytes or not decoder.eof
    return b"", True


def _multipart_shape(raw: bytes) -> dict[str, str]:
    names = re.findall(rb'(?i)content-disposition:[^\r\n]*\bname="([^"]{1,200})"', raw)
    return {name.decode("utf-8", "replace"): "field" for name in names[:200]}


def request_metadata(
    body: Any,
    media_type: str = "",
    *,
    content_encoding: str = "",
    fingerprint_key: bytes | None = None,
    max_body_bytes: int = 2_000_000,
    shape_counters: dict[str, int] | None = None,
    shape_limits: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Return bounded structural request metadata without retaining values."""
    if body is None:
        return {}
    raw = body if isinstance(body, bytes) else str(body).encode("utf-8", "replace")
    result: dict[str, Any] = {
        "request_media_type": media_type.split(";", 1)[0].strip().lower(),
        "request_bytes": len(raw),
    }
    if content_encoding:
        result["request_content_encoding"] = content_encoding.lower()
    decoded, body_truncated = _decode_bounded(raw, content_encoding, max_body_bytes)
    if body_truncated:
        counters = shape_counters if shape_counters is not None else {}
        counters["body_byte_budget"] = counters.get("body_byte_budget", 0) + 1
        result["request_truncated"] = {"reason": "body_byte_budget"}
    parsed: Any = None
    try:
        payload = decode_payload(
            raw, media_type=media_type, content_encoding=content_encoding, max_bytes=max_body_bytes
        )
        parsed = payload.value
        result["request_packaging"] = list(payload.layers)
    except Exception:
        if "multipart/form-data" in media_type:
            parsed = _multipart_shape(decoded)
        elif "application/x-www-form-urlencoded" in media_type:
            parsed = {key: value for key, value in up.parse_qsl(decoded.decode("utf-8", "replace"))}
    if parsed is not None:
        result["request_shape"] = structural_shape(
            parsed,
            counters=shape_counters,
            **(shape_limits or {}),
        )
        if isinstance(parsed, dict):
            result["request_fields"] = sorted(str(k) for k in parsed)[:100]
        elif isinstance(parsed, list):
            result["request_fields"] = sorted(
                {str(k) for item in parsed if isinstance(item, dict) for k in item}
            )[:100]
    else:
        result["request_shape"] = "bytes"
    key = fingerprint_key or os.environ.get("ASTROLABE_FINGERPRINT_KEY", "").encode()
    if key:
        result["request_fingerprint"] = hmac.new(key, raw, hashlib.sha256).hexdigest()
    return result
