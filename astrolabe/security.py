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
import sys
import tempfile
import urllib.parse as up
import zlib

try:
    from .payloads import DecodedPayload, decode_payload
except ImportError:  # flat capture-host deployment
    from payloads import DecodedPayload, decode_payload  # type: ignore[import-not-found,no-redef]
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

# Headers a caller may never set: connection framing, the cookie jar (which would
# silently replace the credential the operator configured), and host routing.
DENIED_HEADERS = frozenset({"connection", "content-length", "cookie", "host", "transfer-encoding"})


def redact(value: Any, *, key: str | None = None, depth: int = 0) -> Any:
    """Recursively remove likely credentials before diagnostic serialization."""
    if depth > 12:
        return "<truncated>"
    if key and _SENSITIVE_KEY.search(key):
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


# Browser egress policy: what the capture browser may fetch outside the target's own
# domain. A real page pulls third-party subresources (CDNs, analytics, auth widgets) and
# blocking them breaks sites, so allowing them is the default -- but "allowed" used to
# mean merely unrecorded, with nothing naming the choice. Operator config only: a tool
# argument must never be able to widen what the browser reaches.
EGRESS_ALLOW_THIRD_PARTY = "allow-third-party"
EGRESS_FIRST_PARTY_ONLY = "first-party-only"
EGRESS_POLICIES = (EGRESS_ALLOW_THIRD_PARTY, EGRESS_FIRST_PARTY_ONLY)
EGRESS_ENV = "ASTROLABE_BROWSER_EGRESS"


def egress_policy() -> str:
    """The operator's egress policy, or the default when unset.

    An unrecognized value is an error rather than a silent fallback: a typo that quietly
    left the permissive policy in place would report a control the run does not have.
    """
    raw = (os.environ.get(EGRESS_ENV) or "").strip().lower()
    if not raw:
        return EGRESS_ALLOW_THIRD_PARTY
    if raw not in EGRESS_POLICIES:
        raise ValueError(f"{EGRESS_ENV} must be one of {list(EGRESS_POLICIES)}, not {raw!r}")
    return raw


def third_party_egress(*, policy: str, recipe_active: bool) -> tuple[bool, str | None]:
    """Decide a request to a non-first-party origin: (abort, truncation reason or None).

    Returns ``abort=False`` for the permissive policy, which still never records the
    request: allowed and recorded are deliberately different things.
    """
    if recipe_active:
        return True, "recipe-egress-policy"
    if policy == EGRESS_FIRST_PARTY_ONLY:
        return True, "egress-policy"
    return False, None


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


# Capture fidelity: how much of each request/response value a chart retains. The
# data-visibility boundary used to be binary -- blank every value to a type name,
# or (ASTROLABE_DEVELOPER_MODE) retain everything including raw tokens and pull the
# HAR + cookie jar into the chart dir. That binary made the default useless to the
# agent that produced the chart: it could not read the data it had just mapped. The
# three levels below replace it.
#   shape  -- value-free structural shapes only (type names). The original boundary;
#             still available for sharing a chart whose data must not leave the host.
#   values -- retain primitive values but mask credentials by field name/pattern
#             (cookie, token, authorization, secret, session, ...). The default:
#             the mapped data is readable, auth material is not written to disk.
#   raw    -- retain everything verbatim, no redaction, and (via the CLI) pull the
#             full HAR + cookies.json + auth.headers.json into the chart dir. The
#             chart dir becomes a live credential artifact. Opt-in footgun only.
CAPTURE_SHAPE = "shape"
CAPTURE_VALUES = "values"
CAPTURE_RAW = "raw"
CAPTURE_FIDELITIES = (CAPTURE_SHAPE, CAPTURE_VALUES, CAPTURE_RAW)
CAPTURE_FIDELITY_ENV = "ASTROLABE_CAPTURE_FIDELITY"


def capture_fidelity() -> str:
    """Resolve the capture fidelity level, honoring the legacy developer-mode flag.

    Unset defaults to ``shape``: the value-free boundary still holds for every
    library caller, the legacy capture sanitizer, and any command that does not opt
    in. The agent-facing ``map`` entrypoint sets ``ASTROLABE_CAPTURE_FIDELITY=values``
    for its own capture subprocess (``mapping_mcp``), so an agent reads the surface it
    just mapped while nothing else changes. ``ASTROLABE_CAPTURE_FIDELITY`` selects a
    level explicitly; the legacy ``ASTROLABE_DEVELOPER_MODE=1`` still means ``raw``.
    An unrecognized value is an error rather than a silent fallback, matching
    ``egress_policy()`` -- a typo must not quietly change what lands on disk.
    """
    raw_env = (os.environ.get(CAPTURE_FIDELITY_ENV) or "").strip().lower()
    if raw_env:
        if raw_env not in CAPTURE_FIDELITIES:
            raise ValueError(
                f"{CAPTURE_FIDELITY_ENV} must be one of {list(CAPTURE_FIDELITIES)}, not {raw_env!r}"
            )
        return raw_env
    if os.environ.get("ASTROLABE_DEVELOPER_MODE"):
        return CAPTURE_RAW
    return CAPTURE_SHAPE


def retain_values() -> bool:
    """True when captured primitive values are kept (``values`` or ``raw``)."""
    return capture_fidelity() in (CAPTURE_VALUES, CAPTURE_RAW)


def retain_raw() -> bool:
    """True only in ``raw`` mode: no redaction, credential artifacts pulled to disk."""
    return capture_fidelity() == CAPTURE_RAW


# Back-compat alias for call sites that gate the raw credential-dump path.
DEVELOPER_MODE = retain_raw()
if retain_raw():
    print(
        "\n!!! astrolabe capture fidelity = raw !!!\n"
        "    request and response bodies retain their values verbatim (PII + tokens).\n"
        "    the full HAR + cookies.json + auth.headers.json will be pulled into the chart dir.\n"
        "    the chart dir is now a credential artifact. treat it as such.\n",
        file=sys.stderr,
    )


def structural_shape(
    value: Any,
    *,
    max_depth: int = 8,
    max_nodes: int = 1000,
    max_keys: int = 200,
    max_array_samples: int = 8,
    counters: dict[str, int] | None = None,
    fidelity: str | None = None,
) -> Any:
    """Return a shape with explicit, counted budget truncation markers.

    The same budget traversal runs at every fidelity level; what differs is whether
    leaf primitives keep their values:

    * ``shape``  -- primitives collapse to their type name (``"str"``, ``"int"`` ...).
    * ``values`` -- primitives keep their value, but any value under a credential-ish
      key (cookie, token, authorization, secret, session ...) is replaced with
      ``<redacted>`` and its subtree is pruned, and free-standing bearer/``key=value``
      secrets inside string leaves are scrubbed. This is the default.
    * ``raw``    -- primitives keep their value verbatim, no redaction.

    ``fidelity`` defaults to the process-wide ``capture_fidelity()`` and is resolved
    once per call (not per node), so callers that need a fixed level -- the legacy
    capture sanitizer forcing ``shape`` -- pass it explicitly.
    """
    level = fidelity or capture_fidelity()
    retain = level in (CAPTURE_VALUES, CAPTURE_RAW)
    redacting = level == CAPTURE_VALUES
    counts = counters if counters is not None else {}
    nodes = 0

    def truncated(reason: str, omitted: int | None = None) -> dict[str, Any]:
        counts[reason] = counts.get(reason, 0) + 1
        detail: dict[str, Any] = {"reason": reason}
        if omitted is not None:
            detail["omitted"] = max(omitted, 0)
        return {"$astrolabe_truncated": detail}

    def visit(item: Any, depth: int, key: str | None = None) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes:
            return truncated("node_budget")
        if depth > max_depth:
            return truncated("depth_budget")
        if redacting and key and _SENSITIVE_KEY.search(key):
            # Prune the whole subtree under a credential-ish key: never enumerate a
            # cookie jar or token object, even its structure.
            return REDACTED
        if isinstance(item, Mapping):
            keys = list(item)
            shaped = {str(k): visit(item[k], depth + 1, str(k)) for k in keys[:max_keys]}
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
                candidate = visit(member, depth + 1, key)
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
            return None if retain else "null"
        if retain:
            # Scrub bearer tokens and inline `secret=...` assignments that sit inside
            # free-text string leaves (an error message, a redirect URL). A value under
            # a credential-ish key was already pruned above.
            if redacting and isinstance(item, str):
                return redact(item)
            return item
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
    decoded_payload: DecodedPayload | None = None,
    fidelity: str | None = None,
) -> dict[str, Any]:
    """Return bounded structural request metadata.

    At the default ``values`` fidelity the structural shape keeps primitive values
    with credentials masked; ``fidelity="shape"`` forces the value-free boundary (the
    legacy capture sanitizer relies on this). See ``structural_shape``.

    `decoded_payload` is what a caller that already ran `decode_payload` on these same
    bytes hands back, so a body is inflated once per request instead of once here and
    again at the call site. None means "not decoded yet", so callers without one keep
    working unchanged.
    """
    if body is None:
        return {}
    raw = body if isinstance(body, bytes) else str(body).encode("utf-8", "replace")
    result: dict[str, Any] = {
        "request_media_type": media_type.split(";", 1)[0].strip().lower(),
        "request_bytes": len(raw),
    }
    if content_encoding:
        result["request_content_encoding"] = content_encoding.lower()
    parsed: Any = None

    def mark_body_budget() -> None:
        counters = shape_counters if shape_counters is not None else {}
        counters["body_byte_budget"] = counters.get("body_byte_budget", 0) + 1
        result["request_truncated"] = {"reason": "body_byte_budget"}

    try:
        payload = (
            decoded_payload
            if decoded_payload is not None
            else decode_payload(
                raw,
                media_type=media_type,
                content_encoding=content_encoding,
                max_bytes=max_body_bytes,
            )
        )
        if "," in content_encoding:
            # A multi-coded content-encoding has always counted against the body budget,
            # because _decode_bounded reads the whole header as one coding. decode_payload
            # unwraps the list instead, so the decode succeeds and that count would
            # otherwise stop happening.
            mark_body_budget()
        parsed = payload.value
        result["request_packaging"] = list(payload.layers)
    except Exception:
        # Only the non-JSON fallbacks below need inflated bytes, and every other
        # over-budget or undecodable body still lands here, so the bounded inflate
        # runs only when the decode could not be trusted to have bounded it.
        decoded, body_truncated = _decode_bounded(raw, content_encoding, max_body_bytes)
        if body_truncated:
            mark_body_budget()
        if "multipart/form-data" in media_type:
            parsed = _multipart_shape(decoded)
        elif "application/x-www-form-urlencoded" in media_type:
            parsed = {key: value for key, value in up.parse_qsl(decoded.decode("utf-8", "replace"))}
    if parsed is not None:
        shape_kwargs: dict[str, Any] = {"counters": shape_counters, "fidelity": fidelity}
        shape_kwargs.update(shape_limits or {})
        result["request_shape"] = structural_shape(parsed, **shape_kwargs)
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
