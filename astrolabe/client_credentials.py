"""Locating the static client credential a single-page app ships in its own bundle.

Many first-party APIs authenticate with two things: the user's session cookies and a
*static public client credential* the application embeds in its JavaScript — an API key
or a bearer that is identical for every visitor. A capture deliberately never persists
header values, so a generated contract knows it needs an `authorization` header but not
where that value comes from. The operator is then left reverse-engineering the bundle by
hand before anything can be replayed, which is exactly the manual step the contract is
supposed to remove.

This module records the *requirement and its provenance*, never the secret: which key
held it, which script it came from, how long it was, and a digest of it. A digest lets a
later run confirm that the credential an operator supplied is the one the application
actually ships, and lets a re-capture notice the value rotated, without the credential
ever entering an artifact.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
from typing import Any

# Identifiers that hold a client credential in shipped application code. Matched against
# the key an opaque literal is assigned to, never against the literal itself, so a long
# random-looking string only counts when the application itself calls it a credential.
#
# The whole key must match. A substring match reads any identifier merely containing a
# credential word as a credential: `SetupPublicKeyCredential` is a WebAuthn operation
# whose value is a persisted query id, not a secret. `public_key` is excluded outright
# for the same reason — in a browser bundle it names WebAuthn, not an API credential.
_CREDENTIAL_KEY = re.compile(
    rb"(x[_-]?)?(authorization|bearer([_-]?token)?|api[_-]?key|client[_-]?(key|token|secret)|"
    rb"access[_-]?token|app[_-]?(id|key|token)|subscription[_-]?key|auth[_-]?token)",
    re.IGNORECASE,
)

# `key: "value"` / `key = "value"` / `"key": "value"`, tolerating minified spacing.
_ASSIGNMENT = re.compile(
    rb"[\"']?([A-Za-z_$][A-Za-z0-9_$-]{2,40})[\"']?\s*[:=]\s*[\"']([A-Za-z0-9+/=._~%-]{20,512})[\"']"
)

# A complete `Bearer <token>` literal in shipped application code. Minified bundles
# routinely hold the credential in an anonymous constant the key-name rule cannot see
# (x.com ships `()=>"Bearer AAAA…"`), but the scheme prefix identifies it on its own: a
# bearer written as a literal in code every visitor downloads is a static client
# credential by construction, never a user's session token.
_BEARER_LITERAL = re.compile(rb"[\"']Bearer\s+([A-Za-z0-9+/=._~%-]{20,512})[\"']")

# Below this length a literal is a label or an identifier, not a credential.
MIN_CREDENTIAL_LENGTH = 20
MAX_SITES_PER_SCRIPT = 32
# A whole capture records a bounded set: a contract needs the credential's location,
# not an inventory of every opaque literal a large bundle happens to contain.
MAX_SITES_PER_CAPTURE = 64


@dataclass(frozen=True)
class ClientCredentialSite:
    """Where a static client credential lives, and what it is — never the value."""

    key: str
    source_url: str
    source_sha256: str
    value_sha256: str
    value_length: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def discover(body: bytes, source_url: str) -> list[ClientCredentialSite]:
    """Find static client credentials a script embeds, recording provenance only."""
    if not body:
        return []
    source_sha256 = hashlib.sha256(body).hexdigest()
    seen: dict[tuple[str, str], ClientCredentialSite] = {}
    candidates = [(b"authorization", match.group(1)) for match in _BEARER_LITERAL.finditer(body)]
    candidates += [
        (match.group(1), match.group(2))
        for match in _ASSIGNMENT.finditer(body)
        if _CREDENTIAL_KEY.fullmatch(match.group(1))
    ]
    for key, value in candidates:
        if len(value) < MIN_CREDENTIAL_LENGTH:
            continue
        decoded_key = key.decode("utf-8", "replace")
        digest = hashlib.sha256(value).hexdigest()
        seen.setdefault(
            (decoded_key, digest),
            ClientCredentialSite(
                key=decoded_key,
                source_url=source_url,
                source_sha256=source_sha256,
                value_sha256=digest,
                value_length=len(value),
            ),
        )
        if len(seen) >= MAX_SITES_PER_SCRIPT:
            break
    return [seen[key] for key in sorted(seen)]


def matches(site: dict[str, Any], candidate: str) -> bool:
    """True when a supplied credential is the one the application ships.

    Compares digests so an operator can prove they hold the right value without the
    artifact ever having stored it.
    """
    if not candidate or not isinstance(site, dict):
        return False
    expected = str(site.get("value_sha256") or "")
    return bool(expected) and hashlib.sha256(candidate.encode("utf-8")).hexdigest() == expected
