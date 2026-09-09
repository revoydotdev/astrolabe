"""Client-computed request attestation headers.

Finding: x.com's `SearchTimeline` GraphQL operation replays as HTTP 404 with an
empty body even though its queryId, URL, and captured variables all match a live
200 -- the only remaining difference is `x-client-transaction-id`, a header value
computed by client-side JavaScript on every request. It cannot be replayed by
copying the captured value (it is per-request, not per-session) and it cannot be
derived from cookies or static config the way `x-csrf-token` can (that one just
mirrors the `ct0` cookie, so it is NOT an attestation header).

Astrolabe has no way today to represent "this operation needs a header a replayer
cannot compute". Without that concept the generator ships a tool that looks fine
and 404s at call time. This module gives the generator and validator a pure,
backend-agnostic way to recognize the condition and gate exposure on it, instead
of exposing a broken tool. It knows nothing about x.com specifically or about how
astrolabe's IR, generator, or validator are shaped -- callers own the wiring.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable
from dataclasses import dataclass
from enum import StrEnum
import re

# Header names independently confirmed to be computed client-side, per request,
# from inputs a replayer does not have (DOM/runtime state, not cookies or static
# config). A match here is high confidence: keep this set small and cited.
CURATED_ATTESTATION_HEADERS: frozenset[str] = frozenset(
    {
        # x.com (Twitter): opaque value computed by obfuscated client JS per
        # request; distinct even for identical queryId/variables/session.
        # Verified by direct replay: HomeTimeline (no header enforcement
        # observed) returns 200, SearchTimeline (enforced) returns 404 with an
        # empty body when replayed with a stale captured value.
        "x-client-transaction-id",
    }
)

# Deliberately excluded, and why -- kept here so nobody re-adds them later:
#   x-csrf-token       -- mirrors the `ct0` cookie; derivable, not computed.
#   x-guest-token      -- issued by the server and cookie/session scoped.
#   x-twitter-*-id     -- static client identifiers, not per-request proofs.
#   authorization      -- ordinary bearer auth, already modeled elsewhere.
#   accept / user-agent -- content negotiation / static identification.

# Conservative name patterns for hosts we have no curated knowledge of. A match
# is a *candidate* only: low confidence, meant to prompt investigation, never
# treated as equivalent to a curated match.
_HEURISTIC_NAME_PATTERN = re.compile(
    r"transaction|nonce|signature|attestation|checksum|proof[-_]?of[-_]?work",
    re.IGNORECASE,
)


class AttestationConfidence(StrEnum):
    CURATED = "curated"
    HEURISTIC = "heuristic"


@dataclass(frozen=True)
class AttestationRequirement:
    """What was found: which headers, how confidently, and why it matters."""

    header_names: frozenset[str]
    confidence: AttestationConfidence
    reason: str


def _normalized(header_names: Iterable[str] | None) -> frozenset[str]:
    if not header_names:
        return frozenset()
    return frozenset(name.strip().lower() for name in header_names if name and name.strip())


def attestation_requirement(header_names: Iterable[str] | None) -> AttestationRequirement | None:
    """Classify a set of observed request header names.

    Returns None when nothing suspicious is present. A curated match takes
    priority over a heuristic one; the two confidence levels are never merged
    into a single requirement, since a heuristic name mixed into a curated
    finding would silently overstate its confidence.
    """
    names = _normalized(header_names)
    if not names:
        return None

    curated_hits = frozenset(name for name in names if name in CURATED_ATTESTATION_HEADERS)
    if curated_hits:
        return AttestationRequirement(
            header_names=curated_hits,
            confidence=AttestationConfidence.CURATED,
            reason=(
                "requires client-computed header "
                f"{_format_names(curated_hits)}; no replay adapter is registered"
            ),
        )

    heuristic_hits = frozenset(name for name in names if _HEURISTIC_NAME_PATTERN.search(name))
    if heuristic_hits:
        return AttestationRequirement(
            header_names=heuristic_hits,
            confidence=AttestationConfidence.HEURISTIC,
            reason=(
                "header name suggests a client-computed attestation "
                f"{_format_names(heuristic_hits)}; unconfirmed, no replay adapter is registered"
            ),
        )

    return None


def is_satisfied(requirement: AttestationRequirement | None, adapters: Collection[str]) -> bool:
    """True when every required header is covered by a registered adapter name.

    With no requirement there is nothing to satisfy. With no adapters, any real
    requirement is unsatisfied -- fail closed rather than assume coverage.
    """
    if requirement is None:
        return True
    if not adapters:
        return False
    registered = frozenset(name.strip().lower() for name in adapters if name and name.strip())
    return requirement.header_names.issubset(registered)


def _format_names(names: frozenset[str]) -> str:
    return ", ".join(f"'{name}'" for name in sorted(names))
