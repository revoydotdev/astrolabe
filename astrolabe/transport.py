"""Shared HTTP retry policy: which statuses are worth retrying, and how long to wait.

A leaf module with no astrolabe imports, deliberately. ``replay`` documents itself
as stdlib + curl_cffi so it can run on a bare capture host, and ``storefront`` is a
standalone capture module; neither can afford to import the MCP facade. What they
can all afford is one copy of this arithmetic, because two copies is how two tiers
end up disagreeing about what a 429 means -- one hammering a rate-limited origin
while the other waits.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

# A status is retryable when the same request could plausibly succeed later:
# the origin asked us to wait (429), is timing us out (408), or is briefly broken
# (5xx). Everything else -- 401/403/404/422 -- is a verdict about the request
# itself, and repeating it only spends the caller's rate-limit budget to be told
# the same thing.
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

MAX_DELAY_SECONDS = 5.0
MAX_BACKOFF_SECONDS = 2.0
JITTER_SECONDS = 0.1


def retry_delay(attempt: int, retry_after: str | None) -> float:
    """Seconds to wait before ``attempt`` + 1.

    An origin-supplied ``Retry-After`` wins over our own schedule and is clamped
    to MAX_DELAY_SECONDS so a hostile or absurd header cannot pin a capture host
    for an hour. Without one, exponential backoff with jitter, capped at
    MAX_BACKOFF_SECONDS.

    The jitter is the point of sharing this: several collectors hitting one
    rate-limited origin on the same schedule stay synchronised, which is how a
    polite client becomes a thundering herd.
    """
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), MAX_DELAY_SECONDS)
        except ValueError:
            try:
                when = parsedate_to_datetime(retry_after)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=UTC)
                return min(max((when - datetime.now(UTC)).total_seconds(), 0.0), MAX_DELAY_SECONDS)
            except (TypeError, ValueError, OverflowError):
                pass
    return min(0.2 * (2**attempt) + random.uniform(0, JITTER_SECONDS), MAX_BACKOFF_SECONDS)


def retry_after_header(response: object) -> str | None:
    """The raw ``Retry-After`` value on a response, or None.

    Defensive on purpose: responses reaching this code may be a live
    curl_cffi/requests response, a test fake, or a bare exception object, and a
    retry helper that raises while inspecting headers is worse than one that
    falls back to its own schedule.
    """
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        value = headers.get("retry-after")
    except AttributeError:
        return None
    return value if isinstance(value, str) else None
