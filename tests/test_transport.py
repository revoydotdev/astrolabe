"""Tests for the shared retry policy in astrolabe.transport.

The policy is now consulted by three tiers (sextant, storefront, replay), so
these assert the arithmetic and the classification rather than any one caller's
use of them.
"""

from __future__ import annotations

from astrolabe.transport import (
    MAX_BACKOFF_SECONDS,
    MAX_DELAY_SECONDS,
    RETRYABLE_STATUS,
    retry_after_header,
    retry_delay,
)


class FakeResponse:
    def __init__(self, headers=None):
        self.headers = headers


def test_numeric_retry_after_is_honoured_exactly():
    assert retry_delay(0, "1.5") == 1.5


def test_retry_after_is_clamped_at_the_ceiling():
    assert retry_delay(0, "86400") == MAX_DELAY_SECONDS


def test_negative_retry_after_clamps_to_zero_rather_than_sleeping_backwards():
    assert retry_delay(0, "-30") == 0.0


def test_http_date_retry_after_is_parsed():
    assert retry_delay(0, "Wed, 21 Oct 2099 07:28:00 GMT") == MAX_DELAY_SECONDS


def test_naive_http_date_retry_after_is_read_as_utc():
    assert retry_delay(0, "Wed, 21 Oct 2099 07:28:00") == MAX_DELAY_SECONDS


def test_past_http_date_retry_after_floors_at_zero():
    assert retry_delay(0, "Wed, 21 Oct 1997 07:28:00 GMT") == 0.0


def test_unparseable_retry_after_falls_back_to_own_schedule():
    for attempt in (0, 1, 2):
        delay = retry_delay(attempt, "not-a-date-or-number")
        assert 0.0 <= delay <= MAX_BACKOFF_SECONDS


def test_backoff_grows_exponentially_and_stays_capped():
    first = retry_delay(0, None)
    second = retry_delay(1, None)
    assert first <= second <= MAX_BACKOFF_SECONDS
    assert retry_delay(30, None) <= MAX_BACKOFF_SECONDS


def test_backoff_is_jittered_not_deterministic():
    delays = {retry_delay(3, None) for _ in range(50)}
    assert len(delays) > 1


def test_retry_after_header_returns_present_value():
    assert retry_after_header(FakeResponse({"retry-after": "2"})) == "2"


def test_retry_after_header_tolerates_absent_and_non_string_values():
    assert retry_after_header(FakeResponse(None)) is None
    assert retry_after_header(FakeResponse({})) is None
    assert retry_after_header(FakeResponse({"retry-after": 7})) is None


def test_retry_after_header_tolerates_objects_with_no_headers():
    assert retry_after_header(object()) is None
    assert retry_after_header(RuntimeError("boom")) is None


def test_retry_after_header_tolerates_headers_that_are_not_a_mapping():
    class NotAMapping:
        pass

    assert retry_after_header(FakeResponse(NotAMapping())) is None


def test_retryable_status_covers_rate_limit_and_transient_faults():
    assert {408, 425, 429, 500, 502, 503, 504} <= RETRYABLE_STATUS


def test_permanent_verdicts_are_not_retryable():
    assert not RETRYABLE_STATUS & {400, 401, 403, 404, 422}


def test_sextant_shares_this_status_set():
    from astrolabe import sextant

    assert set(sextant._RETRYABLE_STATUS) == set(RETRYABLE_STATUS)
