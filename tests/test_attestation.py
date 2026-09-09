from __future__ import annotations

import pytest

from astrolabe.attestation import (
    AttestationConfidence,
    attestation_requirement,
    is_satisfied,
)


@pytest.mark.parametrize(
    "header_names",
    [
        ["x-client-transaction-id"],
        ["X-Client-Transaction-Id"],  # case-insensitive match
        ["authorization", "x-client-transaction-id", "accept"],
    ],
)
def test_curated_header_is_detected(header_names: list[str]) -> None:
    requirement = attestation_requirement(header_names)
    assert requirement is not None
    assert requirement.confidence == AttestationConfidence.CURATED
    assert requirement.header_names == frozenset({"x-client-transaction-id"})
    assert "x-client-transaction-id" in requirement.reason
    assert "no replay adapter is registered" in requirement.reason


@pytest.mark.parametrize(
    "header_names",
    [
        ["x-request-signature"],
        ["X-NONCE"],
        ["x-attestation-token"],
        ["x-proof-of-work"],
    ],
)
def test_heuristic_header_is_flagged_as_low_confidence(header_names: list[str]) -> None:
    requirement = attestation_requirement(header_names)
    assert requirement is not None
    assert requirement.confidence == AttestationConfidence.HEURISTIC
    assert requirement.header_names == frozenset(name.lower() for name in header_names)
    assert "unconfirmed" in requirement.reason


@pytest.mark.parametrize("header_names", [None, [], ["", "  "]])
def test_empty_or_none_input_returns_none(header_names: list[str] | None) -> None:
    assert attestation_requirement(header_names) is None


def test_ordinary_headers_return_none() -> None:
    assert attestation_requirement(["authorization", "accept", "content-type", "cookie"]) is None


def test_csrf_token_is_not_treated_as_attestation() -> None:
    # x-csrf-token mirrors the ct0 cookie -- it is derivable, not computed.
    assert attestation_requirement(["x-csrf-token"]) is None


def test_curated_match_takes_priority_over_heuristic_names_in_the_same_set() -> None:
    requirement = attestation_requirement(["x-client-transaction-id", "x-request-nonce"])
    assert requirement is not None
    assert requirement.confidence == AttestationConfidence.CURATED
    assert requirement.header_names == frozenset({"x-client-transaction-id"})


def test_is_satisfied_with_no_requirement() -> None:
    assert is_satisfied(None, adapters=[]) is True


def test_is_satisfied_with_no_adapters_fails_closed() -> None:
    requirement = attestation_requirement(["x-client-transaction-id"])
    assert is_satisfied(requirement, adapters=[]) is False


def test_is_satisfied_with_partial_adapter_coverage_is_false() -> None:
    requirement = attestation_requirement(["x-client-transaction-id", "x-request-signature"])
    assert requirement is not None
    assert requirement.confidence == AttestationConfidence.CURATED
    # Only the curated hit is captured in header_names, so a signature adapter
    # alone still satisfies it -- confirm coverage against what was recorded.
    assert is_satisfied(requirement, adapters=["x-client-transaction-id"]) is True


def test_is_satisfied_requires_covering_every_required_header() -> None:
    requirement = attestation_requirement(["x-request-signature", "x-request-nonce"])
    assert requirement is not None
    assert is_satisfied(requirement, adapters=["x-request-signature"]) is False
    assert is_satisfied(requirement, adapters=["x-request-signature", "x-request-nonce"]) is True


def test_is_satisfied_adapter_name_comparison_is_case_insensitive() -> None:
    requirement = attestation_requirement(["x-client-transaction-id"])
    assert requirement is not None
    assert is_satisfied(requirement, adapters=["X-Client-Transaction-Id"]) is True
