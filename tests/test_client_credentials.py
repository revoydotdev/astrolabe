from __future__ import annotations

import hashlib

import pytest

from astrolabe.client_credentials import (
    ClientCredentialSite,
    discover,
    matches,
)

BEARER = "AAAAAAAAAAAAAAAAAAAAAA" + "b" * 60


def test_discovers_a_credential_by_the_key_the_application_gives_it():
    body = f'var config={{apiKey:"{BEARER}",theme:"dark"}};'.encode()
    sites = discover(body, "https://cdn.example.com/main.js")
    assert len(sites) == 1
    assert sites[0].key == "apiKey"
    assert sites[0].value_length == len(BEARER)
    assert sites[0].value_sha256 == hashlib.sha256(BEARER.encode()).hexdigest()


def test_never_records_the_credential_value():
    body = f'{{"authorization":"{BEARER}"}}'.encode()
    site = discover(body, "https://cdn.example.com/main.js")[0]
    assert BEARER not in str(site.to_dict())
    assert BEARER not in repr(site)


@pytest.mark.parametrize(
    "body",
    [
        # A long opaque literal the application does not call a credential.
        b'var buildHash="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";',
        # A credential-named key holding something too short to be one.
        b'var apiKey="dev";',
        b"",
    ],
)
def test_ignores_literals_that_are_not_declared_credentials(body):
    assert discover(body, "https://cdn.example.com/main.js") == []


def test_deduplicates_one_credential_seen_many_times():
    body = (f'a={{apiKey:"{BEARER}"}};b={{apiKey:"{BEARER}"}};').encode()
    assert len(discover(body, "https://cdn.example.com/main.js")) == 1


def test_records_the_script_it_came_from():
    body = f'{{"client_token":"{BEARER}"}}'.encode()
    site = discover(body, "https://cdn.example.com/chunk.js")[0]
    assert site.source_url == "https://cdn.example.com/chunk.js"
    assert site.source_sha256 == hashlib.sha256(body).hexdigest()


def test_matches_proves_a_supplied_credential_without_storing_it():
    site = ClientCredentialSite(
        key="authorization",
        source_url="https://cdn.example.com/main.js",
        source_sha256="a" * 64,
        value_sha256=hashlib.sha256(BEARER.encode()).hexdigest(),
        value_length=len(BEARER),
    ).to_dict()
    assert matches(site, BEARER) is True
    assert matches(site, "wrong-value") is False
    assert matches(site, "") is False
    assert matches({}, BEARER) is False


@pytest.mark.parametrize(
    "key",
    [
        # WebAuthn operation names whose values are persisted query ids, seen on a real
        # x.com bundle: a substring match read all four as credentials.
        "SetupPublicKeyCredential",
        "CreatePublicKeyCredential",
        "DeletePublicKeyCredential",
        "ListPublicKeyCredentials",
        "publicKey",
        "apiKeyValidationError",
        "authorizationHeaderName",
    ],
)
def test_only_a_key_that_is_a_credential_counts_not_one_that_mentions_it(key):
    body = f'{{"{key}":"{BEARER}"}}'.encode()
    assert discover(body, "https://cdn.example.com/main.js") == []


@pytest.mark.parametrize(
    "key", ["authorization", "apiKey", "api_key", "x-api-key", "clientSecret", "auth_token"]
)
def test_credential_keys_still_match_exactly(key):
    body = f'{{"{key}":"{BEARER}"}}'.encode()
    assert len(discover(body, "https://cdn.example.com/main.js")) == 1


def test_finds_a_bearer_literal_a_minified_bundle_does_not_name():
    # The shape x.com ships: the credential lives in an anonymous arrow function, so
    # no key names it, but the scheme prefix identifies it.
    body = f'var n=[1,2,3],j=()=>"Bearer {BEARER}";'.encode()
    sites = discover(body, "https://cdn.example.com/main.js")
    assert len(sites) == 1
    assert sites[0].key == "authorization"
    assert sites[0].value_sha256 == hashlib.sha256(BEARER.encode()).hexdigest()
    assert BEARER not in str(sites[0].to_dict())


def test_a_bearer_and_a_named_key_holding_it_collapse_to_one_site():
    body = f'{{"authorization":"{BEARER}"}};x=()=>"Bearer {BEARER}";'.encode()
    assert len(discover(body, "https://cdn.example.com/main.js")) == 1
