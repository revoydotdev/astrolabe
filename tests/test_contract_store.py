from __future__ import annotations

import json

import pytest

from astrolabe.contract_store import (
    ContractStoreError,
    prior_contract,
    publish,
    store_path,
    store_root,
)


def test_store_root_prefers_explicit_then_environment_then_default(tmp_path, monkeypatch):
    monkeypatch.delenv("ASTROLABE_CONTRACT_STORE", raising=False)
    assert store_root().name == "contracts"
    monkeypatch.setenv("ASTROLABE_CONTRACT_STORE", str(tmp_path / "from-env"))
    assert store_root() == tmp_path / "from-env"
    assert store_root(str(tmp_path / "explicit")) == tmp_path / "explicit"


def test_one_contract_per_domain(tmp_path):
    assert store_path("x.com", root=str(tmp_path)) == tmp_path / "x.com.json"
    assert store_path("X.CoM.", root=str(tmp_path)) == tmp_path / "x.com.json"


@pytest.mark.parametrize(
    "domain",
    ["../escape", "x.com/../../etc", "", "  ", "x.com/sub", "-leading", "a" * 300],
)
def test_a_domain_that_is_not_one_path_segment_is_refused(domain, tmp_path):
    # Writing a contract of record outside its store is worse than not accumulating.
    with pytest.raises(ContractStoreError):
        store_path(domain, root=str(tmp_path))


def test_no_prior_contract_until_one_is_published(tmp_path):
    assert prior_contract("x.com", root=str(tmp_path)) is None
    source = tmp_path / "contract.json"
    source.write_text(json.dumps({"operations": {"HomeTimeline": {"status": "observed"}}}))
    publish("x.com", source, root=str(tmp_path / "store"))
    assert prior_contract("x.com", root=str(tmp_path / "store")) is not None


def test_publishing_replaces_the_record_with_the_merged_contract(tmp_path):
    store = tmp_path / "store"
    first = tmp_path / "first.json"
    first.write_text(json.dumps({"operations": {"HomeTimeline": {}}}))
    publish("x.com", first, root=str(store))

    # A later run merges the prior record itself, so what it publishes is the union.
    second = tmp_path / "second.json"
    second.write_text(json.dumps({"operations": {"HomeTimeline": {}, "UserByScreenName": {}}}))
    published = publish("x.com", second, root=str(store))
    assert sorted(json.loads(published.read_text())["operations"]) == [
        "HomeTimeline",
        "UserByScreenName",
    ]


def test_domains_do_not_share_a_record(tmp_path):
    store = tmp_path / "store"
    source = tmp_path / "contract.json"
    source.write_text(json.dumps({"operations": {"getMe": {}}}))
    publish("nextdoor.com", source, root=str(store))
    assert prior_contract("nextdoor.com", root=str(store)) is not None
    assert prior_contract("x.com", root=str(store)) is None


def test_publishing_a_missing_contract_is_refused(tmp_path):
    with pytest.raises(ContractStoreError):
        publish("x.com", tmp_path / "absent.json", root=str(tmp_path / "store"))
