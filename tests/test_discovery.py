from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from astrolabe.discovery import (
    ActionLedger,
    Candidate,
    DiscoveryCorpus,
    DiscoverySource,
    Evidence,
    InteractionCandidate,
    StaticBundleMiner,
    StaticResource,
    TargetPolicy,
    completeness_metrics,
    derive_interactions,
    fuse_candidates,
    mine_javascript,
    plan_interactions,
)
from astrolabe.schema import validate_artifact

FIXTURES = Path(__file__).parent / "fixtures" / "discovery"


def candidate(source: DiscoverySource, **metadata):
    return Candidate(
        "endpoint",
        "stable",
        "/api/items",
        [Evidence(source, 0.5, locator=f"{source.value}:fixture")],
        metadata,
    )


def test_fusion_preserves_source_confidence_conflicts_and_static_execution_gate():
    static = candidate(
        DiscoverySource.BUNDLE,
        semantic_kind="query",
        request_template={"method": "GET"},
        safety_proven=True,
    )
    traffic = candidate(
        DiscoverySource.TRAFFIC,
        semantic_kind="mutation",
        request_template={"method": "POST"},
    )

    fused = fuse_candidates([[static], [traffic]])[0]

    assert {e.source for e in fused.evidence} == {
        DiscoverySource.BUNDLE,
        DiscoverySource.TRAFFIC,
    }
    assert fused.confidence == 0.75
    assert fused.metadata["conflicts"]["semantic_kind"] == ["query", "mutation"]
    assert fused.execution_state == "inventory-only"
    assert static.execution_state == "inventory-only"  # static text is never proof by itself


def test_semantically_proven_safe_read_can_become_eligible():
    item = candidate(
        DiscoverySource.OPENAPI,
        semantic_kind="query",
        request_template={"method": "GET", "path": "/api/items"},
        safety_proven=True,
    )
    assert item.execution_state == "eligible"


def test_corpus_fuses_every_supported_discovery_source_without_flattening():
    corpus = DiscoveryCorpus()
    for source in DiscoverySource:
        corpus.add_records(
            source,
            [{"kind": "endpoint", "key": "same", "value": "/api/items", "confidence": 0.1}],
        )
    report = corpus.to_dict()
    assert report["sources"] == sorted(source.value for source in DiscoverySource)
    assert report["candidate_count"] == 1
    assert len(report["candidates"][0]["evidence"]) == len(DiscoverySource)
    assert report["candidates"][0]["execution_state"] == "inventory-only"
    validate_artifact(report, "discovery-v1.schema.json")


def test_miner_recovers_minified_framework_and_graphql_signals_without_execution():
    body = """
    const r={path:'/products/:id',featureFlags:{newSearch:true}};
    const q={operationName:'ProductQuery',sha256Hash:'abcdef0123456789',
      query:`query ProductQuery($id: ID!){product(id:$id){id}}`,
      url:'/graphql', serializer:serialize};
    """
    mined = mine_javascript(body, "https://example.test/_next/static/app.js")
    kinds = {item.kind for item in mined}
    assert {
        "endpoint",
        "navigation-route",
        "feature-flag",
        "graphql-operation-name",
        "persisted-identifier",
        "graphql-document",
        "serializer",
    } <= kinds
    assert all(item.execution_state == "inventory-only" for item in mined)


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("webpack-runtime.js", {"/api/catalog", "/catalog/:slug"}),
        ("vite-entry.js", {"/api/search"}),
        ("apollo-client.js", {"ProductQuery", "0123456789abcdef0123456789abcdef"}),
        ("relay-artifact.js", {"ViewerQuery", "relayPersistedId12345"}),
        ("vendor-persisted-a.js", {"FeedTimeline", "Qz1FeedTimeline789"}),
        ("vendor-persisted-b.js", {"ProfilePageContentQuery", "9876543210123456"}),
    ],
)
def test_realistic_framework_and_vendor_bundle_fixtures(fixture, expected):
    mined = mine_javascript((FIXTURES / fixture).read_text(), fixture)
    assert expected <= {item.value for item in mined}
    assert all(item.execution_state == "inventory-only" for item in mined)


def test_next_manifest_fixture_associates_routes_with_chunks():
    manifest_url = "https://example.test/_next/build-manifest.json"
    resources = {
        manifest_url: StaticResource(
            manifest_url,
            (FIXTURES / "next-build-manifest.json").read_text(),
            "application/json",
        ),
        "https://example.test/_next/static/chunks/products-a81.js": StaticResource(
            "https://example.test/_next/static/chunks/products-a81.js", "const u='/api/products'"
        ),
        "https://example.test/_next/static/chunks/search-b42.js": StaticResource(
            "https://example.test/_next/static/chunks/search-b42.js", "const u='/api/search'"
        ),
    }
    result = StaticBundleMiner("https://example.test").mine(
        [manifest_url], resources.__getitem__
    )
    routes = {item.value: item.metadata["navigation_routes"] for item in result.candidates}
    assert routes["/api/products"] == ["/products"]
    assert routes["/api/search"] == ["/search"]


def test_static_bundle_miner_follows_vite_chunks_next_manifest_and_source_maps_with_cache():
    resources = {
        "https://example.test/assets/app.js": StaticResource(
            "https://example.test/assets/app.js",
            "import('./route-123.js');const u='/api/root';\n//# sourceMappingURL=app.js.map",
        ),
        "https://example.test/assets/route-123.js": StaticResource(
            "https://example.test/assets/route-123.js", "const x='/api/chunk'"
        ),
        "https://example.test/assets/app.js.map": StaticResource(
            "https://example.test/assets/app.js.map",
            '{"sources":["src.ts"],"sourcesContent":["const q={operationName:\\"MappedQuery\\"}"]}',
            "application/json",
        ),
        "https://example.test/_next/build-manifest.json": StaticResource(
            "https://example.test/_next/build-manifest.json",
            '{"pages":{"/shop":["static/chunks/shop.js","static/chunks/duplicate.js"]}}',
            "application/json",
        ),
        "https://example.test/_next/static/chunks/shop.js": StaticResource(
            "https://example.test/_next/static/chunks/shop.js", "const q='/api/shop'"
        ),
        "https://example.test/_next/static/chunks/duplicate.js": StaticResource(
            "https://example.test/_next/static/chunks/duplicate.js", "const q='/api/shop'"
        ),
    }
    miner = StaticBundleMiner("https://example.test", max_resources=10)
    result = miner.mine(
        ["/assets/app.js", "/_next/build-manifest.json"], resources.__getitem__
    )

    assert set(result.discovered_urls) == set(resources)
    assert result.cache_hits == 1
    assert "https://example.test/assets/app.js.map" in result.source_maps
    values = {item.value for item in result.candidates}
    assert {"/api/root", "/api/chunk", "/api/shop", "MappedQuery"} <= values
    shop = next(item for item in result.candidates if item.value == "/api/shop")
    assert shop.metadata["navigation_routes"] == ["/shop"]


def test_static_miner_denies_third_party_and_enforces_byte_and_resource_budgets():
    fetched = []

    def fetch(url):
        fetched.append(url)
        return StaticResource(url, "const x='/api/a';import('./more.js')")

    miner = StaticBundleMiner(
        "https://example.test", max_resources=1, max_resource_bytes=100, max_total_bytes=100
    )
    result = miner.mine(["https://cdn.attacker.test/x.js", "/app.js"], fetch)
    assert fetched == ["https://example.test/app.js"]
    assert "third-party-denied:https://cdn.attacker.test/x.js" in result.truncations
    assert "resource-count" in result.truncations


def test_static_miner_enforces_per_origin_resource_ceiling():
    miner = StaticBundleMiner(
        "https://example.test", max_resources=4, max_origin_resources=1
    )
    result = miner.mine(
        ["/a.js", "/b.js"], lambda url: StaticResource(url, "const x='/api/a'")
    )
    assert result.discovered_urls == ["https://example.test/a.js"]
    assert "origin-resource-count:https://example.test" in result.truncations


def test_planner_prefers_novel_low_cost_actions_and_suppresses_no_evidence_repeats():
    actions = [
        InteractionCandidate("paginate", "/items", "next-page", frozenset({"a", "b"}), 1, 1),
        InteractionCandidate("filter", "/items", "change-filter", frozenset({"b", "c"}), 2, 3),
        InteractionCandidate("repeat", "/items", "scroll", frozenset({"d"}), 1, 1),
        InteractionCandidate("write", "/items", "submit", frozenset({"e"}), risk="high"),
    ]
    plan = plan_interactions(
        actions,
        missing_candidate_keys={"a", "b", "c", "d", "e"},
        no_evidence_actions={"repeat"},
        request_budget=2,
    )
    assert [row["action_id"] for row in plan] == ["paginate"]
    assert plan[0]["marginal_curve"] == {"requests": 1, "expected_candidates": 2}


def test_interaction_derivation_detects_pagination_get_filters_and_ssr_boundary():
    interactions = derive_interactions(
        {
            "https://example.test/items": {
                "anchors": [{"h": "?page=2", "t": "Next", "same": True}],
                "forms": [
                    {"method": "GET", "inputs": [{"name": "category", "type": "select"}]}
                ],
                "meta": {"ssr_first_page": True},
            }
        }
    )
    assert {item.action.split(":", 1)[0] for item in interactions} == {
        "navigate",
        "change-get-filter",
        "scroll-for-client-pagination",
    }


def test_completeness_reports_relative_denominators_and_convergence_without_absolute_claim():
    report = completeness_metrics(
        observed={"a", "route-a", "field-a"},
        static_candidates={"a", "b"},
        navigation_routes={"route-a", "route-b"},
        spec_operations={"a", "c"},
        schema_fields={"field-a", "field-b"},
        recipe_actions={"paginate", "filter"},
        completed_actions={"paginate"},
        run_operation_sets=[{"a"}, {"a", "b"}, {"a", "b"}],
    )
    assert "not absolute" in report["claim"]
    assert report["static_candidate_coverage"]["ratio"] == 0.5
    assert report["recipe_action_coverage"]["ratio"] == 0.5
    assert report["convergence"] == {
        "runs": 3,
        "confidence": "high",
        "similarity": 1.0,
        "new_in_latest": 0,
    }


def test_policy_enforces_scope_hours_actions_and_evidence_gated_schema_recovery():
    policy = TargetPolicy(
        working_hours_utc=(9, 17),
        authorized_paths=("/api",),
        prohibited_paths=("/api/admin",),
        allow_schema_recovery=True,
    )
    noon = datetime(2026, 1, 1, 12, tzinfo=UTC)
    evening = datetime(2026, 1, 1, 20, tzinfo=UTC)
    assert policy.authorize(path="/api/items", action="GET", now=noon) == (True, "authorized")
    assert policy.authorize(path="/api/items", action="GET", now=evening)[1] == "outside-working-hours"
    assert policy.authorize(path="/outside", action="GET", now=noon)[1] == "outside-authorization-scope"
    assert policy.authorize(path="/api/admin/users", action="GET", now=noon)[1] == "prohibited-path"
    assert policy.authorize(path="/api/items", action="delete item", now=noon)[1] == "prohibited-action"
    assert policy.authorize(
        path="/api/graphql", action="recover-schema", now=noon, schema_recovery=True
    )[1] == "schema-recovery-not-evidence-gated"
    assert policy.authorize(
        path="/api/graphql",
        action="recover-schema",
        now=noon,
        schema_recovery=True,
        recovery_evidence=True,
    ) == (True, "authorized")


def test_action_ledger_is_hash_chained_and_tamper_evident():
    ledger = ActionLedger()
    first = ledger.append(
        action_id="probe-1",
        action="GET",
        target="https://example.test/api/items",
        authorized=True,
        reason="authorized",
        timestamp="2026-01-01T00:00:00+00:00",
    )
    second = ledger.append(
        action_id="write-1",
        action="POST mutation",
        target="https://example.test/graphql",
        authorized=False,
        reason="mutation-refused",
        timestamp="2026-01-01T00:00:01+00:00",
    )
    assert second["previous_hash"] == first["record_hash"]
    assert ledger.verify()
    ledger.records[0]["authorized"] = False
    assert not ledger.verify()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_requests": 0},
        {"concurrency": 0},
        {"delay_ms": -1},
        {"account_risk": "reckless"},
        {"working_hours_utc": (4, 4)},
    ],
)
def test_policy_rejects_invalid_controls(kwargs):
    with pytest.raises(ValueError):
        TargetPolicy(**kwargs)
