import json

import pytest

from astrolabe.relay import RelayCatalog, extract_artifacts, valid_evidence


def source(kind="query", name="InboxQuery", doc_id="1234567890"):
    return (
        f'const node={{kind:"Request",params:{{id:"{doc_id}",name:"{name}",'
        f'operationKind:"{kind}",metadata:{{}},text:null}}}};'
    ).encode()


def entry():
    return {
        "protocol": "graphql-meta-doc-id",
        "persistedHash": "1234567890",
        "operationName": "InboxQuery",
        "semantic_kind": "unknown",
        "query": "",
    }


def test_ast_matches_literals_and_does_not_execute_or_use_comments():
    body = source() + b'\nthrow new Error("must not run");'
    assert extract_artifacts(body, "https://cdn.example/a.js")[0]["operation_kind"] == "query"
    for invalid in [
        b"// " + source(),
        json.dumps(source().decode()).encode(),
        source().replace(b'id:"1234567890"', b"id:lookup()"),
        source().replace(b"params:{", b"params:{...unknown,"),
        source().replace(b"params:{", b'params:{id:"other",'),
        source().replace(b'kind:"Request"', b'kind:"Fragment"'),
        source() + b"\nconst = broken",
    ]:
        assert extract_artifacts(invalid, "https://cdn.example/a.js") == []


def test_binding_requires_exact_name_id_and_rejects_conflicts():
    catalog = RelayCatalog()
    catalog.add(source(), "https://cdn.example/a.js?secret=redacted")
    bound = catalog.bind(entry(), True)
    assert bound["semantic_kind"] == "query"
    assert bound["query"] == ""
    evidence = bound["request_template"]["relay_evidence"]
    assert "redacted" not in evidence["source_url"]
    for key, value in [("operationName", "OtherQuery"), ("persistedHash", "0987654321")]:
        assert catalog.bind({**entry(), key: value}, True)["semantic_kind"] == "unknown"
    catalog.add(source("mutation"), "https://cdn.example/b.js")
    assert catalog.bind(entry(), True)["semantic_kind"] == "unknown"


def test_late_binding_and_evidence_validation(tmp_path):
    path = tmp_path / "capture.jsonl"
    path.write_text(json.dumps({"graphql": [entry()], "graphql_response_success": True}) + "\n")
    catalog = RelayCatalog()
    catalog.add(source(), "https://cdn.example/a.js")
    catalog.enrich_capture(str(path))
    bound = json.loads(path.read_text())["graphql"][0]
    tool = {
        "protocol": bound["protocol"],
        "request_template": bound["request_template"],
        "apq_hash": bound["persistedHash"],
        "operation": bound["operationName"],
        "type": "query",
    }
    assert valid_evidence(tool)
    assert not valid_evidence({**tool, "type": "mutation"})
    assert not valid_evidence({**tool, "apq_hash": "another"})
    tool["request_template"]["relay_evidence"]["observed_response_success"] = False
    assert not valid_evidence(tool)


@pytest.mark.parametrize(
    "limit", ["MAX_ARTIFACTS", "MAX_TOTAL_BYTES", "MAX_SCRIPT_BYTES", "MAX_SCRIPTS"]
)
def test_exhausted_catalog_cannot_authorize_partial_evidence(monkeypatch, limit):
    monkeypatch.setattr("astrolabe.relay." + limit, 0)
    catalog = RelayCatalog()
    catalog.add(source(), "https://cdn.example/a.js")
    assert catalog.exhausted
    assert catalog.bind(entry(), True)["semantic_kind"] == "unknown"


def modules(kind="query", value="1234567890", shadow=""):
    export = (
        f'__d("InboxQuery_instagramRelayOperation",[],(function(a,b,c,d,e,f)'
        f'{{e.exports="{value}"}}),null);'
    ).encode()
    request = (
        f'__d("InboxQuery.graphql",["InboxQuery_instagramRelayOperation"],'
        f"(function(a,b,c,d,e,f){{{shadow}var node=(function(){{return "
        f'{{kind:"Request",params:{{id:b("InboxQuery_instagramRelayOperation"),'
        f'name:"InboxQuery",operationKind:"{kind}",text:null}}}};}})();e.exports=node}}),null);'
    ).encode()
    return export, request


def test_literal_id_module_resolution_works_across_bundle_order():
    export, request = modules()
    catalog = RelayCatalog()
    catalog.add(request, "https://cdn.example/request.js")
    assert catalog.bind(entry(), True)["semantic_kind"] == "unknown"
    catalog.add(export, "https://cdn.example/id.js")
    bound = catalog.bind(entry(), True)
    assert bound["semantic_kind"] == "query"
    assert bound["request_template"]["relay_evidence"]["id_source_sha256"]
    catalog.add(modules(value="9876543210")[0], "https://cdn.example/conflict.js")
    assert catalog.bind(entry(), True)["semantic_kind"] == "unknown"


@pytest.mark.parametrize("shadow", ["b=evil;", "var b=evil;", "function b(){}"])
def test_rebound_module_loader_cannot_authorize(shadow):
    catalog = RelayCatalog()
    for body in modules(shadow=shadow):
        catalog.add(body, "https://cdn.example/bundle.js")
    assert catalog.bind(entry(), True)["semantic_kind"] == "unknown"


def test_id_module_computation_is_not_evaluated():
    export, request = modules()
    catalog = RelayCatalog()
    catalog.add(export.replace(b'"1234567890"', b"compute()"), "https://cdn.example/id.js")
    catalog.add(request, "https://cdn.example/request.js")
    assert catalog.bind(entry(), True)["semantic_kind"] == "unknown"


def test_preloadable_metadata_is_supported_without_normalization_ast():
    body = source().replace(b'"Request"', b'"PreloadableConcreteRequest"')
    catalog = RelayCatalog()
    catalog.add(body, "https://cdn.example/preload.js")
    assert catalog.bind(entry(), True)["semantic_kind"] == "query"


def test_recovered_mutation_is_not_exposed_by_generation():
    import re

    from astrolabe.mcpgen import build_graphql_tools

    catalog = RelayCatalog()
    catalog.add(source(kind="mutation"), "https://cdn.example/request.js")
    bound = catalog.bind(entry(), True)
    tools = build_graphql_tools(
        {
            "base_domain": "example.com",
            "graphql_operations": {
                "InboxQuery": {**bound, "operation": "InboxQuery", "type": bound["semantic_kind"]}
            },
        },
        {},
        {},
        {},
        re.compile(r"^$"),
        False,
        set(),
    )
    assert tools[0]["type"] == "mutation"
    assert tools[0]["exposed"] is False


def x_source(kind="query", name="DataSaverMode", query_id="Synth3ticQueryId_00A", param="e"):
    """One synthetic webpack module in X's persisted-registry shape.

    Independently authored from the documented protocol shape; no vendor source.
    """
    return (
        f"(self.webpackChunk=self.webpackChunk||[]).push([[1],{{123456({param}){{"
        f'{param}.exports={{queryId:"{query_id}",operationName:"{name}",'
        f'operationType:"{kind}",metadata:{{featureSwitches:[],fieldToggles:[]}}}}}}}}]);'
    ).encode()


def x_entry():
    return {
        "protocol": "graphql-x-persisted",
        "persistedHash": "Synth3ticQueryId_00A",
        "operationName": "DataSaverMode",
        "semantic_kind": "unknown",
        "query": "",
    }


def test_x_registry_resolves_precomputed_ids_like_meta_doc_ids():
    """X ships precomputed query IDs, so the kind comes from compiler output."""
    artifact = extract_artifacts(x_source(), "https://cdn.example/main.js")[0]
    assert artifact["source"] == "x-persisted-registry"
    assert (artifact["id"], artifact["name"], artifact["operation_kind"]) == (
        "Synth3ticQueryId_00A",
        "DataSaverMode",
        "query",
    )

    catalog = RelayCatalog()
    catalog.add(x_source(), "https://cdn.example/main.js?token=redacted")
    bound = catalog.bind(x_entry(), True)
    assert bound["semantic_kind"] == "query"
    assert bound["parse_confidence"] == "compiler-metadata"
    assert "redacted" not in bound["request_template"]["relay_evidence"]["source_url"]


def test_x_registry_rejects_anything_but_a_literal_single_statement_export():
    for invalid in [
        b"// " + x_source(),
        json.dumps(x_source().decode()).encode(),
        # A computed ID is a lookup, not evidence.
        x_source().replace(b'queryId:"Synth3ticQueryId_00A"', b"queryId:lookup()"),
        x_source().replace(b"operationType:", b"[dynamic]:"),
        x_source().replace(b'operationType:"query"', b'operationType:"fragment"'),
        # A second statement means the export is not what the literal says.
        x_source().replace(b"}}}]);", b"};e.exports.queryId=steal()}}]);"),
        # Exporting onto anything but the module parameter is not this module.
        x_source().replace(b"e.exports=", b"other.exports="),
        x_source().replace(b'queryId:"Synth3ticQueryId_00A",', b""),
        x_source() + b"\nconst = broken",
    ]:
        assert [
            a
            for a in extract_artifacts(invalid, "https://cdn.example/main.js")
            if a.get("source") == "x-persisted-registry"
        ] == []


def test_x_binding_requires_exact_id_and_name_agreement():
    catalog = RelayCatalog()
    catalog.add(x_source(), "https://cdn.example/main.js")
    for key, value in [
        ("operationName", "OtherQuery"),
        ("persistedHash", "ZZZZZZZZZZZZZZZZZZZZZZ"),
    ]:
        assert catalog.bind({**x_entry(), key: value}, True)["semantic_kind"] == "unknown"
    # A conflicting kind for the same ID poisons the binding rather than picking one.
    catalog.add(x_source(kind="mutation"), "https://cdn.example/other.js")
    assert catalog.bind(x_entry(), True)["semantic_kind"] == "unknown"


def test_x_accepts_both_registry_and_relay_compiler_evidence():
    """X's web client is Relay-based, so an X id resolves from either shape.

    The webpack `queryId` module and a genuine Relay `Request` object with the same
    id are both compiler metadata for the same operation; both must authorize it.
    """
    from_registry = RelayCatalog()
    from_registry.add(x_source(), "https://cdn.example/main.js")

    from_relay = RelayCatalog()
    # A Relay Request whose params.id is the X queryId, in an X bundle.
    from_relay.add(
        source(name="DataSaverMode", doc_id="Synth3ticQueryId_00A"),
        "https://abs.example/responsive-web/shared~bundle.js",
    )

    for catalog, expected_source in [
        (from_registry, "x-persisted-registry"),
        (from_relay, "relay-compiler-ast"),
    ]:
        bound = catalog.bind(x_entry(), True)
        assert bound["semantic_kind"] == "query"
        assert bound["request_template"]["relay_evidence"]["source"] == expected_source
        tool = {
            "protocol": "graphql-x-persisted",
            "request_template": bound["request_template"],
            "apq_hash": bound["persistedHash"],
            "operation": bound["operationName"],
            "type": "query",
        }
        assert valid_evidence(tool)
        # A Meta doc_id op must not be authorized by X-registry evidence, and no
        # binding survives a claimed protocol outside the trusted set or a kind flip.
        if expected_source == "x-persisted-registry":
            assert not valid_evidence({**tool, "protocol": "graphql-meta-doc-id"})
        assert not valid_evidence({**tool, "protocol": "graphql-apq"})
        assert not valid_evidence({**tool, "type": "mutation"})


def test_x_registry_cannot_authorize_once_budget_is_exhausted():
    catalog = RelayCatalog()
    catalog.add(x_source(), "https://cdn.example/main.js")
    catalog.exhausted = True
    assert catalog.bind(x_entry(), True)["semantic_kind"] == "unknown"


def test_markerless_scripts_do_not_consume_the_recovery_budget(monkeypatch):
    """A large framework bundle with no recovery markers must not exhaust the
    byte/script budget, or a page that ships one before its query modules would
    fail closed with nothing classified."""
    monkeypatch.setattr("astrolabe.relay.MAX_TOTAL_BYTES", len(x_source()) + 16)
    catalog = RelayCatalog()
    # A vendor bundle far larger than the whole byte budget, but marker-less.
    catalog.add(b"function f(){return 1}" * 100_000, "https://cdn.example/vendor.js")
    assert not catalog.exhausted and catalog.scripts == 0 and catalog.bytes == 0
    # The real query module still binds afterwards.
    catalog.add(x_source(), "https://cdn.example/main.js")
    assert not catalog.exhausted
    assert catalog.bind(x_entry(), True)["semantic_kind"] == "query"
