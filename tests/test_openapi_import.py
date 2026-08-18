"""Tests for building an endpoints.json inventory from an OpenAPI/Swagger doc."""

from __future__ import annotations

import json

import pytest

from astrolabe.openapi_import import (
    Document,
    OpenAPIImportError,
    import_openapi,
    main,
    schema_to_json_schema,
)


def _doc(**paths) -> dict:
    return {
        "openapi": "3.0.1",
        "info": {"title": "T", "version": "v1"},
        "servers": [{"url": "https://api.example.com/api"}],
        "paths": paths,
    }


def _write(tmp_path, doc) -> str:
    p = tmp_path / "api.json"
    p.write_text(json.dumps(doc))
    return str(p)


# ---------- document recognition ----------


def test_rejects_non_openapi(tmp_path) -> None:
    with pytest.raises(OpenAPIImportError, match="not an OpenAPI"):
        import_openapi(_write(tmp_path, {"paths": {}}))


def test_rejects_missing_file(tmp_path) -> None:
    with pytest.raises(OpenAPIImportError, match="no such file"):
        import_openapi(str(tmp_path / "nope.json"))


def test_swagger_2_is_recognised(tmp_path) -> None:
    doc = {
        "swagger": "2.0",
        "host": "api.example.com",
        "basePath": "/api",
        "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    inv = import_openapi(_write(tmp_path, doc))
    assert inv["base_domain"] == "api.example.com"
    assert inv["rest_endpoints"][0]["method"] == "GET"


def test_base_domain_from_servers_and_override(tmp_path) -> None:
    path = _write(tmp_path, _doc(**{"/x": {"get": {"responses": {}}}}))
    assert import_openapi(path)["base_domain"] == "api.example.com"
    assert import_openapi(path, "other.example.com")["base_domain"] == "other.example.com"


def test_no_server_and_no_override_errors(tmp_path) -> None:
    doc = {"openapi": "3.0.1", "paths": {"/x": {"get": {"responses": {}}}}}
    with pytest.raises(OpenAPIImportError, match="no server host"):
        import_openapi(_write(tmp_path, doc))


# ---------- operations and inputs ----------


def test_path_param_becomes_a_required_input(tmp_path) -> None:
    doc = _doc(
        **{
            "/Item/{itemId}": {
                "get": {
                    "parameters": [
                        {
                            "name": "itemId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        }
    )
    ep = import_openapi(_write(tmp_path, doc))["rest_endpoints"][0]
    assert ep["input_schema"]["properties"]["itemId"] == {"type": "integer"}
    assert ep["input_schema"]["required"] == ["itemId"]


def test_request_body_properties_become_inputs(tmp_path) -> None:
    doc = _doc(
        **{
            "/Search": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["q"],
                                    "properties": {
                                        "q": {"type": "string"},
                                        "page": {"type": "integer"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        }
    )
    ep = import_openapi(_write(tmp_path, doc))["rest_endpoints"][0]
    assert set(ep["input_schema"]["properties"]) == {"q", "page"}
    assert "q" in ep["input_schema"]["required"]


def test_operation_metadata_is_carried(tmp_path) -> None:
    doc = _doc(**{"/x": {"get": {"operationId": "GetX", "summary": "gets x", "responses": {}}}})
    ep = import_openapi(_write(tmp_path, doc))["rest_endpoints"][0]
    assert ep["operationId"] == "GetX"
    assert ep["summary"] == "gets x"
    assert ep["source"] == "openapi"
    assert ep["calls"] == 0  # documentation, not observed traffic


def test_servers_base_paths_ports_variables_and_operation_override_are_preserved(
    tmp_path,
) -> None:
    doc = _doc(
        **{
            "/items/{id}": {
                "get": {
                    "servers": [
                        {"url": "/edge/{version}", "variables": {"version": {"default": "v2"}}}
                    ],
                    "responses": {},
                }
            }
        }
    )
    doc["servers"] = [
        {
            "url": "https://api.example.com:8443/api/{version}",
            "variables": {"version": {"default": "v1"}},
        }
    ]
    endpoint = import_openapi(_write(tmp_path, doc))["rest_endpoints"][0]

    assert endpoint["servers"] == ["https://api.example.com:8443/edge/v2"]
    assert endpoint["request_url"] == "https://api.example.com:8443/edge/v2/items/{id}"


def test_parameter_locations_and_name_collisions_are_preserved(tmp_path) -> None:
    doc = _doc(
        **{
            "/items/{id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "id",
                            "in": "query",
                            "style": "form",
                            "explode": False,
                            "schema": {"type": "array", "items": {"type": "integer"}},
                        },
                        {"name": "id", "in": "header", "schema": {"type": "string"}},
                        {
                            "name": "prefs",
                            "in": "query",
                            "style": "deepObject",
                            "explode": True,
                            "schema": {
                                "type": "object",
                                "additionalProperties": {"type": "string"},
                            },
                        },
                    ],
                    "responses": {},
                }
            }
        }
    )
    endpoint = import_openapi(_write(tmp_path, doc))["rest_endpoints"][0]

    assert set(endpoint["input_schema"]["properties"]) == {
        "path_id",
        "query_id",
        "header_id",
        "prefs",
    }
    by_location = {
        item["location"]: item for item in endpoint["parameters"] if item["name"] == "id"
    }
    assert by_location["path"]["argument"] == "path_id"
    assert by_location["query"]["style"] == "form"
    assert by_location["header"]["argument"] == "header_id"


def test_swagger_body_formdata_and_consumes_are_preserved(tmp_path) -> None:
    doc = {
        "swagger": "2.0",
        "host": "api.example.com:9443",
        "basePath": "/api/v2",
        "schemes": ["https"],
        "consumes": ["multipart/form-data"],
        "paths": {
            "/upload": {
                "post": {
                    "parameters": [
                        {"name": "metadata", "in": "formData", "type": "string"},
                        {"name": "asset", "in": "formData", "type": "file", "required": True},
                    ],
                    "responses": {"204": {"description": "done"}},
                }
            }
        },
    }
    endpoint = import_openapi(_write(tmp_path, doc))["rest_endpoints"][0]

    assert endpoint["request_url"] == "https://api.example.com:9443/api/v2/upload"
    assert endpoint["body_media_type"] == "multipart/form-data"
    assert {item["location"] for item in endpoint["parameters"]} == {"form"}


def test_document_with_no_operations_errors(tmp_path) -> None:
    with pytest.raises(OpenAPIImportError, match="no HTTP operations"):
        import_openapi(_write(tmp_path, _doc(**{"/x": {"description": "no verbs"}})))


# ---------- $ref and schema conversion ----------


def test_ref_is_resolved_in_return_schema(tmp_path) -> None:
    doc = _doc(
        **{
            "/Item": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Item"}
                                }
                            }
                        }
                    }
                }
            }
        }
    )
    doc["components"] = {
        "schemas": {
            "Item": {
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "integer"}, "price": {"type": "number"}},
            }
        }
    }
    ep = import_openapi(_write(tmp_path, doc))["rest_endpoints"][0]
    assert ep["return_schema"]["properties"]["id"] == {"type": "integer"}
    assert ep["return_schema"]["required"] == ["id"]


def test_self_referential_ref_terminates(tmp_path) -> None:
    """A schema that references itself must not recurse forever."""
    d = Document(
        {
            "openapi": "3.0.1",
            "servers": [{"url": "https://h/"}],
            "paths": {},
            "components": {
                "schemas": {
                    "Node": {
                        "type": "object",
                        "properties": {
                            "child": {"$ref": "#/components/schemas/Node"},
                            "v": {"type": "string"},
                        },
                    }
                }
            },
        }
    )
    schema = schema_to_json_schema(d, {"$ref": "#/components/schemas/Node"})
    assert "v" in schema["properties"]  # terminated with structure intact


def test_nullable_and_enum(tmp_path) -> None:
    d = Document({"openapi": "3.0.1", "servers": [{"url": "https://h/"}], "paths": {}})
    assert schema_to_json_schema(d, {"type": "string", "nullable": True}) == {
        "type": ["string", "null"]
    }
    assert schema_to_json_schema(d, {"type": "string", "enum": ["A", "B"]}) == {
        "type": "string",
        "enum": ["A", "B"],
    }


def test_array_items_convert(tmp_path) -> None:
    d = Document({"openapi": "3.0.1", "servers": [{"url": "https://h/"}], "paths": {}})
    assert schema_to_json_schema(d, {"type": "array", "items": {"type": "integer"}}) == {
        "type": "array",
        "items": {"type": "integer"},
    }


def test_schema_unions_constraints_and_discriminator_are_preserved() -> None:
    doc = Document({"openapi": "3.1.0", "servers": [{"url": "https://h/"}], "paths": {}})
    schema = schema_to_json_schema(
        doc,
        {
            "oneOf": [
                {"type": "string", "pattern": "^a", "minLength": 2},
                {"type": "integer", "minimum": 1},
            ],
            "not": {"const": "admin"},
            "discriminator": {"propertyName": "kind"},
            "examples": ["must-not-be-copied"],
        },
    )

    assert schema["oneOf"] == [
        {"type": "string", "pattern": "^a", "minLength": 2},
        {"type": "integer", "minimum": 1},
    ]
    assert schema["not"] == {"const": "admin"}
    assert schema["x-openapi-discriminator"] == {"propertyName": "kind"}
    assert "examples" not in schema


def test_external_refs_fail_closed_until_explicitly_authorized() -> None:
    doc = Document({"openapi": "3.1.0", "servers": [{"url": "https://h/"}], "paths": {}})
    with pytest.raises(OpenAPIImportError, match="external schema ref"):
        schema_to_json_schema(doc, {"$ref": "https://schemas.invalid/user.json"})


def test_authorized_external_refs_are_cached_and_cycle_bounded(tmp_path) -> None:
    external = tmp_path / "schemas.json"
    external.write_text(
        json.dumps(
            {
                "$defs": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "manager": {"$ref": "#/$defs/User"},
                        },
                    }
                }
            }
        )
    )
    uri = "https://schemas.example/v1/schemas.json"
    doc = Document(
        {"openapi": "3.1.0", "servers": [{"url": "https://h/"}], "paths": {}},
        base_uri="https://schemas.example/v1/openapi.json",
        external_ref_paths={uri: str(external)},
    )
    schema = schema_to_json_schema(doc, {"$ref": f"{uri}#/$defs/User"})
    assert schema["properties"]["name"] == {"type": "string"}
    assert schema["properties"]["manager"]["x-astrolabe-cycle"] is True
    external.write_text("not valid after first cached load")
    assert schema_to_json_schema(doc, {"$ref": f"{uri}#/$defs/User"}) == schema


def test_external_ref_requires_exact_uri_authorization(tmp_path) -> None:
    external = tmp_path / "schemas.json"
    external.write_text(json.dumps({"type": "string"}))
    doc = Document(
        {"openapi": "3.1.0", "servers": [{"url": "https://h/"}], "paths": {}},
        base_uri="https://schemas.example/openapi.json",
        external_ref_paths={"https://schemas.example/user.json": str(external)},
    )
    with pytest.raises(OpenAPIImportError, match="not authorized"):
        schema_to_json_schema(doc, {"$ref": "https://schemas.example/admin.json"})


def test_import_openapi_accepts_explicit_uri_to_local_ref_mapping(tmp_path) -> None:
    external = tmp_path / "schemas.json"
    external.write_text(json.dumps({"$defs": {"Item": {"type": "string", "minLength": 2}}}))
    uri = "https://schemas.example/schemas.json"
    source = tmp_path / "openapi.json"
    source.write_text(
        json.dumps(
            _doc(
                **{
                    "/item": {
                        "get": {
                            "responses": {
                                "200": {
                                    "content": {
                                        "application/json": {
                                            "schema": {"$ref": f"{uri}#/$defs/Item"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            )
        )
    )
    inventory = import_openapi(str(source), external_refs=[f"{uri}={external}"])
    assert inventory["rest_endpoints"][0]["return_schema"] == {
        "type": "string",
        "minLength": 2,
    }


def test_all_response_status_and_media_variants_are_preserved(tmp_path) -> None:
    doc = _doc(
        **{
            "/items": {
                "get": {
                    "responses": {
                        "200": {
                            "headers": {"X-Next": {"schema": {"type": "string"}}},
                            "content": {
                                "application/json": {
                                    "schema": {"type": "array", "items": {"type": "string"}}
                                },
                                "text/csv": {"schema": {"type": "string"}},
                            },
                        },
                        "204": {"description": "empty"},
                        "400": {
                            "content": {"application/problem+json": {"schema": {"type": "object"}}}
                        },
                    }
                }
            }
        }
    )
    endpoint = import_openapi(_write(tmp_path, doc))["rest_endpoints"][0]

    assert {(item["status"], item["media_type"]) for item in endpoint["response_variants"]} == {
        ("200", "application/json"),
        ("200", "text/csv"),
        ("204", None),
        ("400", "application/problem+json"),
    }
    assert endpoint["return_schema"]["oneOf"]
    error = next(item for item in endpoint["response_variants"] if item["status"] == "400")
    assert error["success"] is False


def test_callbacks_and_webhooks_are_inventory_only(tmp_path) -> None:
    doc = _doc(
        **{
            "/subscribe": {
                "post": {
                    "operationId": "subscribe",
                    "callbacks": {"onEvent": {"{$request.body#/callback}": {}}},
                    "responses": {"202": {"description": "accepted"}},
                }
            }
        }
    )
    doc["webhooks"] = {"accountChanged": {"post": {"responses": {"200": {}}}}}
    inventory = import_openapi(_write(tmp_path, doc))

    assert {item["protocol"] for item in inventory["misc_operations"].values()} == {"webhook"}
    assert len(inventory["misc_operations"]) == 2
    assert all(item["executable"] is False for item in inventory["misc_operations"].values())


# ---------- auth ----------


def test_bearer_security_implies_authorization_header(tmp_path) -> None:
    doc = _doc(**{"/x": {"get": {"responses": {}}}})
    doc["components"] = {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}}
    doc["security"] = [{"b": []}]
    ep = import_openapi(_write(tmp_path, doc))["rest_endpoints"][0]
    assert ep["auth_headers"] == ["authorization"]


def test_apikey_header_name_is_used(tmp_path) -> None:
    doc = _doc(**{"/x": {"get": {"responses": {}}}})
    doc["components"] = {
        "securitySchemes": {"k": {"type": "apiKey", "in": "header", "name": "X-Api-Key"}}
    }
    doc["security"] = [{"k": []}]
    ep = import_openapi(_write(tmp_path, doc))["rest_endpoints"][0]
    assert ep["auth_headers"] == ["X-Api-Key"]


# ---------- CLI ----------


def test_main_writes_endpoints_json(tmp_path, capsys) -> None:
    path = _write(tmp_path, _doc(**{"/x": {"get": {"responses": {}}}}))
    out = tmp_path / "endpoints.json"
    main([path, "--out", str(out)])
    inv = json.loads(out.read_text())
    assert inv["source"] == "openapi"
    assert inv["graphql_operations"] == {}
    assert "REST operation" in capsys.readouterr().out


def test_main_exits_nonzero_on_bad_doc(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"paths": {}}')
    with pytest.raises(SystemExit):
        main([str(bad)])
