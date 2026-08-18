#!/usr/bin/env python3
"""astrolabe import-openapi — turn an OpenAPI / Swagger document into an endpoints.json.

Capture-driven mapping infers a REST surface from observed traffic. When a target
already publishes an OpenAPI/Swagger document, that document is the authoritative
contract — every operation, every parameter, real types and required-ness,
including operations no capture ever exercised — and it is available with zero
live-traffic risk. This importer consumes such a document and emits the same
`endpoints.json` shape `astrolabe analyze` produces, so the rest of the pipeline
(`contract`, `mcp-gen`, the server) consumes it unchanged.

Supports OpenAPI 3.x (`paths` + `components/schemas`) and Swagger 2.0 (`paths` +
`definitions`). `$ref` is resolved within the document, depth-bounded against the
self-referential schemas these documents routinely contain.

Scope: REST only. The output carries `rest_endpoints` with typed path/query/body
inputs and, where the document declares a 2xx response schema, a `return_schema`.
It does not fabricate a capture: proof tiers stay the contract's job, and an
imported endpoint is `typed-unproven` until a real capture observes it.

This reads a document the operator supplies; it does not fetch anything. A
malicious document can only produce a malformed inventory, never execute — it is
parsed as data, never imported as code.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

from .artifact import atomic_write_json, build_manifest, write_manifest
from .ir import SourceKind, graph_from_inventory, write_graph

MAX_REF_DEPTH = 8
MAX_EXTERNAL_REF_BYTES = 2_000_000
MAX_EXTERNAL_REF_DOCUMENTS = 32
MAX_EXTERNAL_REF_TOTAL_BYTES = 8_000_000
_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options"}
_SCALAR = {
    "integer": "integer",
    "number": "number",
    "string": "string",
    "boolean": "boolean",
}


class OpenAPIImportError(ValueError):
    """Raised when a document cannot be read as OpenAPI/Swagger."""


def _load(path: str) -> Any:
    if not os.path.exists(path):
        raise OpenAPIImportError(f"no such file: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise OpenAPIImportError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        # YAML swagger is common; only support it if PyYAML happens to be present,
        # since astrolabe does not depend on it.
        try:
            import yaml  # type: ignore[import-untyped]
        except ModuleNotFoundError:
            raise OpenAPIImportError(
                f"{path} is not JSON and PyYAML is not installed to parse YAML: {exc}"
            ) from exc
        return yaml.safe_load(text)


class Document:
    """An OpenAPI 3.x or Swagger 2.0 document with within-document $ref resolution."""

    def __init__(
        self,
        raw: Any,
        *,
        base_uri: str = "",
        external_ref_paths: dict[str, str] | None = None,
    ) -> None:
        if not isinstance(raw, dict):
            raise OpenAPIImportError("document root must be an object")
        self.raw = raw
        self.is_v3 = "openapi" in raw
        self.is_v2 = str(raw.get("swagger", "")).startswith("2")
        if not self.is_v3 and not self.is_v2:
            raise OpenAPIImportError("not an OpenAPI 3.x or Swagger 2.0 document")
        paths = raw.get("paths")
        if not isinstance(paths, dict):
            raise OpenAPIImportError("document declares no paths")
        self.paths = paths
        self.base_uri = base_uri
        self.external_ref_paths = dict(external_ref_paths or {})
        self._external_cache: dict[str, Any] = {}
        self._external_bytes = 0
        if len(self.external_ref_paths) > MAX_EXTERNAL_REF_DOCUMENTS:
            raise OpenAPIImportError("too many authorized external reference documents")
        for uri in self.external_ref_paths:
            base, fragment = urldefrag(uri)
            if not base or fragment or base != uri:
                raise OpenAPIImportError(
                    "external reference authorization keys must be absolute fragment-free URIs"
                )

    def base_domain(self, override: str | None) -> str:
        if override:
            return override
        # OpenAPI 3: servers[].url ; Swagger 2: host (+ basePath).
        if self.is_v3:
            servers = self.raw.get("servers")
            if isinstance(servers, list) and servers:
                url = servers[0].get("url") if isinstance(servers[0], dict) else None
                host = urlparse(url or "").hostname
                if host:
                    return host
        host = self.raw.get("host")
        if isinstance(host, str) and host:
            return host.split(":")[0]
        raise OpenAPIImportError(
            "document declares no server host; pass --base-domain to name the target"
        )

    def resolve(self, node: Any, depth: int = 0) -> Any:
        """Follow a local `$ref` one hop; returns the node unchanged if not a ref."""
        if depth > MAX_REF_DEPTH or not isinstance(node, dict):
            return node
        ref = node.get("$ref")
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return node
        target: Any = self.raw
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(target, dict) and part in target:
                target = target[part]
            else:
                return {}
        return target

    def resolve_schema_ref(
        self, ref: str, *, current_uri: str | None = None
    ) -> tuple[Any, str, tuple[str, str]]:
        """Resolve a local or exactly authorized external schema reference."""
        context_uri = self.base_uri if current_uri is None else current_uri
        if ref.startswith("#"):
            document_uri = context_uri
            fragment = ref[1:]
            root = self.raw if document_uri == self.base_uri else self._load_external(document_uri)
        else:
            absolute = urljoin(context_uri, ref)
            document_uri, fragment = urldefrag(absolute)
            if document_uri not in self.external_ref_paths:
                raise OpenAPIImportError(
                    f"external schema ref {ref!r} is not authorized; "
                    "pass an exact URI=PATH authorization"
                )
            root = self._load_external(document_uri)
        target: Any = root
        if fragment:
            if not fragment.startswith("/"):
                raise OpenAPIImportError("external schema ref fragment must be a JSON Pointer")
            for raw_part in fragment[1:].split("/"):
                part = raw_part.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or part not in target:
                    raise OpenAPIImportError(f"schema ref {ref!r} points to a missing value")
                target = target[part]
        return target, document_uri, (document_uri, fragment)

    def _load_external(self, uri: str) -> Any:
        if uri in self._external_cache:
            return self._external_cache[uri]
        path = self.external_ref_paths.get(uri)
        if path is None:
            raise OpenAPIImportError(f"external schema ref {uri!r} is not authorized")
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            raise OpenAPIImportError(f"cannot stat authorized external ref {uri!r}: {exc}") from exc
        if size > MAX_EXTERNAL_REF_BYTES:
            raise OpenAPIImportError(f"authorized external ref {uri!r} exceeds the size limit")
        if self._external_bytes + size > MAX_EXTERNAL_REF_TOTAL_BYTES:
            raise OpenAPIImportError("authorized external refs exceed the total size limit")
        value = _load(path)
        if not isinstance(value, dict):
            raise OpenAPIImportError(f"authorized external ref {uri!r} must contain an object")
        self._external_bytes += size
        self._external_cache[uri] = value
        return value

    def server_urls(
        self,
        path_item: dict[str, Any],
        operation: dict[str, Any],
        base_domain: str,
    ) -> list[str]:
        """Resolve operation/path/root servers, including variables and Swagger basePath."""
        if self.is_v2:
            host = str(self.raw.get("host") or base_domain)
            schemes = self.raw.get("schemes") or ["https"]
            base_path = str(self.raw.get("basePath") or "")
            return [f"{scheme}://{host}{base_path}".rstrip("/") for scheme in schemes]

        servers = operation.get("servers") or path_item.get("servers") or self.raw.get("servers")
        if not servers:
            return [f"https://{base_domain}"]
        root_servers = self.raw.get("servers") or []
        root_base = None
        if root_servers and isinstance(root_servers[0], dict):
            candidate = self._expand_server(root_servers[0])
            if urlparse(candidate).scheme:
                root_base = candidate
        root_base = root_base or f"https://{base_domain}/"
        urls: list[str] = []
        for server in servers:
            if not isinstance(server, dict):
                continue
            value = self._expand_server(server)
            resolved = urljoin(root_base.rstrip("/") + "/", value)
            urls.append(resolved.rstrip("/"))
        return list(dict.fromkeys(urls))

    @staticmethod
    def _expand_server(server: dict[str, Any]) -> str:
        value = server.get("url")
        if not isinstance(value, str):
            raise OpenAPIImportError("server.url must be a string")
        variables = server.get("variables") or {}
        for name in re.findall(r"\{([^{}]+)\}", value):
            spec = variables.get(name) if isinstance(variables, dict) else None
            default = spec.get("default") if isinstance(spec, dict) else None
            if default is None:
                raise OpenAPIImportError(f"server variable {name!r} has no default")
            value = value.replace("{" + name + "}", str(default))
        return value


def schema_to_json_schema(
    doc: Document,
    node: Any,
    depth: int = 0,
    *,
    current_uri: str | None = None,
    seen_refs: frozenset[tuple[str, str]] = frozenset(),
) -> dict[str, Any]:
    """Convert an OpenAPI/Swagger schema object to JSON Schema, resolving $ref.

    Nullability is rendered as a union with "null" so a caller can tell a
    guaranteed field from an optional one — the same convention astrolabe's
    capture-derived schemas use.
    """
    if depth > MAX_REF_DEPTH:
        return {"x-astrolabe-truncated": "schema-depth"}
    if not isinstance(node, dict):
        return {}
    ref = node.get("$ref")
    if isinstance(ref, str):
        if depth >= MAX_REF_DEPTH:
            return {"x-astrolabe-truncated-ref": ref}
        resolved, resolved_uri, ref_key = doc.resolve_schema_ref(ref, current_uri=current_uri)
        if ref_key in seen_refs:
            return {"x-astrolabe-truncated-ref": ref, "x-astrolabe-cycle": True}
        return schema_to_json_schema(
            doc,
            resolved,
            depth + 1,
            current_uri=resolved_uri,
            seen_refs=seen_refs | {ref_key},
        )

    def convert(value: Any) -> dict[str, Any]:
        return schema_to_json_schema(
            doc,
            value,
            depth + 1,
            current_uri=current_uri,
            seen_refs=seen_refs,
        )

    out: dict[str, Any] = {}
    for combiner in ("allOf", "oneOf", "anyOf"):
        if isinstance(node.get(combiner), list):
            out[combiner] = [convert(item) for item in node[combiner]]
    if isinstance(node.get("not"), dict):
        out["not"] = convert(node["not"])

    typ = node.get("type")
    if typ == "file":
        typ = "string"
        out["format"] = "binary"
        out["contentEncoding"] = "base64"
    if isinstance(typ, (str, list)):
        out["type"] = typ
    elif "properties" in node:
        out["type"] = "object"

    if isinstance(node.get("properties"), dict):
        out["properties"] = {
            str(name): convert(schema) for name, schema in node["properties"].items()
        }
    if "items" in node:
        if isinstance(node["items"], list):
            out["prefixItems"] = [convert(item) for item in node["items"]]
        else:
            out["items"] = convert(node["items"])
    additional = node.get("additionalProperties")
    if isinstance(additional, bool):
        out["additionalProperties"] = additional
    elif isinstance(additional, dict):
        out["additionalProperties"] = convert(additional)
    if isinstance(node.get("required"), list):
        out["required"] = sorted({str(item) for item in node["required"]})

    copied_keywords = {
        "title",
        "description",
        "default",
        "deprecated",
        "readOnly",
        "writeOnly",
        "format",
        "pattern",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "multipleOf",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
        "const",
        "enum",
        "contentEncoding",
        "contentMediaType",
    }
    for keyword in copied_keywords:
        if keyword in node:
            out[keyword] = node[keyword]
    for keyword in ("exclusiveMinimum", "exclusiveMaximum"):
        value = node.get(keyword)
        if isinstance(value, bool):
            boundary = node.get("minimum" if keyword == "exclusiveMinimum" else "maximum")
            if value and isinstance(boundary, (int, float)):
                out[keyword] = boundary
                out.pop("minimum" if keyword == "exclusiveMinimum" else "maximum", None)
        elif isinstance(value, (int, float)):
            out[keyword] = value
    if isinstance(node.get("discriminator"), dict):
        out["x-openapi-discriminator"] = node["discriminator"]
    if node.get("nullable") is True:
        current_type = out.get("type")
        if isinstance(current_type, str):
            out["type"] = [current_type, "null"]
        elif isinstance(current_type, list) and "null" not in current_type:
            out["type"] = [*current_type, "null"]
        else:
            out = {"anyOf": [out, {"type": "null"}]}
    if not out and isinstance(node.get("enum"), list):
        out = {"enum": node["enum"]}
    return out


def _parameters(
    doc: Document, operation: dict[str, Any], shared: Any
) -> tuple[dict[str, Any], list[dict[str, Any]], str | None]:
    """Build the MCP input schema and an exact location/serialization contract."""
    raw_specs: list[dict[str, Any]] = []
    body_media_type: str | None = None
    params = list(shared or []) + list(operation.get("parameters") or [])
    for raw_param in params:
        param = doc.resolve(raw_param)
        if not isinstance(param, dict):
            continue
        name = param.get("name")
        location = param.get("in")
        if not isinstance(name, str) or location not in {
            "path",
            "query",
            "header",
            "cookie",
            "body",
            "formData",
        }:
            continue
        schema_node = param.get("schema") if (doc.is_v3 or location == "body") else param
        schema = schema_to_json_schema(doc, schema_node) or {"type": "string"}
        if location == "body":
            body_media_type = next(
                iter(operation.get("consumes") or doc.raw.get("consumes") or ["application/json"])
            )
            if schema.get("type") == "object" and isinstance(schema.get("properties"), dict):
                for property_name, property_schema in schema["properties"].items():
                    raw_specs.append(
                        {
                            "name": property_name,
                            "location": "body",
                            "required": property_name in set(schema.get("required") or []),
                            "schema": property_schema,
                        }
                    )
            else:
                raw_specs.append(
                    {
                        "name": "body",
                        "location": "body",
                        "required": bool(param.get("required")),
                        "schema": schema,
                    }
                )
            continue
        normalized_location = "form" if location == "formData" else location
        if normalized_location == "form":
            consumes = operation.get("consumes") or doc.raw.get("consumes") or []
            body_media_type = (
                "multipart/form-data"
                if "multipart/form-data" in consumes or param.get("type") == "file"
                else "application/x-www-form-urlencoded"
            )
        raw_specs.append(
            {
                "name": name,
                "location": normalized_location,
                "required": bool(param.get("required") or location == "path"),
                "schema": schema,
                "style": param.get("style") or _default_style(normalized_location),
                "explode": param.get("explode", _default_explode(normalized_location)),
                "allow_reserved": bool(param.get("allowReserved")),
                "collection_format": param.get("collectionFormat"),
            }
        )

    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        request_body = doc.resolve(request_body)
        content = request_body.get("content") if isinstance(request_body, dict) else None
        if isinstance(content, dict) and content:
            body_media_type = (
                "application/json" if "application/json" in content else next(iter(content))
            )
            media = content[body_media_type]
            body_schema = (
                schema_to_json_schema(doc, media.get("schema")) if isinstance(media, dict) else {}
            )
            body_required = bool(request_body.get("required"))
            if body_schema.get("type") == "object" and isinstance(
                body_schema.get("properties"), dict
            ):
                schema_required = set(body_schema.get("required") or [])
                for name, schema in body_schema["properties"].items():
                    raw_specs.append(
                        {
                            "name": name,
                            "location": "body",
                            "required": name in schema_required,
                            "schema": schema,
                        }
                    )
            else:
                raw_specs.append(
                    {
                        "name": "body",
                        "location": "body",
                        "required": body_required,
                        "schema": body_schema or {},
                    }
                )

    name_counts: dict[str, int] = {}
    for spec in raw_specs:
        name_counts[spec["name"]] = name_counts.get(spec["name"], 0) + 1
    properties: dict[str, Any] = {}
    required: list[str] = []
    for spec in raw_specs:
        argument = (
            spec["name"] if name_counts[spec["name"]] == 1 else f"{spec['location']}_{spec['name']}"
        )
        spec["argument"] = argument
        properties[argument] = spec["schema"]
        if spec["required"]:
            required.append(argument)
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = sorted(set(required))
    return schema, raw_specs, body_media_type


def _default_style(location: str) -> str:
    return "simple" if location in {"path", "header"} else "form"


def _default_explode(location: str) -> bool:
    return location in {"query", "cookie", "form"}


def _response_variants(doc: Document, operation: dict[str, Any]) -> list[dict[str, Any]]:
    """Preserve every declared status/media variant without conflating errors and success."""
    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return []
    variants: list[dict[str, Any]] = []
    for raw_code, raw_response in responses.items():
        code = str(raw_code).upper()
        resp = raw_response
        if not isinstance(resp, dict):
            continue
        resp = doc.resolve(resp)
        success = code.startswith("2")
        headers = resp.get("headers") or {}
        header_schemas = {
            str(name): schema_to_json_schema(
                doc,
                value.get("schema") if doc.is_v3 and isinstance(value, dict) else value,
            )
            for name, value in headers.items()
            if isinstance(value, dict)
        }
        if doc.is_v3:
            content = resp.get("content")
            if isinstance(content, dict) and content:
                for media_type, media in content.items():
                    schema = media.get("schema") if isinstance(media, dict) else None
                    variants.append(
                        {
                            "status": code,
                            "success": success,
                            "media_type": media_type,
                            "schema": schema_to_json_schema(doc, schema) if schema else None,
                            "headers": header_schemas,
                            "links": sorted((resp.get("links") or {}).keys()),
                        }
                    )
                continue
        else:
            schema = resp.get("schema")
            produces = operation.get("produces") or doc.raw.get("produces") or ["application/json"]
            for media_type in produces:
                variants.append(
                    {
                        "status": code,
                        "success": success,
                        "media_type": media_type,
                        "schema": schema_to_json_schema(doc, schema) if schema else None,
                        "headers": header_schemas,
                        "links": [],
                    }
                )
            continue
        variants.append(
            {
                "status": code,
                "success": success,
                "media_type": None,
                "schema": None,
                "headers": header_schemas,
                "links": sorted((resp.get("links") or {}).keys()),
            }
        )
    return variants


def _return_schema(variants: list[dict[str, Any]]) -> Any:
    schemas = [item["schema"] for item in variants if item["success"] and item.get("schema")]
    if not schemas:
        return None
    unique = {json.dumps(item, sort_keys=True): item for item in schemas}
    return next(iter(unique.values())) if len(unique) == 1 else {"oneOf": list(unique.values())}


def build_inventory(doc: Document, base_domain: str) -> dict[str, Any]:
    """Emit an endpoints.json-shaped inventory from the document's REST operations."""
    rest: list[dict[str, Any]] = []
    misc: dict[str, dict[str, Any]] = {}
    auth_headers: dict[str, int] = {}
    for path, item in doc.paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters")
        for method, operation in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            input_schema, parameters, body_media_type = _parameters(doc, operation, shared_params)
            server_urls = doc.server_urls(item, operation, base_domain)
            normalized_path = _normalise_path(path)
            request_urls = [server.rstrip("/") + normalized_path for server in server_urls]
            response_variants = _response_variants(doc, operation)
            entry: dict[str, Any] = {
                "method": method.upper(),
                "path": normalized_path,
                "request_url": request_urls[0],
                "servers": server_urls,
                "operationId": operation.get("operationId"),
                "summary": operation.get("summary"),
                "auth_headers": _auth_names(doc, operation),
                "calls": 0,  # never observed — this is documentation, not traffic
                "status": [],
                "input_schema": input_schema,
                "parameters": parameters,
                "body_media_type": body_media_type,
                "return_schema": _return_schema(response_variants),
                "response_variants": response_variants,
                "callbacks": sorted((operation.get("callbacks") or {}).keys()),
                "source": "openapi",
            }
            for name in entry["auth_headers"]:
                auth_headers[name] = auth_headers.get(name, 0) + 1
            rest.append(entry)
            for callback_name in entry["callbacks"]:
                identifier = f"webhook:callback:{operation.get('operationId') or method + ' ' + path}:{callback_name}"
                misc[identifier] = {
                    "id": identifier,
                    "protocol": "webhook",
                    "url": f"callback://{callback_name}",
                    "method": "CALLBACK",
                    "calls": 0,
                    "executable": False,
                    "disabled_reason": "declared callback; inventory-only",
                }
    for webhook_name, webhook_path in (doc.raw.get("webhooks") or {}).items():
        if not isinstance(webhook_path, dict):
            continue
        identifier = f"webhook:declared:{webhook_name}"
        misc[identifier] = {
            "id": identifier,
            "protocol": "webhook",
            "url": f"webhook://{webhook_name}",
            "method": sorted(
                method.upper() for method in webhook_path if method.lower() in _HTTP_METHODS
            ),
            "calls": 0,
            "executable": False,
            "disabled_reason": "declared webhook; inventory-only",
        }
    if not rest:
        raise OpenAPIImportError("document declares no HTTP operations")
    return {
        "base_domain": base_domain,
        "graphql_endpoints": [],
        "auth_headers": auth_headers,
        "graphql_operations": {},
        "rest_endpoints": rest,
        "websocket_operations": {},
        "misc_operations": misc,
        "source": "openapi",
    }


def _normalise_path(path: str) -> str:
    """OpenAPI already uses `{name}` placeholders — astrolabe's convention — so this is
    mostly a guard that the path is well-formed."""
    return path if path.startswith("/") else "/" + path


def _auth_names(doc: Document, operation: dict[str, Any]) -> list[str]:
    """Header names implied by the operation's security requirement.

    Only apiKey-in-header schemes name a concrete header; bearer/oauth imply
    Authorization. This is advisory (like capture's auth detection), so it is
    generous rather than exact.
    """
    schemes: dict[str, Any]
    if doc.is_v3:
        schemes = ((doc.raw.get("components") or {}).get("securitySchemes")) or {}
    else:
        schemes = doc.raw.get("securityDefinitions") or {}
    security = operation.get("security")
    if security is None:
        security = doc.raw.get("security")
    if not isinstance(security, list):
        return []
    names: list[str] = []
    for requirement in security:
        if not isinstance(requirement, dict):
            continue
        for scheme_name in requirement:
            scheme = schemes.get(scheme_name) if isinstance(schemes, dict) else None
            if not isinstance(scheme, dict):
                continue
            kind = scheme.get("type", "").lower()
            if kind == "apikey" and scheme.get("in") == "header" and scheme.get("name"):
                names.append(scheme["name"])
            elif kind in ("http", "oauth2") or scheme.get("scheme") == "bearer":
                names.append("authorization")
    return sorted(set(names))


def _external_ref_mapping(specs: list[str] | None) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for spec in specs or []:
        if "=" not in spec:
            raise OpenAPIImportError("--external-ref must use exact URI=LOCAL_PATH syntax")
        uri, path = spec.split("=", 1)
        if not uri or not path or not urlparse(uri).scheme:
            raise OpenAPIImportError("--external-ref requires an absolute URI and local path")
        if uri in mapping and os.path.abspath(mapping[uri]) != os.path.abspath(path):
            raise OpenAPIImportError(f"external ref {uri!r} was authorized more than once")
        mapping[uri] = os.path.abspath(os.path.expanduser(path))
    return mapping


def import_openapi(
    doc_path: str,
    base_domain: str | None = None,
    external_refs: list[str] | None = None,
) -> dict[str, Any]:
    absolute_path = os.path.abspath(doc_path)
    doc = Document(
        _load(absolute_path),
        base_uri=Path(absolute_path).as_uri(),
        external_ref_paths=_external_ref_mapping(external_refs),
    )
    return build_inventory(doc, doc.base_domain(base_domain))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="astrolabe-import-openapi")
    ap.add_argument("doc", help="path to an OpenAPI 3.x / Swagger 2.0 JSON (or YAML) file")
    ap.add_argument("--out", help="endpoints.json (default: <doc-dir>/endpoints.json)")
    ap.add_argument("--base-domain", help="override the target host (else read from the doc)")
    ap.add_argument(
        "--external-ref",
        action="append",
        default=[],
        metavar="URI=LOCAL_PATH",
        help="authorize one exact external $ref URI using a bounded local document",
    )
    a = ap.parse_args(argv)

    try:
        inv = import_openapi(a.doc, a.base_domain, a.external_ref)
    except OpenAPIImportError as exc:
        raise SystemExit(f"[import-openapi] {exc}") from exc

    out = a.out or os.path.join(os.path.dirname(os.path.abspath(a.doc)), "endpoints.json")
    atomic_write_json(out, inv)
    directory = os.path.dirname(os.path.abspath(out))
    graph_path = os.path.join(directory, "graph.json")
    now = datetime.now(UTC).isoformat()
    graph = graph_from_inventory(
        inv,
        [],
        {"run_id": f"openapi-{inv['base_domain']}", "captured_at": now},
        source=SourceKind.OPENAPI,
    )
    write_graph(graph_path, graph)
    manifest = build_manifest(
        directory,
        artifact_type="openapi-import",
        artifact_schema_version=1,
        run_id=graph.runs[0].id,
        target=inv["base_domain"],
        completeness="complete",
        started_at=now,
        completed_at=now,
        artifact_names=[os.path.basename(out), "graph.json"],
        adapters=["openapi"],
    )
    write_manifest(os.path.join(directory, "artifact-manifest.json"), manifest)
    rest = inv["rest_endpoints"]
    typed_ret = sum(1 for e in rest if e.get("return_schema"))
    print(
        f"[import-openapi] {len(rest)} REST operations "
        f"({typed_ret} with a declared return schema) on {inv['base_domain']} -> {out}"
    )
    print("  next: astrolabe contract <dir>  then  astrolabe mcp-gen <dir>")


if __name__ == "__main__":
    main()
