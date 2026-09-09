"""Exact APQ document recovery from the browser's own SHA-256 inputs.

No bundle evaluation, guessed documents, or semantic classification by name.
Unmatched hash inputs stay in a bounded browser-local cache and are never exported.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

try:
    from .graphql_doc import parse_graphql_document
    from .security import safe_url
except ImportError:  # flat capture-host deployment
    from graphql_doc import parse_graphql_document  # type: ignore[import-not-found,no-redef]
    from security import safe_url  # type: ignore[import-not-found,no-redef]

MAX_DOCUMENT_BYTES = 262_144

# Observe without replacing the returned promise or modifying the input/result.
# Rejected digests remain rejected; observation failures never break application code.
RECOVERY_INIT_SCRIPT = r"""(() => {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle || globalThis.__astrolabeAPQ) return;
  const documents = new Map();
  let bytes = 0;
  Object.defineProperty(globalThis, '__astrolabeAPQ', {
    value: hashes => hashes.slice(0, 32).map(hash => ({hash, document: documents.get(hash)}))
  });
  const digest = subtle.digest;
  subtle.digest = function(algorithm, data) {
    let document;
    try {
      const name = typeof algorithm === 'string' ? algorithm : algorithm.name;
      if (String(name).toUpperCase() === 'SHA-256' && data.byteLength <= 262144) {
        const buffer = ArrayBuffer.isView(data)
          ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
          : new Uint8Array(data);
        const text = new TextDecoder('utf-8', {fatal: true}).decode(buffer);
        if (/^\s*(query|mutation|subscription|fragment)\b/.test(text)) document = text;
      }
    } catch (_) {}
    const result = digest.call(this, algorithm, data);
    if (document) result.then(value => {
      try {
        const hash = Array.from(new Uint8Array(value), b => b.toString(16).padStart(2, '0')).join('');
        if (!documents.has(hash)) {
          while (documents.size >= 128 || bytes + document.length * 2 > 2097152) {
            const oldest = documents.keys().next().value;
            bytes -= documents.get(oldest).length * 2;
            documents.delete(oldest);
          }
          documents.set(hash, document);
          bytes += document.length * 2;
        }
      } catch (_) {}
    }, () => {});
    return result;
  };
})();"""

RECOVERY_READ_SCRIPT = (
    "hashes => globalThis.__astrolabeAPQ ? globalThis.__astrolabeAPQ(hashes) : []"
)


def bind_document(
    entry: dict[str, Any], document: Any, *, source_url: str, observed_at: str
) -> dict[str, Any]:
    """Return enriched evidence only for one strictly parsed, exactly matched APQ op."""
    digest = entry.get("persistedHash")
    if (
        entry.get("protocol") != "graphql-apq"
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-fA-F]{64}", digest)
        or not isinstance(document, str)
        or len(document) > MAX_DOCUMENT_BYTES
    ):
        return entry
    try:
        encoded = document.encode("utf-8")
    except UnicodeError:
        return entry
    if len(encoded) > MAX_DOCUMENT_BYTES or hashlib.sha256(encoded).hexdigest() != digest.lower():
        return entry
    parsed = parse_graphql_document(document, entry.get("operationName"))
    # Multi-operation and tolerant documents remain inventory-only in this recovery path.
    if len(parsed) != 1 or not parsed[0].selected or parsed[0].parse_confidence != "parsed":
        return entry
    operation = parsed[0]
    evidence = {
        "source": "browser-webcrypto-sha256",
        "source_url": safe_url(source_url),
        "observed_at": observed_at,
        "sha256": digest.lower(),
        "binding": "exact-sha256",
    }
    return {
        **entry,
        "query": document,
        "semantic_kind": operation.semantic_kind,
        "parse_confidence": "parsed",
        "selected": True,
        "declared_variables": operation.variable_names,
        "response_keys": operation.response_keys,
        "root_fields": operation.root_fields,
        "directives": operation.directives,
        "request_template": {
            **(entry.get("request_template") or {}),
            "document_evidence": evidence,
        },
    }


def graphql_response_success(value: Any, entries: list[dict[str, Any]]) -> bool:
    """Observed semantic success, distinct from HTTP success or active verification."""
    if (
        not isinstance(value, dict)
        or value.get("errors")
        or not isinstance(value.get("data"), dict)
    ):
        return False
    selected = [item for item in entries if item.get("selected") is not False]
    if len(selected) != 1:
        return False
    keys = selected[0].get("response_keys") or []
    # Directives may omit selections; retain conservative evidence rather than guessing.
    return bool(value["data"]) and all(key in value["data"] for key in keys)
