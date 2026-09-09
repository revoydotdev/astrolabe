"""The per-domain contract of record, accumulated across runs.

A contract already merges with a prior one, but only ever found that prior inside the
run's own output directory. Every run writes to a fresh directory, so in practice
nothing was ever merged: each capture produced a contract describing only the surfaces
that walk happened to touch. Two runs against the same target a minute apart added ten
operations and dropped eighteen, and the "contract of record" was really a record of
one walk.

Completeness is a property of a target, not of a directory. This keeps one contract per
domain outside any single run, so a walk of a site's profile pages and a walk of its
search pages compose into one contract instead of overwriting each other.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re

DEFAULT_STORE = ".astrolabe/contracts"
STORE_ENVIRONMENT_VARIABLE = "ASTROLABE_CONTRACT_STORE"

# A domain becomes a filename, so it must be one path segment of an expected shape and
# nothing else. Anything unexpected is refused rather than sanitized into a neighbouring
# path: a contract written outside the store is worse than no accumulation at all.
_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


class ContractStoreError(ValueError):
    """Raised when a contract store path cannot be formed safely."""


def store_root(explicit: str | None = None) -> Path:
    """Where per-domain contracts live: explicit, else environment, else the default."""
    configured = explicit or os.environ.get(STORE_ENVIRONMENT_VARIABLE) or DEFAULT_STORE
    return Path(configured).expanduser()


def store_path(domain: str, *, root: str | None = None) -> Path:
    """Path of the contract of record for one domain."""
    normalized = (domain or "").strip().lower().rstrip(".")
    if not _DOMAIN.match(normalized) or ".." in normalized:
        raise ContractStoreError(f"unsupported contract domain: {domain!r}")
    return store_root(root) / f"{normalized}.json"


def prior_contract(domain: str, *, root: str | None = None) -> Path | None:
    """The accumulated contract to merge into this run, if one exists yet."""
    path = store_path(domain, root=root)
    return path if path.is_file() else None


def publish(domain: str, contract_path: str | Path, *, root: str | None = None) -> Path:
    """Promote a run's contract to the domain's contract of record.

    The run's own contract already merged the prior one, so it is the more complete
    document by construction. Written atomically, because a half-written contract of
    record would silently narrow every later run that merges it.
    """
    from .artifact import atomic_write_json

    source = Path(contract_path)
    if not source.is_file():
        raise ContractStoreError(f"no contract to publish at {source}")
    with source.open(encoding="utf-8") as handle:
        contract = json.load(handle)
    destination = store_path(domain, root=root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(str(destination), contract)
    return destination
