"""Versioned, atomic, recoverable artifact I/O and lineage manifests."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
MANIFEST_SCHEMA_VERSION = 1


class ArtifactError(RuntimeError):
    """An artifact is corrupt, incompatible, or could not be written durably."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_dir(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(
    path: str | os.PathLike[str],
    data: bytes,
    *,
    mode: int = 0o644,
    retain_last_known_good: bool = True,
) -> None:
    """Write, fsync, validate-by-construction, replace, and fsync the directory."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    backup = target.with_name(f".{target.name}.lkg")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if retain_last_known_good and target.is_file():
            shutil.copyfile(target, backup)
            os.chmod(backup, mode)
            with backup.open("rb") as handle:
                os.fsync(handle.fileno())
        os.replace(temporary, target)
        _fsync_dir(target.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_json(
    path: str | os.PathLike[str],
    value: Any,
    *,
    mode: int = 0o644,
    retain_last_known_good: bool = True,
) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    # Validate serialization before touching either current or LKG state.
    json.loads(payload)
    atomic_write_bytes(
        path,
        payload,
        mode=mode,
        retain_last_known_good=retain_last_known_good,
    )


def atomic_write_text(
    path: str | os.PathLike[str],
    value: str,
    *,
    mode: int = 0o644,
    retain_last_known_good: bool = True,
) -> None:
    atomic_write_bytes(
        path,
        value.encode(),
        mode=mode,
        retain_last_known_good=retain_last_known_good,
    )


def read_json_artifact(
    path: str | os.PathLike[str],
    *,
    label: str = "artifact",
    supported_versions: set[int] | frozenset[int] | None = None,
) -> Any:
    target = Path(path)
    try:
        with target.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"cannot read valid {label} at {target}: {exc}") from exc
    if supported_versions is not None:
        if not isinstance(value, dict) or not isinstance(value.get("schema_version"), int):
            raise ArtifactError(f"{label} has no integer schema_version")
        version = value["schema_version"]
        if version not in supported_versions:
            raise ArtifactError(
                f"unsupported {label} schema_version {version}; "
                f"supported: {sorted(supported_versions)}; run `astrolabe migrate-artifact`"
            )
    return value


@dataclass(slots=True)
class ArtifactManifest:
    artifact_schema_version: int
    artifact_type: str
    run_id: str
    target: str
    completeness: str
    started_at: str
    completed_at: str
    profile: str | None = None
    parent_artifacts: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    adapters: list[str] = field(default_factory=list)
    failures: list[dict[str, Any]] = field(default_factory=list)
    truncations: dict[str, int] = field(default_factory=dict)
    safety_mode: str = "read-only"
    astrolabe_version: str = __version__
    astrolabe_commit: str | None = None
    schema_version: int = MANIFEST_SCHEMA_VERSION
    generated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["$schema"] = JSON_SCHEMA_DIALECT
        return value


def build_manifest(
    directory: str | os.PathLike[str],
    *,
    artifact_type: str,
    artifact_schema_version: int,
    run_id: str,
    target: str,
    completeness: str,
    started_at: str,
    completed_at: str,
    artifact_names: list[str],
    **kwargs: Any,
) -> ArtifactManifest:
    root = Path(directory)
    hashes = {
        name: sha256_file(root / name)
        for name in artifact_names
        if (root / name).is_file()
    }
    return ArtifactManifest(
        artifact_schema_version=artifact_schema_version,
        artifact_type=artifact_type,
        run_id=run_id,
        target=target,
        completeness=completeness,
        started_at=started_at,
        completed_at=completed_at,
        artifacts=hashes,
        **kwargs,
    )


def verify_manifest(directory: str | os.PathLike[str], manifest: ArtifactManifest) -> list[str]:
    root = Path(directory)
    failures = []
    for name, expected in manifest.artifacts.items():
        path = root / name
        if not path.is_file():
            failures.append(f"missing:{name}")
        elif sha256_file(path) != expected:
            failures.append(f"checksum:{name}")
    return failures


def write_manifest(path: str | os.PathLike[str], manifest: ArtifactManifest) -> None:
    from .schema import validate_artifact

    value = manifest.to_dict()
    validate_artifact(value, "artifact-manifest-v1.schema.json")
    atomic_write_json(path, value)


def load_manifest(path: str | os.PathLike[str]) -> ArtifactManifest:
    value = read_json_artifact(
        path,
        label="artifact manifest",
        supported_versions={MANIFEST_SCHEMA_VERSION},
    )
    from .schema import validate_artifact

    validate_artifact(value, "artifact-manifest-v1.schema.json")
    fields = {key: item for key, item in value.items() if key != "$schema"}
    return ArtifactManifest(**fields)
