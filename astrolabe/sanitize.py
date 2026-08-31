"""Migrate legacy capture JSONL to the current structural-only boundary."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .security import request_metadata, safe_url


def sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
    cleaned = dict(record)
    sample = cleaned.pop("req_body_sample", None)
    if sample is not None:
        cleaned.update(request_metadata(sample, cleaned.get("request_media_type", "")))
    if isinstance(cleaned.get("url"), str):
        cleaned["url"] = safe_url(cleaned["url"])
    return cleaned


def sanitize_capture(path: str | os.PathLike[str]) -> int:
    target = Path(path).resolve()
    count = 0
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with (
            os.fdopen(fd, "w", encoding="utf-8") as output,
            target.open(encoding="utf-8") as source,
        ):
            for line in source:
                if not line.strip():
                    continue
                record = sanitize_record(json.loads(line))
                output.write(json.dumps(record, separators=(",", ":")) + "\n")
                count += 1
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    return count


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture_jsonl")
    args = parser.parse_args(argv)
    count = sanitize_capture(args.capture_jsonl)
    print(f"sanitized {count} structural capture records")


if __name__ == "__main__":
    main()
