"""Dogfood: fetch reels missing from the grid backup via the Chart's media-info REST op.

usage: uv run python scripts/ig_reels.py <toolpack.json> <out_dir>
Reads reels_not_in_grid.txt + reels_tab.json (written by ig_extras.py), saves to reels/.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

from curl_cffi import requests

sys.path.insert(0, str(Path(__file__).parent))
from ig_backup import save_media  # noqa: E402


async def main() -> None:
    toolpack, out = sys.argv[1], Path(sys.argv[2])
    os.environ["ASTROLABE_TOOLPACKS"] = toolpack
    os.environ.setdefault("ASTROLABE_MAX_RESPONSE_BYTES", "8000000")
    from fastmcp import Client

    from astrolabe.sextant import create_server

    pks = {
        r["code"]: r.get("pk") or r.get("id")
        for r in json.loads((out / "reels_tab.json").read_text())
    }
    codes = (out / "reels_not_in_grid.txt").read_text().split()
    rdir = out / "reels"
    rdir.mkdir(exist_ok=True)
    cdn = requests.Session(impersonate="chrome")
    meta, got = [], 0
    async with Client(create_server()) as c:
        for code in codes:
            r = await c.call_tool(
                "call_tool",
                {
                    "operation_id": "instagram_com__getApiV1MediaIdInfo",
                    "arguments": {"id": str(pks[code])},
                },
            )
            d = r.structured_content or json.loads(r.content[0].text)
            if d.get("ok") is False:
                print(f"  {code}: {d.get('error_code')}", flush=True)
                continue
            for n in d["data"].get("items") or []:
                meta.append(n)
                stem = (
                    f"{time.strftime('%Y-%m-%d', time.gmtime(n.get('taken_at') or 0))}_{n['code']}"
                )
                got += save_media(cdn, n, rdir, stem)
                if cap := ((n.get("caption") or {}).get("text")):
                    (rdir / f"{stem}.txt").write_text(cap, encoding="utf-8")
                print(f"  {code}: ok", flush=True)
            await asyncio.sleep(1.5)
    (out / "reels.json").write_text(json.dumps(meta, indent=1, ensure_ascii=False))
    print(f"reels: {len(meta)}/{len(codes)}, {got} new files")


if __name__ == "__main__":
    asyncio.run(main())
