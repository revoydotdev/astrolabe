"""Dogfood: Reels tab, Tagged tab and profile picture through sextant.

usage: uv run python scripts/ig_extras.py <toolpack.json> <user_pk> <out_dir>
Reels tab nodes carry no video URLs; this lists every reel code and records which are
already in the grid backup (posts.json). Tagged posts are downloaded in full.
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

PV = "__relay_internal__pv__Polaris{}relayprovider"


async def call(c, op: str, args: dict) -> dict:
    r = await c.call_tool("call_tool", {"operation_id": f"instagram_com__{op}", "arguments": args})
    d = r.structured_content or json.loads(r.content[0].text)
    if d.get("ok") is False:
        raise SystemExit(f"{op} refused: {d.get('error_code')}: {str(d.get('error_detail'))[:300]}")
    return d["data"]


async def main() -> None:
    toolpack, pk, out = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    os.environ["ASTROLABE_TOOLPACKS"] = toolpack
    os.environ.setdefault("ASTROLABE_MAX_RESPONSE_BYTES", "8000000")
    from fastmcp import Client

    from astrolabe.sextant import create_server

    cdn = requests.Session(impersonate="chrome")
    async with Client(create_server()) as c:
        # Reels tab
        reels: list[dict] = []
        after = None
        while True:
            base = {
                "data": {"include_feed_video": True, "page_size": 12, "target_user_id": pk},
                PV.format("ShortDramaEnabled"): True,
            }
            if after:
                d = await call(
                    c,
                    "PolarisProfileReelsTabContentQuery_connection",
                    {**base, "after": after, "first": 12, "id": pk},
                )
            else:
                d = await call(c, "PolarisProfileReelsTabContentQuery", {**base, "user_id": pk})
            conn = d["fetch__XDTUserDict"]["clips_connection"]
            reels += [e["node"]["media"] for e in conn["edges"]]
            print(f"  reels: {len(reels)}", flush=True)
            if not conn["page_info"].get("has_next_page"):
                break
            after = conn["page_info"]["end_cursor"]
            await asyncio.sleep(1.5)
        (out / "reels_tab.json").write_text(json.dumps(reels, indent=1, ensure_ascii=False))

        # Tagged tab
        tagged: list[dict] = []
        after = None
        tdir = out / "tagged"
        tdir.mkdir(parents=True, exist_ok=True)
        while True:
            base = {
                "count": 12,
                "user_id": pk,
                PV.format("ShortDramaEnabled"): True,
                PV.format("SEOIsCrawler"): False,
            }
            if after:
                d = await call(
                    c,
                    "PolarisProfileTaggedTabContentQuery_connection",
                    {**base, "after": after, "first": 12, "before": None, "last": None},
                )
            else:
                d = await call(c, "PolarisProfileTaggedTabContentQuery", base)
            conn = d["xdt_api__v1__usertags__user_id__feed_connection"]
            page = [e["node"] for e in conn["edges"]]
            tagged += page
            for n in page:
                owner = (n.get("user") or {}).get("username") or "unknown"
                stem = f"{time.strftime('%Y-%m-%d', time.gmtime(n.get('taken_at') or 0))}_{owner}_{n['code']}"
                save_media(cdn, n, tdir, stem)
                if cap := ((n.get("caption") or {}).get("text")):
                    (tdir / f"{stem}.txt").write_text(cap, encoding="utf-8")
            (out / "tagged.json").write_text(json.dumps(tagged, indent=1, ensure_ascii=False))
            print(f"  tagged: {len(tagged)}", flush=True)
            if not conn["page_info"].get("has_next_page"):
                break
            after = conn["page_info"]["end_cursor"]
            await asyncio.sleep(1.5)

        # Profile picture + metadata
        prof = await call(
            c,
            "PolarisProfilePageContentQuery",
            {"id": pk, "enable_integrity_filters": True}
            | {
                PV.format(k): False
                for k in (
                    "CASB976ProfileEnabled",
                    "CannesGuardianExperienceEnabled",
                    "ProfileInformTreatmentBannerEnabled",
                    "ProfileRingsGradientEnabled",
                    "RepostsConsumptionEnabled",
                    "ShortDramaEnabled",
                    "WebSchoolsEnabled",
                )
            },
        )
        (out / "profile.json").write_text(json.dumps(prof, indent=1, ensure_ascii=False))
        user = prof.get("user") or {}
        pic = (user.get("hd_profile_pic_url_info") or {}).get("url") or user.get("profile_pic_url")
        if pic:
            r = cdn.get(pic, timeout=60)
            if r.status_code == 200:
                (out / "profile_pic.jpg").write_bytes(r.content)

    grid = (
        {n["code"] for n in json.loads((out / "posts.json").read_text())}
        if (out / "posts.json").exists()
        else set()
    )
    missing = [r["code"] for r in reels if r["code"] not in grid]
    (out / "reels_not_in_grid.txt").write_text("\n".join(missing))
    print(
        f"reels {len(reels)} (not in grid yet: {len(missing)}), tagged {len(tagged)}, profile_pic {'yes' if pic else 'no'}"
    )


if __name__ == "__main__":
    asyncio.run(main())
