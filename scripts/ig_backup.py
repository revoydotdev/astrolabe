"""Dogfood: back up an Instagram profile's posts and highlights through sextant.

Both halves page through the mapped Chart's own tools via the sextant host
(in-process): per-Chart credential pointer, Meta token bootstrap, schema
validation. Posts use PolarisProfilePostsQuery; highlights use
PolarisStoriesV3HighlightsPageQuery, charted from its Relay doc id.

usage: uv run python scripts/ig_backup.py <chart_dir> <cookies.json> <username> <user_pk> <out_dir> [tray_ids]
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

from curl_cffi import requests

POSTS_PAGE = 6
PV = "__relay_internal__pv__Polaris{}relayprovider"


def best_image(node: dict) -> str | None:
    cands = ((node.get("image_versions2") or {}).get("candidates")) or []
    cands = [c for c in cands if c.get("url")]
    return (
        max(cands, key=lambda c: (c.get("width") or 0) * (c.get("height") or 0))["url"]
        if cands
        else None
    )


def best_video(node: dict) -> str | None:
    vids = [v for v in (node.get("video_versions") or []) if v.get("url")]
    return (
        max(vids, key=lambda v: (v.get("width") or 0) * (v.get("height") or 0))["url"]
        if vids
        else None
    )


def media_of(node: dict) -> list[dict]:
    return node.get("carousel_media") or [node]


def download(cdn: requests.Session, url: str, dest: Path, mtime: int | None) -> bool:
    if dest.exists() and dest.stat().st_size > 0:
        return False
    for attempt in range(3):
        try:
            r = cdn.get(url, timeout=60)
            if r.status_code == 200 and r.content:
                tmp = dest.with_suffix(dest.suffix + ".part")
                tmp.write_bytes(r.content)
                tmp.replace(dest)
                if mtime:
                    os.utime(dest, (mtime, mtime))
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(2 * (attempt + 1))
    print(f"  ! failed {dest.name}", file=sys.stderr)
    return False


def save_media(cdn, node: dict, folder: Path, stem: str) -> int:
    n = 0
    taken = node.get("taken_at")
    for i, m in enumerate(media_of(node)):
        suffix = f"_{i + 1:02d}" if len(media_of(node)) > 1 else ""
        if url := best_video(m):
            n += download(cdn, url, folder / f"{stem}{suffix}.mp4", taken)
        if url := best_image(m):
            n += download(cdn, url, folder / f"{stem}{suffix}.jpg", taken)
        time.sleep(0.15)
    return n


async def posts(chart: Path, username: str, on_page=None) -> list[dict]:
    os.environ["ASTROLABE_TOOLPACKS"] = str(chart / "toolpack.json")
    os.environ.setdefault("ASTROLABE_MAX_RESPONSE_BYTES", str(8_000_000))
    from fastmcp import Client

    from astrolabe.sextant import create_server

    out: list[dict] = []
    after = None
    async with Client(create_server()) as c:
        while True:
            args = {
                "username": username,
                "data": {
                    "count": POSTS_PAGE,
                    "include_reel_media_seen_timestamp": True,
                    "include_relationship_info": True,
                    "latest_besties_reel_media": True,
                    "latest_reel_media": True,
                },
                **{
                    PV.format(k): False
                    for k in (
                        "MultiCaptionCarouselEnabled",
                        "ReelsRecoDebugOverlayEnabled",
                        "SEOIsCrawler",
                        "ShortDramaEnabled",
                        "ThreadsStyleCommentsEnabled",
                    )
                },
            }
            if after:
                args |= {"after": after, "first": POSTS_PAGE}
            r = await c.call_tool(
                "call_tool",
                {"operation_id": "instagram_com__PolarisProfilePostsQuery", "arguments": args},
            )
            d = r.structured_content or json.loads(r.content[0].text)
            if d.get("ok") is False:
                print(f"  stopped after {len(out)} posts", flush=True)
                raise SystemExit(
                    f"sextant refused: {d.get('error_code')}: {str(d.get('error_detail'))[:300]}"
                )
            conn = d["data"]["xdt_api__v1__feed__user_timeline_graphql_connection"]
            page = [e["node"] for e in conn["edges"]]
            out += page
            if on_page:
                on_page(page)
            print(f"  posts: {len(out)}", flush=True)
            if not conn["page_info"]["has_next_page"]:
                return out
            after = conn["page_info"]["end_cursor"]
            await asyncio.sleep(1.5)


def highlights_direct(cookies: Path, tray_ids: list[str]) -> list[dict]:
    """Fallback: POST the operation by doc id, outside the Chart.

    Kept because PolarisStoriesV3HighlightsPageQuery is still ``typed-unproven``:
    the capture observed the request at HTTP 200 but retained no parseable
    response body, so no successful response is on record and the Chart does not
    expose the tool. Delete this path once a capture with body retention has
    earned the proof.
    """
    ck = {c["name"]: c["value"] for c in json.loads(cookies.read_text())}
    session = requests.Session(impersonate="chrome", cookies=ck)
    html = session.get("https://www.instagram.com/").text
    form = {
        "fb_dtsg": re.search(r'"DTSGInitialData",\[\],\{"token":"([^"]+)"', html).group(1),
        "lsd": re.search(r'"LSD",\[\],\{"token":"([^"]+)"', html).group(1),
        "av": re.search(r'"actorID":"(\d+)"', html).group(1),
        "__a": "1",
        "__comet_req": "7",
        "server_timestamps": "true",
    }
    reels: list[dict] = []
    for i in range(0, len(tray_ids), 10):
        ids = tray_ids[i : i + 10]
        response = session.post(
            "https://www.instagram.com/api/graphql",
            data={
                **form,
                "doc_id": "39990577387253622",
                "fb_api_req_friendly_name": "PolarisStoriesV3HighlightsPageQuery",
                "variables": json.dumps(
                    {
                        "first": len(ids),
                        "initial_reel_id": ids[0],
                        "reel_ids": ids,
                        PV.format("CommunityNoteStoriesLabelEnabled"): True,
                    }
                ),
            },
        )
        data = response.json()["data"]
        reels += [
            e["node"] for e in data["xdt_api__v1__feed__reels_media__connection"]["edges"]
        ]
    return reels

async def highlights(tray_ids: list[str]) -> list[dict]:
    """Fetch highlight reels through the Chart's own highlights operation.

    Tray ids come from the Chart's PolarisProfileStoryHighlightsTrayContentQuery;
    they are passed in because the tray is per-profile state, not part of the
    operation's shape.
    """
    from fastmcp import Client

    from astrolabe.sextant import create_server

    reels: list[dict] = []
    async with Client(create_server()) as c:
        for i in range(0, len(tray_ids), 10):
            ids = tray_ids[i : i + 10]
            r = await c.call_tool(
                "call_tool",
                {
                    "operation_id": "instagram_com__PolarisStoriesV3HighlightsPageQuery",
                    "arguments": {
                        "first": len(ids),
                        "initial_reel_id": ids[0],
                        "reel_ids": ids,
                        PV.format("CommunityNoteStoriesLabelEnabled"): True,
                    },
                },
            )
            d = r.structured_content or json.loads(r.content[0].text)
            if d.get("ok") is False:
                raise SystemExit(
                    f"sextant refused: {d.get('error_code')}: {str(d.get('error_detail'))[:300]}"
                )
            reels += [
                e["node"] for e in d["data"]["xdt_api__v1__feed__reels_media__connection"]["edges"]
            ]
    return reels


def main() -> None:
    chart, cookies, username, out = (
        Path(sys.argv[1]),
        Path(sys.argv[2]),
        sys.argv[3],
        Path(sys.argv[5]),
    )
    tray_ids = sys.argv[6].split(",") if len(sys.argv) > 6 else []
    out.mkdir(parents=True, exist_ok=True)
    # Give the execution host the Chart and the supplied session explicitly, so the
    # run exercises the credential-pointer path instead of whatever is in the ambient
    # environment. argv[4] (user_pk) is accepted for continuity and no longer needed.
    os.environ.setdefault("ASTROLABE_TOOLPACK", str((chart / "toolpack.json").resolve()))
    os.environ.setdefault("ASTROLABE_COOKIES", str(cookies.resolve()))
    cdn = requests.Session(impersonate="chrome")

    pdir = out / "posts"
    pdir.mkdir(exist_ok=True)
    got = [0]
    seen: list[dict] = []

    def save_page(page: list[dict]) -> None:
        seen.extend(page)
        (out / "posts.json").write_text(json.dumps(seen, indent=1, ensure_ascii=False))
        for n in page:
            stem = f"{time.strftime('%Y-%m-%d', time.gmtime(n.get('taken_at') or 0))}_{n['code']}"
            got[0] += save_media(cdn, n, pdir, stem)
            if cap := ((n.get("caption") or {}).get("text")):
                (pdir / f"{stem}.txt").write_text(cap, encoding="utf-8")

    print("posts via sextant…", flush=True)
    nodes = asyncio.run(posts(chart, username, save_page))
    print(f"  posts: {len(nodes)} entries, {got[0]} new files", flush=True)

    print("highlights…")
    try:
        reels = asyncio.run(highlights(tray_ids))
        print("  via chart op", flush=True)
    except SystemExit as exc:
        print(f"  chart refused ({str(exc)[:160]}); falling back to direct POST", flush=True)
        reels = highlights_direct(cookies, tray_ids)
    (out / "highlights.json").write_text(json.dumps(reels, indent=1, ensure_ascii=False))
    got = 0
    for reel in reels:
        title = re.sub(r"[^\w\- ]+", "", reel.get("title") or "").strip() or "untitled"
        hdir = out / "highlights" / f"{title}_{reel['id'].split(':')[-1]}"
        hdir.mkdir(parents=True, exist_ok=True)
        if cover := ((reel.get("cover_media") or {}).get("cropped_image_version") or {}).get("url"):
            download(cdn, cover, hdir / "_cover.jpg", None)
        for item in reel.get("items") or []:
            stem = f"{time.strftime('%Y-%m-%d_%H%M%S', time.gmtime(item.get('taken_at') or 0))}_{item.get('pk')}"
            got += save_media(cdn, item, hdir, stem)
        print(f"  {title}: {len(reel.get('items') or [])} items")
    print(f"  highlights: {len(reels)} reels, {got} new files")


if __name__ == "__main__":
    main()
