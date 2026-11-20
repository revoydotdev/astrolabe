"""Sort backed-up posts into memes / selfies / other with CLIP zero-shot.

usage: uv run --with torch --with transformers --with pillow python scripts/ig_classify.py <backup_dir>

Scores every image (video posts: their cover jpg), votes per post, writes
classification.csv and symlink folders sorted/{memes,selfies,other}/. Per-image scores
are cached in .clip_cache.json so reruns only score new images.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import torch
from PIL import Image
from transformers import CLIPModel, CLIPProcessor

MODEL = "openai/clip-vit-large-patch14"
PROMPTS = {
    "memes": [
        "an internet meme with text on it",
        "a screenshot of a tweet or social media post",
        "a funny meme image with a caption",
        "a screenshot of text",
        "a meme with white caption text above a picture",
        "a cartoon or comic strip with text",
    ],
    "selfies": [
        "a selfie of a person",
        "a mirror selfie",
        "a photo of a young woman with blonde hair",
        "a close-up photo of a young woman's face",
        "a photo of a young woman riding a horse",
        "a photo of a young woman with her friends",
        "a full-body photo of a young woman posing",
    ],
    "other": [
        "a landscape or nature photo with no people",
        "a photo of a lake or river",
        "a photo of a dog",
        "a photo of several dogs",
        "a photo of a horse",
        "a view between a horse's ears while riding",
        "a photo of food",
        "a painting or artwork",
        "a photo of a vehicle or a room with no people",
    ],
}
MIN_SHARE = 0.6  # a post needs this share of its images in one class, else "other"


def main() -> None:
    root = Path(sys.argv[1])
    posts_dir = root / "posts"
    cache_path = root / ".clip_cache.json"
    cache: dict[str, str] = json.loads(cache_path.read_text()) if cache_path.exists() else {}

    images = sorted(p for p in posts_dir.glob("*.jpg"))
    todo = [p for p in images if p.name not in cache]
    if todo:
        device = "cuda" if torch.cuda.is_available() else "cpu"
        model = (
            CLIPModel.from_pretrained(
                MODEL, torch_dtype=torch.float16 if device == "cuda" else torch.float32
            )
            .to(device)
            .eval()
        )
        proc = CLIPProcessor.from_pretrained(MODEL)
        labels = [(cls, p) for cls, ps in PROMPTS.items() for p in ps]
        with torch.no_grad():
            t = proc(text=[p for _, p in labels], return_tensors="pt", padding=True).to(device)
            for i in range(0, len(todo), 32):
                batch = todo[i : i + 32]
                imgs = []
                for p in batch:
                    try:
                        imgs.append(Image.open(p).convert("RGB"))
                    except Exception:  # noqa: BLE001
                        imgs.append(Image.new("RGB", (224, 224)))
                px = proc(images=imgs, return_tensors="pt")["pixel_values"].to(
                    device, dtype=model.dtype
                )
                # The full forward pass: its logits_per_image is stable across
                # transformers versions, unlike get_*_features' return type.
                out = model(
                    input_ids=t["input_ids"], attention_mask=t["attention_mask"], pixel_values=px
                )
                probs = out.logits_per_image.softmax(dim=-1).float().cpu()
                for p, row in zip(batch, probs):
                    per = defaultdict(float)
                    for (cls, _), v in zip(labels, row.tolist()):
                        per[cls] += v
                    cache[p.name] = max(per, key=per.get)
                print(f"  scored {min(i + 32, len(todo))}/{len(todo)}", flush=True)
                cache_path.write_text(json.dumps(cache))

    by_post: dict[str, list[str]] = defaultdict(list)
    for name, cls in cache.items():
        stem = re.sub(r"_\d{2}$", "", Path(name).stem)
        by_post[stem].append(cls)

    sorted_dir = root / "sorted"
    rows = []
    totals: Counter[str] = Counter()
    for stem, votes in sorted(by_post.items()):
        top, n = Counter(votes).most_common(1)[0]
        label = top if n / len(votes) >= MIN_SHARE else "other"
        totals[label] += 1
        rows.append({"post": stem, "label": label, "images": len(votes), **Counter(votes)})
        dest = sorted_dir / label
        dest.mkdir(parents=True, exist_ok=True)
        for f in posts_dir.glob(f"{stem}*"):
            link = dest / f.name
            for other in ("memes", "selfies", "other"):
                stale = sorted_dir / other / f.name
                if other != label and stale.is_symlink():
                    stale.unlink()
            if not link.exists():
                link.symlink_to(Path("../../posts") / f.name)

    with open(root / "classification.csv", "w", newline="") as fh:
        w = csv.DictWriter(
            fh, fieldnames=["post", "label", "images", "memes", "selfies", "other"], restval=0
        )
        w.writeheader()
        w.writerows(rows)
    print(f"posts {len(rows)}: {dict(totals)}")


if __name__ == "__main__":
    main()
