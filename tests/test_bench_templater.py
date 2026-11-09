"""PathTemplater cost model: the templater used to be cubic in the number of
distinct ids at a position, which made a large real capture unanalyzable.

Every test here is gated behind ASTROLABE_BENCH=1. This repo configures no
`slow` marker, and a benchmark that runs by default is a benchmark CI can hang
on -- the pre-fix 1000-id case exceeded a 400s timeout. The gate is an env var
rather than a marker so nothing in pyproject.toml has to change.

The fixture shape is the whole point, and it is the trap: a *distinct* shape per
id makes _distinct_endpoints return True on the very first pair, so the
templating branch is never taken and the whole run costs ~1ms at every n -- a
benchmark written that way measures nothing while proving nothing. The blowup
lives in the *shared* shape, where the pairwise overlap loop runs to completion
and the position then templates to {id}. Both branches are asserted in
test_analyze.py; this file measures only the expensive one.
"""

from __future__ import annotations

import os
import time

import pytest

import astrolabe.analyze as analyze

pytestmark = pytest.mark.skipif(
    os.environ.get("ASTROLABE_BENCH") != "1",
    reason="benchmark; set ASTROLABE_BENCH=1 to run (pre-fix 1000 ids exceeded 400s)",
)

# Shared response shape across every id -- the branch with the real cost.
SHARED_ID_SHAPE = {
    "id": "int",
    "name": "str",
    "price": "float",
    "tags": ["str"],
    "vendor": {"id": "int", "name": "str"},
}

SIZES = (50, 200, 500)


def _apply_all(n):
    urls = [f"https://shop.example.test/api/products/{i}" for i in range(n)]
    t = analyze.PathTemplater(urls, [SHARED_ID_SHAPE] * n)
    started = time.perf_counter()
    templated = {t.apply(u) for u in urls}
    return time.perf_counter() - started, templated


@pytest.mark.parametrize("n", SIZES)
def test_path_templater_at_size(n):
    elapsed, templated = _apply_all(n)
    print(f"\nPathTemplater.apply over {n} shared-shape ids: {elapsed:.4f}s")
    # The fixture must actually be on the expensive branch, or the number below
    # is meaningless: a literal-only fixture runs in microseconds at every size.
    assert templated == {"/api/products/{id}"}


def test_path_templater_growth_is_sub_quadratic():
    """Compare the cost ratio at 500 against the ratio at 200.

    500/200 is a 2.5x increase in n, so a quadratic implementation would show a
    2.5^2 = 6.25x cost ratio and a cubic one 2.5^3 = 15.6x. Measured pre-fix
    ratios were ~8x and ~30x; the threshold is set at 5.0x rather than at the
    6.25x quadratic line so a merely-quadratic implementation cannot pass by
    timing noise -- a linear implementation measures 1.4-2.5x here, leaving
    roughly 2x of headroom over the observed worst case.

    Best-of-three per size: the per-call work is now ~1ms, well inside timer
    resolution, so a single noisy sample is the bigger risk to the assertion.
    """
    timings = {}
    for n in SIZES:
        timings[n] = min(_apply_all(n)[0] for _ in range(3))

    ratio_500_over_200 = timings[500] / timings[200]
    print(
        f"\nPathTemplater.apply: 200={timings[200]:.4f}s 500={timings[500]:.4f}s "
        f"ratio={ratio_500_over_200:.2f} (quadratic would be 6.25, cubic 15.63)"
    )
    assert ratio_500_over_200 < 5.0, (
        f"growth from 200 to 500 ids is {ratio_500_over_200:.2f}x, which is at or above "
        f"the 6.25x a quadratic implementation would show: the templater is not linear"
    )
