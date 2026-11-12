"""Experiment 10: how many work sessions does the map need before its band can be trusted?

Experiment 09 found that a flat seven-hour shift passes the rhythm test with only 10 sessions. Passing
is not the question: the map shows a band that claims to hold the crew's offset 90 % of the time. This
experiment simulates crews with a known offset and counts, for each number of sessions, how many get a
map and how often that map's band holds the truth.

Usage, from the project root:
    python -I experiments/exp10_minimo_sesiones.py [--trials 200]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rastro import rhythm  # noqa: E402

RESULTS = ROOT / "experiments" / "results"
SIZES = [5, 8, 10, 15, 20, 30, 50]
SIMS = 300          # per estimate: enough to tell p < 0.01


def profile(rng: random.Random) -> float:
    return rng.choices(range(24), weights=rhythm.PROFILE)[0] + rng.random()


# local hour of one sitting, for each kind of crew
KINDS = {
    "working day": profile,
    "working day, starts 2 h late": lambda rng: profile(rng) + 2,
    "working day, 40 % bots": lambda rng: rng.uniform(0, 24) if rng.random() < 0.4 else profile(rng),
    "flat 7-hour shift, 9 to 16": lambda rng: rng.uniform(9, 16),
    "flat 7-hour shift, 17 to 24": lambda rng: rng.uniform(17, 24),
}


def simulated(trials: int) -> list[dict]:
    rows = []
    for k, (kind, draw) in enumerate(KINDS.items()):
        for n in SIZES:
            maps = near = inside = width = 0
            for t in range(trials):
                rng = random.Random(100_000 * k + 1000 * n + t)
                offset = rng.choice(rhythm.OFFSETS)
                est = rhythm.estimate([(draw(rng) - offset) % 24 for _ in range(n)], sims=SIMS)
                if not est.human:
                    continue
                maps += 1
                near += rhythm.circular_distance(est.offset, offset) <= 1
                inside += offset in est.band
                width += len(est.band)
            rows.append({"kind": kind, "sessions": n, "maps": round(maps / trials, 3),
                         "offset_within_1h": round(near / maps, 3) if maps else None,
                         "band_holds_truth": round(inside / maps, 3) if maps else None,
                         "band_width": round(width / maps, 1) if maps else None})
        print(f"  {kind} done", flush=True)
    return rows


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=200, help="simulated crews per kind and size")
    args = ap.parse_args()
    rows = simulated(args.trials)

    def pct(v):
        return "—" if v is None else f"{v:.0%}"

    text = [
        "# Experiment 10 · how many sessions the map needs",
        "",
        f"Run on {date.today().isoformat()}.",
        "",
        f"{args.trials} crews of each kind per size, each at a random offset. Maps: share that passes both tests. "
        "The next columns are over those maps only.",
        "",
        "| Kind | Sessions | Maps | Offset within 1 h | Band holds the truth | Band width (offsets) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        text.append(f"| {r['kind']} | {r['sessions']} | {pct(r['maps'])} | {pct(r['offset_within_1h'])} | "
                    f"{pct(r['band_holds_truth'])} | {r['band_width'] if r['band_width'] is not None else '—'} |")
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    (RESULTS / f"exp10_minimo_sesiones-{stamp}.json").write_text(json.dumps({"simulated": rows}, indent=2),
                                                                  encoding="utf-8", newline="\n")
    (RESULTS / f"exp10_minimo_sesiones-{stamp}.md").write_text("\n".join(text) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
