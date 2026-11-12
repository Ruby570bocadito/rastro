"""Experiment 09: does a scheduled job pass for a crew's working day, and does the regularity test stop it?

The rhythm test asks whether the hours beat a flat day. A job that acts at a fixed hour beats it too.
Part 1 simulates crews and jobs and counts how often each gets a map, with the rhythm test alone and
with the regularity test added (`rhythm.regularity_p_value`). Part 2 runs the regularity test on the
hour counts of the real families of experiment 01c, read from its committed results.

Usage, from the project root:
    python -I experiments/exp09_tarea_programada.py [--trials 100]
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
FAMILIES = RESULTS / "exp01c_familias-2026-10-30.json"
SIZES = [5, 10, 20, 50, 100]
SIMS = 300          # per estimate: enough to tell p < 0.01, and the full run stays under ten minutes


def working_day(rng: random.Random, offset: int = 3) -> float:
    return (rng.choices(range(24), weights=rhythm.PROFILE)[0] + rng.random() - offset) % 24


KINDS = {
    # people: these should keep their map
    "working day": lambda rng: working_day(rng),
    "working day, 40 % bots": lambda rng: rng.uniform(0, 24) if rng.random() < 0.4 else working_day(rng),
    "flat 7-hour shift": lambda rng: rng.uniform(9, 16),
    # neither a full working day nor a job
    "flat 4-hour window": lambda rng: rng.uniform(19, 23),
    # jobs: these should get no map
    "job at one hour": lambda rng: 3.0,
    "job at one hour, ±1 h": lambda rng: 3 + rng.randint(-1, 1),
    "job at two hours": lambda rng: rng.choice((3, 15)),
    "job at one hour, 50 % noise": lambda rng: 3.0 if rng.random() < 0.5 else rng.uniform(0, 24),
    "job every 6 hours": lambda rng: rng.choice((0, 6, 12, 18)),
    "round the clock": lambda rng: rng.uniform(0, 24),
}


def simulated(trials: int) -> list[dict]:
    rows = []
    for k, (kind, draw) in enumerate(KINDS.items()):
        for n in SIZES:
            before = after = flagged = 0
            for t in range(trials):
                rng = random.Random(100_000 * k + 1000 * n + t)
                est = rhythm.estimate([draw(rng) for _ in range(n)], sims=SIMS)
                before += est.p_value < rhythm.RHYTHM_P
                after += est.human
                flagged += est.too_regular
            rows.append({"kind": kind, "sessions": n, "map_before": round(before / trials, 3),
                         "map_after": round(after / trials, 3), "too_regular": round(flagged / trials, 3)})
        print(f"  {kind} done", flush=True)
    return rows


def families() -> list[dict]:
    out = []
    for fam in json.loads(FAMILIES.read_text(encoding="utf-8")):
        for part in ("all", "burst"):
            counts = (fam.get(part) or {}).get("hour_counts_utc")
            if not counts:
                continue
            out.append({"family": fam["brand"], "part": part, "events": sum(counts),
                        "entropy_bits": round(rhythm.entropy_bits(counts), 2),
                        "busiest_hour_share": round(max(counts) / sum(counts), 2),
                        "regular_p": rhythm.regularity_p_value(counts, sims=20000)})
    return out


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=100, help="simulated crews or jobs per kind and size")
    args = ap.parse_args()
    print("Part 1 · simulated crews and jobs", flush=True)
    rows = simulated(args.trials)
    print("Part 2 · real families", flush=True)
    real = families()

    text = [
        "# Experiment 09 · a scheduled job is not a working day",
        "",
        f"Run on {date.today().isoformat()}.",
        "",
        "## Part 1 · simulated crews and jobs",
        "",
        f"{args.trials} of each kind per size. Share that gets a map with the rhythm test alone (p < "
        f"{rhythm.RHYTHM_P}), and with the regularity test added (not packed tighter than a flat "
        f"{rhythm.NARROWEST_DAY}-hour shift, p < {rhythm.REGULAR_P}).",
        "",
        "| Kind | Sessions | Map before | Map now | Called too regular |",
        "|---|---:|---:|---:|---:|",
    ]
    for r in rows:
        text.append(f"| {r['kind']} | {r['sessions']} | {r['map_before']:.0%} | {r['map_after']:.0%} | "
                    f"{r['too_regular']:.0%} |")
    text += ["", "## Part 2 · the real families of experiment 01c", "",
             "| Family | Part | Timed events | Entropy (bits) | Busiest hour | Regularity p |", "|---|---|---:|---:|---:|---:|"]
    for r in real:
        text.append(f"| {r['family']} | {r['part']} | {r['events']} | {r['entropy_bits']} | "
                    f"{r['busiest_hour_share']:.0%} | {r['regular_p']:.4f} |")
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    (RESULTS / f"exp09_tarea_programada-{stamp}.json").write_text(
        json.dumps({"simulated": rows, "families": real}, indent=2), encoding="utf-8")
    (RESULTS / f"exp09_tarea_programada-{stamp}.md").write_text("\n".join(text), encoding="utf-8")
    print("\n".join(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
