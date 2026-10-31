"""Experiment 06: how much data each map clue needs, and what it says about the real families.

Part 1 simulates crews with a known UTC offset, daylight-saving regime and weekend,
and counts how often `rastro.calendar_clues` recovers each one for a given number
of work sessions. Part 2 runs the same analysis on the template families of
experiment 01c, from the cached crt.sh times.

Usage, from the project root:
    python -I experiments/exp06_pistas_mapa.py [--trials 60]
"""

from __future__ import annotations

import argparse
import io
import json
import random
import sys
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))

import exp01b_lista as listing  # noqa: E402
import exp01c_familias as fam  # noqa: E402

from rastro import calendar_clues as cc  # noqa: E402
from rastro import rhythm  # noqa: E402

RESULTS = ROOT / "experiments" / "results"
CREWS = [(1, "eu", "sat-sun"), (-6, "us", "sat-sun"), (3, "none", "fri-sat"), (8, "none", "sat-sun")]
SIZES = [25, 50, 100, 200, 400]


def power(trials: int) -> list[dict]:
    rows = []
    for n in SIZES:
        hits = {"offset ±1 h": 0, "DST regime": 0, "weekend": 0}
        for k, (offset, regime, weekend) in enumerate(CREWS):
            for t in range(trials):
                clues = cc.analyse(cc.simulate_crew(offset, regime, weekend, n, seed=1000 * k + t), sims=0)
                hits["offset ±1 h"] += rhythm.circular_distance(clues.offset, offset) <= 1
                # raw best guesses, before the reporting bars, to show what each clue can do
                hits["DST regime"] += max(clues.dst_probs, key=clues.dst_probs.get) == regime
                hits["weekend"] += max(clues.weekend_probs, key=clues.weekend_probs.get) == weekend
        total = trials * len(CREWS)
        rows.append({"sessions": n, **{k: round(v / total, 2) for k, v in hits.items()}})
        print(f"  {n} sessions done", flush=True)
    return rows


def families() -> list[dict]:
    out = []
    for brand, members, p in fam.families(25, 25)[:4]:
        sample = random.Random(f"{brand}:{p.regex}").sample(members, len(members))
        with redirect_stdout(io.StringIO()):
            times, _ = listing.first_cert_times(sample, 0, 4, offline=True)
        if len(rhythm.sessions(times)) < 15:
            continue
        c = cc.analyse(times)
        out.append({
            "family": brand, "sessions": c.sessions, "p_value": c.p_value, "offset": c.offset, "band": list(c.band),
            "dst": c.dst, "dst_probs": {k: round(v, 2) for k, v in c.dst_probs.items()},
            "weekend": c.weekend, "weekend_probs": {k: round(v, 2) for k, v in c.weekend_probs.items()},
            "holidays": c.holidays,
        })
    return out


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=60, help="simulated crews per configuration and size")
    args = ap.parse_args()
    print("Part 1 · simulated crews", flush=True)
    rows = power(args.trials)
    print("Part 2 · real families", flush=True)
    real = families()

    text = [
        "# Experiment 06 · calendar clues for the map: how much data they need, and what they say",
        "",
        f"Run on {date.today().isoformat()}.",
        "",
        "## Part 1 · simulated crews",
        "",
        f"{len(CREWS)} kinds of crew (UTC+1 with European DST and a Saturday-Sunday weekend; UTC−6 with US DST; "
        f"UTC+3 with no DST and a Friday-Saturday weekend; UTC+8 with neither), {args.trials} crews of each per size, "
        "work sessions spread over two years. Share recovered:",
        "",
        "| Sessions | Offset ±1 h | DST regime | Weekend |",
        "|---:|---:|---:|---:|",
    ]
    for r in rows:
        text.append(f"| {r['sessions']} | {r['offset ±1 h']:.0%} | {r['DST regime']:.0%} | {r['weekend']:.0%} |")
    text += ["", "## Part 2 · the real families", ""]
    for r in real:
        p = "p < 0.0001" if r["p_value"] < 0.0001 else f"p = {r['p_value']:.4f}"
        band = f"{rhythm.tz_name(r['band'][0])} to {rhythm.tz_name(r['band'][-1])}"
        dst = ", ".join(f"{k} {v:.0%}" for k, v in sorted(r["dst_probs"].items(), key=lambda kv: -kv[1]))
        wk = ", ".join(f"{k} {v:.0%}" for k, v in sorted(r["weekend_probs"].items(), key=lambda kv: -kv[1]))
        text += [
            f"### {r['family']} ({r['sessions']} sessions, {p})",
            "",
            f"- Most probable {rhythm.tz_name(r['offset'])}, band {band}",
            f"- Daylight saving: **{r['dst']}** ({dst})",
            f"- Weekend: **{r['weekend']}** ({wk})",
            "- Holidays: " + "; ".join(f"{n}: seen {s}, expected {e} ({v})" for n, s, e, v in r["holidays"]),
            "",
        ]
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    (RESULTS / f"exp06_pistas_mapa-{stamp}.json").write_text(json.dumps({"power": rows, "families": real}, indent=2),
                                                              encoding="utf-8")
    (RESULTS / f"exp06_pistas_mapa-{stamp}.md").write_text("\n".join(text), encoding="utf-8")
    print("\n".join(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
