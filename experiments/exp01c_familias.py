"""Experiment 01c: human rhythm per template family.

Brand groups mix every crew that imitated a brand over the years. In
experiment 01b, Apple's 29 timed domains span 2017 to 2024 and show no rhythm.
A family that shares a narrow naming template (experiment 03) is much more
likely to be one crew. For each such family we time the first certificate of
its domains and test the rhythm twice: over all of them, and inside the
family's busiest 120-day burst, which is the closest thing to one campaign.

Usage, from the project root:
    python -I experiments/exp01c_familias.py --list-only   # which families qualify, no network
    python -I experiments/exp01c_familias.py               # look them up on crt.sh (slow)
    python -I experiments/exp01c_familias.py --offline     # analyse cached answers only
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))

import exp01b_lista as listing  # noqa: E402

from rastro import pattern, rhythm  # noqa: E402

RESULTS = ROOT / "experiments" / "results"
FREE_TLDS = {"tk", "ml", "ga", "cf", "gq"}   # Freenom TLDs, closed to new domains since 2023
MIN_FAMILY = 40
NARROW_LOG10 = 15
BURST = timedelta(days=120)
MIN_BURST = 15
SIMS = 20000   # Monte Carlo draws per test: p-values down to 0.00005


def families(min_family: int = MIN_FAMILY, narrow: float = NARROW_LOG10) -> list[tuple[str, list[str], pattern.Pattern]]:
    out = []
    for brand, domains in listing.load_groups(listing.LIST).items():
        layouts: dict[str, list[str]] = defaultdict(list)
        for d in domains:
            layouts[pattern.shape(d)].append(d)
        for members in layouts.values():
            if len(members) < min_family:
                continue
            p = pattern.learn_one(members)
            free = sum(d.rsplit(".", 1)[1] in FREE_TLDS for d in members) / len(members)
            if p.breadth_log10 <= narrow and free <= 0.5:
                out.append((brand, sorted(members), p))
    return sorted(out, key=lambda f: -len(f[1]))


def busiest_window(times: list) -> list:
    """The longest run of first certificates that fits in BURST."""
    best, lo = (0, 0), 0
    for hi in range(len(times)):
        while times[hi] - times[lo] > BURST:
            lo += 1
        if hi - lo + 1 > best[1] - best[0]:
            best = (lo, hi + 1)
    return times[best[0]:best[1]]


def rhythm_summary(times: list) -> dict:
    """Rhythm test on work sessions, so a burst of domains in one sitting counts once."""
    starts = rhythm.sessions(times)
    hours = [t.hour + t.minute / 60 for t in starts]
    est = rhythm.estimate(hours, sims=SIMS)
    return {
        "n": len(times), "sessions": len(starts), "days": len({t.date() for t in times}),
        "from": times[0].date().isoformat(), "to": times[-1].date().isoformat(),
        "p_value": est.p_value, "human_rhythm": est.p_value < 0.01, "offset": est.offset,
        "band": list(est.band), "band_mass": est.band_mass, "bot_share": est.bot_share,
        "hour_counts_utc": rhythm.hour_counts(hours),
    }


def describe(s: dict) -> str:
    band = f"{rhythm.tz_name(s['band'][0])} to {rhythm.tz_name(s['band'][-1])}"
    p = "p < 0.0001" if s["p_value"] < 0.0001 else f"p = {s['p_value']:.4f}"
    return (f"{s['n']} domains on {s['days']} days in {s['sessions']} work sessions, {s['from']} to {s['to']}: "
            f"human rhythm **{'yes' if s['human_rhythm'] else 'no'}** "
            f"({p}), most probable {rhythm.tz_name(s['offset'])}, {s['band_mass']:.0%} band {band}, "
            f"bots about {s['bot_share']:.0%}")


def render(results: list[dict]) -> str:
    out = [
        "# Experiment 01c · human rhythm per template family",
        "",
        f"Run on {date.today().isoformat()}. Families from Phishing.Database that share a brand, a token layout and a "
        "narrow naming template, with at most half of their domains on closed Freenom TLDs. First certificates timed "
        "through crt.sh (Let's Encrypt notBefore + 1 h).",
        "",
    ]
    for r in results:
        out += [f"## {r['brand']} · `{r['pattern']}`", "",
                f"- Family size: {r['size']} · looked up: {r['sampled']} · timed: {r['timed']}"
                + "".join(f" · {k}: {v}" for k, v in r["tally"].items() if k != "timed")]
        if "all" in r:
            out.append(f"- All of it: {describe(r['all'])}")
        if "burst" in r:
            out += [f"- Busiest 120 days: {describe(r['burst'])}", "", "```"]
            top = max(r["burst"]["hour_counts_utc"]) or 1
            for h, n in enumerate(r["burst"]["hour_counts_utc"]):
                out.append(f"{h:02d}h UTC {'█' * round(30 * n / top):<30} {n}")
            out.append("```")
        else:
            out.append(f"- Not enough timed domains in any 120-day burst (< {MIN_BURST}).")
        out.append("")
    # Primary test: each whole family, by work session. Several families are tested, so the bar is
    # corrected for that (Bonferroni); bursts are reported but do not count.
    tested = [r for r in results if "all" in r]
    bar = 0.01 / max(1, len(tested))
    strong = [r["brand"] for r in tested if r["all"]["p_value"] < bar]
    moderate = [r["brand"] for r in tested if bar <= r["all"]["p_value"] < 0.01]
    if len(tested) < 2:
        verdict = f"Only {len(tested)} family(ies) had enough timed domains, which is not enough to decide."
    elif len(strong) >= 2:
        verdict = (f"{len(strong)} of {len(tested)} families pass the corrected test (p < {bar:.4f}): "
                   f"{', '.join(strong)}. The time-zone map stays as a main piece.")
    elif len(strong) + len(moderate) >= 2:
        verdict = (f"{len(strong)} of {len(tested)} families pass the corrected test (p < {bar:.4f}): "
                   f"{', '.join(strong) or 'none'}; {len(moderate)} more pass at p < 0.01: {', '.join(moderate)}. "
                   "The rhythm is real in some campaigns but not robust across them. The map stays as a "
                   "conditional clue, shown only when its test passes for that campaign, and the next-domain "
                   "watch becomes the star.")
    else:
        verdict = (f"{len(strong) + len(moderate)} of {len(tested)} families show a rhythm. Kill criterion met: the "
                   "map becomes a secondary clue and the next-domain watch becomes the star.")
    out += ["## Verdict", "", verdict, "",
            "This criterion (whole family, by work session, corrected for the number of families) was set after "
            "experiment 01b and after seeing part of these results. Only the families finished later were judged "
            "blind to it.", "",
            "## Caveats", "",
            "- The test counts work sessions (first certificates less than 30 minutes apart count once), not domains. "
            "The hour histograms above still show every domain.",
            "- A shared template suggests one crew but does not prove it; kits are sold and copied.",
            "- The offset is where the crew's working day falls, not proof of where anyone is.",
            "- Domains whose first certificate came from another CA are left out.",
            "- Daylight saving time is ignored, so offsets can blur by an hour.", ""]
    return "\n".join(out)


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", type=int, default=5)
    ap.add_argument("--per-family", type=int, default=40)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--pause", type=float, default=1.5)
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--list-only", action="store_true")
    ap.add_argument("--min-family", type=int, default=MIN_FAMILY)
    ap.add_argument("--narrow", type=float, default=NARROW_LOG10, help="largest pattern breadth, log10 of names")
    args = ap.parse_args()

    chosen = families(args.min_family, args.narrow)[: args.families]
    print("Families:")
    for brand, members, p in chosen:
        print(f"  {brand:<10} {len(members):>4}  {p.regex}")
    if args.list_only:
        return 0

    results = []
    for brand, members, p in chosen:
        sample = random.Random(f"{brand}:{p.regex}").sample(members, min(args.per_family, len(members)))
        print(f"· {brand} ({len(sample)} domains){' from cache' if args.offline else ''}…", flush=True)
        times, tally = listing.first_cert_times(sample, args.pause, args.workers, args.offline)
        r = {"brand": brand, "pattern": p.regex, "size": len(members), "sampled": len(sample),
             "timed": len(times), "tally": dict(tally)}
        if len(times) >= listing.MIN_TIMED:
            r["all"] = rhythm_summary(times)
        burst = busiest_window(times) if times else []
        if len(burst) >= MIN_BURST:
            r["burst"] = rhythm_summary(burst)
        results.append(r)

    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat() + ("-partial" if args.offline else "")
    (RESULTS / f"exp01c_familias-{stamp}.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    text = render(results)
    (RESULTS / f"exp01c_familias-{stamp}.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
