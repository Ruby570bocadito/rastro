"""Experiment 01b: the human-rhythm test on domains from a public phishing list.

The first run of experiment 01 showed that crt.sh alone finds too few lookalike
domains. Here the domains come from Phishing.Database (MIT licence), grouped by
the brand they imitate. For a sample of each group we look up the domain's own
certificates on crt.sh and take the issuance time of its first one.

Only domains the attacker registered count: names on shared hosting
(000webhostapp.com, weeblysite.com…) carry the platform's certificate, so the
brand must appear in the registrable domain itself.

Usage, from the project root, with the list in data/raw/lists/:
    python -I experiments/exp01b_lista.py --census      # brand counts only, no network
    python -I experiments/exp01b_lista.py               # full run (slow: one crt.sh lookup per domain)
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rastro import brands, rhythm  # noqa: E402
from rastro.sources import crtsh  # noqa: E402

LIST = ROOT / "data" / "raw" / "lists" / "phishing-domains-ACTIVE.txt"
CACHE = ROOT / "data" / "raw" / "crtsh-domains"
RESULTS = ROOT / "experiments" / "results"
HOST = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")
MIN_TIMED = 20
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

brand_of = brands.brand_of


def load_groups(path: Path) -> dict[str, list[str]]:
    registrable = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        d = line.strip().lower()
        if d and HOST.match(d):
            registrable.add(crtsh.registrable(d))
    groups: dict[str, list[str]] = defaultdict(list)
    for d in sorted(registrable):
        b = brand_of(d)
        if b:
            groups[b].append(d)
    return groups


def lookup(d: str, pause: float, offline: bool = False) -> tuple[str, object]:
    """Outcome and first-certificate time of one domain. Answers are cached, so a stopped run resumes."""
    cached = crtsh.cache_path(d, CACHE).exists()
    if offline and not cached:
        return "not looked up yet", None
    try:
        rows = crtsh.fetch(d, CACHE, max_age_hours=24 * 30, retries=4, timeout=60)
    except RuntimeError:
        return "lookup failed", None
    finally:
        if not cached:
            time.sleep(pause)
    entries = crtsh.parse(rows)
    seen = crtsh.first_seen(entries, keep=lambda x: x == d)
    if d in seen:
        return "timed", seen[d]
    first = crtsh.first_cert(entries, d)
    if first is None:
        return "no certificate", None
    if offline and not crtsh.cert_page_path(first.cert_id, CACHE).exists():
        return "not looked up yet", None
    when = crtsh.log_time(first.cert_id, CACHE)
    if not offline:
        time.sleep(pause)
    return ("timed from its certificate page", when) if when else ("first certificate time unknown", None)


def first_cert_times(sample: list[str], pause: float, workers: int, offline: bool = False) -> tuple[list, Counter]:
    times, tally = [], Counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(lookup, d, pause, offline) for d in sample]
        for i, fut in enumerate(as_completed(futures), 1):
            outcome, when = fut.result()
            tally[outcome] += 1
            if when:
                times.append(when)
            if i % 10 == 0:
                print(f"    {i}/{len(sample)} looked up", flush=True)
    return sorted(times), tally


def analyse(brand: str, times: list, tally: Counter, listed: int, sampled: int) -> dict:
    result = {"brand": brand, "listed": listed, "sampled": sampled, "tally": dict(tally), "timed": len(times)}
    if len(times) < MIN_TIMED:
        result["verdict"] = f"too few timed domains (< {MIN_TIMED})"
        return result
    hours = [t.hour + t.minute / 60 for t in times]
    est = rhythm.estimate(hours)
    weekdays = Counter(t.weekday() for t in times)
    result.update({
        "first_seen_from": times[0].date().isoformat(),
        "first_seen_to": times[-1].date().isoformat(),
        "hour_counts_utc": rhythm.hour_counts(hours),
        "weekday_counts_utc": [weekdays.get(i, 0) for i in range(7)],
        "p_value": est.p_value,
        "human_rhythm": est.p_value < 0.01,
        "offset": est.offset,
        "band": list(est.band),
        "band_mass": est.band_mass,
        "bot_share": est.bot_share,
        "entropy_bits": est.entropy_bits,
        "posterior": {str(k): v for k, v in est.posterior.items()},
    })
    return result


def render(results: list[dict], total_domains: int) -> str:
    out = [
        "# Experiment 01b · human rhythm in domains from a public phishing list",
        "",
        f"Run on {date.today().isoformat()}. Domains from Phishing.Database (phishing-domains-ACTIVE.txt, MIT licence), "
        f"{total_domains:,} registrable domains, grouped by the brand in their name. Each sampled domain was looked up "
        "on crt.sh and timed by its first certificate (Let's Encrypt notBefore + 1 h).",
        "",
    ]
    showing = tested = 0
    for r in results:
        t = r["tally"]
        out += [
            f"## {r['brand']}",
            "",
            f"- In the list: {r['listed']:,} · looked up: {r['sampled']} · timed: {r['timed']}"
            + "".join(f" · {k}: {v}" for k, v in t.items() if k != "timed"),
        ]
        if "verdict" in r:
            out += [f"- {r['verdict']}", ""]
            continue
        tested += 1
        showing += r["human_rhythm"]
        band = r["band"]
        out += [
            f"- First certificates between {r['first_seen_from']} and {r['first_seen_to']}",
            f"- Human rhythm: **{'yes' if r['human_rhythm'] else 'no'}** (p = {r['p_value']:.4f})",
            f"- Most probable offset: {rhythm.tz_name(r['offset'])} · {r['band_mass']:.0%} band: "
            f"{rhythm.tz_name(band[0])} to {rhythm.tz_name(band[-1])} · estimated bot share: {r['bot_share']:.0%}",
            f"- Entropy: {r['entropy_bits']:.2f} bits (a flat day is {rhythm.UNIFORM_BITS:.2f})",
            "",
            "```",
        ]
        top = max(r["hour_counts_utc"]) or 1
        for h, n in enumerate(r["hour_counts_utc"]):
            out.append(f"{h:02d}h UTC {'█' * round(32 * n / top):<32} {n}")
        out += ["```", "", "Weekday (UTC): " + " · ".join(f"{d} {n}" for d, n in zip(WEEKDAYS, r["weekday_counts_utc"], strict=True)), ""]
    if tested < 2:
        verdict = f"Only {tested} brand(s) had enough timed domains, which is not enough to apply the kill criterion."
    elif showing >= 2:
        verdict = f"{showing} of {tested} brands show a human rhythm. The time-zone map stays in the plan."
    else:
        verdict = (f"{showing} of {tested} brands show a human rhythm. Kill criterion met: the map becomes a "
                   "secondary clue and the next-domain watch becomes the star.")
    out += [
        "## Verdict", "", verdict, "",
        "## Caveats", "",
        "- A brand group mixes every crew that imitated it. A rhythm here is a lower bound on what one campaign shows, "
        "and the offset is the dominant crew's at best.",
        "- Domains whose first certificate came from another CA are left out, which may favour crews that use Let's Encrypt.",
        "- Daylight saving time is ignored, so offsets can blur by an hour across the year.",
        "- The list holds domains that were still active when it was built; some first certificates are years old.",
        "- Brand matching is by name. A few domains may be unrelated businesses that happen to contain the word.",
        "",
    ]
    return "\n".join(out)


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--census", action="store_true", help="only count domains per brand")
    ap.add_argument("--per-brand", type=int, default=45)
    ap.add_argument("--min-brand", type=int, default=45)
    ap.add_argument("--max-brands", type=int, default=7)
    ap.add_argument("--brands", nargs="*", help="brands to test instead of the most common ones")
    ap.add_argument("--offline", action="store_true", help="analyse only the crt.sh answers already cached")
    ap.add_argument("--pause", type=float, default=1.5, help="seconds each worker waits between crt.sh requests")
    ap.add_argument("--workers", type=int, default=3, help="crt.sh requests in flight at once; keep it small")
    args = ap.parse_args()

    groups = load_groups(LIST)
    counts = Counter({b: len(v) for b, v in groups.items()})
    total = sum(counts.values())
    print(f"{total:,} registrable domains match a brand. Top brands:")
    for b, n in counts.most_common(25):
        print(f"  {b:<18} {n:>6,}")
    if args.census:
        return 0

    if args.brands:
        chosen = [b for b in args.brands if b in groups]
    else:
        chosen = [b for b, n in counts.most_common() if n >= args.min_brand][: args.max_brands]
    rng = random.Random(20261030)
    results = []
    for b in chosen:
        sample = rng.sample(groups[b], min(args.per_brand, len(groups[b])))
        print(f"· {b}: looking up {len(sample)} domains on crt.sh{' (cache only)' if args.offline else ''}…", flush=True)
        times, tally = first_cert_times(sample, args.pause, args.workers, args.offline)
        results.append(analyse(b, times, tally, len(groups[b]), len(sample)))

    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat() + ("-partial" if args.offline else "")
    (RESULTS / f"exp01b_lista-{stamp}.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    text = render(results, total)
    (RESULTS / f"exp01b_lista-{stamp}.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
