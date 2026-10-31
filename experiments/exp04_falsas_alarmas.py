"""Experiment 04: false alarms of learned patterns on fresh Certificate Transparency names.

Experiment 03 measured how well a learned pattern catches its family, but it had
no benign names to measure false alarms. Here the 40 patterns from experiment
03 run against real, fresh certificate names from Let's Encrypt's Sycamore log,
read from tiles spread over the last hours. Matches are counted and projected
to a day of this log. The matched names stay in data/raw, because some of them
may be legitimate businesses.

Usage, from the project root:
    python -I experiments/exp04_falsas_alarmas.py [--tiles 120] [--stride 200]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))

import exp03_patron as exp03  # noqa: E402

from rastro.domains import registrable  # noqa: E402
from rastro.sources import ctlog  # noqa: E402

RESULTS = ROOT / "experiments" / "results"
PRIVATE = ROOT / "data" / "raw" / "ct"


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=ctlog.DEFAULT_LOG)
    ap.add_argument("--tiles", type=int, default=120)
    ap.add_argument("--stride", type=int, default=200, help="read one tile out of every N, going back in time")
    args = ap.parse_args()

    _, _, families = exp03.learned_families()
    last = ctlog.tree_size(args.log) // ctlog.TILE - 1
    entries = []
    for k in range(args.tiles):
        entries += ctlog.fetch_tile(args.log, last - k * args.stride)
        if (k + 1) % 20 == 0:
            print(f"  {k + 1}/{args.tiles} tiles · {len(entries):,} certificates", flush=True)
        time.sleep(0.2)
    regs = [{registrable(n) for n in e.names} for e in entries]
    unique = set().union(*regs)
    first, final = min(entries, key=lambda e: e.index), max(entries, key=lambda e: e.index)
    span = (final.logged_at - first.logged_at).total_seconds()
    per_day = (final.index - first.index) / span * 86400

    rows, private = [], []
    for fam in families:
        rx = fam["pattern"].compiled
        hits = sorted(d for d in unique if rx.fullmatch(d))
        hit_entries = sum(1 for r in regs if any(rx.fullmatch(d) for d in r))
        rows.append({
            "brand": fam["brand"], "pattern": fam["pattern"].regex,
            "breadth_log10": round(fam["pattern"].breadth_log10, 2),
            "matched_names": len(hits), "matched_certificates": hit_entries,
            "alarms_per_day": round(hit_entries / len(entries) * per_day, 1),
        })
        private += [f"{fam['brand']}\t{fam['pattern'].regex}\t{d}" for d in hits]

    narrow = [r for r in rows if r["breadth_log10"] <= exp03.NARROW_LOG10]
    broad = [r for r in rows if r["breadth_log10"] > exp03.NARROW_LOG10]
    # With zero matches, the rule of three bounds the rate at 3/n with 95 % confidence.
    narrow_hits = sum(r["matched_certificates"] for r in narrow)
    narrow_bound = (3 if narrow_hits == 0 else narrow_hits) / len(entries) * per_day
    text = [
        "# Experiment 04 · false alarms of learned patterns on fresh CT names",
        "",
        f"Run on {date.today().isoformat()}. {len(entries):,} certificates from {args.tiles} tiles of `{args.log}`, "
        f"one tile every {args.stride}, logged between {first.logged_at:%Y-%m-%d %H:%M} and "
        f"{final.logged_at:%H:%M} UTC: {len(unique):,} distinct registrable domains. This log takes about "
        f"{per_day / 1e6:.1f} million entries a day (pre-certificates and certificates).",
        "",
        f"- Narrow patterns (at most 10^{exp03.NARROW_LOG10} names): {len(narrow)}. Certificates they match in the "
        f"sample: **{narrow_hits}**, about **{sum(r['alarms_per_day'] for r in narrow):,.0f} alarms a day** on this log"
        + (f" (95 % upper bound with this sample size: {narrow_bound:,.0f} a day; a full day of the log would bring "
           f"it to about 3)." if narrow_hits == 0 else "."),
        f"- Broad patterns: {len(broad)}. Certificates matched: {sum(r['matched_certificates'] for r in broad)}, "
        f"about {sum(r['alarms_per_day'] for r in broad):,.0f} alarms a day.",
        "",
        "| Brand | Pattern | Breadth (log10) | Names matched | Alarms a day |",
        "|---|---|---:|---:|---:|",
    ]
    for r in sorted(rows, key=lambda r: r["breadth_log10"]):
        text.append(f"| {r['brand']} | `{r['pattern']}` | {r['breadth_log10']} | {r['matched_names']} | {r['alarms_per_day']:,.1f} |")
    text += [
        "",
        "A match is not a confirmed phish: some are legitimate businesses, some may be the campaign's new domains. "
        "The matched names are kept out of the repository, in `data/raw/ct/`.",
        "",
    ]
    RESULTS.mkdir(parents=True, exist_ok=True)
    PRIVATE.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    (RESULTS / f"exp04_falsas_alarmas-{stamp}.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (RESULTS / f"exp04_falsas_alarmas-{stamp}.md").write_text("\n".join(text), encoding="utf-8")
    (PRIVATE / f"exp04_matches-{stamp}.tsv").write_text("\n".join(private), encoding="utf-8")
    print("\n".join(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
