"""Experiment 03 (offline): does a learned naming pattern catch a family's other domains?

A first proxy for the next-domain watch, run on the public list. A "family" is a
set of listed domains that imitate the same brand with the same token layout,
like apple-xxx-1234.com. For each family the pattern is learned from 10 of its
domains and then scored on:

- recall: the share of the family's other domains it catches;
- spill-over: how many other domains of the list it matches;
- breadth: how many names it could match at all (log10).

A real false-alarm rate needs a day of benign Certificate Transparency names;
that comes with the live watcher.

Usage, from the project root:
    python -I experiments/exp03_patron.py
"""

from __future__ import annotations

import json
import random
import statistics
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))

import exp01b_lista as listing  # noqa: E402

from rastro import pattern  # noqa: E402
from rastro.sources import crtsh  # noqa: E402

RESULTS = ROOT / "experiments" / "results"
TRAIN = 10
MIN_FAMILY = 15
MAX_FAMILIES = 40
NARROW_LOG10 = 9


def all_registrable() -> set[str]:
    out = set()
    for line in listing.LIST.read_text(encoding="utf-8", errors="replace").splitlines():
        d = line.strip().lower()
        if d and listing.HOST.match(d):
            out.add(crtsh.registrable(d))
    return out


def learned_families() -> tuple[set[str], int, list[dict]]:
    """Every registrable domain in the list, the number of families, and the largest ones with their learned pattern."""
    everything = all_registrable()
    families = []
    for brand, domains in listing.load_groups(listing.LIST).items():
        layouts: dict[str, list[str]] = defaultdict(list)
        for d in domains:
            layouts[pattern.shape(d)].append(d)
        families += [(brand, shp, sorted(m)) for shp, m in layouts.items() if len(m) >= MIN_FAMILY]
    families.sort(key=lambda f: -len(f[2]))
    rng = random.Random(1105)
    learned = []
    for brand, shp, members in families[:MAX_FAMILIES]:
        train = rng.sample(members, TRAIN)
        learned.append({"brand": brand, "layout": shp, "members": members, "train": train,
                        "pattern": pattern.learn_one(train)})
    return everything, len(families), learned


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    everything, n_families, learned = learned_families()
    by_shape: dict[str, list[str]] = defaultdict(list)
    for d in everything:
        by_shape[pattern.shape(d)].append(d)

    rows = []
    for fam in learned:
        brand, shp, members, train, p = fam["brand"], fam["layout"], fam["members"], fam["train"], fam["pattern"]
        held_out = [d for d in members if d not in train]
        family = set(members)
        recall = sum(p.matches(d) for d in held_out) / len(held_out)
        spill = sum(p.matches(d) for d in by_shape[shp] if d not in family)
        rows.append({
            "brand": brand, "layout": shp, "size": len(members), "pattern": p.regex,
            "breadth_log10": round(p.breadth_log10, 2), "recall": round(recall, 3), "spill_over": spill,
            "example": members[0],
        })

    recalls = [r["recall"] for r in rows]
    narrow = [r for r in rows if r["breadth_log10"] <= NARROW_LOG10]
    narrow_line = (f"- Narrow patterns (at most 10^{NARROW_LOG10} possible names, the kind worth watching live): "
                   f"{len(narrow)} of {len(rows)}, median recall "
                   f"**{statistics.median(r['recall'] for r in narrow):.0%}**, spill-over {sum(r['spill_over'] for r in narrow)}"
                   if narrow else "- No narrow patterns.")
    text = [
        "# Experiment 03 · learned naming patterns on the public list (offline)",
        "",
        f"Run on {date.today().isoformat()}. {len(everything):,} registrable domains from Phishing.Database. "
        f"{n_families} families (same brand and token layout, at least {MIN_FAMILY} domains); the "
        f"{len(rows)} largest were tested. Each pattern was learned from {TRAIN} domains of its family.",
        "",
        f"- Median recall on the rest of the family: **{statistics.median(recalls):.0%}**",
        f"- Families where the pattern catches at least 80 %: {sum(r >= 0.8 for r in recalls)} of {len(rows)}",
        f"- Domains outside the family that some pattern matches: {sum(r['spill_over'] for r in rows)}",
        narrow_line,
        "",
        "| Brand | Example | Size | Pattern | Breadth (log10) | Recall | Spill-over |",
        "|---|---|---:|---|---:|---:|---:|",
    ]
    for r in rows:
        text.append(f"| {r['brand']} | `{r['example']}` | {r['size']} | `{r['pattern']}` | {r['breadth_log10']} | "
                    f"{r['recall']:.0%} | {r['spill_over']} |")
    text += [
        "",
        "## Reading it",
        "",
        "- High recall with a broad pattern ([a-z]{m,n} slots) catches siblings but risks false alarms on benign names.",
        "- Narrow patterns (a vocabulary of words and a few TLDs) fire rarely, so they are the ones worth watching live.",
        "- Families here are grouped by brand and layout, not by confirmed campaign, so some mix several crews.",
        "",
    ]
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    (RESULTS / f"exp03_patron-{stamp}.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (RESULTS / f"exp03_patron-{stamp}.md").write_text("\n".join(text), encoding="utf-8")
    print("\n".join(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
