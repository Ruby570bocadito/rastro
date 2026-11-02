"""Experiment 07c, a closer look: which names does its model score exactly 1.0?

Experiment 07c failed at the strict end: the threshold that lets 0.1 % of benign names through
came out at 1.0, the top of the scale, where benign and phishing names sit together. The model
adds up one weight per feature of a name, and a long name has more features, so its sum can grow
until the score is 1.0 to the last bit of a float. This replays 07c from its caches (its tiles and
RDAP answers, without the network: an answer never cached counts as no answer, as a failed lookup
did), trains the same models and counts the names at exactly 1.0 by the length of their label, in
the cross-validation and in the later sample. Only counts reach the results.

Usage, from the project root, after experiment 07c:
    python -I experiments/exp07c_saturacion.py --db data/raw/ct/brands.sqlite
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
import zlib
from collections import Counter
from datetime import date
from itertools import pairwise
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))

import exp07_puntuador as exp07  # noqa: E402
import exp07b_edad as exp07b  # noqa: E402
import exp07c_marcas as exp07c  # noqa: E402

from rastro import brands, scorer  # noqa: E402
from rastro.sources import rdap  # noqa: E402

BANDS = (1, 9, 13, 17, 21, 26, 31)      # label lengths: each band runs up to the next
LABELS = [f"{b}-{n - 1}" for b, n in pairwise(BANDS)] + [f"{BANDS[-1]}+"]


def band(domain: str) -> str:
    n = len(scorer.split(domain)[0])
    return LABELS[max((i for i, b in enumerate(BANDS) if b <= n), default=0)]


def shape(names: list[str], enc: dict[str, list[int]]) -> dict:
    """How long the names are, and how many carry hyphens and digits."""
    labels = [scorer.split(d)[0] for d in names]
    if not labels:
        return {"names": 0}
    return {"names": len(names), "median_label_length": statistics.median(len(x) for x in labels),
            "median_features": statistics.median(len(enc[d]) for d in names),
            "with_hyphen": round(sum("-" in x for x in labels) / len(labels), 3),
            "with_digit": round(sum(any(c.isdigit() for c in x) for x in labels) / len(labels), 3)}


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="the store experiment 07c read")
    ap.add_argument("--sample", type=int, default=6000, help="as given to experiment 07c")
    ap.add_argument("--epochs", type=int, default=4)
    args = ap.parse_args()
    t0 = time.time()

    # experiment 07c's data, rebuilt from its caches
    _, _, listed, whole = exp07.phishing_list()
    positives = sorted(whole)
    fresh_tiles, _, seen = exp07.ct_samples(exp07.ctlog.DEFAULT_LOG)
    fresh = {r for t in fresh_tiles for r in t["registrables"] if exp07.usable(r)}
    for r, at in exp07c.stored(Path(args.db)).items():
        seen[r] = min(seen.get(r, at), at)
    official = brands.official_domains()
    servers = rdap.servers_for(exp07b.CACHE, offline=True)
    pool = sorted(r for r in seen if exp07.usable(r) and r not in listed and r not in fresh and r not in official
                  and r.rsplit(".", 1)[-1] in servers)
    branded = [r for r in pool if brands.brand_of(r)]
    others = random.Random(7).sample([r for r in pool if not brands.brand_of(r)],
                                     min(args.sample, len(pool) - len(branded)))
    benign = [d for d in branded + others if exp07b.aged(d, seen[d], offline=True)[1]]
    negatives = sorted(set(benign) | (official - listed))
    print(f"benign: {len(negatives):,} · phishing: {len(positives):,} · later sample: {len(fresh):,}", flush=True)

    enc = {d: scorer.encode(d) for d in set(positives) | set(negatives) | fresh}
    fold = {d: zlib.crc32(exp07.group(d).encode()) % exp07.FOLDS for d in enc}
    oof: dict[str, float] = {}
    for k in range(exp07.FOLDS):
        m = scorer.train_encoded([enc[d] for d in positives if fold[d] != k],
                                 [enc[d] for d in negatives if fold[d] != k], epochs=args.epochs)
        for d in [*positives, *negatives]:
            if fold[d] == k:
                oof[d] = m.score_encoded(enc[d])
        print(f"  fold {k + 1}/{exp07.FOLDS} done ({time.time() - t0:.0f} s)", flush=True)
    m = scorer.train_encoded([enc[d] for d in positives if d not in fresh], [enc[d] for d in negatives],
                             epochs=args.epochs)
    later = {d: m.score_encoded(enc[d]) for d in fresh}

    groups = {"benign": (negatives, oof), "phishing": (positives, oof), "later_sample": (sorted(fresh), later)}
    totals = {g: Counter(band(d) for d in names) for g, (names, _) in groups.items()}
    tops = {g: Counter(band(d) for d in names if scores[d] == 1.0) for g, (names, scores) in groups.items()}
    at_top = [d for d in sorted(fresh) if later[d] == 1.0]
    plain = {d for d in fresh if d not in official and brands.brand_of(d) and brands.suspicious(d)}
    neg_scores = [oof[d] for d in negatives]
    result = {
        "at_1.0": {"benign": sum(tops["benign"].values()), "of_benign": len(negatives),
                   "benign_with_brand": sum(1 for d in negatives if oof[d] == 1.0 and brands.brand_of(d)),
                   "of_benign_with_brand": sum(1 for d in negatives if brands.brand_of(d)),
                   "phishing": sum(tops["phishing"].values()), "of_phishing": len(positives),
                   "later_sample": len(at_top), "of_later_sample": len(fresh),
                   "plain_rule_in_later_sample": len(plain), "plain_rule_at_1.0": sum(later[d] == 1.0 for d in plain)},
        "cuts_unrounded": {"fpr_0.01": exp07.cut_at(neg_scores, 0.01), "fpr_0.001": exp07.cut_at(neg_scores, 0.001)},
        "later_sample_at_1.0": shape(at_top, enc), "later_sample_all": shape(sorted(fresh), enc),
        "by_label_length": [{"label_length": lab, **{g: {"at_1.0": tops[g][lab], "names": totals[g][lab]}
                                                     for g in groups}} for lab in LABELS],
        "seconds": round(time.time() - t0)}
    exp07.RESULTS.mkdir(parents=True, exist_ok=True)
    (exp07.RESULTS / f"exp07c_saturacion-{date.today().isoformat()}.json").write_text(json.dumps(result, indent=2),
                                                                                       encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "by_label_length"}, indent=1))
    print("\n| Label length | Benign at 1.0 (cross-validation) | Phishing at 1.0 | Later sample at 1.0 |")
    print("|---|---:|---:|---:|")
    for row in result["by_label_length"]:
        print(f"| {row['label_length']} | "
              + " | ".join(f"{row[g]['at_1.0']:,} of {row[g]['names']:,}" for g in groups) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
