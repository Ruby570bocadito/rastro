"""Experiment 07c: the name model with thousands of aged benign names that carry a brand.

Experiment 07b showed what the model lacks: clean benign names that carry a brand. Its 3,602
names registered at least a year before they were seen held only 131 with a brand, and the
model learned that any brand means phishing. A watcher store (`rastro watch --db`) keeps only
the certificates whose names carry a brand, about 0.4 % of the log, so hours of it collect
thousands of them. RDAP then keeps the names registered at least a year before they were seen
and not on hold: phishing domains get their first certificate days after registration, so an
old name seen again is a renewal of an ordinary site. Everything else is experiment 07b's: the
positives, the folds, the later sample of the log and the model.

Kill criterion, set before the run: the model ships only if, on the later sample of the log
(never trained on), at the threshold that lets 0.1 % of benign names through in
cross-validation, it raises fewer alarms a day than the plain rule (a brand plus a throwaway
shape) and catches at least as many of the sample's names that the public list holds whole.

The collection, measured on a pilot on 2026-11-01: 47,616 certificates (about four minutes of
Let's Encrypt's log) took 77.1 MB and held 72 names with a brand, 66 with an RDAP server, 18 of
them aged and unsuspended (27 %). So 1,000 aged branded names, seven times 07b's 131, take about
10,000 tiles and 4.3 GB; 3,000 take about 30,000 tiles and 13 GB. Past tiles read as fast as the
connection allows, so the collection need not wait for the log in real time.

Usage, from the project root (the collection first; the store and the names stay in data/raw):
    rastro watch --tiles 10000 --db data/raw/ct/brands.sqlite
    python -I experiments/exp07c_marcas.py --db data/raw/ct/brands.sqlite [--sample 6000] [--save FILE]
"""

from __future__ import annotations

import argparse
import json
import random
import sqlite3
import sys
import time
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))

import exp07_puntuador as exp07  # noqa: E402
import exp07b_edad as exp07b  # noqa: E402

from rastro import brands, scorer  # noqa: E402
from rastro.sources import rdap  # noqa: E402


def stored(db: Path) -> dict[str, str]:
    """When the watcher first saw each registrable name of its store (ISO time)."""
    with sqlite3.connect(db) as conn:
        return dict(conn.execute("SELECT registrable, MIN(logged_at) FROM names GROUP BY registrable"))


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="a store written by `rastro watch --db`")
    ap.add_argument("--sample", type=int, default=6000, help="names without a brand to look up, as in 07b")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--save", help="write the final model to this file")
    args = ap.parse_args()
    t0 = time.time()

    _, _, listed, whole = exp07.phishing_list()
    positives = sorted(whole)
    fresh_tiles, _, seen = exp07.ct_samples(exp07.ctlog.DEFAULT_LOG)
    fresh = {r for t in fresh_tiles for r in t["registrables"] if exp07.usable(r)}
    for r, at in stored(Path(args.db)).items():
        seen[r] = min(seen.get(r, at), at)
    official = brands.official_domains()
    servers = rdap.servers_for(exp07b.CACHE)
    pool = sorted(r for r in seen if exp07.usable(r) and r not in listed and r not in fresh and r not in official
                  and r.rsplit(".", 1)[-1] in servers)
    branded = [r for r in pool if brands.brand_of(r)]
    others = random.Random(7).sample([r for r in pool if not brands.brand_of(r)],
                                     min(args.sample, len(pool) - len(branded)))
    todo = branded + others
    print(f"looking up {len(todo):,} names ({len(branded):,} with a brand) through RDAP", flush=True)

    outcomes: Counter = Counter()
    benign = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for k, (d, (outcome, old)) in enumerate(zip(todo, ex.map(lambda d: exp07b.aged(d, seen[d]), todo),
                                                    strict=True), 1):
            outcomes[outcome] += 1
            if old:
                benign.append(d)
            if k % 500 == 0:
                print(f"  {k:,}/{len(todo):,} · {len(benign):,} aged benign names so far", flush=True)
    negatives = sorted(set(benign) | (official - listed))
    branded_neg = [d for d in negatives if brands.brand_of(d)]
    print(f"benign: {len(negatives):,} ({len(branded_neg):,} with a brand; 07b had 131) · {dict(outcomes)}", flush=True)

    enc = {d: scorer.encode(d) for d in set(positives) | set(negatives) | fresh | set(exp07b.PROBES)}
    fold = {d: zlib.crc32(exp07.group(d).encode()) % exp07.FOLDS for d in enc}
    oof: dict[str, float] = {}
    for k in range(exp07.FOLDS):
        m = scorer.train_encoded([enc[d] for d in positives if fold[d] != k],
                                 [enc[d] for d in negatives if fold[d] != k], epochs=args.epochs)
        for d in [*positives, *negatives]:
            if fold[d] == k:
                oof[d] = m.score_encoded(enc[d])
        print(f"  fold {k + 1}/{exp07.FOLDS} done ({time.time() - t0:.0f} s)", flush=True)
    neg_scores = [oof[d] for d in negatives]
    cv = {"all": exp07.summary([oof[d] for d in positives], neg_scores),
          "with_brand": exp07.summary([oof[d] for d in positives if brands.brand_of(d)],
                                      [oof[d] for d in branded_neg]),
          "threshold_at_fpr_0.01": round(exp07.cut_at(neg_scores, 0.01), 4),
          "threshold_at_fpr_0.001": round(exp07.cut_at(neg_scores, 0.001), 4)}
    print(json.dumps(cv, indent=1), flush=True)

    # the later sample of the log, never trained on, against the plain rule
    m = scorer.train_encoded([enc[d] for d in positives if d not in fresh], [enc[d] for d in negatives],
                             epochs=args.epochs)
    scores = {d: m.score_encoded(enc[d]) for d in fresh}
    entries = sum(t["count"] for t in fresh_tiles)
    newest = max(fresh_tiles, key=lambda t: t["last_index"])
    oldest = min(fresh_tiles, key=lambda t: t["first_index"])
    span = (datetime.fromisoformat(newest["last_at"]) - datetime.fromisoformat(oldest["first_at"])).total_seconds()
    per_day = (newest["last_index"] - oldest["first_index"]) / span * 86400
    known = fresh & whole
    plain = {d for d in fresh if d not in official and brands.brand_of(d) and brands.suspicious(d)}
    model = {d for d, s in scores.items() if s >= cv["threshold_at_fpr_0.001"]}
    deploy = {"names": len(fresh), "known_listed_whole": len(known),
              "plain_rule": {"flagged": len(plain), "per_day": round(len(plain) / entries * per_day),
                             "known_caught": len(plain & known)},
              "model": {"threshold": cv["threshold_at_fpr_0.001"], "flagged": len(model),
                        "per_day": round(len(model) / entries * per_day), "known_caught": len(model & known)}}
    ships = (deploy["model"]["per_day"] < deploy["plain_rule"]["per_day"]
             and deploy["model"]["known_caught"] >= deploy["plain_rule"]["known_caught"])
    probes = {d: round(m.score_encoded(enc[d]), 4) for d in exp07b.PROBES}
    stamp = date.today().isoformat()
    if args.save and ships:
        final = scorer.train_encoded([enc[d] for d in positives], [enc[d] for d in negatives], epochs=args.epochs)
        final.meta.update({"trained": stamp, "negatives": "aged, with a brand from a watcher store",
                           "threshold_at_fpr_0.001": cv["threshold_at_fpr_0.001"]})
        scorer.save(final, args.save)

    result = {"positives": len(positives), "looked_up": len(todo), "looked_up_with_brand": len(branded),
              "rdap_outcomes": dict(outcomes), "negatives": len(negatives), "negatives_with_brand": len(branded_neg),
              "cross_validation": cv, "fresh_sample": deploy, "ships": ships, "probes": probes,
              "seconds": round(time.time() - t0)}
    exp07.RESULTS.mkdir(parents=True, exist_ok=True)
    (exp07.RESULTS / f"exp07c_marcas-{stamp}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "probes"}, indent=2))
    print(f"\nVerdict: {'the model beats the plain rule and may ship' if ships else 'no model ships'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
