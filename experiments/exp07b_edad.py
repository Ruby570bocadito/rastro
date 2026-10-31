"""Experiment 07b: the name model again, with benign names checked by age.

Experiment 07 took raw Certificate Transparency names as its benign examples, and live
campaigns hid among them. Here a benign example must have been registered at least a year
before it was seen in the log, according to its registry (RDAP), and must not be on hold:
phishing domains are registered days before their first certificate, so a name a year old
is very unlikely to belong to a live campaign. Names whose TLD has no RDAP server stay out.
The brands' official domains join the benign side too.

Every name that carries a brand is looked up, because those are the ones the model must
learn to tell apart, plus a random sample of the rest. The positives, the folds and the
later sample are experiment 07's, so the two runs compare directly.

Usage, from the project root:
    python -I experiments/exp07b_edad.py [--sample 6000] [--save FILE]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))

import exp07_puntuador as exp07  # noqa: E402

from rastro import brands, scorer  # noqa: E402
from rastro.sources import rdap  # noqa: E402

CACHE = ROOT / "data" / "raw" / "rdap"
MIN_AGE = timedelta(days=365)
# Made-up or official names, so that the results can show how the model reads them without naming live domains.
PROBES = ["paypal-verify-4821.top", "facebook--signup-zsignupzzzzq7.ph", "amazon-cloud-accounts-xy.ph",
          "correos-envio-4821.top", "microsofterrorfound-help-desk-1.ph", "google.com", "paypal.com",
          "microsoftonline.com", "amazonaws.com", "riverhomebakery.com", "applevalleyplumbing.com",
          "chasepointdental.com", "smith-garden-design.co.uk"]


def aged(domain: str, seen: str) -> tuple[str, bool]:
    """The registry's outcome, and whether the name is an old, unsuspended registration when it was seen."""
    outcome, reg = rdap.check(domain, CACHE, pause=0.1)
    if outcome != "found" or reg.registered_day is None:
        return outcome, False
    held = any(word in s.lower() for s in reg.status for word in ("hold", "pending delete", "redemption"))
    return outcome, not held and reg.registered_day <= datetime.fromisoformat(seen) - MIN_AGE


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=6000, help="names without a brand to look up")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--save", help="write the final model to this file")
    args = ap.parse_args()
    t0 = time.time()

    hosts, platforms, listed, whole = exp07.phishing_list()
    positives = sorted(whole)
    fresh_tiles, _, seen = exp07.ct_samples(exp07.ctlog.DEFAULT_LOG)
    fresh = {r for t in fresh_tiles for r in t["registrables"] if exp07.usable(r)}
    servers = rdap.servers_for(CACHE)
    pool = sorted(r for r in seen if exp07.usable(r) and r not in listed and r not in fresh
                  and r.rsplit(".", 1)[-1] in servers)
    branded = [r for r in pool if brands.brand_of(r)]
    others = random.Random(7).sample([r for r in pool if not brands.brand_of(r)], min(args.sample, len(pool)))
    todo = branded + others
    print(f"looking up {len(todo):,} names ({len(branded)} with a brand) through RDAP", flush=True)

    outcomes: Counter = Counter()
    benign = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for k, (d, (outcome, old)) in enumerate(zip(todo, ex.map(lambda d: aged(d, seen[d]), todo), strict=True), 1):
            outcomes[outcome] += 1
            if old:
                benign.append(d)
            if k % 500 == 0:
                print(f"  {k:,}/{len(todo):,} · {len(benign):,} aged benign names so far", flush=True)
    official = sorted(brands.official_domains() - set(listed))
    negatives = sorted(set(benign) | set(official))
    branded_neg = [d for d in negatives if brands.brand_of(d)]
    print(f"benign: {len(negatives):,} ({len(branded_neg)} with a brand) · outcomes {dict(outcomes)}", flush=True)

    enc = {d: scorer.encode(d) for d in set(positives) | set(negatives) | fresh | set(PROBES)}
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

    m = scorer.train_encoded([enc[d] for d in positives if d not in fresh], [enc[d] for d in negatives],
                             epochs=args.epochs)
    scores = {d: m.score_encoded(enc[d]) for d in fresh}
    entries = sum(t["count"] for t in fresh_tiles)
    newest = max(fresh_tiles, key=lambda t: t["last_index"])
    oldest = min(fresh_tiles, key=lambda t: t["first_index"])
    span = (datetime.fromisoformat(newest["last_at"]) - datetime.fromisoformat(oldest["first_at"])).total_seconds()
    per_day = (newest["last_index"] - oldest["first_index"]) / span * 86400
    fresh_branded = sorted((d for d in fresh if brands.brand_of(d) and d not in brands.official_domains()),
                           key=lambda d: -scores[d])
    deploy = {"names": len(fresh), "names_with_brand": len(fresh_branded), "thresholds": []}
    for t in exp07.THRESHOLDS:
        above = [d for d, s in scores.items() if s >= t]
        deploy["thresholds"].append({"threshold": t, "flagged": len(above), "per_day": round(len(above) / entries
                                                                                              * per_day),
                                     "with_brand": sum(1 for d in above if d in set(fresh_branded))})
    stamp = date.today().isoformat()
    (exp07.PRIVATE / f"branded-{stamp}-aged.tsv").write_text(
        "\n".join(f"{scores[d]:.4f}\t{d}" for d in fresh_branded), encoding="utf-8")
    probes = {d: round(m.score_encoded(enc[d]), 4) for d in PROBES}
    print(json.dumps(probes, indent=1), flush=True)

    if args.save:
        final = scorer.train_encoded([enc[d] for d in positives], [enc[d] for d in negatives], epochs=args.epochs)
        final.meta.update({"trained": stamp, "negatives": "aged", "threshold_at_fpr_0.001": cv["threshold_at_fpr_0.001"]})
        scorer.save(final, args.save)

    result = {"positives": len(positives), "looked_up": len(todo), "looked_up_with_brand": len(branded),
              "rdap_outcomes": dict(outcomes), "negatives": len(negatives), "negatives_with_brand": len(branded_neg),
              "cross_validation": cv, "fresh_sample": deploy, "probes": probes, "seconds": round(time.time() - t0)}
    exp07.RESULTS.mkdir(parents=True, exist_ok=True)
    (exp07.RESULTS / f"exp07b_edad-{stamp}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k not in ("probes",)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
