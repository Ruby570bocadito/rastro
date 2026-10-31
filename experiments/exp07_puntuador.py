"""Experiment 07: can a model of the name alone rank fresh certificate names by how phishy they look?

The Phishing.Database ACTIVE list mixes two kinds of names. Some domains were registered
for phishing and are listed whole (the bare name or www). Others are only listed through a
subdomain: tricks like amazon.x1g.top, but also legitimate sites that were hacked, whose
names nobody can tell apart from any other business. Hosting platforms (ten or more listed
host names under one registrable domain) are left out altogether.

The model trains on the first kind against registrable names seen in Let's Encrypt's
Sycamore log, and is measured three ways:

1. Five-fold cross-validation grouped by template (brand or first word, plus token layout),
   so no family sits on both sides: ROC AUC and recall at 1 % and 0.1 % false positives,
   for all names and for the names that carry a brand, the watcher's real triage task.
2. Names listed only through subdomains, never trained on, scored the same way.
3. A later sample of the log, never trained on: names a day above each threshold, fresh
   names already on the list that it catches, and the rule the watcher used so far (a
   brand plus a throwaway shape).

`--negatives no-brand` leaves the names that carry a brand out of the negatives, because a
live campaign can hide among them, and adds the brands' official domains instead.

`--save FILE` keeps the final model, trained on everything, for `--name-model`. Fresh names
stay in data/raw/ct/exp07/; only counts reach the results.

Usage, from the project root:
    python -I experiments/exp07_puntuador.py [--negatives all|no-brand] [--save FILE]
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
import zlib
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rastro import brands, pattern, scorer  # noqa: E402
from rastro.domains import registrable  # noqa: E402
from rastro.sources import ctlog  # noqa: E402

RESULTS = ROOT / "experiments" / "results"
PRIVATE = ROOT / "data" / "raw" / "ct" / "exp07"
LIST = ROOT / "data" / "raw" / "lists" / "phishing-domains-ACTIVE.txt"
LIVE = ROOT / "data" / "raw" / "ct" / "live.sqlite"
PLATFORM_MIN = 10
FOLDS = 5
THRESHOLDS = (0.5, 0.8, 0.9, 0.95, 0.99)


def tile(log: str, n: int) -> dict:
    """Registrable names and times of one tile, cached in data/raw."""
    path = PRIVATE / f"tile-{n}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    entries = ctlog.fetch_tile(log, n)
    row = {"tile": n, "count": len(entries), "first_index": entries[0].index, "last_index": entries[-1].index,
           "first_at": min(e.logged_at for e in entries).isoformat(),
           "last_at": max(e.logged_at for e in entries).isoformat(),
           "registrables": sorted({registrable(x) for e in entries for x in e.names})}
    path.write_text(json.dumps(row), encoding="utf-8")
    time.sleep(0.2)
    return row


def usable(domain: str) -> bool:
    label, suffix = scorer.split(domain)
    return bool(suffix) and any(c.isalpha() for c in label) and not re.fullmatch(r"[\d.]+", domain)


def group(domain: str) -> str:
    label, _ = scorer.split(domain)
    head = brands.brand_of(domain) or (re.split(r"[^a-z]+", label)[0] or label[:4])
    return f"{head}|{pattern.shape(label)}"


def auc(pos: list[float], neg: list[float]) -> float:
    """Chance that a random positive outscores a random negative (ties count half)."""
    ranked = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
    total, i, rank_sum = len(ranked), 0, 0.0
    while i < total:
        j = i
        while j < total and ranked[j][0] == ranked[i][0]:
            j += 1
        rank_sum += (i + j + 1) / 2 * sum(1 for k in range(i, j) if ranked[k][1])
        i = j
    return (rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def cut_at(neg: list[float], fpr: float) -> float:
    """The score that only `fpr` of the negatives exceed."""
    return sorted(neg, reverse=True)[max(0, int(len(neg) * fpr) - 1)]


def summary(pos: list[float], neg: list[float]) -> dict:
    out = {"positives": len(pos), "negatives": len(neg), "auc": round(auc(pos, neg), 4)}
    for fpr in (0.01, 0.001):
        cut = cut_at(neg, fpr)
        out[f"recall_at_fpr_{fpr}"] = round(sum(1 for s in pos if s > cut) / len(pos), 4)
    return out


def phishing_list() -> tuple[dict[str, set[str]], set[str], set[str], set[str]]:
    """The list's registrable domains with their listed host names, the hosting platforms among them, the usable
    listed domains, and those listed whole (registered for phishing)."""
    hosts: dict[str, set[str]] = defaultdict(set)
    for line in LIST.read_text(encoding="utf-8", errors="replace").splitlines():
        name = line.strip().lower()
        if name and not name.startswith("#"):
            hosts[registrable(name)].add(name)
    platforms = {r for r, hs in hosts.items() if len(hs) >= PLATFORM_MIN}
    listed = {r for r in hosts if r not in platforms and usable(r)}
    whole = {r for r in listed if r in hosts[r] or f"www.{r}" in hosts[r]}
    return hosts, platforms, listed, whole


def ct_samples(log: str, eval_tiles: int = 60, eval_stride: int = 50, train_tiles: int = 160,
               train_stride: int = 200) -> tuple[list[dict], list[dict], dict[str, str]]:
    """The later tiles, the training tiles, and when each training name was first seen (ISO time), the
    five-minute live sample included."""
    tiles_file = PRIVATE / "tiles.json"
    if tiles_file.exists():
        eval_ids, train_ids = json.loads(tiles_file.read_text(encoding="utf-8"))
    else:
        last = ctlog.tree_size(log) // ctlog.TILE - 1
        eval_ids = [last - k * eval_stride for k in range(eval_tiles)]
        train_ids = [eval_ids[-1] - train_stride * (k + 1) for k in range(train_tiles)]
        tiles_file.write_text(json.dumps([eval_ids, train_ids]), encoding="utf-8")
    fresh_tiles = [tile(log, n) for n in eval_ids]
    train = [tile(log, n) for n in train_ids]
    seen: dict[str, str] = {}
    for t in train:
        for r in t["registrables"]:
            seen[r] = min(seen.get(r, t["first_at"]), t["first_at"])
    if LIVE.exists():
        for r, at in sqlite3.connect(LIVE).execute("SELECT registrable, MIN(logged_at) FROM names GROUP BY registrable"):
            seen[r] = min(seen.get(r, at), at)
    return fresh_tiles, train, seen


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=ctlog.DEFAULT_LOG)
    ap.add_argument("--train-tiles", type=int, default=160)
    ap.add_argument("--train-stride", type=int, default=200)
    ap.add_argument("--eval-tiles", type=int, default=60)
    ap.add_argument("--eval-stride", type=int, default=50)
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--negatives", choices=["all", "no-brand"], default="all")
    ap.add_argument("--save", help="write the final model to this file")
    args = ap.parse_args()
    PRIVATE.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    hosts, platforms, listed, whole = phishing_list()
    through_subdomains = listed - whole
    print(f"list: {len(hosts):,} registrables · {len(platforms):,} platforms left out · {len(whole):,} listed whole "
          f"· {len(through_subdomains):,} only through subdomains", flush=True)

    fresh_tiles, _, seen = ct_samples(args.log, args.eval_tiles, args.eval_stride, args.train_tiles, args.train_stride)
    ct_train = set(seen)
    fresh = {r for t in fresh_tiles for r in t["registrables"] if usable(r)}
    official = brands.official_domains()
    if args.negatives == "no-brand":
        negatives = sorted(({r for r in ct_train if usable(r) and not brands.brand_of(r)} - listed - fresh)
                           | official)
    else:
        negatives = sorted({r for r in ct_train if usable(r)} - listed - fresh)
    positives = sorted(whole)
    print(f"negatives: {len(negatives):,} · fresh names: {len(fresh):,}", flush=True)

    enc = {d: scorer.encode(d) for d in set(positives) | set(negatives) | through_subdomains | fresh}
    print(f"encoded {len(enc):,} names in {time.time() - t0:.0f} s", flush=True)

    # 1 and 2: cross-validation grouped by template; names listed through subdomains are never trained on
    fold = {d: zlib.crc32(group(d).encode()) % FOLDS for d in enc}
    oof: dict[str, float] = {}
    for k in range(FOLDS):
        m = scorer.train_encoded([enc[d] for d in positives if fold[d] != k],
                                 [enc[d] for d in negatives if fold[d] != k], epochs=args.epochs)
        for d in [*positives, *negatives, *through_subdomains]:
            if fold[d] == k:
                oof[d] = m.score_encoded(enc[d])
        print(f"  fold {k + 1}/{FOLDS} done ({time.time() - t0:.0f} s)", flush=True)
    neg_scores = [oof[d] for d in negatives]
    branded_neg = [oof[d] for d in negatives if brands.brand_of(d)]
    cv = {
        "all": summary([oof[d] for d in positives], neg_scores),
        "with_brand": summary([oof[d] for d in positives if brands.brand_of(d)], branded_neg),
        "only_through_subdomains": summary([oof[d] for d in through_subdomains], neg_scores),
        "threshold_at_fpr_0.01": round(cut_at(neg_scores, 0.01), 4),
        "threshold_at_fpr_0.001": round(cut_at(neg_scores, 0.001), 4),
    }
    print(json.dumps(cv, indent=1), flush=True)

    # 3: the later sample of the log, never trained on
    m = scorer.train_encoded([enc[d] for d in positives if d not in fresh], [enc[d] for d in negatives],
                             epochs=args.epochs)
    scores = {d: m.score_encoded(enc[d]) for d in fresh}
    entries = sum(t["count"] for t in fresh_tiles)
    newest = max(fresh_tiles, key=lambda t: t["last_index"])
    oldest = min(fresh_tiles, key=lambda t: t["first_index"])
    span = (datetime.fromisoformat(newest["last_at"]) - datetime.fromisoformat(oldest["first_at"])).total_seconds()
    per_day = (newest["last_index"] - oldest["first_index"]) / span * 86400
    known_whole, known_any = fresh & whole, fresh & listed
    old_rule = {d for d in fresh if d not in official and brands.brand_of(d) and brands.suspicious(d)}
    branded = {d for d in fresh if d not in official and brands.brand_of(d)}
    thresholds = sorted(set(THRESHOLDS) | {cv["threshold_at_fpr_0.01"], cv["threshold_at_fpr_0.001"]})
    deploy = {"certificates": entries, "names": len(fresh), "log_entries_per_day": round(per_day),
              "known_listed_whole": len(known_whole), "known_listed_any": len(known_any),
              "names_with_brand": len(branded),
              "old_rule": {"flagged": len(old_rule), "per_day": round(len(old_rule) / entries * per_day),
                           "known_whole_caught": len(old_rule & known_whole)},
              "thresholds": []}
    for t in thresholds:
        above = {d for d, s in scores.items() if s >= t}
        deploy["thresholds"].append({"threshold": t, "flagged": len(above),
                                     "per_day": round(len(above) / entries * per_day),
                                     "known_whole_caught": len(above & known_whole),
                                     "known_any_caught": len(above & known_any),
                                     "with_brand": len(above & branded)})
    stamp = f"{date.today().isoformat()}-{args.negatives}"
    top = sorted(scores.items(), key=lambda kv: -kv[1])[:80]
    (PRIVATE / f"top-{stamp}.tsv").write_text("\n".join(
        f"{s:.4f}\t{d}\t{'whole' if d in known_whole else 'listed' if d in known_any else ''}\t"
        + "; ".join(f"{k}:{v}" for k, v, _ in m.reasons(d)) for d, s in top), encoding="utf-8")
    branded_ranked = sorted(branded, key=lambda d: -scores[d])
    (PRIVATE / f"branded-{stamp}.tsv").write_text("\n".join(
        f"{scores[d]:.4f}\t{d}\t{'old-rule' if d in old_rule else ''}" for d in branded_ranked), encoding="utf-8")

    if args.save:
        extra = sorted(d for d in fresh - listed if args.negatives == "all" or not brands.brand_of(d))
        final = scorer.train_encoded([enc[d] for d in positives],
                                     [enc[d] for d in negatives] + [enc[d] for d in extra], epochs=args.epochs)
        final.meta.update({"trained": date.today().isoformat(), "list": LIST.name, "log": args.log,
                           "negatives": args.negatives, "threshold_at_fpr_0.01": cv["threshold_at_fpr_0.01"],
                           "threshold_at_fpr_0.001": cv["threshold_at_fpr_0.001"]})
        scorer.save(final, args.save)

    result = {"negatives_kind": args.negatives, "listed_registrables": len(hosts), "platforms_left_out": len(platforms), "positives": len(positives),
              "only_through_subdomains": len(through_subdomains), "negatives": len(negatives),
              "cross_validation": cv, "fresh_sample": deploy, "seconds": round(time.time() - t0)}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"exp07_puntuador-{stamp}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
