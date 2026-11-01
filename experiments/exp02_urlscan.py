"""Experiment 02: does one phishing domain expand to its siblings through urlscan.io?

Kits are copied whole, so a campaign's sites load the same files even when their names
share nothing. For each seed, the search API finds its newest scan, takes the files its
page loaded, leaves out shared libraries (loaded by more than COMMON scans) and searches
for the other domains whose pages loaded the rest. Only existing scans are searched;
nothing is submitted, so urlscan never visits the sites on Rastro's behalf.

Kill criterion, set before the run: the expansion goes into `rastro investigate` only if,
among the seeds urlscan has seen, the median seed finds at least 10 sibling domains within
2 minutes of fresh requests, and most siblings are already on the public phishing list or
carry the seed's brand (a proxy for precision).

Needs a free urlscan.io account, its key in URLSCAN_API_KEY. Usage, from the project root:
    python -I experiments/exp02_urlscan.py --seeds 20
    python -I experiments/exp02_urlscan.py --seeds-file data/raw/my-seeds.txt
Domain names stay in data/raw/, out of the repository; results/ gets the aggregate numbers.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))

import exp01b_lista as listing  # noqa: E402

from rastro import brands  # noqa: E402
from rastro.domains import platform  # noqa: E402
from rastro.sources import urlscan  # noqa: E402

RESULTS = ROOT / "experiments" / "results"
PRIVATE = ROOT / "data" / "raw"
CACHE = PRIVATE / "urlscan"
MIN_SIBLINGS = 10
MAX_SECONDS = 120


def seeds_from_list(n: int, rng: random.Random) -> list[str]:
    """`n` brand lookalikes from the public list, spread over brands so one big family cannot fill the sample."""
    groups = listing.load_groups(listing.LIST)
    out: list[str] = []
    pools = {b: rng.sample(ds, len(ds)) for b, ds in groups.items()}
    while len(out) < n and any(pools.values()):
        for b in sorted(pools, key=lambda b: -len(groups[b])):
            if pools[b] and len(out) < n:
                out.append(pools[b].pop())
    return out


def score(e: urlscan.Expansion, listed: set[str]) -> dict:
    brand = brands.brand_of(e.seed)
    sibs = [d for d in e.siblings if not platform(d) and d not in brands.official_domains()]
    return {
        "seen": e.scan is not None, "files": e.hashes, "shared_libraries": e.common, "siblings": len(sibs),
        "listed": sum(d in listed for d in sibs), "same_brand": sum(bool(brand) and brands.brand_of(d) == brand
                                                                     for d in sibs),
        "requests": e.requests, "seconds": e.seconds,
    }


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=20, help="how many seeds to sample from the public list")
    ap.add_argument("--seeds-file", help="seed domains, one per line, instead of sampling the list")
    ap.add_argument("--common", type=int, default=urlscan.COMMON)
    ap.add_argument("--max-hashes", type=int, default=urlscan.MAX_HASHES)
    args = ap.parse_args()
    try:
        client = urlscan.Client(CACHE)
    except urlscan.NoKey as err:
        print(err)
        return 2
    if not args.seeds_file and not listing.LIST.exists():
        print(f"No seeds: pass --seeds-file, or download phishing-domains-ACTIVE.txt from Phishing.Database to "
              f"{listing.LIST.relative_to(ROOT)} (see experiment 01b).")
        return 2
    listed = set(d for ds in listing.load_groups(listing.LIST).values() for d in ds) if listing.LIST.exists() else set()
    if args.seeds_file:
        seeds = [s.strip().lower() for s in Path(args.seeds_file).read_text(encoding="utf-8").splitlines() if s.strip()]
    else:
        seeds = seeds_from_list(args.seeds, random.Random(2))

    rows, private = [], []
    for k, seed in enumerate(seeds, 1):
        e = urlscan.expand(client, seed, common=args.common, max_hashes=args.max_hashes)
        row = score(e, listed)
        rows.append(row)
        private += [f"{seed}\t{d}\t{len(h)}" for d, h in sorted(e.siblings.items())] or [f"{seed}\t\t0"]
        print(f"{k}/{len(seeds)} seen={row['seen']} siblings={row['siblings']} listed={row['listed']} "
              f"requests={row['requests']} {row['seconds']} s")

    seen = [r for r in rows if r["seen"]]
    med = statistics.median([r["siblings"] for r in seen]) if seen else 0
    secs = statistics.median([r["seconds"] for r in seen]) if seen else 0
    found = sum(r["siblings"] for r in seen)
    backed = sum(max(r["listed"], r["same_brand"]) for r in seen)
    passed = bool(seen) and med >= MIN_SIBLINGS and secs <= MAX_SECONDS and backed * 2 >= found
    text = [
        "# Experiment 02 · expansion from one domain through urlscan.io",
        "",
        f"Run on {date.today().isoformat()}. {len(seeds)} seeds; urlscan had scanned {len(seen)} of them. "
        f"Shared libraries: files loaded by more than {args.common} scans; at most {args.max_hashes} files per seed.",
        "",
        "| | Median | Total |",
        "|---|---:|---:|",
        f"| Sibling domains per seen seed | {med} | {found} |",
        f"| Of them on the public list, or carrying the seed's brand | | {backed} |",
        f"| Seconds per seen seed | {secs} | |",
        f"| Requests per seen seed | {statistics.median([r['requests'] for r in seen]) if seen else 0} | "
        f"{sum(r['requests'] for r in rows)} |",
        "",
        f"**Verdict:** {'passes' if passed else 'fails'} the bar set before the run (median of at least "
        f"{MIN_SIBLINGS} siblings in {MAX_SECONDS} s, half of them backed by the list or the brand).",
        "",
        "Domain names are kept out of the repository, in `data/raw/`.",
        "",
    ]
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    (RESULTS / f"exp02_urlscan-{stamp}.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (RESULTS / f"exp02_urlscan-{stamp}.md").write_text("\n".join(text), encoding="utf-8")
    PRIVATE.mkdir(parents=True, exist_ok=True)
    (PRIVATE / f"exp02_urlscan-{stamp}.tsv").write_text("\n".join(private), encoding="utf-8")
    print("\n".join(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
