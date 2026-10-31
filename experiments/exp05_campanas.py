"""Experiment 05: campaigns inside the template families, from certificates, timing and infrastructure.

Experiment 01c treated each template family as one crew. Here the families'
domains are grouped into campaigns with `rastro.campaigns`, using the clues that
public data gives for free: names that shared a certificate (crt.sh), when each
domain got its first certificate (work sessions), and the addresses and name
servers each domain resolves to today, asked through a public DNS-over-HTTPS
resolver. Rastro never connects to the domains themselves.

Usage, from the project root (after experiment 01c has filled the crt.sh cache):
    python -I experiments/exp05_campanas.py
"""

from __future__ import annotations

import io
import json
import random
import sys
from collections import Counter
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))

import exp01b_lista as listing  # noqa: E402
import exp01c_familias as fam  # noqa: E402

from rastro import campaigns, rhythm  # noqa: E402
from rastro.domains import registrable  # noqa: E402
from rastro.sources import crtsh, dns  # noqa: E402

RESULTS = ROOT / "experiments" / "results"
PRIVATE = ROOT / "data" / "raw"
DNS_CACHE = PRIVATE / "dns"
MIN_SESSIONS = 15


def gather() -> tuple[list[campaigns.Domain], dict[str, str]]:
    domains, family_of = [], {}
    for brand, members, p in fam.families(25, 25)[:4]:
        sample = random.Random(f"{brand}:{p.regex}").sample(members, len(members))
        with redirect_stdout(io.StringIO()):
            times, _ = listing.first_cert_times(sample, 0, 4, offline=True)
        timed = {}
        for d in sample:
            outcome, when = listing.lookup(d, 0, offline=True)
            if when:
                timed[d] = when
        for d in members:
            family_of[d] = brand
            rows = crtsh.fetch(d, listing.CACHE, max_age_hours=24 * 365) if crtsh.cache_path(d, listing.CACHE).exists() else []
            co = {registrable(n) for e in crtsh.parse(rows) if any(registrable(x) == d for x in e.names)
                  for n in e.names} - {d}
            domains.append(campaigns.Domain(
                name=d, brand=brand, first_seen=timed.get(d), co_certified=frozenset(co),
                ips=dns.addresses(d, DNS_CACHE), nameservers=dns.nameservers(d, DNS_CACHE),
            ))
    return domains, family_of


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    domains, family_of = gather()
    found = campaigns.cluster(domains)
    in_campaigns = {d for c in found for d in c.domains}
    resolving = sum(bool(d.ips) for d in domains)
    rows, private = [], []
    for k, c in enumerate(found, 1):
        times = [d.first_seen for d in domains if d.name in c.domains and d.first_seen]
        starts = rhythm.sessions(times)
        row = {
            "campaign": k, "size": c.size, "families": dict(Counter(family_of[d] for d in c.domains)),
            "clues": dict(c.links), "sessions": len(starts),
            "from": c.first_seen.date().isoformat() if c.first_seen else None,
            "to": c.last_seen.date().isoformat() if c.last_seen else None,
            "patterns": c.patterns,
        }
        if len(starts) >= MIN_SESSIONS:
            est = rhythm.estimate([t.hour + t.minute / 60 for t in starts], sims=20000)
            row["rhythm"] = {"p_value": est.p_value, "offset": est.offset, "band": list(est.band)}
        rows.append(row)
        private += [f"{k}\t{d}" for d in c.domains]

    fams = Counter(family_of.values())
    text = [
        "# Experiment 05 · campaigns inside the template families",
        "",
        f"Run on {date.today().isoformat()}. {len(domains)} domains from the four families of experiment 01c. "
        f"{resolving} still resolve to an address. {len(found)} campaigns of two or more domains hold "
        f"{len(in_campaigns)} domains; {len(domains) - len(in_campaigns)} stay on their own.",
        "",
        "| # | Size | Families | Clues that joined it | First seen | Sessions | Rhythm |",
        "|---:|---:|---|---|---|---:|---|",
    ]
    for r in rows:
        families = ", ".join(f"{b} {n}" for b, n in r["families"].items())
        clues = ", ".join(f"{k} {v}" for k, v in sorted(r["clues"].items(), key=lambda kv: -kv[1]))
        if "rhythm" in r:
            rh = r["rhythm"]
            p = "p < 0.0001" if rh["p_value"] < 0.0001 else f"p = {rh['p_value']:.4f}"
            rhythm_txt = f"{rhythm.tz_name(rh['offset'])} ({rhythm.tz_name(rh['band'][0])} to {rhythm.tz_name(rh['band'][-1])}), {p}"
        else:
            rhythm_txt = f"too few sessions (< {MIN_SESSIONS})"
        span = f"{r['from']} to {r['to']}" if r["from"] else "unknown"
        text.append(f"| {r['campaign']} | {r['size']} | {families} | {clues} | {span} | {r['sessions']} | {rhythm_txt} |")
    text += ["", "## How each family splits", ""]
    for brand, n in fams.items():
        mine = [r for r in rows if brand in r["families"]]
        joined = sum(r["families"][brand] for r in mine)
        text.append(f"- {brand}: {n} domains, {joined} of them in {len(mine)} campaign(s), {n - joined} on their own.")
    cross = [r for r in rows if len(r["families"]) > 1]
    text += ["", f"Campaigns that span more than one family: {len(cross)}.", "",
             "Domain names are kept out of the repository, in `data/raw/`.", ""]
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    (RESULTS / f"exp05_campanas-{stamp}.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (RESULTS / f"exp05_campanas-{stamp}.md").write_text("\n".join(text), encoding="utf-8")
    (PRIVATE / f"exp05_campanas-{stamp}.tsv").write_text("\n".join(private), encoding="utf-8")
    print("\n".join(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
