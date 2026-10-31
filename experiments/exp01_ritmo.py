"""Experiment 01: do lookalike domains of a brand show a human working rhythm?

For each brand, pull every certificate whose names contain it (crt.sh), keep
suspicious lookalike registrable domains and take the first time each one
appears in the CT logs. That first certificate follows the person who set the
domain up; renewals are automatic and are ignored. Then test whether those
hours fit a human working day better than round-the-clock activity.

Kill criterion from the plan: if fewer than 2 brands show a rhythm (p < 0.01),
the time-zone map becomes a secondary clue and the next-domain watch becomes
the star.

Usage, from the project root:
    python -I experiments/exp01_ritmo.py              # default brands
    python -I experiments/exp01_ritmo.py correos dhl
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rastro import rhythm  # noqa: E402
from rastro.sources import crtsh  # noqa: E402

RAW = ROOT / "data" / "raw"
RESULTS = ROOT / "experiments" / "results"
MIN_DOMAINS = 20

# TLDs that keep showing up in smishing campaigns. A heuristic, not a verdict.
ABUSED_TLDS = {
    "top", "xyz", "icu", "cc", "vip", "shop", "live", "online", "site", "buzz", "cfd", "sbs", "cyou", "bond",
    "info", "click", "life", "lat", "autos", "rest", "mom", "help", "support", "win", "monster", "fun", "pw",
    "ws", "tk", "ml", "ga", "cf", "gq", "app", "link", "store", "today", "space", "website", "host", "quest",
    "boats", "skin", "homes", "cam", "ink", "run", "club", "pro", "pics", "lol", "biz", "one", "best", "xin",
    "loan", "date", "bid", "trade", "work", "world", "digital", "tel",
}

BRANDS = {
    "correos": {"correos.es", "correos.com", "correosexpress.com", "correosexpress.es"},
    "tributaria": {"agenciatributaria.es", "agenciatributaria.gob.es"},
    "dhl": {"dhl.com", "dhl.es", "dhl.de", "dhl.fr", "dhl.it", "dhl.co.uk", "dhl.nl", "dhl.us",
            "dhlparcel.es", "dhlparcel.nl", "dhlecommerce.com"},
}
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def suspicious(domain: str, brand: str, official: set[str]) -> bool:
    if brand not in domain or domain in official:
        return False
    label, _, tld = domain.rpartition(".")
    tricky = "-" in label and any(ch.isdigit() for ch in label)
    return tld in ABUSED_TLDS or tricky


def analyse(brand: str, official: set[str]) -> dict:
    entries = crtsh.parse(crtsh.fetch(f"%{brand}%", RAW))
    seen = crtsh.first_seen(entries, keep=lambda d: suspicious(d, brand, official))
    times = sorted(seen.values())
    result = {
        "brand": brand,
        "certificates": len(entries),
        "timed_certificates": sum(e.issued_at is not None for e in entries),
        "domains": len(seen),
    }
    if len(times) < MIN_DOMAINS:
        result["verdict"] = f"too few suspicious domains (< {MIN_DOMAINS})"
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


def render(results: list[dict]) -> str:
    out = [
        "# Experiment 01 · human rhythm in lookalike domains",
        "",
        f"Run on {date.today().isoformat()} with crt.sh data. Domains are suspicious lookalikes picked by a "
        "heuristic (brand name plus an abused TLD, or hyphens and digits). They are not verified phishing.",
        "",
    ]
    showing = 0
    for r in results:
        out.append(f"## {r['brand']}")
        out.append("")
        out.append(f"- Certificates read: {r['certificates']:,} ({r.get('timed_certificates', 0):,} with a usable time) · "
                   f"suspicious lookalike domains with a timed first certificate: {r['domains']:,}")
        if "verdict" in r:
            out += [f"- {r['verdict']}", ""]
            continue
        showing += r["human_rhythm"]
        band = r["band"]
        out += [
            f"- First seen between {r['first_seen_from']} and {r['first_seen_to']}",
            f"- Human rhythm: **{'yes' if r['human_rhythm'] else 'no'}** (p = {r['p_value']:.4f})",
            f"- Most probable offset: {rhythm.tz_name(r['offset'])} · {r['band_mass']:.0%} band: "
            f"{rhythm.tz_name(band[0])} to {rhythm.tz_name(band[-1])} · estimated bot share: {r['bot_share']:.0%}",
            f"- Entropy: {r['entropy_bits']:.2f} bits (a flat day is {rhythm.UNIFORM_BITS:.2f})",
            "",
            "UTC hour of each domain's first certificate:",
            "",
            "```",
        ]
        top = max(r["hour_counts_utc"]) or 1
        for h, n in enumerate(r["hour_counts_utc"]):
            out.append(f"{h:02d}h {'█' * round(36 * n / top):<36} {n}")
        out += ["```", "", "Weekday (UTC): " + " · ".join(f"{d} {n}" for d, n in zip(WEEKDAYS, r["weekday_counts_utc"], strict=True)), ""]
    tested = sum("verdict" not in r for r in results)
    if tested < 2:
        verdict = f"Only {tested} brand(s) had enough data, which is not enough to apply the kill criterion."
    elif showing >= 2:
        verdict = f"{showing} of {tested} brands show a human rhythm. The time-zone map stays in the plan."
    else:
        verdict = (f"{showing} of {tested} brands show a human rhythm. Kill criterion met: the map becomes a "
                   "secondary clue and the next-domain watch becomes the star.")
    out += [
        "## Verdict",
        "",
        verdict,
        "",
        "## Caveats",
        "",
        "- Each brand mixes every group that ever imitated it, often across years and time zones, so a rhythm here "
        "is a lower bound on what a single campaign shows.",
        "- crt.sh answers broad wildcard searches with a partial sample, not the full history.",
        "- Wildcard answers carry no CT log time. Times come from Let's Encrypt notBefore plus its one-hour backdate "
        "(checked on two certificates, within two minutes). Certificates from other CAs are left out of the timing.",
        "- Hosting panels may issue a certificate minutes after the person adds the domain, and on their own schedule.",
        "- The working-day profile is a typical one; groups on night shifts shift the estimate.",
        "",
    ]
    return "\n".join(out)


def main(argv: list[str]) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    brands = argv or list(BRANDS)
    results = []
    for brand in brands:
        print(f"· {brand}: asking crt.sh…", flush=True)
        try:
            results.append(analyse(brand, BRANDS.get(brand, set())))
        except RuntimeError as err:
            print(f"  {err}", flush=True)
            results.append({"brand": brand, "certificates": 0, "domains": 0, "verdict": f"crt.sh unavailable: {err}"})
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    (RESULTS / f"exp01_ritmo-{stamp}.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    text = render(results)
    (RESULTS / f"exp01_ritmo-{stamp}.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
