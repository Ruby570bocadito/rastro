"""Spot campaigns being born: several new lookalike domains of one brand with the same naming template.

No seed is needed. Among the names stored by `rastro watch`, recent registrable
domains that carry a brand and look like throwaway lookalikes are grouped two
ways:

- same brand and same token layout, with a narrow learned pattern;
- same brand, same TLD and the same long, unusual word around the brand
  (microsofterrorfound), even when the rest of the name changes.

Each group with enough members is reported with a pattern ready to arm.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from rastro import brands, pattern
from rastro.domains import ending


@dataclass(frozen=True)
class Burst:
    brand: str
    regex: str
    breadth_log10: float | None   # None when the pattern is anchored on a distinctive word instead
    domains: tuple[str, ...]
    first_seen: str
    last_seen: str


def find_bursts(conn: sqlite3.Connection, hours: float = 48, min_domains: int = 5, max_breadth: float = 12.0,
                now: datetime | None = None, allow: set[str] | None = None) -> list[Burst]:
    cutoff = (now or datetime.now(UTC)) - timedelta(hours=hours)
    rows = conn.execute(
        "SELECT registrable, MIN(logged_at), MAX(logged_at) FROM names WHERE logged_at >= ? GROUP BY registrable",
        (cutoff.isoformat(),),
    ).fetchall()
    skip = brands.official_domains() | (allow or set())
    by_layout: dict[tuple[str, str], list[tuple[str, str, str]]] = defaultdict(list)
    by_word: dict[tuple[str, str, str], list[tuple[str, str, str]]] = defaultdict(list)
    for domain, first, last in rows:
        if domain in skip or not brands.suspicious(domain):
            continue
        brand = brands.brand_of(domain)
        if not brand:
            continue
        by_layout[(brand, pattern.shape(domain))].append((domain, first, last))
        word = brands.distinctive_word(domain, brand)
        if word:
            by_word[(brand, word, ending(domain))].append((domain, first, last))

    def burst(brand: str, regex: str, breadth: float | None, items) -> Burst:
        return Burst(brand=brand, regex=regex, breadth_log10=breadth, domains=tuple(sorted(d for d, _, _ in items)),
                     first_seen=min(f for _, f, _ in items), last_seen=max(last for _, _, last in items))

    out: list[Burst] = []
    for (brand, _), items in by_layout.items():
        if len(items) >= min_domains:
            p = pattern.learn_one([d for d, _, _ in items])
            if p.breadth_log10 <= max_breadth:
                out.append(burst(brand, p.regex, round(p.breadth_log10, 2), items))
    covered = {frozenset(b.domains) for b in out}
    for (brand, word, tld), items in by_word.items():
        if len(items) >= min_domains and frozenset(d for d, _, _ in items) not in covered:
            regex = rf"(?=.*{pattern.literal(word)})[a-z0-9.-]+\.{pattern.literal(tld)}"
            out.append(burst(brand, regex, None, items))
    return sorted(out, key=lambda b: -len(b.domains))
