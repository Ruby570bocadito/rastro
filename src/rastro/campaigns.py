"""Group domains into campaigns from clues that are weak alone and strong together.

Each clue links two domains with a weight. Links add up per pair, and pairs
whose evidence reaches 1.0 end up in the same campaign:

- certificate (1.0): both names in one certificate, so one operator asked for it;
- word (1.0): the same long, unusual word around the brand and the same TLD;
- template (0.5): the same brand and token layout, since kits are sold and copied;
- session (0.5): the same brand, first seen less than 30 minutes apart;
- burst (0.5): the same brand and layout, each domain less than 72 hours after
  the previous one, so the sittings of one launch join up;
- ip and nameserver: weighted by rarity, ln(N/n)/ln(N), so an address shared by
  thousands of sites (a CDN, a registrar's default DNS) adds almost nothing.

A template alone never joins two domains; a template seen in the same work
session, or on the same rare server, does.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from rastro import brands, pattern, rhythm
from rastro.domains import ending

WEIGHTS = {"certificate": 1.0, "word": 1.0, "template": 0.5, "session": 0.5, "burst": 0.5, "ip": 1.2,
           "nameserver": 0.8}
BURST_GAP = timedelta(hours=72)
THRESHOLD = 1.0
MAX_GROUP = 200          # larger groups share something too common to mean anything


@dataclass(frozen=True)
class Domain:
    name: str
    brand: str | None = None
    first_seen: datetime | None = None
    co_certified: frozenset[str] = frozenset()   # registrable domains that shared a certificate with it
    ips: frozenset[str] = frozenset()
    nameservers: frozenset[str] = frozenset()    # registrable domains of its NS hosts


@dataclass
class Campaign:
    domains: list[str]
    brands: Counter
    links: Counter                                # clue -> number of links inside the campaign
    first_seen: datetime | None
    last_seen: datetime | None
    patterns: list[str] = field(default_factory=list)   # narrow patterns ready to arm

    @property
    def size(self) -> int:
        return len(self.domains)


def _rarity(n: int, total: int) -> float:
    return max(0.0, math.log(total / n) / math.log(total)) if total > 2 and n > 0 else 0.0


class _Links:
    def __init__(self) -> None:
        self.weight: dict[tuple[str, str], float] = defaultdict(float)
        self.kinds: dict[tuple[str, str], set[str]] = defaultdict(set)

    def add(self, a: str, b: str, w: float, kind: str) -> None:
        if a == b or w <= 0:
            return
        key = (a, b) if a < b else (b, a)
        self.weight[key] += w
        self.kinds[key].add(kind)

    def add_groups(self, groups: dict, kind: str, weight) -> None:
        for members in groups.values():
            members = sorted(set(members))
            if not 2 <= len(members) <= MAX_GROUP:
                continue
            w = weight(len(members))
            for i, a in enumerate(members):
                for b in members[i + 1:]:
                    self.add(a, b, w, kind)


def link(domains: list[Domain]) -> _Links:
    known = {d.name for d in domains}
    total = len(domains)
    links = _Links()
    for d in domains:
        for other in d.co_certified & known:
            links.add(d.name, other, WEIGHTS["certificate"], "certificate")
    templates, words, ips, servers = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
    by_brand: dict[str, list[Domain]] = defaultdict(list)
    for d in domains:
        if d.brand:
            templates[(d.brand, pattern.shape(d.name))].append(d.name)
            word = brands.distinctive_word(d.name, d.brand)
            if word:
                words[(d.brand, word, ending(d.name))].append(d.name)
            if d.first_seen:
                by_brand[d.brand].append(d)
        for ip in d.ips:
            ips[ip].append(d.name)
        for ns in d.nameservers:
            servers[ns].append(d.name)
    links.add_groups(templates, "template", lambda n: WEIGHTS["template"])
    links.add_groups(words, "word", lambda n: WEIGHTS["word"])
    links.add_groups(ips, "ip", lambda n: WEIGHTS["ip"] * _rarity(n, total))
    links.add_groups(servers, "nameserver", lambda n: WEIGHTS["nameserver"] * _rarity(n, total))
    links.add_groups(_runs(by_brand, lambda d: d.brand, rhythm.SESSION_GAP), "session", lambda n: WEIGHTS["session"])
    links.add_groups(_runs(by_brand, lambda d: (d.brand, pattern.shape(d.name)), BURST_GAP), "burst",
                     lambda n: WEIGHTS["burst"])
    return links


def _runs(by_brand: dict[str, list[Domain]], key, gap: timedelta) -> dict:
    """Groups of domains with the same key whose first sightings follow each other within `gap`."""
    keyed: dict = defaultdict(list)
    for items in by_brand.values():
        for d in items:
            keyed[key(d)].append(d)
    runs: dict = defaultdict(list)
    for k, items in keyed.items():
        items.sort(key=lambda d: d.first_seen)
        run, last = 0, None
        for d in items:
            if last is not None and d.first_seen - last > gap:
                run += 1
            runs[(k, run)].append(d.name)
            last = d.first_seen
    return runs


def cluster(domains: list[Domain], threshold: float = THRESHOLD, max_breadth: float = 9.0) -> list[Campaign]:
    """Campaigns of two or more domains, largest first."""
    by_name = {d.name: d for d in domains}
    links = link(domains)
    parent = {name: name for name in by_name}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    strong = [(pair, links.kinds[pair]) for pair, w in links.weight.items() if w >= threshold]
    for (a, b), _ in strong:
        parent[find(a)] = find(b)
    members: dict[str, list[str]] = defaultdict(list)
    for name in by_name:
        members[find(name)].append(name)
    used: dict[str, Counter] = defaultdict(Counter)
    for (a, _), kinds in strong:
        used[find(a)].update(kinds)
    out = []
    for root, names in members.items():
        if len(names) < 2:
            continue
        names.sort()
        times = [by_name[n].first_seen for n in names if by_name[n].first_seen]
        learned = pattern.learn(names, min_support=2)
        out.append(Campaign(
            domains=names,
            brands=Counter(by_name[n].brand for n in names if by_name[n].brand),
            links=used[root],
            first_seen=min(times) if times else None,
            last_seen=max(times) if times else None,
            patterns=[p.regex for p in learned if p.breadth_log10 <= max_breadth],
        ))
    return sorted(out, key=lambda c: -c.size)
