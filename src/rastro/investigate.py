"""From one phishing link to its campaign: siblings, the crew's clock, the next domain and abuse reports.

1. The seed: the link's registrable domain and the brand it imitates.
2. Candidates: lookalikes built like the seed (same brand and token layout, or the same
   distinctive word and TLD) in the public list and the watcher's store, and the names that
   shared a certificate with the seed.
3. Profiles: first certificate (crt.sh), registration and registrar (RDAP), addresses and
   name servers (public DNS over HTTPS). None of them connects to the domains.
4. Two levels, as experiment 05 found. The crew is every domain built from the seed's
   narrow naming template, possibly over years. The campaign is the seed's group once
   clues that add up are clustered (campaigns.cluster).
5. The clock: the crew's first certificates and registrations, by work session, through the
   time-zone model and its calendar clues. A registration counts only when the first
   certificate followed within 30 days; a later one may belong to somebody who registered
   the name again.
6. The next domain: the template, ready for `rastro watch`.
7. Abuse reports: one draft per registrar for the domains still registered. Rastro never
   sends anything.
"""

from __future__ import annotations

import re
import sqlite3
import urllib.parse
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from rastro import brands, calendar_clues, campaigns, pattern, rhythm, scorer
from rastro.domains import (
    ABUSE_FORMS,
    SHORTENERS,
    dns_hides_takedown,
    dynamic_dns,
    ending,
    host_label,
    is_ip,
    platform,
    registrable,
    shares_certificate,
)
from rastro.sources import crtsh, dns, rdap

HOSTNAME = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")
NARROW_LOG10 = 9.0
REGISTRATION_SLACK = timedelta(days=30)
FRESH = timedelta(days=2)          # a store sighting this soon after registration is the first certificate
MAX_CO_CERTIFIED = 25              # more names on the seed's certificates means shared hosting, not one owner
MIN_WORD = 5                       # shortest shared word that relates two names without a brand
RHYTHM_P = 0.01
SUSPENDED = ("hold", "pending delete", "redemption")
REASONS = {
    "unregistered": "not registered now, or its registry has no RDAP",
    "suspended": "already suspended",
    "defensive": "held by a brand-protection registrar, probably a defensive registration",
    "reregistered": "registered again after its phishing days, maybe by somebody else",
    "unresolved": "on a hosting platform and no longer resolves",
    "sinkholed": "already points at a sinkhole: someone neutralized it",
}
# Registrars that hold names for brand-protection programmes; a lookalike there is probably defensive.
BRAND_PROTECTION = ("markmonitor", "csc corporate domains", "corporation service company", "com laude",
                    "safenames", "brandsight", "lexsynergy", "nom-iq", "comlaude")


def seed_host(link: str) -> str:
    """Host name of a link, defanged forms included (hxxps://evil[.]top/x). The path is dropped on purpose:
    it often carries a token that identifies whoever received the link."""
    s = link.strip().lower().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    s = re.sub(r"^h[tx]{2}p(s?)", r"http\1", s)
    if "://" not in s:
        s = "http://" + s
    host = (urllib.parse.urlsplit(s).hostname or "").rstrip(".")
    if is_ip(host):
        raise ValueError(f"{link!r} points at an address, not a domain name: there is no registration or naming "
                         "template to follow")
    if registrable(host) in SHORTENERS:
        raise ValueError(f"{host} is a link shortener: expand the link with a link-preview service, without opening "
                         "it, and investigate the link it leads to")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    if not HOSTNAME.match(host):
        raise ValueError(f"not a domain name: {link!r}")
    return host


def seed_domain(link: str) -> str:
    return registrable(seed_host(link))


def _tld(domain: str) -> str:
    return ending(domain)


def _words(domain: str) -> set[str]:
    return {t for t in pattern.tokens(domain.rsplit(".", 1)[0]) if t.isalpha() and len(t) >= MIN_WORD}


def related(seed: str, other: str) -> int | None:
    """How closely `other` looks like a sibling of `seed`: 0 same layout and TLD, 1 same layout, 2 same
    distinctive word and TLD; None when unrelated. With a brand, both must carry it."""
    if other == seed:
        return None
    brand = brands.brand_of(seed)
    same_layout = pattern.shape(other) == pattern.shape(seed)
    same_tld = _tld(other) == _tld(seed)
    if brand:
        if brands.brand_of(other) != brand:
            return None
        if same_layout:
            return 0 if same_tld else 1
        word = brands.distinctive_word(seed, brand)
        return 2 if word and same_tld and word in other else None
    if same_layout and same_tld and _words(seed) & _words(other):
        return 0
    return None


@dataclass
class Member:
    name: str
    brand: str | None
    sources: set[str] = field(default_factory=set)        # seed, list, store, certificate
    first_cert: datetime | None = None
    seen_in_store: datetime | None = None
    registration: rdap.Registration | None = None
    ips: frozenset[str] = frozenset()
    nameservers: frozenset[str] = frozenset()
    co_certified: frozenset[str] = frozenset()
    dns_checked: bool = False                             # its addresses were asked for, so empty means none
    sinkhole: str | None = None                           # the reverse DNS name that says its address is a sinkhole
    score: float | None = None                            # the name scorer's 0-1, when a model is shipped

    @property
    def registered(self) -> datetime | None:
        return self.registration.registered if self.registration else None

    def clock(self) -> list[datetime]:
        """The moments the crew acted on this domain: its first certificate, and its registration when that
        first certificate followed within REGISTRATION_SLACK."""
        reg, first = self.registered, self.first_cert
        if first is None and reg and self.seen_in_store and timedelta(0) <= self.seen_in_store - reg <= FRESH:
            first = self.seen_in_store
        out = [first] if first else []
        if reg and first and timedelta(0) <= first - reg <= REGISTRATION_SLACK:
            out.append(reg)
        return sorted(out)

    @property
    def first_seen(self) -> datetime | None:
        times = self.clock()
        return times[0] if times else None

    @property
    def alive(self) -> bool:
        """Still there as far as public data can tell: registered, or for a platform's site still in DNS. On a
        platform that answers DNS for any name nothing can tell without visiting it, so it counts as alive."""
        if self.sinkhole:
            return False
        if platform(self.name):
            return dns_hides_takedown(self.name) or not (self.dns_checked and not self.ips)
        return self.registration is not None

    @property
    def infrastructure(self) -> tuple[frozenset[str], frozenset[str]]:
        """Addresses and name servers that can tie it to another domain. A platform's site has none of its own: it
        shares the platform's addresses with every other site there. A dynamic DNS name keeps its address, its
        owner's server, but not the service's name servers. A sinkhole ties together everything it took over."""
        if self.sinkhole:
            return frozenset(), frozenset()
        if dynamic_dns(self.name):
            return self.ips, frozenset()
        return (frozenset(), frozenset()) if platform(self.name) else (self.ips, self.nameservers)

    def reportable(self) -> str | None:
        """Why this domain stays out of an abuse report (a key of REASONS), or None when it belongs in one."""
        if self.sinkhole:
            return "sinkholed"
        if platform(self.name):
            return None if self.alive else "unresolved"
        r = self.registration
        if r is None:
            return "unregistered"
        if any(word in s.lower() for s in r.status for word in SUSPENDED):
            return "suspended"
        if r.registrar and any(b in r.registrar.lower() for b in BRAND_PROTECTION):
            return "defensive"
        if r.registered and self.first_cert and self.first_cert < r.registered - timedelta(days=1):
            return "reregistered"
        return None


@dataclass
class AbuseReport:
    registrar: str                    # or the hosting platform, as host_label names it
    registrar_id: str | None
    email: str | None
    phone: str | None
    domains: list[str]
    subject: str
    body: str
    hosted: bool = False              # addressed to a hosting platform, not a registrar
    form: str | None = None           # the platform's abuse form, when one is known


@dataclass
class Investigation:
    host: str
    seed: str
    brand: str | None
    when: datetime
    members: dict[str, Member]
    crew_pattern: pattern.Pattern | None
    crew: list[str]
    campaign: list[str]
    groups: list[campaigns.Campaign]
    edges: list[tuple[str, str, float, tuple[str, ...]]]
    clues: calendar_clues.Clues | None
    clock_events: int
    session_hours: list[float]
    guess: str | None
    reports: list[AbuseReport]
    left_out: dict[str, str]
    notes: list[tuple[str, dict]]          # (code, values): husmo.note() words them
    sources_used: list[str]
    name_score: float | None = None        # the seed's name score, and the features behind it
    name_reasons: list[tuple[str, str]] = field(default_factory=list)

    @property
    def attributed(self) -> list[str]:
        """Every domain attributed to the seed's operators: its crew and its campaign."""
        return sorted(set(self.crew) | set(self.campaign))

    @property
    def rhythm_found(self) -> bool:
        return bool(self.clues and self.clues.p_value is not None and self.clues.p_value < RHYTHM_P)


@dataclass
class Sources:
    """Where profiles come from. Tests swap in fakes; `public` builds the real, cached ones."""
    certificates: Callable[[str], tuple[datetime | None, frozenset[str]]] | None = None
    registration: Callable[[str], rdap.Registration | None] | None = None
    addresses: Callable[[str], frozenset[str]] | None = None
    nameservers: Callable[[str], frozenset[str]] | None = None
    reverse: Callable[[str], frozenset[str]] | None = None        # an address's reverse DNS names

    @classmethod
    def public(cls, cache_dir: Path, offline: bool = False, crt: bool = True, rdap_: bool = True,
               dns_: bool = True) -> Sources:
        cache_dir = Path(cache_dir)

        def certificates(d: str):
            return crtsh.profile(d, cache_dir / "crtsh-domains", offline=offline)

        def registration(d: str):
            return rdap.lookup(d, cache_dir / "rdap", offline=offline)

        def addresses(d: str):
            return frozenset() if offline else dns.addresses(d, cache_dir / "dns")

        def nameservers(d: str):
            return frozenset() if offline else dns.nameservers(d, cache_dir / "dns")

        def reverse(ip: str):
            return frozenset() if offline else dns.reverse(ip, cache_dir / "dns")

        return cls(certificates if crt else None, registration if rdap_ else None,
                   addresses if dns_ else None, nameservers if dns_ else None, reverse if dns_ else None)

    def names(self) -> list[str]:
        return [name for name, used in [("crtsh", self.certificates), ("rdap", self.registration),
                                        ("dns", self.addresses)] if used]


def _from_list(seed: str, lines: Iterable[str]) -> dict[str, int]:
    brand = brands.brand_of(seed)
    # a quick filter when the seed spells its brand out; a lookalike spelling (paypa1) needs every name read
    spelled = brand if brand and brand in seed else None
    out: dict[str, int] = {}
    for line in lines:
        name = line.strip().lower()
        if not name or name.startswith("#") or (spelled and spelled not in name):
            continue
        d = registrable(name)
        rank = related(seed, d)
        if rank is not None and rank < out.get(d, 9):
            out[d] = rank
    return out


def _from_store(seed: str, conn: sqlite3.Connection) -> tuple[dict[str, datetime], dict[str, frozenset[str]]]:
    seen = {}
    for d, first in conn.execute("SELECT registrable, MIN(logged_at) FROM names GROUP BY registrable"):
        if d == seed or related(seed, d) is not None:
            seen[d] = datetime.fromisoformat(first)
    co = {}
    for d in seen:
        certs = conn.execute("SELECT DISTINCT log, idx FROM names WHERE registrable = ?", (d,)).fetchall()
        co[d] = frozenset({r for log, idx in certs for (r,) in conn.execute(
            "SELECT registrable FROM names WHERE log = ? AND idx = ?", (log, idx))} - {d})
    return seen, co


def _profile(m: Member, sources: Sources) -> Member:
    if sources.certificates and not shares_certificate(m.name):     # CT has nothing of its own to tell
        first, co = sources.certificates(m.name)
        m.first_cert, m.co_certified = first, m.co_certified | co
    if sources.registration:
        m.registration = sources.registration(m.name)
    if sources.addresses:
        m.ips = sources.addresses(m.name)
        m.dns_checked = True
        if sources.reverse and m.ips:
            m.sinkhole = dns.sinkhole_name({n for ip in m.ips for n in sources.reverse(ip)})
    if sources.nameservers:
        m.nameservers = sources.nameservers(m.name)
    return m


def guess_from_one(seed: str) -> str | None:
    """With no siblings, the usual variable part of a throwaway name is its numbers: keep the words, free the
    digits (paqexpres-entrega-4821.top -> paqexpres\\-entrega\\-\\d{4}\\.top)."""
    toks = pattern.tokens(seed)
    if not any(t.isdigit() for t in toks):
        return None
    return "".join(rf"\d{{{len(t)}}}" if t.isdigit() else pattern.literal(t) for t in toks)


def _crew(seed: str, names: Iterable[str]) -> pattern.Pattern | None:
    """The narrowest template learned from the seed and its same-layout siblings of the same brand that still
    matches the seed. Other brands on the seed's certificates join the campaign, not the template."""
    brand = brands.brand_of(seed)
    same = sorted({d for d in names if pattern.shape(d) == pattern.shape(seed) and brands.brand_of(d) == brand}
                  | {seed})
    for group in (same, [d for d in same if _tld(d) == _tld(seed)]):
        if len(group) >= 3:
            p = pattern.learn_one(group)
            if p.breadth_log10 <= NARROW_LOG10 and p.matches(seed):
                return p
    return None


def _evidence(m: Member, members: dict[str, Member], edges) -> list[str]:
    """Clues that tie this domain to one other domain in particular: a certificate or a rare address."""
    lines = []
    for a, b, _, kinds in edges:
        if m.name in (a, b):
            other = b if a == m.name else a
            if "certificate" in kinds:
                lines.append(f"it shares a TLS certificate with {other}")
            if "ip" in kinds:
                ips = ", ".join(sorted(m.ips & members[other].ips))
                lines.append(f"it resolves to {ips}, like {other}")
    return lines[:4]


def _together(ms: list[Member], crew_pattern: pattern.Pattern | None, crew_listed: int, edges) -> list[str]:
    """What the reported domains share, said once for all of them."""
    names = {m.name for m in ms}
    lines = []
    if crew_pattern and any(crew_pattern.matches(n) for n in names):
        listed = (f"; {crew_listed} domains built from it are on the public Phishing.Database list of phishing "
                  "domains") if crew_listed else ""
        whose = "Their names follow one template" if len(ms) > 1 else "Its name follows a template"
        lines.append(f"- {whose}, {crew_pattern.regex}{listed}.")
    kinds = {k for a, b, _, ks in edges if a in names or b in names for k in ks}
    if kinds & {"session", "burst"}:
        acts = "first certificates" if all(platform(n) for n in names) else "registrations and first certificates"
        lines.append(f"- Their {acts} came in the same work sessions or launches.")
    if "word" in kinds:
        lines.append("- They share the same long, unusual word around the brand.")
    return lines


def abuse_reports(seed: str, brand: str | None, members: dict[str, Member], domains: Iterable[str],
                  crew_pattern: pattern.Pattern | None, crew_listed: int, edges) -> tuple[list[AbuseReport],
                                                                                         dict[str, str]]:
    """One draft per registrar for the attributed domains still registered, and why the others stay out."""
    groups: dict[tuple[str, str | None], list[Member]] = defaultdict(list)
    left_out = {}
    for d in sorted(set(domains) | {seed}):
        m = members[d]
        why = m.reportable()
        if why:
            left_out[d] = why
            continue
        if label := host_label(d):
            groups[(label, None)].append(m)
            continue
        r = m.registration
        groups[(r.registrar or "Unknown registrar", r.abuse_email)].append(m)
    who = f"imitating {brands.display(brand)}" if brand else "used for phishing"
    reports = []
    for (registrar, email), ms in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        ms.sort(key=lambda m: (m.name != seed, m.name))
        many = len(ms) > 1
        hosted = platform(ms[0].name)
        where = "hosted on your platform" if hosted else "registered through you"
        lines = [f"Hello {registrar} abuse team,", "",
                 f"{'These domains' if many else 'This domain'}, {where}, "
                 f"{'appear' if many else 'appears'} to be part of one phishing operation {who}:", ""]
        for m in ms:
            facts = []
            if m.registered:
                facts.append(f"registered {m.registered:%Y-%m-%d %H:%M} UTC")
            if m.first_cert:
                facts.append(f"first TLS certificate {m.first_cert:%Y-%m-%d %H:%M} UTC")
            lines.append(f"- {m.name}" + (f" ({'; '.join(facts)})" if facts else ""))
            if m.name == seed:
                lines.append("    [Say how you received this link, for example an SMS or e-mail on a given date.]")
            lines += [f"    {e}" for e in _evidence(m, members, edges)]
        together = _together(ms, crew_pattern, crew_listed, edges)
        if together:
            lines += ["", "Why they belong together:" if many else "Why it looks like phishing:", *together]
        if hosted and dns_hides_takedown(ms[0].name):
            lines += ["", f"Your platform answers DNS for any name and nobody visited the sites, so please check "
                          f"whether {'they are' if many else 'it is'} still up."]
        lines += ["", f"Please review {'them' if many else 'it'} and suspend {'them' if many else 'it'} if "
                      f"{'they break' if many else 'it breaks'} your abuse policy.", "",
                  "This was gathered from public sources only (Certificate Transparency logs, RDAP and public DNS);"
                  " nobody connected to the domains.", "",
                  "Found with Rastro, an open-source phishing investigation tool."]
        subject = f"Phishing domain{'s' if many else ''} {who}: {', '.join(m.name for m in ms[:3])}" + (
            f" and {len(ms) - 3} more" if len(ms) > 3 else "")
        first = ms[0].registration
        reports.append(AbuseReport(registrar, first and first.registrar_id, email, first and first.abuse_phone,
                                   [m.name for m in ms], subject, "\n".join(lines),
                                   hosted is not None, ABUSE_FORMS.get(hosted) if hosted else None))
    return reports, left_out


def investigate(link: str, sources: Sources, list_lines: Iterable[str] = (), conn: sqlite3.Connection | None = None,
                max_candidates: int = 150, sims: int = 5000, workers: int = 4,
                on_status: Callable[[str], None] = lambda s: None, now: datetime | None = None,
                model: scorer.Model | None = None, use_model: bool = True) -> Investigation:
    host = seed_host(link)
    seed = registrable(host)
    brand = brands.brand_of(seed)
    notes: list[tuple[str, dict]] = []
    members = {seed: Member(seed, brand, {"seed"})}
    # amazon.co.uk.login-check.top: the brand sits in a subdomain the crew makes up at will, so it names the
    # target but not the template its siblings share
    if brand is None and (brand := brands.brand_of(host)):
        notes.append(("brand_in_subdomain", {"brand": brands.display(brand), "seed": seed}))

    ranks = _from_list(seed, list_lines)
    listed = set(ranks)
    seen, store_co = _from_store(seed, conn) if conn else ({}, {})
    for d in seen:
        ranks[d] = -1                  # fresh from the watcher: checked first

    on_status(f"seed {seed}" + (f", imitating {brand}" if brand else ", no known brand"))
    _profile(members[seed], sources)
    co = members[seed].co_certified
    if len(co) > MAX_CO_CERTIFIED:
        notes.append(("shared_hosting", {"n": len(co)}))
    else:
        for d in co:
            ranks[d] = -2
    # closest first: how it relates to the seed, then how many of the seed's words it shares (help-ledger-support
    # before abc-ledger-xyz for help-ledger-login), so a capped list keeps the likeliest siblings
    words = set(pattern.tokens(seed)) - {"-", "."}
    chosen = sorted((d for d in ranks if d != seed),
                    key=lambda d: (ranks[d], -len(words & set(pattern.tokens(d))), d))
    if len(chosen) > max_candidates:
        notes.append(("capped", {"n": len(chosen), "max": max_candidates}))
        chosen = chosen[:max_candidates]
    for d in chosen:
        m = Member(d, brands.brand_of(d))
        m.sources |= ({"list"} if d in listed else set()) | ({"store"} if d in seen else set()) | (
            {"certificate"} if d in co and len(co) <= MAX_CO_CERTIFIED else set())
        members[d] = m
    for d, t in seen.items():
        if d in members:
            members[d].seen_in_store = t
            members[d].co_certified |= store_co.get(d, frozenset())
            members[d].sources.add("store")

    on_status(f"profiling {len(chosen)} related domains (cached lookups are instant, crt.sh is slow)")
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for _ in pool.map(lambda m: _profile(m, sources), [members[d] for d in chosen]):
            done += 1
            if done % 10 == 0:
                on_status(f"  {done}/{len(chosen)} profiled")

    domains = [campaigns.Domain(m.name, m.brand, m.first_seen, m.co_certified, *m.infrastructure)
               for m in members.values()]
    groups = campaigns.cluster(domains, max_breadth=NARROW_LOG10)
    campaign = next((c.domains for c in groups if seed in c.domains), [seed])
    links = campaigns.link(domains)
    edges = sorted((a, b, round(w, 3), tuple(sorted(links.kinds[(a, b)])))
                   for (a, b), w in links.weight.items() if links.kinds[(a, b)] != {"template"})

    crew_pattern = _crew(seed, members)
    crew = sorted(d for d in members if crew_pattern.matches(d)) if crew_pattern else []
    attributed = set(crew) | set(campaign)
    times = sorted(t for d in attributed for t in members[d].clock())
    clues = calendar_clues.analyse(times, sims=sims) if times else None
    starts = rhythm.sessions(times)
    if crew_pattern is None and len(attributed) == 1:
        notes.append(("lonely", {}))

    model = model or (scorer.default() if use_model else None)
    if model:
        for m in members.values():
            m.score = round(model.score(m.name), 4)
    crew_listed = len(set(crew) & listed)
    reports, left_out = abuse_reports(seed, brand, members, attributed, crew_pattern, crew_listed, edges)
    return Investigation(
        host=host, seed=seed, brand=brand, when=now or datetime.now(UTC), members=members,
        crew_pattern=crew_pattern, crew=crew, campaign=campaign, groups=groups, edges=edges, clues=clues,
        clock_events=len(times), session_hours=[t.hour + t.minute / 60 for t in starts],
        guess=None if crew_pattern else guess_from_one(seed), reports=reports, left_out=left_out, notes=notes,
        sources_used=sources.names() + (["list"] if listed else []) + (["store"] if conn else []),
        name_score=members[seed].score,
        name_reasons=[(k, v) for k, v, _ in model.reasons(seed, 3)] if model else [],
    )
