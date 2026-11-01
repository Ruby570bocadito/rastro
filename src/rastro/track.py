"""Follow phishing domains after they are found, and measure how long each registrar takes to act.

Every check asks the registry (RDAP) and a public resolver (DNS over HTTPS) about each domain
still standing, never the domain itself, and records one of these states:

- live: registered and resolving;
- offline: registered, but without an address (the host or the crew took the site down);
- held: the registrar or the registry suspended it (client hold or server hold);
- deleting: pending delete or in redemption;
- gone: no longer registered, or no longer in its TLD's zone (NXDOMAIN);
- unknown: neither source answered.

A takedown is the first check that finds a domain held, deleting or gone before it expired.
Time runs from when the domain entered the tracker or, with `from_report`, from when its
abuse report went out (`rastro track add --reported`). Domains still standing are censored,
not dropped, so each registrar's curve is a Kaplan-Meier estimate of how many of its domains
are still up after a given time, not an average over the ones already taken down.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from rastro import __version__
from rastro.domains import dns_hides_takedown, host_label, registrable
from rastro.sources import dns, rdap

DOWN = {"held", "deleting", "gone"}
UNKNOWN_REGISTRAR = "Unknown registrar"
SCHEMA = """
CREATE TABLE IF NOT EXISTS tracked (
    domain TEXT PRIMARY KEY, since TEXT NOT NULL, reported_at TEXT, source TEXT, registrar TEXT
);
CREATE TABLE IF NOT EXISTS checks (
    domain TEXT NOT NULL, at TEXT NOT NULL, state TEXT NOT NULL, registrar TEXT, status TEXT, expires TEXT, ips TEXT,
    PRIMARY KEY (domain, at)
);
"""


def connect(path: Path | str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(tracked)")}
    if "reported_at" not in columns:          # databases from before the report time was kept
        with conn:
            conn.execute("ALTER TABLE tracked ADD COLUMN reported_at TEXT")
            conn.execute("UPDATE tracked SET reported_at = since WHERE reported = 1")
    return conn


def unfollowable(domains: Iterable[str]) -> list[str]:
    """The domains a check could never see come down: sites on platforms that answer DNS for any name, which no
    registry knows either. Only visiting them would tell, and Rastro never visits."""
    names = {registrable(d.strip().lower()) for d in domains if d.strip()}
    return sorted(d for d in names if dns_hides_takedown(d))


def add(conn: sqlite3.Connection, domains: Iterable[str], since: datetime, source: str = "",
        reported: bool = False) -> int:
    """Start following domains; a domain already followed keeps its first `since`. With `reported`, the abuse
    report went out at `since`: new domains get that time, and followed ones without one get it too. Domains
    `unfollowable` leaves out are skipped. Returns how many domains are new."""
    domains = list(domains)
    skip = set(unfollowable(domains))
    names = sorted({registrable(d.strip().lower()) for d in domains if d.strip()} - skip)
    at = since.isoformat()
    before = conn.total_changes
    with conn:
        conn.executemany("INSERT OR IGNORE INTO tracked (domain, since, reported_at, source) VALUES (?, ?, ?, ?)",
                         [(d, at, at if reported else None, source) for d in names])
        new = conn.total_changes - before
        if reported:
            conn.executemany("UPDATE tracked SET reported_at = ? WHERE domain = ? AND reported_at IS NULL",
                             [(at, d) for d in names])
    return new


@dataclass(frozen=True)
class Seen:
    state: str
    registrar: str | None = None
    status: tuple[str, ...] = ()
    expires: datetime | None = None
    ips: tuple[str, ...] = ()


def classify(outcome: str, reg: rdap.Registration | None, verdict: str | None, ips: Iterable[str]) -> str:
    """The state of a domain from the registry's answer and the resolver's verdict."""
    status = " ".join(reg.status).lower() if reg else ""
    if "hold" in status:
        return "held"
    if "pending delete" in status or "redemption" in status:
        return "deleting"
    if outcome == "not-found" or verdict == "nxdomain":
        return "gone"
    if ips:
        return "live"
    if verdict == "noerror":
        return "offline"
    return "unknown"


@dataclass
class Sources:
    """Where checks come from. Tests swap in fakes; `public` asks the registry and the resolver afresh."""
    registry: Callable[[str], tuple[str, rdap.Registration | None]]
    resolver: Callable[[str], tuple[str | None, frozenset[str]]]

    @classmethod
    def public(cls, cache_dir: Path) -> Sources:
        cache_dir = Path(cache_dir)
        return cls(lambda d: rdap.check(d, cache_dir / "rdap", fresh=True),
                   lambda d: dns.resolve(d, cache_dir / "dns", fresh=True))


def look(domain: str, sources: Sources) -> Seen:
    outcome, reg = sources.registry(domain)
    verdict, ips = sources.resolver(domain)
    return Seen(classify(outcome, reg, verdict, ips), reg.registrar if reg else host_label(domain),
                reg.status if reg else (),
                reg.expires if reg else None, tuple(sorted(ips)))


def standing(conn: sqlite3.Connection) -> list[str]:
    """Domains not yet found held, deleting or gone."""
    down = {d for (d,) in conn.execute(
        f"SELECT DISTINCT domain FROM checks WHERE state IN ({','.join('?' * len(DOWN))})", sorted(DOWN))}
    return [d for (d,) in conn.execute("SELECT domain FROM tracked ORDER BY since") if d not in down]


def check(conn: sqlite3.Connection, sources: Sources, now: datetime | None = None,
          on_seen: Callable[[str, Seen], None] = lambda d, s: None) -> dict[str, int]:
    """Look at every domain still standing once, record what was seen and return how many are in each state."""
    now = now or datetime.now(UTC)
    counts: dict[str, int] = defaultdict(int)
    for domain in standing(conn):
        seen = look(domain, sources)
        counts[seen.state] += 1
        on_seen(domain, seen)
        with conn:
            conn.execute("INSERT OR REPLACE INTO checks VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (domain, now.isoformat(), seen.state, seen.registrar, json.dumps(list(seen.status)),
                          seen.expires.isoformat() if seen.expires else None, json.dumps(list(seen.ips))))
            if seen.registrar:
                conn.execute("UPDATE tracked SET registrar = ? WHERE domain = ? AND registrar IS NULL",
                             (seen.registrar, domain))
    return dict(counts)


@dataclass
class Course:
    """What happened to one domain: when it was taken down, or until when it was seen standing."""
    domain: str
    registrar: str
    since: datetime
    reported_at: datetime | None
    source: str
    checks: int = 0
    last: datetime | None = None
    state: str = "unknown"
    down_at: datetime | None = None
    expired: bool = False              # gone after its expiry date: not a takedown

    @property
    def taken_down(self) -> bool:
        return self.down_at is not None and not self.expired

    @property
    def reported(self) -> bool:
        return self.reported_at is not None

    def hours_after(self, start: datetime) -> float:
        """Hours from `start` to the takedown, or to the last check while the domain stands; 0 if it fell earlier."""
        end = self.down_at or self.last or start
        return max(0.0, (end - start).total_seconds() / 3600)

    @property
    def hours(self) -> float:
        return self.hours_after(self.since)


def courses(conn: sqlite3.Connection) -> list[Course]:
    out = []
    for domain, since, reported_at, source, registrar in conn.execute(
            "SELECT domain, since, reported_at, source, registrar FROM tracked ORDER BY since"):
        c = Course(domain, registrar or UNKNOWN_REGISTRAR, datetime.fromisoformat(since),
                   datetime.fromisoformat(reported_at) if reported_at else None, source or "")
        expires = None
        for at, state, exp in conn.execute("SELECT at, state, expires FROM checks WHERE domain = ? ORDER BY at",
                                           (domain,)):
            at = datetime.fromisoformat(at)
            c.checks += 1
            c.last, c.state = at, state
            expires = datetime.fromisoformat(exp) if exp else expires
            if state in DOWN and c.down_at is None:
                c.down_at = at
                c.expired = state == "gone" and expires is not None and expires <= at
        out.append(c)
    return out


def kaplan_meier(durations: Iterable[tuple[float, bool]]) -> list[tuple[float, float]]:
    """(hours, share still standing) at each takedown time; censored durations only shrink the risk set."""
    data = list(durations)
    curve, alive = [(0.0, 1.0)], 1.0
    for t in sorted({h for h, event in data if event}):
        at_risk = sum(1 for h, _ in data if h >= t)
        events = sum(1 for h, event in data if event and h == t)
        alive *= 1 - events / at_risk
        curve.append((t, alive))
    return curve


def standing_after(curve: list[tuple[float, float]], hours: float) -> float:
    return next((s for t, s in reversed(curve) if t <= hours), 1.0)


def median_hours(curve: list[tuple[float, float]]) -> float | None:
    """When half of the domains were down, or None if that has not happened yet."""
    return next((t for t, s in curve if s <= 0.5), None)


@dataclass
class Row:
    registrar: str
    domains: int
    taken_down: int
    still_up: int
    median_hours: float | None
    after: dict[int, float] = field(default_factory=dict)      # hours -> share still standing
    curve: list[tuple[float, float]] = field(default_factory=list)


MARKS = (24, 72, 168)


def scoreboard(conn: sqlite3.Connection, from_report: bool = False) -> list[Row]:
    """One row per registrar: fastest median first, registrars that have not got there yet last. With
    `from_report`, only reported domains count, timed from their report."""
    groups: dict[str, list[Course]] = defaultdict(list)
    for c in courses(conn):
        if c.checks and (c.reported or not from_report):
            groups[c.registrar].append(c)
    rows = []
    for registrar, cs in groups.items():
        curve = kaplan_meier((c.hours_after(c.reported_at if from_report else c.since), c.taken_down) for c in cs)
        rows.append(Row(registrar, len(cs), sum(c.taken_down for c in cs),
                        sum(1 for c in cs if c.down_at is None), median_hours(curve),
                        {m: standing_after(curve, m) for m in MARKS}, curve))
    return sorted(rows, key=lambda r: (r.median_hours is None, r.median_hours or 0, r.after[72], -r.domains))


def hours_text(h: float | None) -> str:
    if h is None:
        return "not yet"
    return f"{h:.0f} h" if h < 48 else f"{h / 24:.1f} days"


def page_data(conn: sqlite3.Connection, lang: str = "en", now: datetime | None = None,
              from_report: bool = False) -> dict:
    """What the scoreboard page shows."""
    all_courses = courses(conn)
    seen = [c for c in all_courses if c.checks and (c.reported or not from_report)]
    rows = scoreboard(conn, from_report)

    def hours(c: Course) -> float:
        return c.hours_after(c.reported_at if from_report else c.since)

    return {
        "lang": lang, "version": __version__, "from_report": from_report,
        "generated": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {"domains": len(seen), "taken_down": sum(c.taken_down for c in seen),
                   "still_up": sum(1 for c in seen if c.down_at is None), "registrars": len(rows),
                   "waiting": len(all_courses) - len(seen)},
        "marks": list(MARKS),
        "horizon": max([hours(c) for c in seen] + [MARKS[-1]]),
        "rows": [{"registrar": r.registrar, "domains": r.domains, "taken_down": r.taken_down, "still_up": r.still_up,
                  "median_hours": r.median_hours, "after": {str(k): round(v, 4) for k, v in r.after.items()},
                  "curve": [[round(h, 3), round(s, 4)] for h, s in r.curve]} for r in rows],
        "domains": [{"domain": c.domain, "registrar": c.registrar, "since": c.since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "state": c.state, "hours": round(hours(c), 1), "taken_down": c.taken_down, "expired": c.expired,
                     "reported": c.reported, "source": c.source}
                    for c in sorted(seen, key=lambda c: (c.registrar, c.hours))],
    }
