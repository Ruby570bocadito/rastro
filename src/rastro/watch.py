"""Live watch: read new certificates from a CT log and alert on names that match armed patterns.

What experiments 03 and 04 taught, built in:
- only narrow patterns are armed (broad ones raised thousands of false alarms a day);
- the brands' official domains never alert (microsoftonline.com matched a broad pattern);
- each domain alerts once, although its pre-certificate and certificate both reach the log;
- with a database, the watch remembers where it stopped and picks up from there;
- it stores only certificates that carry a brand lookalike or an alert (0.4 % of a live
  sample; storing everything would take about 6 GB a day) and counts the rest;
- with the name model (experiment 07) it can also keep, or alert on, names that score high
  without any seed, brand or pattern.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass

from rastro import brands, pattern, scorer, store
from rastro.bursts import Burst, find_bursts
from rastro.domains import registrable
from rastro.sources import ctlog

NARROW_LOG10 = 9.0


@dataclass(frozen=True)
class Armed:
    regex: str
    compiled: re.Pattern
    breadth_log10: float | None   # None for patterns given by hand


@dataclass(frozen=True)
class Alert:
    logged_at: str
    domain: str
    pattern: str
    log: str
    index: int
    score: float | None = None    # set when the name model, not a pattern, raised the alert

    def line(self) -> str:
        why = f"matches {self.pattern}" if self.pattern else f"scores {self.score:.3f} on the name model"
        return f"ALERT {self.logged_at} UTC  {self.domain}  {why}"

    def json(self) -> str:
        return json.dumps(asdict(self))


class Watcher:
    def __init__(self, log: str, allow: Iterable[str] = (), max_breadth: float = NARROW_LOG10,
                 allow_broad: bool = False, model: scorer.Model | None = None, keep_score: float | None = None,
                 alert_score: float | None = None):
        self.log = log
        self.model = model
        self.keep_score = keep_score if model else None
        self.alert_score = alert_score if model else None
        self._scores: dict[str, float] = {}
        self.allow = set(allow) | brands.official_domains()
        self.max_breadth = max_breadth
        self.allow_broad = allow_broad
        self.armed: list[Armed] = []
        self.skipped: list[tuple[str, float]] = []
        self.alerted: set[str] = set()
        self.seen = 0
        self.kept = 0
        self.suppressed = 0

    def arm_learned(self, domains: Iterable[str], min_support: int = 3) -> None:
        for p in pattern.learn([d.lower() for d in domains], min_support=min_support):
            if p.breadth_log10 > self.max_breadth and not self.allow_broad:
                self.skipped.append((p.regex, p.breadth_log10))
            else:
                self.armed.append(Armed(p.regex, p.compiled, p.breadth_log10))

    def arm_regex(self, regexes: Iterable[str]) -> None:
        for r in regexes:
            self.armed.append(Armed(r, re.compile(r), None))

    def score(self, name: str) -> float:
        """The name model's score, remembered so a name met again costs nothing."""
        s = self._scores.get(name)
        if s is None:
            if len(self._scores) > 500_000:
                self._scores.clear()
            s = self._scores[name] = self.model.score(name)
        return s

    def handle(self, entries: list[ctlog.Entry]) -> list[Alert]:
        alerts = []
        self.seen += len(entries)
        for e in entries:
            for name in sorted({registrable(n) for n in e.names}):
                if name in self.alerted:
                    continue
                hit = next((a for a in self.armed if a.compiled.fullmatch(name)), None)
                score = None
                if hit is None:
                    if self.alert_score is None or (score := self.score(name)) < self.alert_score:
                        continue
                if name in self.allow:
                    self.suppressed += 1
                    continue
                self.alerted.add(name)
                alerts.append(Alert(f"{e.logged_at:%Y-%m-%d %H:%M:%S}", name, hit.regex if hit else "", self.log,
                                    e.index, None if hit else round(score, 4)))
        return alerts

    def keep(self, entries: list[ctlog.Entry]) -> list[ctlog.Entry]:
        """The entries worth storing: those with a name that alerted, that carries a brand without being one of
        its official domains, or that the name model scores at least `keep_score`. Each is kept whole, so the
        names it shares a certificate with stay linked."""
        def wanted(name: str) -> bool:
            if name in self.alerted:
                return True
            if name in self.allow:
                return False
            return brands.brand_of(name) is not None or (
                self.keep_score is not None and self.score(name) >= self.keep_score)

        kept = [e for e in entries if any(wanted(registrable(n)) for n in e.names)]
        self.kept += len(kept)
        return kept


def read_tiles(log: str, first: int, last: int, workers: int = 4) -> Iterator[list[ctlog.Entry]]:
    """Tiles first..last in order, with a few fetched ahead so a single client keeps up with the log.
    Only a small window is in flight, so stopping early never downloads the whole backlog."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending: deque = deque()
        n = first
        try:
            while n <= last or pending:
                while n <= last and len(pending) < workers * 2:
                    pending.append(pool.submit(ctlog.fetch_tile, log, n))
                    n += 1
                yield pending.popleft().result()
        finally:
            for f in pending:
                f.cancel()


def follow(watcher: Watcher, conn: sqlite3.Connection | None, minutes: float, poll: float = 5,
           max_backlog: int = 2000, bursts_every: float = 0, burst_hours: float = 48, burst_min: int = 5,
           on_alert: Callable[[Alert], None] = print, on_status: Callable[[str], None] = print,
           on_burst: Callable[[Burst], None] = print, keep_all: bool = False) -> None:
    """Keep reading new tiles for `minutes`, resuming from the database's saved position when there is one.
    The database gets only what `Watcher.keep` picks, unless `keep_all`."""
    deadline = time.monotonic() + minutes * 60
    full = ctlog.tree_size(watcher.log) // ctlog.TILE
    saved = store.get_progress(conn, watcher.log) if conn else None
    nxt = max(saved, full - max_backlog) if saved is not None else full - 1
    if saved is not None:
        on_status(f"resuming at tile {nxt:,} ({full - nxt:,} tiles behind)")
    next_bursts = time.monotonic() + bursts_every * 60 if bursts_every else None
    reported: set[str] = set()
    while time.monotonic() < deadline:
        size = ctlog.tree_size(watcher.log)
        full = size // ctlog.TILE
        if nxt < full:
            for entries in read_tiles(watcher.log, nxt, full - 1):
                for alert in watcher.handle(entries):
                    on_alert(alert)
                if conn:
                    store.record(conn, watcher.log, nxt, entries, entries if keep_all else watcher.keep(entries))
                nxt += 1
                if time.monotonic() >= deadline:
                    break
        kept = f"{watcher.kept:,} kept · " if conn and not keep_all else ""
        on_status(f"{watcher.seen:,} certificates · {kept}{len(watcher.alerted)} alerts · "
                  f"{max(0, size - nxt * ctlog.TILE):,} entries behind")
        if conn and next_bursts and time.monotonic() >= next_bursts:
            for b in find_bursts(conn, burst_hours, burst_min, allow=watcher.allow):
                if b.regex not in reported:
                    reported.add(b.regex)
                    on_burst(b)
            next_bursts = time.monotonic() + bursts_every * 60
        time.sleep(poll)
