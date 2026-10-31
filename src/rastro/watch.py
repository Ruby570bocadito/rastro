"""Live watch: read new certificates from a CT log and alert on names that match armed patterns.

What experiments 03 and 04 taught, built in:
- only narrow patterns are armed (broad ones raised thousands of false alarms a day);
- the brands' official domains never alert (microsoftonline.com matched a broad pattern);
- each domain alerts once, although its pre-certificate and certificate both reach the log;
- with a database, the watch remembers where it stopped and picks up from there;
- it stores only certificates that carry a brand lookalike or an alert (0.4 % of a live
  sample; storing everything would take about 6 GB a day) and counts the rest.
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

from rastro import brands, pattern, store
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

    def line(self) -> str:
        return f"ALERT {self.logged_at} UTC  {self.domain}  matches {self.pattern}"

    def json(self) -> str:
        return json.dumps(asdict(self))


class Watcher:
    def __init__(self, log: str, allow: Iterable[str] = (), max_breadth: float = NARROW_LOG10,
                 allow_broad: bool = False):
        self.log = log
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

    def handle(self, entries: list[ctlog.Entry]) -> list[Alert]:
        alerts = []
        self.seen += len(entries)
        for e in entries:
            for name in sorted({registrable(n) for n in e.names}):
                if name in self.alerted:
                    continue
                hit = next((a for a in self.armed if a.compiled.fullmatch(name)), None)
                if hit is None:
                    continue
                if name in self.allow:
                    self.suppressed += 1
                    continue
                self.alerted.add(name)
                alerts.append(Alert(f"{e.logged_at:%Y-%m-%d %H:%M:%S}", name, hit.regex, self.log, e.index))
        return alerts

    def keep(self, entries: list[ctlog.Entry]) -> list[ctlog.Entry]:
        """The entries worth storing: those with a name that alerted or that carries a brand without being one of
        its official domains. Each is kept whole, so the names it shares a certificate with stay linked."""
        def wanted(name: str) -> bool:
            return name in self.alerted or (name not in self.allow and brands.brand_of(name) is not None)

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
