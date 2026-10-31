"""Local store of the names seen in Certificate Transparency logs (SQLite, standard library).

A watch keeps only the certificates worth looking at again (see `Watcher.keep`), but it
counts everything it read per hour in `seen`, so the store still knows how much of the
log it covered.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from pathlib import Path

from rastro.domains import registrable
from rastro.sources.ctlog import Entry

SCHEMA = """
CREATE TABLE IF NOT EXISTS certs (
    log TEXT NOT NULL, idx INTEGER NOT NULL, logged_at TEXT NOT NULL, precert INTEGER NOT NULL, issuer TEXT,
    PRIMARY KEY (log, idx)
);
CREATE TABLE IF NOT EXISTS names (
    log TEXT NOT NULL, idx INTEGER NOT NULL, name TEXT NOT NULL, registrable TEXT NOT NULL, logged_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS names_registrable ON names (registrable);
CREATE INDEX IF NOT EXISTS names_time ON names (logged_at);
CREATE TABLE IF NOT EXISTS progress (log TEXT PRIMARY KEY, next_tile INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS seen (
    log TEXT NOT NULL, hour TEXT NOT NULL, certs INTEGER NOT NULL, kept INTEGER NOT NULL,
    PRIMARY KEY (log, hour)
);
"""


def get_progress(conn: sqlite3.Connection, log: str) -> int | None:
    """Next tile to read from `log`, if a previous watch got that far."""
    row = conn.execute("SELECT next_tile FROM progress WHERE log = ?", (log,)).fetchone()
    return row[0] if row else None


def set_progress(conn: sqlite3.Connection, log: str, next_tile: int) -> None:
    with conn:
        _set_progress(conn, log, next_tile)


def _set_progress(conn: sqlite3.Connection, log: str, next_tile: int) -> None:
    conn.execute("INSERT INTO progress VALUES (?, ?) ON CONFLICT(log) DO UPDATE SET next_tile = excluded.next_tile",
                 (log, next_tile))


def connect(path: Path | str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn


def save(conn: sqlite3.Connection, log: str, entries: list[Entry]) -> int:
    """Store entries once each; returns how many were new."""
    with conn:
        return _insert(conn, log, entries)


def _insert(conn: sqlite3.Connection, log: str, entries: list[Entry]) -> int:
    if not entries:
        return 0
    before = conn.total_changes
    conn.executemany(
        "INSERT OR IGNORE INTO certs VALUES (?, ?, ?, ?, ?)",
        [(log, e.index, e.logged_at.isoformat(), int(e.precert), e.issuer) for e in entries],
    )
    new = conn.total_changes - before
    if new:
        known = {row[0] for row in conn.execute(
            "SELECT idx FROM names WHERE log = ? AND idx BETWEEN ? AND ?",
            (log, entries[0].index, entries[-1].index))}
        conn.executemany(
            "INSERT INTO names VALUES (?, ?, ?, ?, ?)",
            [(log, e.index, n, registrable(n), e.logged_at.isoformat())
             for e in entries if e.index not in known for n in e.names],
        )
    return new


def record(conn: sqlite3.Connection, log: str, tile: int, entries: list[Entry], kept: list[Entry]) -> bool:
    """Store one tile's kept entries, count what the tile held per hour and move the log's position past it,
    in one transaction, so a crash never stores or counts a tile twice. Returns False for a tile already
    recorded."""
    with conn:
        nxt = get_progress(conn, log)
        if nxt is not None and tile < nxt:
            return False
        _insert(conn, log, kept)
        read = Counter(f"{e.logged_at:%Y-%m-%dT%H}" for e in entries)
        stored = Counter(f"{e.logged_at:%Y-%m-%dT%H}" for e in kept)
        conn.executemany(
            "INSERT INTO seen VALUES (?, ?, ?, ?) ON CONFLICT(log, hour) "
            "DO UPDATE SET certs = certs + excluded.certs, kept = kept + excluded.kept",
            [(log, hour, n, stored[hour]) for hour, n in read.items()],
        )
        _set_progress(conn, log, tile + 1)
    return True


def coverage(conn: sqlite3.Connection, since: str = "") -> tuple[int, int, str | None, str | None]:
    """Certificates read and kept since an ISO hour (all by default), and the first and last hour covered."""
    certs, kept, first, last = conn.execute(
        "SELECT COALESCE(SUM(certs), 0), COALESCE(SUM(kept), 0), MIN(hour), MAX(hour) FROM seen WHERE hour >= ?",
        (since[:13],)).fetchone()
    return certs, kept, first, last
