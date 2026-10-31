"""Certificate Transparency search through crt.sh (public, no key).

crt.sh is free and often overloaded: it answers 502 now and then, so every
query retries with backoff and the raw answer is cached on disk.
"""

from __future__ import annotations

import html
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from rastro.domains import registrable
from rastro.sources import NETWORK_ERRORS, USER_AGENT

BASE = "https://crt.sh/"


HOSTNAME = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")

# Let's Encrypt backdates notBefore by one hour. Checked on 2026-10-30 against the CT log time of two
# certificates (R3, 2021, and E8, 2025): the log time was notBefore + 1 h, within two minutes.
LE_BACKDATE = timedelta(hours=1)
# How close the first timed certificate must be to the domain's first certificate of any kind.
FIRST_CERT_SLACK = timedelta(days=2)


@dataclass(frozen=True)
class CertEntry:
    cert_id: int
    names: tuple[str, ...]
    not_before: datetime          # validity start (UTC); some CAs round it to midnight
    issued_at: datetime | None    # issuance time (UTC) when it can be trusted to the minute, else None
    issuer: str


def _slug(query: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", query.lower()).strip("_") or "query"


def cache_path(query: str, cache_dir: Path) -> Path:
    return Path(cache_dir) / f"crtsh_{_slug(query)}.json"


def fetch(query: str, cache_dir: Path, max_age_hours: float = 24, retries: int = 6, timeout: float = 150) -> list[dict]:
    """Rows of crt.sh's JSON answer for `query` (crt.sh wildcards use %)."""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_path(query, cache_dir)
    if path.exists() and time.time() - path.stat().st_mtime < max_age_hours * 3600:
        return json.loads(path.read_text(encoding="utf-8"))
    url = BASE + "?" + urllib.parse.urlencode({"q": query, "output": "json"})
    delay, last_error = 5.0, None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
            rows = json.loads(body)
            path.write_bytes(body)
            return rows
        except (*NETWORK_ERRORS, json.JSONDecodeError) as err:
            last_error = err
            time.sleep(delay)
            delay = min(delay * 2, 60)
    raise RuntimeError(f"crt.sh did not answer for {query!r}: {last_error}")


def _utc(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.rstrip("Z")).replace(tzinfo=UTC)


def parse(rows: Iterable[dict]) -> list[CertEntry]:
    """Parse crt.sh rows. Wildcard searches return no log time, so the issuance time comes from
    the CT log time when present, else from a Let's Encrypt notBefore plus its one-hour backdate.
    Other CAs often round notBefore or backdate it by unknown amounts, so their time stays unknown."""
    out = []
    for r in rows:
        if not r.get("not_before"):
            continue
        not_before = _utc(r["not_before"])
        issuer = r.get("issuer_name") or ""
        if r.get("entry_timestamp"):
            issued_at = _utc(r["entry_timestamp"])
        elif "Let's Encrypt" in issuer:
            issued_at = not_before + LE_BACKDATE
        else:
            issued_at = None
        names = set()
        for raw in (r.get("name_value") or "").splitlines():
            name = raw.strip().lower().removeprefix("*.")
            if HOSTNAME.match(name):
                names.add(name)
        if names:
            out.append(CertEntry(int(r["id"]), tuple(sorted(names)), not_before, issued_at, issuer))
    return out


def first_cert(entries: Iterable[CertEntry], domain: str) -> CertEntry | None:
    """The earliest certificate of a registrable domain, whatever its CA."""
    mine = [e for e in entries if any(registrable(n) == domain for n in e.names)]
    return min(mine, key=lambda e: e.not_before) if mine else None


def cert_page_path(cert_id: int, cache_dir: Path) -> Path:
    return Path(cache_dir) / f"crtsh_cert_{cert_id}.html"


def log_time(cert_id: int, cache_dir: Path, timeout: float = 60, retries: int = 4) -> datetime | None:
    """When the CT logs took a certificate, from its crt.sh page (JSON answers leave this out)."""
    path = cert_page_path(cert_id, cache_dir)
    if path.exists():
        page = path.read_text(encoding="utf-8", errors="replace")
    else:
        delay, page = 5.0, None
        for _ in range(retries):
            try:
                req = urllib.request.Request(f"{BASE}?id={cert_id}", headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    page = resp.read().decode("utf-8", errors="replace")
                break
            except NETWORK_ERRORS:
                time.sleep(delay)
                delay = min(delay * 2, 60)
        if page is None:
            return None
        Path(cache_dir).mkdir(parents=True, exist_ok=True)
        path.write_text(page, encoding="utf-8")
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(page)))
    start = text.find("Timestamp Entry #")
    if start < 0:
        return None
    end = text.find("Revocation", start)
    stamps = re.findall(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC", text[start:end if end > 0 else None])
    if not stamps:
        return None
    return min(datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC) for s in stamps)


def profile(domain: str, cache_dir: Path, offline: bool = False) -> tuple[datetime | None, frozenset[str]]:
    """When a domain got its first certificate, and which registrable domains shared a certificate with it."""
    path = cache_path(domain, cache_dir)
    if offline and not path.exists():
        return None, frozenset()
    try:
        entries = parse(fetch(domain, cache_dir, max_age_hours=24 * 30, retries=4, timeout=60))
    except RuntimeError:
        return None, frozenset()
    mine = [e for e in entries if any(registrable(n) == domain for n in e.names)]
    co = frozenset({registrable(n) for e in mine for n in e.names} - {domain})
    when = first_seen(mine, keep=lambda d: d == domain).get(domain)
    if when is None:
        first = first_cert(mine, domain)
        if first and (not offline or cert_page_path(first.cert_id, cache_dir).exists()):
            when = log_time(first.cert_id, cache_dir)
    return when, co


def first_seen(entries: Iterable[CertEntry], keep: Callable[[str], bool] = lambda d: True) -> dict[str, datetime]:
    """Issuance time of each registrable domain's first certificate.

    Later certificates are renewals, which software sends on its own schedule, so they are ignored.
    A domain is dropped when its first certificate has no trustworthy time and the first timed one
    came more than FIRST_CERT_SLACK later, since that one may already be a renewal."""
    first_any: dict[str, datetime] = {}
    first_timed: dict[str, datetime] = {}
    for e in entries:
        for d in {registrable(n) for n in e.names}:
            if not keep(d):
                continue
            if d not in first_any or e.not_before < first_any[d]:
                first_any[d] = e.not_before
            if e.issued_at and (d not in first_timed or e.issued_at < first_timed[d]):
                first_timed[d] = e.issued_at
    return {
        d: t for d, t in first_timed.items()
        if t - first_any[d] <= FIRST_CERT_SLACK + LE_BACKDATE
    }
