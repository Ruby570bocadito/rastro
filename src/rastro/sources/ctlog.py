"""Read Certificate Transparency logs directly through the static CT API (tiled logs).

Let's Encrypt and other operators publish their logs as static tiles of 256
entries, built for monitors that want every certificate. Each entry carries the
moment the log took the certificate, to the millisecond, so no backdating
guesswork is needed. Shards rotate every six months; `tiled_logs()` lists the
current ones from Google's log list.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from rastro.sources import NETWORK_ERRORS, USER_AGENT, der, retryable, wait

TILE = 256
LOG_LIST = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
DEFAULT_LOG = "https://mon.sycamore.ct.letsencrypt.org/2027h1"


@dataclass(frozen=True)
class Entry:
    index: int
    logged_at: datetime      # when the log took the certificate (UTC, millisecond precision)
    precert: bool
    names: tuple[str, ...]   # DNS names, wildcards stripped
    issuer: str


def _get(url: str, timeout: float = 60, retries: int = 4) -> bytes:
    delay, last_error = 2.0, None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except NETWORK_ERRORS as err:
            last_error = err
            if not retryable(err):
                break
            time.sleep(wait(err, delay))
            delay *= 2
    raise RuntimeError(f"{url} did not answer: {last_error}")


def tiled_logs(days_ahead: int = 90) -> list[tuple[str, str]]:
    """(description, monitoring URL) of usable tiled logs taking certificates that expire in `days_ahead` days."""
    data = json.loads(_get(LOG_LIST))
    when = datetime.now(UTC) + timedelta(days=days_ahead)
    out = []
    for op in data["operators"]:
        for log in op.get("tiled_logs", []):
            interval = log.get("temporal_interval") or {}
            start, end = interval.get("start_inclusive"), interval.get("end_exclusive")
            if "usable" not in log.get("state", {}) or not (start and end):
                continue
            begins = datetime.fromisoformat(start.replace("Z", "+00:00"))
            ends = datetime.fromisoformat(end.replace("Z", "+00:00"))
            if begins <= when < ends:
                out.append((log["description"], log["monitoring_url"].rstrip("/")))
    return out


def tree_size(log_url: str) -> int:
    """Number of entries in the log, from its signed checkpoint."""
    return int(_get(log_url.rstrip("/") + "/checkpoint").decode().splitlines()[1])


def tile_path(n: int, width: int = TILE) -> str:
    """Path of data tile `n`: 1234067 -> tile/data/x001/x234/067, partial tiles get .p/<width>."""
    groups = []
    while True:
        groups.append(f"{n % 1000:03d}")
        n //= 1000
        if n == 0:
            break
    groups.reverse()
    path = "/".join([f"x{g}" for g in groups[:-1]] + [groups[-1]])
    return f"tile/data/{path}" + ("" if width == TILE else f".p/{width}")


def fetch_tile(log_url: str, n: int, width: int = TILE) -> list[Entry]:
    return parse_tile(_get(f"{log_url.rstrip('/')}/{tile_path(n, width)}"), n * TILE)


def _u(buf: bytes, pos: int, size: int) -> int:
    return int.from_bytes(buf[pos:pos + size], "big")


def parse_tile(data: bytes, first_index: int) -> list[Entry]:
    """Entries of one data tile (TileLeaf records of the static CT API)."""
    out, pos, index = [], 0, first_index
    while pos < len(data):
        stamp, entry_type = _u(data, pos, 8), _u(data, pos + 8, 2)
        pos += 10
        if entry_type == 0:                       # x509_entry: the certificate itself
            size = _u(data, pos, 3)
            cert = data[pos + 3:pos + 3 + size]
            pos += 3 + size
            _, inner, _ = der.tlv(cert, 0)
            _, _, tbs_end = der.tlv(cert, inner)
            tbs = cert[inner:tbs_end]
        else:                                     # precert_entry: issuer key hash, then the TBSCertificate
            pos += 32
            size = _u(data, pos, 3)
            tbs = data[pos + 3:pos + 3 + size]
            pos += 3 + size
        pos += 2 + _u(data, pos, 2)               # CT extensions
        if entry_type == 1:
            pos += 3 + _u(data, pos, 3)           # the pre-certificate
        pos += 2 + _u(data, pos, 2)               # fingerprints of the chain
        try:
            names, issuer = der.tbs_fields(tbs)
        except (IndexError, ValueError):
            names, issuer = [], ""
        out.append(Entry(
            index=index,
            logged_at=datetime.fromtimestamp(stamp / 1000, UTC),
            precert=entry_type == 1,
            names=tuple(sorted({n.removeprefix("*.") for n in names})),
            issuer=issuer,
        ))
        index += 1
    return out
