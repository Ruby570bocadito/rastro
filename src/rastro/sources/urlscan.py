"""Read-only searches on urlscan.io: the sites that loaded the same files as a phishing page.

Phishing kits are copied whole, so the sites of one campaign load the same scripts, images and
styles even when their names share nothing. urlscan.io has already visited many of them for other
people; Rastro only searches what is there. It never submits a scan: that would make urlscan visit
the attacker's site on Rastro's behalf, and publish a page whose address may carry a victim's token.

The search API needs a free account. The key is read from the URLSCAN_API_KEY environment variable,
sent only to urlscan.io and never written to disk; answers are cached without it.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from rastro.domains import registrable
from rastro.sources import NETWORK_ERRORS, USER_AGENT, retryable, wait

API = "https://urlscan.io/api/v1/"
KEY_VARIABLE = "URLSCAN_API_KEY"
COMMON = 200          # a file loaded by more scans than this is a shared library (jQuery, a CDN font), not a kit
MAX_HASHES = 25       # most of the seed's files to look up, to stay inside the free quota


class NoKey(RuntimeError):
    pass


class Client:
    """Searches and scan results, cached on disk, with the key from the environment."""

    def __init__(self, cache_dir: Path, key: str | None = None, pause: float = 1.0, retries: int = 4):
        self.key = key or os.environ.get(KEY_VARIABLE)
        if not self.key:
            raise NoKey(f"set {KEY_VARIABLE} to a urlscan.io API key (free account) to search urlscan")
        self.cache_dir = Path(cache_dir)
        self.pause, self.retries = pause, retries
        self.requests = 0                    # answers that came from urlscan, not the cache

    def _get(self, url: str, cache: Path) -> dict | None:
        if cache.exists():
            return json.loads(cache.read_text(encoding="utf-8"))
        req = urllib.request.Request(url, headers={"API-Key": self.key, "User-Agent": USER_AGENT,
                                                   "Accept": "application/json"})
        delay = 2.0
        for _ in range(self.retries):
            try:
                self.requests += 1
                with urllib.request.urlopen(req, timeout=30) as resp:
                    payload = json.loads(resp.read())
                break
            except urllib.error.HTTPError as err:
                if err.code == 404:
                    return None
                if not retryable(err):
                    raise RuntimeError(f"urlscan refused {url}: HTTP {err.code}") from err
                time.sleep(wait(err, delay))
            except (*NETWORK_ERRORS, json.JSONDecodeError) as err:
                if not retryable(err):
                    raise RuntimeError(f"urlscan did not answer {url}: {err}") from err
                time.sleep(delay)
            delay = min(delay * 2, 60)
        else:
            raise RuntimeError(f"urlscan did not answer {url}")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(payload), encoding="utf-8")
        time.sleep(self.pause)
        return payload

    def search(self, query: str, size: int = 100) -> dict:
        """The search API's answer for `query` (urlscan's Elasticsearch syntax, e.g. page.domain:x.top)."""
        name = hashlib.sha256(f"{query}|{size}".encode()).hexdigest()[:32]
        url = API + "search/?" + urllib.parse.urlencode({"q": query, "size": size})
        return self._get(url, self.cache_dir / f"search_{name}.json") or {}

    def result(self, uuid: str) -> dict | None:
        """A scan's full result, or None when urlscan has none under that id."""
        if not all(c.isalnum() or c == "-" for c in uuid):
            raise ValueError(f"not a urlscan scan id: {uuid!r}")
        return self._get(f"{API}result/{uuid}/", self.cache_dir / f"result_{uuid}.json")


def hits(payload: dict) -> list[tuple[str, str, str]]:
    """(registrable domain, scan time, scan id) of each search hit that names a page."""
    out = []
    for r in payload.get("results") or []:
        page, task = r.get("page") or {}, r.get("task") or {}
        domain = (page.get("domain") or task.get("domain") or "").lower()
        if domain:
            out.append((registrable(domain), task.get("time") or "", r.get("_id") or task.get("uuid") or ""))
    return out


def live_first(payload: dict, seed: str) -> list[str]:
    """The seed's scan ids, richest live page first. The newest scan is usually of the page already taken down
    (a 404, 403 or 451 that loads two or three files), which says nothing about the kit; experiment 02 found it so."""
    def rank(r: dict) -> tuple:
        page, stats = r.get("page") or {}, r.get("stats") or {}
        return (str(page.get("status")) == "200", stats.get("requests") or 0, (r.get("task") or {}).get("time") or "")
    mine = [r for r in payload.get("results") or []
            if registrable(((r.get("page") or {}).get("domain") or "").lower()) == seed and r.get("_id")]
    return [r["_id"] for r in sorted(mine, key=rank, reverse=True)]


@dataclass
class Expansion:
    seed: str
    scan: str | None = None                          # the seed's richest live scan, None when urlscan never saw it
    hashes: int = 0                                  # files on the seed's page
    common: int = 0                                  # of them, shared libraries left out
    siblings: dict[str, set[str]] = field(default_factory=dict)   # domain -> the seed's files it loaded too
    requests: int = 0
    seconds: float = 0.0


def expand(client: Client, seed: str, common: int = COMMON, max_hashes: int = MAX_HASHES) -> Expansion:
    """The domains whose scanned pages loaded the same distinctive files as the seed's richest live scan."""
    start, before = time.monotonic(), client.requests
    out = Expansion(seed)
    scans = live_first(client.search(f"page.domain:{seed}", size=100), seed)
    result = client.result(scans[0]) if scans else None
    if result:
        out.scan = scans[0]
        hashes = list(dict.fromkeys((result.get("lists") or {}).get("hashes") or []))
        out.hashes = len(hashes)
        looked = []
        for h in hashes:
            if not (len(h) == 64 and all(c in "0123456789abcdef" for c in h)):
                continue
            payload = client.search(f"hash:{h}", size=100)
            if (payload.get("total") or 0) > common:
                out.common += 1
                continue
            looked.append(h)
            for d, _, _ in hits(payload):
                if d != seed:
                    out.siblings.setdefault(d, set()).add(h)
            if len(looked) >= max_hashes:
                break
    out.requests = client.requests - before
    out.seconds = round(time.monotonic() - start, 1)
    return out
