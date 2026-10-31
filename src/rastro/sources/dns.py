"""DNS lookups through a public resolver (DNS over HTTPS), cached on disk.

Rastro never connects to a suspicious domain itself: the question goes to
Cloudflare's resolver, which answers from its cache or asks the domain's name
servers on its own.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from rastro.domains import registrable

RESOLVER = "https://cloudflare-dns.com/dns-query"
USER_AGENT = "rastro-osint/0.0.1 (phishing research)"
TYPES = {"A": 1, "NS": 2}


def answers(payload: dict, rtype: str) -> list[str]:
    """Records of one type from a DNS-over-HTTPS JSON answer, without trailing dots."""
    code = TYPES[rtype]
    return sorted({a["data"].rstrip(".").lower() for a in payload.get("Answer", []) if a.get("type") == code})


def query(name: str, rtype: str, cache_dir: Path, pause: float = 0.1, retries: int = 3) -> dict:
    path = Path(cache_dir) / f"dns_{rtype}_{name}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    url = RESOLVER + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT})
    payload: dict = {}
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read())
            break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            time.sleep(2 ** attempt)
    if payload:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    time.sleep(pause)
    return payload


def addresses(domain: str, cache_dir: Path) -> frozenset[str]:
    return frozenset(answers(query(domain, "A", cache_dir), "A"))


def nameservers(domain: str, cache_dir: Path) -> frozenset[str]:
    """Registrable domains of the name servers, e.g. ns1.evil-ns.ru -> evil-ns.ru."""
    return frozenset(registrable(ns) for ns in answers(query(domain, "NS", cache_dir), "NS"))
