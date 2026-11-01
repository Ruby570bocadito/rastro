"""DNS lookups through a public resolver (DNS over HTTPS), cached on disk.

Rastro never connects to a suspicious domain itself: the question goes to
Cloudflare's resolver, which answers from its cache or asks the domain's name
servers on its own.
"""

from __future__ import annotations

import ipaddress
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from rastro.domains import registrable
from rastro.sources import NETWORK_ERRORS, USER_AGENT, retryable, wait

RESOLVER = "https://cloudflare-dns.com/dns-query"
TYPES = {"A": 1, "NS": 2, "PTR": 12}
# Phishing domains move and die within days, so a day-old answer is old news: asked again after this.
MAX_AGE_HOURS = 24.0


def answers(payload: dict, rtype: str) -> list[str]:
    """Records of one type from a DNS-over-HTTPS JSON answer, without trailing dots."""
    code = TYPES[rtype]
    return sorted({a["data"].rstrip(".").lower() for a in payload.get("Answer", []) if a.get("type") == code})


def query(name: str, rtype: str, cache_dir: Path, pause: float = 0.1, retries: int = 3, fresh: bool = False,
          max_age_hours: float = MAX_AGE_HOURS) -> dict:
    """The resolver's JSON answer, from the cache when younger than `max_age_hours`, unless `fresh` (the tracker
    needs today's answer). A stale answer is still better than none when the resolver never answers."""
    path = Path(cache_dir) / f"dns_{rtype}_{name}.json"
    cached = path.exists() and not fresh
    if cached and time.time() - path.stat().st_mtime < max_age_hours * 3600:
        return json.loads(path.read_text(encoding="utf-8"))
    url = RESOLVER + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT})
    payload: dict = {}
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read())
            break
        except (*NETWORK_ERRORS, json.JSONDecodeError) as err:
            if not retryable(err):
                break
            time.sleep(wait(err, 2 ** attempt))
    if payload:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    elif cached:
        payload = json.loads(path.read_text(encoding="utf-8"))
    time.sleep(pause)
    return payload


STATUS = {0: "noerror", 2: "servfail", 3: "nxdomain"}


def resolve(domain: str, cache_dir: Path, fresh: bool = False) -> tuple[str | None, frozenset[str]]:
    """The resolver's verdict (noerror, nxdomain, servfail...) and the domain's addresses; None if it never
    answered. NXDOMAIN means the name is not in its TLD's zone: deleted, or suspended by the registry."""
    payload = query(domain, "A", cache_dir, fresh=fresh)
    if not payload:
        return None, frozenset()
    return STATUS.get(payload.get("Status"), "other"), frozenset(answers(payload, "A"))


def addresses(domain: str, cache_dir: Path) -> frozenset[str]:
    return frozenset(answers(query(domain, "A", cache_dir), "A"))


def reverse(ip: str, cache_dir: Path) -> frozenset[str]:
    """The names an address's owner gives it in reverse DNS (PTR), e.g. 192.169.69.26 -> sinkhole.hyas.com. The
    question goes to the resolver, which asks whoever runs the address's reverse zone, never the address itself."""
    try:
        arpa = ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return frozenset()
    return frozenset(answers(query(arpa, "PTR", cache_dir), "PTR"))


def nameservers(domain: str, cache_dir: Path) -> frozenset[str]:
    """Registrable domains of the name servers, e.g. ns1.evil-ns.ru -> evil-ns.ru."""
    return frozenset(registrable(ns) for ns in answers(query(domain, "NS", cache_dir), "NS"))
