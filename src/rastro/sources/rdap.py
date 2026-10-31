"""Registration data through RDAP, the public successor of WHOIS (no key).

Each TLD's registry answers for its domains, and IANA's bootstrap file says which server
that is. Rastro reads only what the map and an abuse report need: when the domain was
registered, by which registrar, and that registrar's abuse desk. It skips every
registrant, administrative, technical and billing contact, even when a registry shows
them: Rastro stops at infrastructure, never people.

The registry, not the domain, answers, so asking never touches attacker infrastructure.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from rastro.sources import NETWORK_ERRORS, USER_AGENT

BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_MAX_AGE = 7 * 24 * 3600
PEOPLE = {"registrant", "administrative", "technical", "billing"}


@dataclass(frozen=True)
class Registration:
    domain: str
    registered: datetime | None       # None when the registry gives no time, or only a date
    expires: datetime | None
    registrar: str | None
    registrar_id: str | None          # IANA registrar ID
    abuse_email: str | None
    abuse_phone: str | None
    status: tuple[str, ...]
    server: str
    registered_day: datetime | None = None   # the registration even when the registry gives only its date


def servers(bootstrap: dict) -> dict[str, str]:
    """TLD -> RDAP base URL, from IANA's bootstrap file (HTTPS preferred)."""
    out = {}
    for tlds, urls in bootstrap.get("services", []):
        url = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
        if url:
            for tld in tlds:
                out[tld.lower()] = url if url.endswith("/") else url + "/"
    return out


def _get(url: str, timeout: float, retries: int, accept: str = "application/rdap+json") -> dict | None:
    """JSON answer, {} when the server says the domain does not exist, None when it never answered."""
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": USER_AGENT})
    delay = 2.0
    for _ in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return {}
            if err.code not in (429, 500, 502, 503, 504):
                return None
        except (*NETWORK_ERRORS, json.JSONDecodeError):
            pass
        time.sleep(delay)
        delay = min(delay * 2, 30)
    return None


_SERVERS: dict[tuple[str, bool], dict[str, str]] = {}


def servers_for(cache_dir: Path, offline: bool = False) -> dict[str, str]:
    """TLD -> RDAP base URL, read once per run."""
    key = (str(cache_dir), offline)
    if key not in _SERVERS:
        _SERVERS[key] = servers(bootstrap(cache_dir, offline))
    return _SERVERS[key]


def bootstrap(cache_dir: Path, offline: bool = False) -> dict:
    path = Path(cache_dir) / "iana-dns.json"
    fresh = path.exists() and time.time() - path.stat().st_mtime < BOOTSTRAP_MAX_AGE
    if fresh or (offline and path.exists()):
        return json.loads(path.read_text(encoding="utf-8"))
    if offline:
        return {}
    payload = _get(BOOTSTRAP, timeout=30, retries=3, accept="application/json")
    if payload:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return payload
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _vcard(entity: dict) -> dict[str, str]:
    """fn, email and tel of an entity's vCard (jCard), first value of each."""
    out: dict[str, str] = {}
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return out
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "email", "tel") and item[0] not in out:
            value = item[3].strip().removeprefix("tel:").removeprefix("mailto:") if isinstance(item[3], str) else ""
            if value:
                out[item[0]] = value
    return out


def _when(stamp: str | None) -> datetime | None:
    if not stamp:
        return None
    try:
        t = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t.astimezone(UTC) if t.tzinfo else t.replace(tzinfo=UTC)


def parse(payload: dict, domain: str, server: str) -> Registration:
    events = {e.get("eventAction"): _when(e.get("eventDate")) for e in payload.get("events", [])
              if isinstance(e, dict)}
    registered = events.get("registration")
    if registered and (registered.hour, registered.minute, registered.second) == (0, 0, 0):
        registered = None         # a bare date says nothing about the hour
    name = rid = email = phone = None
    for entity in payload.get("entities", []):
        roles = set(entity.get("roles") or [])
        if "registrar" not in roles or roles & PEOPLE:
            continue
        name = _vcard(entity).get("fn")
        rid = next((p.get("identifier") for p in entity.get("publicIds") or []
                    if "iana" in (p.get("type") or "").lower()), None)
        for inner in entity.get("entities") or []:
            if "abuse" in (inner.get("roles") or []):
                card = _vcard(inner)
                email, phone = card.get("email"), card.get("tel")
        break
    if email is None:             # some registries list the abuse desk at the top level
        for entity in payload.get("entities", []):
            roles = set(entity.get("roles") or [])
            if "abuse" in roles and not roles & PEOPLE:
                card = _vcard(entity)
                email, phone = card.get("email"), card.get("tel")
                break
    return Registration(domain=domain, registered=registered, expires=events.get("expiration"), registrar=name,
                        registrar_id=rid, abuse_email=email, abuse_phone=phone,
                        status=tuple(payload.get("status") or ()), server=server,
                        registered_day=events.get("registration"))


def check(domain: str, cache_dir: Path, offline: bool = False, fresh: bool = False,
          pause: float = 0.2) -> tuple[str, Registration | None]:
    """What the registry says about a domain: ("found", registration), or "not-found", "no-server" (its TLD has
    no RDAP server) or "no-answer" with None. `fresh` skips the cache, as the tracker needs today's answer."""
    cache_dir = Path(cache_dir)
    path = cache_dir / f"rdap_{domain}.json"
    base = servers_for(cache_dir, offline).get(domain.rsplit(".", 1)[-1])
    if path.exists() and not fresh:
        payload = json.loads(path.read_text(encoding="utf-8"))
    elif base is None:
        return "no-server", None
    elif offline:
        return "no-answer", None
    else:
        payload = _get(f"{base}domain/{domain}", timeout=30, retries=3)
        time.sleep(pause)
        if payload is None:
            return "no-answer", None
        if payload:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload), encoding="utf-8")
    if not payload:
        return "not-found", None
    return "found", parse(payload, domain, base or "")


def lookup(domain: str, cache_dir: Path, offline: bool = False, pause: float = 0.2) -> Registration | None:
    """The registration of a registrable domain, or None when it is not registered, its TLD has no RDAP
    server, or the server never answered."""
    return check(domain, cache_dir, offline=offline, pause=pause)[1]
