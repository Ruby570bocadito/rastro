"""Take a case to a hunter's own tools: its indicators, and searches for their logs.

Everything here is made from case data (`report.case_data`, or the file `rastro investigate --json`
writes), so it runs offline and long after the investigation. Two questions it answers:

- has anybody here been to one of the crew's domains, or to the next one it registers? The searches
  (`sigma`, `kql`, `spl`) look for the domains found and for the crew's naming pattern;
- how do I load this into my platform? The exports (`csv_text`, `stix`, `misp`, `blocklist`).

How sure each indicator is, is carried along:

- the seed and its campaign are tied by clues that add up; the rest of the crew only by its template;
- a domain now held by a brand-protection registrar, or registered again maybe by somebody else, is
  never exported: it is no longer the crew's;
- addresses are exported for context only, marked as not for detection, and never go into a blocklist
  or a search: an address is often shared with thousands of innocent sites.

The searches use regular expressions that RE2 accepts (Sentinel, Defender, most Sigma backends), so a
pattern's look-ahead for a moving core becomes a separate "contains" condition.

A case file may come from somebody else, and what is written here is pasted into query languages. So
nothing from the case reaches a search or a comment unchecked: names must be host names, addresses must
be addresses, a pattern may only use the characters Rastro's own patterns use, and free text is cut to
one line. What does not pass is left out, and `dropped()` says how much.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass

NAMESPACE = uuid.UUID("5f0b1f6e-2d1c-4c1e-9b0a-7a5d1c0e8a11")       # makes every id the same on every export
NOT_THE_CREWS = {"defensive", "reregistered"}
HOSTNAME = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?")
LOOKAHEAD = re.compile(r"^\(\?=\.\*(.+?)\)")
PATTERN_CHARS = re.compile(r"[A-Za-z0-9\\\[\]{}()|?=.*,-]+")     # what `rastro.pattern` writes, and nothing else
CORE = re.compile(r"[a-z0-9-]+")
FORMATS = {"csv": "iocs.csv", "blocklist": "blocklist.txt", "stix": "stix.json", "misp": "misp.json",
           "sigma": "sigma.yml", "kql": "hunt.kql", "spl": "hunt.spl"}
ATTACK = ("attack.initial-access", "attack.t1566.002")             # phishing: spearphishing link


@dataclass(frozen=True)
class Indicator:
    value: str
    kind: str                  # domain or ip
    role: str                  # seed, campaign, crew; for an address, the role of its domain
    alive: bool
    first_seen: str | None
    registrar: str | None
    status: str | None         # why it was left out of the abuse reports, if it was
    of: str | None = None      # for an address: the domain it answers for

    @property
    def confidence(self) -> int:
        """0 to 100, as STIX counts it: clues that add up, a shared template alone, or an address."""
        return 25 if self.kind == "ip" else 85 if self.role in ("seed", "campaign") else 60

    @property
    def detect(self) -> bool:
        return self.kind == "domain"


def _safe(name: str) -> bool:
    """Only plain host names leave Rastro: these files end up inside other tools' query languages."""
    return isinstance(name, str) and bool(HOSTNAME.fullmatch(name)) and ".." not in name and len(name) <= 253


def _address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except (ValueError, TypeError):
        return False
    return True


def _line(text, limit: int = 200) -> str:
    """Free text from the case as one plain line: no line breaks or control characters, which would end a
    comment and start a query, and no backticks or quotes."""
    return re.sub(r"[\x00-\x1f\x7f`\"']+", " ", str(text)).strip()[:limit]


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def patterns(case: dict) -> list[dict]:
    """The case's naming patterns that are safe to hand on: only Rastro's own pattern characters, a regular
    expression that compiles, and a known kind."""
    out = []
    for p in case.get("patterns") or []:
        regex = p.get("regex") if isinstance(p, dict) else None
        if not isinstance(regex, str) or not PATTERN_CHARS.fullmatch(regex) or len(regex) > 400:
            continue
        if p.get("kind") not in ("crew", "campaign", "guess"):
            continue
        try:
            re.compile(regex)
        except re.error:
            continue
        out.append({"regex": regex, "kind": p["kind"], "support": int(p.get("support") or 0),
                    "breadth": float(p.get("breadth") or 0)})
    return out


def dropped(case: dict) -> dict[str, int]:
    """How much of the case was left out for not being what it should be: a tampered or broken case file."""
    rows = [r for r in case.get("domains") or [] if isinstance(r, dict) and (r.get("attributed") or r.get("seed"))]
    return {
        "domains": sum(not _safe(r.get("id")) for r in rows),
        "addresses": sum(not _address(ip) for r in rows for ip in r.get("ips") or []),
        "patterns": len(case.get("patterns") or []) - len(patterns(case)),
    }


def indicators(case: dict) -> list[Indicator]:
    """The seed first, then its campaign, then the rest of the crew, each with its addresses."""
    def role(r: dict) -> str:
        return "seed" if r.get("seed") else "campaign" if r.get("campaign") else "crew"

    out = []
    rank = {"seed": 0, "campaign": 1, "crew": 2}
    rows = [r for r in case["domains"] if r.get("attributed") or r.get("seed")]
    for r in sorted(rows, key=lambda r: (rank[role(r)], r["id"])):
        if r.get("status") in NOT_THE_CREWS or not _safe(r.get("id")):
            continue
        out.append(Indicator(r["id"], "domain", role(r), bool(r.get("alive")), r.get("first") or r.get("registered"),
                             r.get("registrar"), r.get("status")))
        for ip in r.get("ips") or []:
            if _address(ip):
                out.append(Indicator(ip, "ip", role(r), bool(r.get("alive")), None, None, None, of=r["id"]))
    return out


@dataclass(frozen=True)
class Search:
    regex: str                 # RE2: matches the name, or any name under it
    contains: tuple[str, ...]  # literal cores a matching name must also carry
    kind: str                  # crew, campaign or guess
    source: str                # the pattern as Rastro learned it


def searches(case: dict) -> list[Search]:
    """The case's naming patterns, ready for a log search. A guess from the seed's name alone is used only when
    nothing better was learned."""
    safe = patterns(case)
    learned = [p for p in safe if p["kind"] != "guess"]
    out = []
    for p in learned or safe:
        body, cores = p["regex"], []
        while (m := LOOKAHEAD.match(body)):
            cores.append(re.sub(r"\\(.)", r"\1", m.group(1)))
            body = body[m.end():]
        if "(?" in body or not all(CORE.fullmatch(c) for c in cores):
            continue                                  # a look-around Rastro never writes: no search from it
        out.append(Search(rf"(^|\.){body}$", tuple(cores), p["kind"], p["regex"]))
    return out


def _title(case: dict) -> str:
    brand = f" imitating {_line(case['brand_name'], 60)}" if case.get("brand_name") else ""
    return f"Rastro case {_line(case['seed'], 253)}: phishing domains{brand}"


def _header(case: dict, found: list[Indicator]) -> list[str]:
    domains = [i for i in found if i.kind == "domain"]
    live = sum(i.alive for i in domains)
    return [f"{_title(case)}",
            f"Generated {_line(case['generated'], 20)} by Rastro {_line(case['version'], 20)} from public sources.",
            f"{_plural(len(domains), 'domain', 'domains')}: {sum(i.role != 'crew' for i in domains)} tied to the seed "
            f"by clues that add up, {sum(i.role == 'crew' for i in domains)} by its naming template alone. "
            f"{live} {'was' if live == 1 else 'were'} live when the case was made."]


# ---------- exports ----------

def _cell(value) -> str:
    """A cell a spreadsheet will not run: text that starts like a formula gets a quote in front."""
    text = _line(value, 300) if isinstance(value, str) else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def csv_text(case: dict) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["indicator", "type", "role", "confidence", "for_detection", "live", "first_seen", "registrar", "status",
                "address_of", "case"])
    for i in indicators(case):
        w.writerow([_cell(c) for c in (
            i.value, i.kind, i.role, i.confidence, "yes" if i.detect else "no", "yes" if i.alive else "no",
            i.first_seen or "", i.registrar or "", i.status or "", i.of or "", case["seed"])])
    return out.getvalue()


def blocklist(case: dict) -> str:
    """Live domains only, one per line: a dead one may be somebody else's tomorrow."""
    found = indicators(case)
    live = [i.value for i in found if i.kind == "domain" and i.alive]
    lines = [f"# {line}" for line in _header(case, found)]
    lines.append(f"# {len(live)} live domains. Dead ones are left out: a lapsed name may be registered by somebody "
                 "else. Addresses are left out: they are often shared.")
    return "\n".join(lines + live) + "\n"


def _once(found: list[Indicator]) -> list[tuple[Indicator, list[str]]]:
    """Each indicator once, an address with every domain it answers for: a crew's domains often share one, and
    a platform takes the same indicator twice badly."""
    out: list[tuple[Indicator, list[str]]] = []
    seen: dict[str, list[str]] = {}
    for i in found:
        if i.kind != "ip":
            out.append((i, []))
        elif i.value in seen:
            seen[i.value].append(i.of)
        else:
            seen[i.value] = [i.of]
            out.append((i, seen[i.value]))
    return out


def _hosts(domains: list[str]) -> str:
    return ", ".join(domains[:3]) + (f" and {len(domains) - 3} more" if len(domains) > 3 else "")


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, kind + '|' + key)}"


def _stix_time(iso: str) -> str:
    return iso[:19] + ".000Z"


def _stix_string(text: str) -> str:
    return text.replace("\\", "\\\\").replace("'", "\\'")


def stix(case: dict) -> str:
    """A STIX 2.1 bundle: one indicator per domain and address, one per naming pattern, and a report over them."""
    now = _stix_time(case["generated"])
    found = indicators(case)
    objects = []
    for i, hosts in _once(found):
        path = ("domain-name:value" if i.kind == "domain" else
                "ipv6-addr:value" if ":" in i.value else "ipv4-addr:value")
        what = (f"Address of {_hosts(hosts)} when the case was made. Often shared with unrelated sites: context, not "
                "detection."
                if i.kind == "ip" else
                {"seed": "The link the case started from.", "campaign": "Tied to the seed by clues that add up.",
                 "crew": "Built from the same naming template as the seed."}[i.role]
                + (" Live when the case was made." if i.alive else " No longer live when the case was made."))
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": _id("indicator", case["seed"] + "|" + i.value),
            "created": now, "modified": now, "name": i.value, "description": what,
            "indicator_types": ["malicious-activity"] if i.detect else ["anomalous-activity"],
            "pattern": f"[{path} = '{_stix_string(i.value)}']", "pattern_type": "stix",
            "valid_from": _stix_time(i.first_seen) if i.first_seen else now, "confidence": i.confidence,
            "labels": ["phishing", i.role],
        })
    for p in patterns(case):
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": _id("indicator", case["seed"] + "|pattern|" + p["regex"]),
            "created": now, "modified": now, "name": f"Naming pattern ({p['kind']}): {p['regex']}",
            "description": f"Learned from {p['support']} domains; about 10^{p['breadth']} possible names. "
                           "Matches the registrable domain."
                           + (" A guess from one name." if p["kind"] == "guess" else ""),
            "indicator_types": ["malicious-activity"],
            "pattern": f"[domain-name:value MATCHES '^{_stix_string(p['regex'])}$']", "pattern_type": "stix",
            "valid_from": now, "confidence": 30 if p["kind"] == "guess" else 70, "labels": ["phishing", "pattern"],
        })
    objects.append({
        "type": "report", "spec_version": "2.1", "id": _id("report", case["seed"]), "created": now, "modified": now,
        "name": _title(case), "description": " ".join(_header(case, found)[1:]), "published": now,
        "report_types": ["threat-report"], "labels": ["phishing"], "object_refs": [o["id"] for o in objects],
    })
    return json.dumps({"type": "bundle", "id": _id("bundle", case["seed"] + "|" + case["generated"]),
                       "objects": objects}, indent=1, ensure_ascii=False) + "\n"


def misp(case: dict) -> str:
    """A MISP event, as its import reads it. Addresses carry to_ids false."""
    found = indicators(case)
    attributes = []
    for i, hosts in _once(found):
        comment = (f"address of {_hosts(hosts)}; often shared, context only" if i.kind == "ip" else
                   f"{i.role}; {'live' if i.alive else 'not live'} when the case was made"
                   + (f"; {i.status}" if i.status else "") + (f"; registrar: {i.registrar}" if i.registrar else ""))
        attributes.append({"type": "domain" if i.kind == "domain" else "ip-dst", "category": "Network activity",
                           "value": i.value, "to_ids": i.detect and i.alive, "comment": comment,
                           **({"first_seen": i.first_seen} if i.first_seen else {})})
    for p in patterns(case):
        attributes.append({"type": "pattern-in-traffic", "category": "Network activity", "value": p["regex"],
                           "to_ids": False, "comment": f"naming pattern ({p['kind']}) of the registrable domain, "
                                                       f"learned from {p['support']} domains"})
    return json.dumps({"Event": {
        "info": _title(case), "date": case["generated"][:10], "threat_level_id": "2", "analysis": "1",
        "distribution": "0", "uuid": str(uuid.uuid5(NAMESPACE, "misp|" + case["seed"])), "Attribute": attributes,
    }}, indent=1, ensure_ascii=False) + "\n"


# ---------- searches ----------

def _hunted(case: dict) -> list[str]:
    return [i.value for i in indicators(case) if i.kind == "domain"]


def _yaml(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def sigma(case: dict) -> str:
    """One Sigma rule for DNS logs: a domain of the case, a name under one, or a name the crew's pattern builds."""
    names, found = _hunted(case), searches(case)
    lines = [f"title: {_yaml(_title(case))}", f"id: {uuid.uuid5(NAMESPACE, 'sigma|' + case['seed'])}",
             "status: experimental",
             "description: " + _yaml(" ".join(_header(case, indicators(case))[1:])
                                     + " Found without visiting any domain."),
             f"author: Rastro {case['version']}", f"date: {case['generated'][:10]}", "tags:"]
    lines += [f"    - {t}" for t in ATTACK]
    lines += ["logsource:", "    category: dns", "detection:", "    known:", "        query:"]
    lines += [f"            - {_yaml(n)}" for n in names]
    lines += ["    under_known:", "        query|endswith:"] + [f"            - {_yaml('.' + n)}" for n in names]
    selections = ["known", "under_known"]
    for k, s in enumerate(found, 1):
        lines += [f"    pattern_{k}:", f"        query|re: {_yaml(s.regex)}"]
        lines += [f"        query|contains: {_yaml(core)}" for core in s.contains[:1]]
        selections.append(f"pattern_{k}")
    lines += [f"    condition: {' or '.join(selections)}", "falsepositives:",
              "    - A lapsed domain of the crew registered again by somebody else",
              "    - An unrelated name that happens to fit the naming pattern",
              f"level: {'high' if any(s.kind != 'guess' for s in found) or names else 'medium'}"]
    return "\n".join(lines) + "\n"


def _kql_list(names: list[str]) -> str:
    return ", ".join('"' + n + '"' for n in names)


def kql(case: dict, days: int = 30) -> str:
    """Two searches in Kusto: DNS answers in Microsoft Sentinel, and connections in Defender for Endpoint."""
    names, found = _hunted(case), searches(case)
    pattern = " or ".join(
        f'(Name matches regex @"{s.regex}"' + "".join(f' and Name contains "{c}"' for c in s.contains) + ")"
        for s in found) or "false"
    head = [f"// {line}" for line in _header(case, indicators(case))]
    head.append("// Looks for the case's domains and for names the crew's pattern builds, itself or as a parent name.")
    common = [f"let rastro_domains = dynamic([{_kql_list(names)}]);"]
    sentinel = ["// Microsoft Sentinel: DNS queries", *common, "DnsEvents", f"| where TimeGenerated > ago({days}d)",
                "| extend Name = tolower(Name)",
                f"| where Name in (rastro_domains) or {pattern}",
                "| summarize Queries = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by Name, "
                "ClientIP"]
    defender = ["// Microsoft Defender for Endpoint: connections", *common, "DeviceNetworkEvents",
                f"| where Timestamp > ago({days}d)",
                '| extend Name = tolower(tostring(coalesce(parse_url(RemoteUrl).Host, RemoteUrl)))',
                f"| where Name in (rastro_domains) or {pattern}",
                "| summarize Connections = count(), First = min(Timestamp), Last = max(Timestamp) by Name, "
                "DeviceName"]
    return "\n".join(head + [""] + sentinel + [""] + defender) + "\n"


def spl(case: dict, days: int = 30) -> str:
    """A Splunk search over DNS and proxy events, on the field names of the Common Information Model."""
    names, found = _hunted(case), searches(case)
    listed = "in(rastro_host, " + ", ".join('"' + n + '"' for n in names) + ")" if names else "false()"
    pattern = " OR ".join(
        '(match(rastro_host, "' + s.regex.replace('"', '\\"') + '")'
        + "".join(f' AND like(rastro_host, "%{c}%")' for c in s.contains) + ")" for s in found)
    head = [f"``` {line} ```" for line in _header(case, indicators(case))]
    return "\n".join(head + [
        f"(tag=dns OR tag=web OR tag=proxy) earliest=-{days}d",
        "| eval rastro_host=lower(coalesce(query, url_domain, dest_host, dest))",
        f"| where {listed}" + (f" OR {pattern}" if pattern else ""),
        "| stats count min(_time) as first max(_time) as last by rastro_host, src",
        "| convert ctime(first) ctime(last)",
    ]) + "\n"


BUILDERS = {"csv": csv_text, "blocklist": blocklist, "stix": stix, "misp": misp, "sigma": sigma, "kql": kql, "spl": spl}


def build(case: dict, fmt: str, days: int = 30) -> str:
    days = max(1, int(days))
    if fmt in ("kql", "spl"):
        return BUILDERS[fmt](case, days)
    return BUILDERS[fmt](case)
