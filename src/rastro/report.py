"""The case file: one self-contained HTML page per investigation.

The page carries its data, styles and script inline and a Content-Security-Policy that
forbids every network request, so opening a report never contacts anybody. Every name in
it comes from attackers, so the data travels as escaped JSON and the script writes it with
textContent only.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from collections import defaultdict
from importlib import resources

from rastro import __version__, brands, husmo, pattern, rhythm
from rastro.investigate import NARROW_LOG10, Investigation

MAX_NODES = 160
MAX_STRONG_PER_NODE = 4


def safe_json(data) -> str:
    """JSON that cannot close the <script> element it travels in."""
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    for raw, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), (" ", "\\u2028"),
                         (" ", "\\u2029")):
        text = text.replace(raw, escaped)
    return text


def _iso(t) -> str | None:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


def _row(inv: Investigation, d: str) -> dict:
    m = inv.members[d]
    r = m.registration
    return {
        "id": d, "seed": d == inv.seed, "campaign": d in inv.campaign, "crew": d in inv.crew,
        "attributed": d in inv.campaign or d in inv.crew, "alive": r is not None, "first": _iso(m.first_seen),
        "registered": _iso(m.registered), "registrar": r.registrar if r else None, "sources": sorted(m.sources),
        "score": m.score,
        "status": inv.left_out.get(d) or ("reported" if any(d in rep.domains for rep in inv.reports) else None),
    }


def _graph(inv: Investigation) -> dict:
    attributed = set(inv.attributed)
    campaign, crew = set(inv.campaign), set(inv.crew)
    touching = {x for a, b, _, _ in inv.edges if a in attributed or b in attributed for x in (a, b)}

    def recency(d: str) -> float:
        t = inv.members[d].first_seen
        return -t.timestamp() if t else 0.0

    order = ([inv.seed] + sorted(campaign - {inv.seed}, key=recency) + sorted(crew - campaign - {inv.seed}, key=recency)
             + sorted(touching - attributed, key=recency))
    keep = list(dict.fromkeys(order))[:MAX_NODES]
    kept = set(keep)
    group_of = {d: k for k, g in enumerate(inv.groups) for d in g.domains}
    nodes = [dict(_row(inv, d), group=group_of.get(d)) for d in keep]
    # draw every strong link (up to a few per node) and, for the weak ones, a chain through time
    strong: dict[str, list] = defaultdict(list)
    weak = []
    for a, b, w, kinds in inv.edges:
        if a not in kept or b not in kept:
            continue
        (strong[a] if w >= 1.0 else weak).append((a, b, w, kinds))
    edges, seen = [], set()
    for items in strong.values():
        for a, b, w, kinds in sorted(items, key=lambda e: -e[2])[:MAX_STRONG_PER_NODE]:
            if (a, b) not in seen:
                seen.add((a, b))
                edges.append({"a": a, "b": b, "w": w, "kinds": list(kinds)})
    linked: set[str] = set()
    for a, b, w, kinds in sorted(weak, key=lambda e: (-e[2], e[0], e[1])):
        if a in linked and b in linked:
            continue
        linked |= {a, b}
        edges.append({"a": a, "b": b, "w": w, "kinds": list(kinds)})
    return {"nodes": nodes, "edges": edges, "hidden": max(0, len(order) - len(keep))}


def case_data(inv: Investigation, lang: str = "en", demo: dict | None = None) -> dict:
    """Everything the page shows. `demo` marks a made-up case and carries its truth, e.g. {"offset": 3}."""
    c = inv.clues
    patterns = []
    if inv.crew_pattern:
        patterns.append({"regex": inv.crew_pattern.regex, "breadth": round(inv.crew_pattern.breadth_log10, 1),
                         "kind": "crew", "support": inv.crew_pattern.support})
    campaign_group = next((g for g in inv.groups if inv.seed in g.domains), None)
    for p in pattern.learn(campaign_group.domains, min_support=2) if campaign_group else []:
        if p.breadth_log10 <= NARROW_LOG10 and all(x["regex"] != p.regex for x in patterns):
            patterns.append({"regex": p.regex, "breadth": round(p.breadth_log10, 1), "kind": "campaign",
                             "support": p.support})
    if inv.guess:
        digits = sum(int(n) for n in re.findall(r"\\d\{(\d+)\}", inv.guess))
        patterns.append({"regex": inv.guess, "breadth": float(digits), "kind": "guess", "support": 1})
    registered = [d for d in inv.attributed if inv.members[d].registration]
    return {
        "lang": lang, "version": __version__, "generated": _iso(inv.when),
        "host": inv.host, "seed": inv.seed, "brand": inv.brand, "demo": demo,
        "brand_name": brands.display(inv.brand) if inv.brand else None,
        "counts": {"crew": len(inv.crew), "campaign": len(inv.campaign), "attributed": len(inv.attributed),
                   "registered": len(registered), "checked": len(inv.members) - 1,
                   "reported": sum(len(r.domains) for r in inv.reports)},
        "narration": [{"kind": k, "text": t, "speech": husmo.spoken(t, lang)} for k, t in husmo.narrate(inv, lang)],
        "graph": _graph(inv),
        "template": inv.crew_pattern.regex if inv.crew_pattern else None,
        "clock": None if c is None else {
            "found": inv.rhythm_found, "p": c.p_value, "offset": c.offset, "tz": rhythm.tz_name(c.offset),
            "band": list(c.band), "mass": round(c.band_mass, 3),
            "posterior": {str(k): round(v, 5) for k, v in sorted(c.posterior.items())},
            "hours": [round(h, 3) for h in inv.session_hours], "events": inv.clock_events, "sessions": c.sessions,
            "weekend": c.weekend, "dst": c.dst,
        },
        "patterns": patterns,
        "reports": [{"registrar": r.registrar, "registrar_id": r.registrar_id, "email": r.email, "phone": r.phone,
                     "domains": r.domains, "subject": r.subject, "body": r.body} for r in inv.reports],
        "left_out": [{"domain": d, "why": why} for d, why in sorted(inv.left_out.items())],
        "notes": [husmo.note(code, values, lang) for code, values in inv.notes], "sources": inv.sources_used,
        "domains": [_row(inv, d) for d in [inv.seed] + sorted(set(inv.members) - {inv.seed})],
    }


def _asset(name: str) -> str:
    return resources.files("rastro").joinpath("assets", name).read_text(encoding="utf-8")


def render(inv: Investigation, lang: str = "en", demo: dict | None = None) -> str:
    page = _asset("report.html")
    scripts = re.findall(r"<script>(.*?)</script>", page, flags=re.S)
    hashes = " ".join("'sha256-" + base64.b64encode(hashlib.sha256(s.encode("utf-8")).digest()).decode() + "'"
                      for s in scripts)
    title = f"Rastro · {inv.seed}"
    for placeholder, value in (("{{SCRIPT_HASHES}}", hashes), ("{{LANG}}", "es" if lang == "es" else "en"),
                               ("{{TITLE}}", html.escape(title)), ("/*CASE*/", safe_json(case_data(inv, lang, demo))),
                               ("/*LAND*/", _asset("land.json"))):
        assert page.count(placeholder) == 1, placeholder
        page = page.replace(placeholder, value)
    return page
