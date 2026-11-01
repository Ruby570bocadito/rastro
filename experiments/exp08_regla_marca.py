"""Experiment 08: can a stricter brand rule drop innocent names without losing phishing ones?

The watcher keeps every name in which a long brand appears anywhere, so it also keeps
purchase (chase), pineapple (apple) or grupostefanini (poste), as the live trial of
2026-11-01 found. Three stricter rules for long brands (short ones already have to be a
whole word) are measured against the names of the public phishing list that the plain
rule finds:

- edge: the brand starts or ends a word of the name;
- word: the brand is a whole word;
- word or shape: a whole word, or anywhere when the name has a throwaway shape
  (an abused TLD, or hyphens and digits).

Kill criterion, set before the run: a stricter rule replaces the plain one only if it keeps
at least 97 % of the listed names the plain rule finds. Only then would fresh Certificate
Transparency names be read, to see how many innocents it drops. This half needs no network.

Usage, from the project root (with the public list in data/raw/lists/, see `rastro list update`):
    python -I experiments/exp08_regla_marca.py
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rastro import brands  # noqa: E402
from rastro.domains import registrable  # noqa: E402

LIST = ROOT / "data" / "raw" / "lists" / "phishing-domains-ACTIVE.txt"
RESULTS = ROOT / "experiments" / "results"
BAR = 0.97


def words(label: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", label) if t]


def verdicts(domain: str) -> dict[str, bool] | None:
    """Which rules keep a name the plain rule finds through a long brand; None when it does not."""
    label = brands._label(domain)
    brand = brands._find(label)
    if not brand or brands.short(brand):
        return None
    holders = [(b, w) for b in brands.BRANDS if not brands.short(b) for w in words(label) if b in w]
    whole = any(w == b for b, w in holders)
    edge = whole or any(w.startswith(b) or w.endswith(b) for b, w in holders)
    return {"edge": edge, "word": whole, "word or shape": whole or brands.suspicious(domain)}


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    if not LIST.exists():
        print(f"No list at {LIST.relative_to(ROOT)}: run `rastro list update` first.")
        return 2
    lines = LIST.read_text(encoding="utf-8", errors="replace").splitlines()
    names = sorted({registrable(s.strip().lower()) for s in lines if s.strip() and not s.startswith("#")})
    kept, dropped = Counter(), {rule: Counter() for rule in ("edge", "word", "word or shape")}
    found = 0
    for d in names:
        v = verdicts(d)
        if v is None:
            continue
        found += 1
        for rule, keeps in v.items():
            if keeps:
                kept[rule] += 1
            else:
                dropped[rule][brands._find(brands._label(d))] += 1
    rows = [{"rule": rule, "kept": kept[rule], "share": round(kept[rule] / found, 4), "passes": kept[rule] / found >= BAR,
             "dropped_by_brand": dict(dropped[rule].most_common(8))} for rule in ("edge", "word", "word or shape")]
    text = [
        "# Experiment 08 · a stricter brand rule",
        "",
        f"Run on {date.today().isoformat()}. {len(names):,} registrable names on the public list; the plain rule finds a "
        f"long brand in {found:,} of them.",
        "",
        "| Rule | Listed names kept | Share | Passes the 97 % bar |",
        "|---|---:|---:|---|",
        *[f"| {r['rule']} | {r['kept']:,} | {r['share']:.1%} | {'yes' if r['passes'] else 'no'} |" for r in rows],
        "",
        f"**Verdict:** {'a stricter rule passes' if any(r['passes'] for r in rows) else 'no stricter rule passes'}; "
        "the plain rule stays.",
        "",
    ]
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    (RESULTS / f"exp08_regla_marca-{stamp}.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (RESULTS / f"exp08_regla_marca-{stamp}.md").write_text("\n".join(text), encoding="utf-8")
    print("\n".join(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
