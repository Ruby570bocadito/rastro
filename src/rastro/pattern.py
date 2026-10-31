"""Learn the naming pattern of a campaign's domains and match new ones.

Campaigns mint domains from a template, like paqexpres-aduana-7093.icu. Each
name is split into tokens (words, numbers, separators). Names that share the
same token layout are aligned slot by slot, and each slot is generalised:

- a word that never changes stays literal;
- a small vocabulary of words that repeat becomes an alternation;
- numbers become \\d{m,n};
- varied words that share a core (accountappleid, myapplecenter) keep the core
  literal and wrap it in letter classes: [a-z]{2,7}apple[a-z]{0,6};
- other varied words become [a-z]{m,n};
- the TLD always stays an alternation, since a class would match any TLD.

The result is a readable regular expression, plus its breadth: how many names
it could match, which bounds how often it can fire by chance.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field

TOKEN = re.compile(r"[a-z]+|[0-9]+|[-.]")
MAX_ALTERNATION = 8      # more distinct words than this in a slot means a class
VOCAB_REPEAT = 0.5       # a slot is a vocabulary when each word shows up twice on average
MAX_TLDS = 12
MIN_CORE = 4             # shortest shared core worth keeping literal


def literal(text: str) -> str:
    r"""re.escape without the backslash before hyphens, which are literal outside a character class anyway:
    usps-redelivery-\d{4}\.top reads better than usps\-redelivery\-\d{4}\.top."""
    return re.escape(text).replace("\\-", "-")


def tokens(domain: str) -> list[str]:
    return TOKEN.findall(domain.lower())


def shape(domain: str) -> str:
    """Token layout of a name, e.g. paqexpres-aduana-7093.icu -> a-a-9.a"""
    return "".join(t if t in "-." else ("9" if t.isdigit() else "a") for t in tokens(domain))


@dataclass(frozen=True)
class Pattern:
    regex: str
    breadth_log10: float     # log10 of how many names the pattern can match
    support: int             # examples it was learned from
    compiled: re.Pattern = field(compare=False, repr=False)

    def matches(self, domain: str) -> bool:
        return self.compiled.fullmatch(domain.lower()) is not None


def _range(lengths: list[int]) -> str:
    lo, hi = min(lengths), max(lengths)
    return f"{{{lo}}}" if lo == hi else f"{{{lo},{hi}}}"


def _count_log10(alphabet: int, lengths: list[int]) -> float:
    return math.log10(sum(alphabet ** n for n in range(min(lengths), max(lengths) + 1)))


def _letters(lengths: list[int]) -> tuple[str, float]:
    if max(lengths) == 0:
        return "", 0.0
    return "[a-z]" + _range(lengths), _count_log10(26, lengths)


def _shared_core(values: list[str]) -> str:
    """Longest substring present in every value."""
    shortest = min(values, key=len)
    for size in range(len(shortest), MIN_CORE - 1, -1):
        for start in range(len(shortest) - size + 1):
            core = shortest[start:start + size]
            if all(core in v for v in values):
                return core
    return ""


def _slot(values: list[str], is_tld: bool) -> tuple[str, float]:
    distinct = sorted(set(values))
    first = values[0]
    if first in "-.":
        return literal(first), 0.0
    if len(distinct) == 1:
        return literal(first), 0.0
    if first.isdigit():
        return r"\d" + _range([len(v) for v in values]), _count_log10(10, [len(v) for v in values])
    vocabulary = len(distinct) <= MAX_ALTERNATION and len(distinct) <= VOCAB_REPEAT * len(values)
    if (is_tld and len(distinct) <= MAX_TLDS) or vocabulary:
        return "(" + "|".join(literal(v) for v in distinct) + ")", math.log10(len(distinct))
    core = "" if is_tld else _shared_core(distinct)
    if core:
        pre, b_pre = _letters([v.index(core) for v in distinct])
        post, b_post = _letters([len(v) - v.index(core) - len(core) for v in distinct])
        return pre + literal(core) + post, b_pre + b_post
    return _letters([len(v) for v in values])


def learn_one(domains: list[str]) -> Pattern:
    """Pattern for names that all share one token layout."""
    rows = [tokens(d) for d in domains]
    if len({len(r) for r in rows}) != 1 or len({shape(d) for d in domains}) != 1:
        raise ValueError("learn_one needs names with the same token layout")
    parts, breadth = [], 0.0
    width = len(rows[0])
    for i in range(width):
        regex, b = _slot([r[i] for r in rows], is_tld=i == width - 1)
        parts.append(regex)
        breadth += b
    regex = "".join(parts)
    # When the shared core moves between slots (apple-login, my-apple), require it anywhere in the name.
    core = _shared_core([d.lower().rsplit(".", 1)[0] for d in domains])
    if core and literal(core) not in regex:
        regex = f"(?=.*{literal(core)})" + regex
    return Pattern(regex, breadth, len(domains), re.compile(regex))


def learn(domains, min_support: int = 2) -> list[Pattern]:
    """One pattern per token layout seen at least `min_support` times, most supported first."""
    groups: dict[str, list[str]] = defaultdict(list)
    for d in domains:
        groups[shape(d)].append(d.lower())
    patterns = [learn_one(v) for v in groups.values() if len(v) >= min_support]
    return sorted(patterns, key=lambda p: -p.support)


def first_match(patterns: list[Pattern], domain: str) -> Pattern | None:
    return next((p for p in patterns if p.matches(domain)), None)
