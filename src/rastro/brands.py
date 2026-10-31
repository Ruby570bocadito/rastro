"""Brands that phishing imitates, their official domains, and what makes a lookalike suspicious."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

from rastro.domains import platform

KEY = re.compile(r"^[a-z0-9]+$")


def parse(text: str) -> list[tuple[str, str | None, list[str]]]:
    """(key, how it is written, official domains) for each line of a brands file: `key | Name | a.com b.com`."""
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, name, official = ([f.strip() for f in line.split("|")] + ["", ""])[:3]
        key = key.lower()
        if not KEY.match(key):
            raise ValueError(f"line {n}: {key!r} is not a brand key (lowercase letters and digits only)")
        out.append((key, name or None, official.lower().split()))
    return out


# Spanish brands first, as assets/brands.txt lists them; `rastro --brands FILE` adds more.
BRANDS: list[str] = []
DISPLAY: dict[str, str] = {}       # how each brand is written when Rastro names it; the rest are just capitalised
OFFICIAL: dict[str, list[str]] = {}   # registrable domains the brands themselves use; `rastro watch --allow` adds more
for _key, _name, _official in parse(resources.files("rastro").joinpath("assets", "brands.txt")
                                    .read_text(encoding="utf-8")):
    BRANDS.append(_key)
    if _name:
        DISPLAY[_key] = _name
    if _official:
        OFFICIAL[_key] = _official


def short(brand: str) -> bool:
    """Short names must match a whole token, longer ones anywhere in the name."""
    return len(brand) <= 4


# TLDs that keep showing up in smishing campaigns. A heuristic, not a verdict.
ABUSED_TLDS = {
    "top", "xyz", "icu", "cc", "vip", "shop", "live", "online", "site", "buzz", "cfd", "sbs", "cyou", "bond",
    "info", "click", "life", "lat", "autos", "rest", "mom", "help", "support", "win", "monster", "fun", "pw",
    "ws", "tk", "ml", "ga", "cf", "gq", "app", "link", "store", "today", "space", "website", "host", "quest",
    "boats", "skin", "homes", "cam", "ink", "run", "club", "pro", "pics", "lol", "biz", "one", "best", "xin",
    "loan", "date", "bid", "trade", "work", "world", "digital", "tel",
}


def display(brand: str) -> str:
    return DISPLAY.get(brand, brand.capitalize())


@contextmanager
def extra(names: dict[str, str | None], official: dict[str, list[str]] | None = None) -> Iterator[None]:
    """Recognise more brands for a while ({key: how it is written}, and their official domains), e.g. the made-up
    ones of `rastro demo` or those of `rastro --brands FILE`."""
    added = [k for k in names if k not in BRANDS]
    shown = {k: v for k, v in names.items() if v and k not in DISPLAY}
    owned = {k: v for k, v in (official or {}).items() if v and k not in OFFICIAL}
    BRANDS.extend(added)
    DISPLAY.update(shown)
    OFFICIAL.update(owned)
    try:
        yield
    finally:
        for k in added:
            BRANDS.remove(k)
        for k in shown:
            DISPLAY.pop(k, None)
        for k in owned:
            OFFICIAL.pop(k, None)


def from_file(path: str) -> tuple[dict[str, str | None], dict[str, list[str]]]:
    """The arguments of `extra` for a brands file."""
    rows = parse(Path(path).read_text(encoding="utf-8"))
    return {k: name for k, name, _ in rows}, {k: official for k, _, official in rows if official}


# Letters from other scripts that look Latin (Cyrillic, Greek), as homograph lookalikes use them.
HOMOGLYPHS = str.maketrans({
    "а": "a", "в": "b", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i", "ј": "j", "к": "k", "м": "m",
    "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "ԁ": "d", "ԛ": "q",
    "ԝ": "w", "ӏ": "l", "ɡ": "g", "ɑ": "a", "ı": "i",
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x",
})
# Digits that stand in for letters (paypa1, app1e, 5team). A one reads as l or i, so both are tried. Only a lone
# digit among letters counts: in app1369 the digits are a number, not a disguise.
DIGIT_SWAPS = [dict(zip("01345", "oleas", strict=True)), dict(zip("01345", "oieas", strict=True))]
LONE_DIGIT = re.compile(r"(?<![0-9])[01345](?![0-9])")
# Letter pairs that read as one letter at a glance (arnazon, vvhatsapp).
PAIRS = (("rn", "m"), ("vv", "w"))


def _label(domain: str) -> str:
    """The name without its public suffix, as far as Rastro knows it."""
    suffix = platform(domain)
    return domain[: -len(suffix) - 1] if suffix else domain.rsplit(".", 1)[0]


def _find(label: str) -> str | None:
    tokens = set(re.split(r"[^a-z0-9]+", label))
    for b in BRANDS:
        if (b in tokens) if short(b) else (b in label):
            return b
    return None


def _unicode(label: str) -> str:
    """Punycode labels decoded, accents dropped and look-alike letters turned Latin (xn--pypal-4ve -> paypal)."""
    out = []
    for part in label.split("."):
        if part.startswith("xn--"):
            try:
                part = part[4:].encode("ascii").decode("punycode")
            except UnicodeError:
                pass
        out.append(part)
    text = unicodedata.normalize("NFKD", ".".join(out).lower().translate(HOMOGLYPHS))
    return "".join(ch for ch in text if not unicodedata.combining(ch))


def readings(label: str) -> list[str]:
    """How a name reads to the eye, when that differs from how it is spelled."""
    base = _unicode(label) if "xn--" in label or not label.isascii() else label
    out = [] if base == label else [base]
    for table in DIGIT_SWAPS:
        swapped = LONE_DIGIT.sub(lambda m, t=table: t[m.group()], base)
        if swapped != base and swapped not in out:
            out.append(swapped)
    for text in [base, *out]:
        for pair, letter in PAIRS:
            if pair in text and (merged := text.replace(pair, letter)) not in out:
                out.append(merged)
    return out


def brand_of(domain: str) -> str | None:
    """The brand a name imitates: spelled out, or written to look like it (paypa1, arnazon, Cyrillic letters)."""
    label = _label(domain)
    if found := _find(label):
        return found
    for text in readings(label):
        if found := _find(text):
            return found
    return None


DISTINCT_EXTRA = 6   # a word around the brand must add this many letters to point at one operator


def distinctive_word(domain: str, brand: str) -> str | None:
    """The token that carries the brand when it is long and unusual enough to point at one operator
    (microsofterrorfound), else None."""
    label = domain.rsplit(".", 1)[0]
    word = next((t for t in re.split(r"[^a-z0-9]+", label) if brand in t), brand)
    return word if len(word) >= len(brand) + DISTINCT_EXTRA else None


def official_domains() -> set[str]:
    return {d for domains in OFFICIAL.values() for d in domains}


def suspicious(domain: str) -> bool:
    """Abused TLD, a free hosting subdomain, or hyphens and digits in the name: the usual shape of a throwaway
    lookalike."""
    if platform(domain):
        return True
    label, _, tld = domain.rpartition(".")
    return tld in ABUSED_TLDS or ("-" in label and any(ch.isdigit() for ch in label))
