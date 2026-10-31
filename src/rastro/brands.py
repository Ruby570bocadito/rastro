"""Brands that phishing imitates, their official domains, and what makes a lookalike suspicious."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager

from rastro.domains import platform

# Spanish brands first. Short names must match a whole token, longer ones anywhere in the name.
BRANDS = [
    "correos", "dgt", "agenciatributaria", "aeat", "bbva", "santander", "caixabank", "bankinter", "sabadell",
    "unicaja", "ibercaja", "kutxabank", "bizum", "endesa", "iberdrola", "naturgy", "movistar", "vodafone",
    "usps", "dhl", "fedex", "ups", "evri", "royalmail", "auspost", "canadapost", "postnl", "laposte", "poste",
    "paypal", "netflix", "amazon", "apple", "icloud", "microsoft", "office365", "outlook", "facebook", "instagram",
    "whatsapp", "telegram", "binance", "coinbase", "metamask", "ledger", "trezor", "chase", "wellsfargo",
    "bankofamerica", "docusign", "adobe", "dropbox", "steam", "roblox", "att", "verizon", "tmobile", "ezpass",
    "sunpass", "fastrak", "toll",
]
SHORT = {b for b in BRANDS if len(b) <= 4}
# How each brand is written when Rastro names it; the rest are just capitalised.
DISPLAY = {
    "agenciatributaria": "Agencia Tributaria", "aeat": "AEAT", "bbva": "BBVA", "dgt": "DGT", "caixabank": "CaixaBank",
    "usps": "USPS", "dhl": "DHL", "fedex": "FedEx", "ups": "UPS", "royalmail": "Royal Mail",
    "auspost": "Australia Post", "canadapost": "Canada Post", "postnl": "PostNL", "laposte": "La Poste",
    "poste": "Poste Italiane",
    "paypal": "PayPal", "icloud": "iCloud", "office365": "Office 365", "whatsapp": "WhatsApp", "metamask": "MetaMask",
    "wellsfargo": "Wells Fargo", "bankofamerica": "Bank of America", "docusign": "DocuSign", "att": "AT&T",
    "tmobile": "T-Mobile", "ezpass": "E-ZPass", "sunpass": "SunPass", "fastrak": "FasTrak",
}

# Registrable domains the brands themselves use. A starter list; `rastro watch --allow FILE` adds more.
OFFICIAL = {
    "correos": ["correos.es", "correos.com", "correosexpress.com", "correosexpress.es"],
    "dgt": ["dgt.es"],
    "agenciatributaria": ["agenciatributaria.es", "agenciatributaria.gob.es"],
    "bbva": ["bbva.es", "bbva.com", "bbva.mx"],
    "santander": ["santander.com", "bancosantander.es", "santander.co.uk", "santander.com.br"],
    "caixabank": ["caixabank.es", "caixabank.com"],
    "usps": ["usps.com"],
    "dhl": ["dhl.com", "dhl.de", "dhl.es", "dhl.fr", "dhl.it", "dhl.co.uk", "dhl.nl", "dhlparcel.nl", "dhlparcel.es"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "royalmail": ["royalmail.com"],
    "paypal": ["paypal.com", "paypal.me", "paypalobjects.com"],
    "netflix": ["netflix.com", "nflxvideo.net"],
    "amazon": ["amazon.com", "amazon.es", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.co.jp",
               "amazon.ca", "amazon.com.mx", "amazon.com.br", "amazon.in", "amazon.com.au", "amazonaws.com",
               "primevideo.com"],
    "apple": ["apple.com", "icloud.com", "me.com", "mac.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com",
                  "azure.com", "windows.net", "bing.com", "msn.com", "sharepoint.com", "onmicrosoft.com"],
    "facebook": ["facebook.com", "fb.com", "fbcdn.net", "meta.com", "messenger.com"],
    "instagram": ["instagram.com", "cdninstagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "telegram": ["telegram.org", "t.me", "telegram.me"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "ledger": ["ledger.com"],
    "chase": ["chase.com", "chaseonline.com", "jpmorganchase.com"],
    "steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com"],
    "dropbox": ["dropbox.com"],
}

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
def extra(names: dict[str, str]) -> Iterator[None]:
    """Recognise more brands for a while ({key: how it is written}), e.g. the made-up ones of `rastro demo`."""
    added = [k for k in names if k not in BRANDS]
    shown = {k: v for k, v in names.items() if k not in DISPLAY}
    BRANDS.extend(added)
    DISPLAY.update(shown)
    try:
        yield
    finally:
        for k in added:
            BRANDS.remove(k)
        for k in shown:
            DISPLAY.pop(k, None)


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
        if (b in tokens) if b in SHORT else (b in label):
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
