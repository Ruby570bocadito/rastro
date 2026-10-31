"""A small model that scores how much a domain name looks like a phishing lookalike.

Logistic regression on hashed features of the name alone: character n-grams, words, the
ending, the brand it carries and its shape (length, hyphens, digits, punycode). It is
trained by experiments/exp07_puntuador.py on a public phishing list against real names
from Certificate Transparency, and it explains each score with the features that weighed
most.

A name is only a name. A high score means "built like the lookalikes on public lists",
not "is phishing": the watcher uses it to decide what to keep and what to look at first,
never to accuse anybody.
"""

from __future__ import annotations

import json
import math
import random
import re
import zlib
from array import array
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from rastro import brands
from rastro.domains import registrable

BUCKETS = 1 << 18
NGRAMS = (3, 4, 5)
FORMAT = "rastro-scorer/1"


def split(domain: str) -> tuple[str, str]:
    """The part of a registrable domain its owner chose, and the public suffix after it."""
    reg = registrable(domain)
    label, _, suffix = reg.partition(".")
    return label, suffix


def _bucket(n: int) -> str:
    return "0" if n == 0 else "1-2" if n <= 2 else "3-4" if n <= 4 else "5+"


def features(domain: str) -> list[str]:
    """Readable features of a name. Prefixes: g (letters), w (word), tld, brand, shape."""
    label, suffix = split(domain)
    out = [f"tld:{suffix}"]
    padded = f"^{label}$"
    for n in NGRAMS:
        out += [f"g:{padded[i:i + n]}" for i in range(len(padded) - n + 1)]
    words = [w for w in re.split(r"[^a-z]+", label) if len(w) >= 3]
    out += [f"w:{w}" for w in words]
    brand = brands.brand_of(f"{label}.{suffix}")
    if brand:
        out.append(f"brand:{brand}")
        out.append("brand+more" if label != brand else "brand-only")
    digits, hyphens = sum(c.isdigit() for c in label), label.count("-")
    out += [f"digits:{_bucket(digits)}", f"hyphens:{_bucket(hyphens)}",
            f"length:{min(len(label) // 8, 5)}"]
    if label.startswith("xn--"):
        out.append("punycode")
    if digits and hyphens:
        out.append("digits+hyphens")
    return out


def bucket(feature: str) -> int:
    return zlib.crc32(feature.encode("utf-8")) & (BUCKETS - 1)


def encode(domain: str) -> list[int]:
    """The buckets a name lights up, each once."""
    return sorted({bucket(f) for f in features(domain)})


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x)) if x > -40 else 0.0


@dataclass
class Model:
    weights: array                     # one float per bucket
    bias: float
    meta: dict = field(default_factory=dict)

    def score_encoded(self, idx: Iterable[int]) -> float:
        return _sigmoid(self.bias + sum(self.weights[i] for i in idx))

    def score(self, domain: str) -> float:
        """0 to 1: how much the name is built like the lookalikes the model was trained on."""
        return self.score_encoded(encode(domain))

    def reasons(self, domain: str, k: int = 4) -> list[tuple[str, str, float]]:
        """The features that pushed the score up most, as (kind, value, weight); letters count once."""
        seen: dict[str, tuple[str, str, float]] = {}
        for f in set(features(domain)):
            w = self.weights[bucket(f)]
            if w <= 0:
                continue
            kind, _, value = f.partition(":")
            key = "g" if kind == "g" else f
            if key not in seen or w > seen[key][2]:
                seen[key] = (kind, value.strip("^$"), w)
        return sorted(seen.values(), key=lambda r: -r[2])[:k]


def train(positives: Iterable[str], negatives: Iterable[str], epochs: int = 4, rate: float = 0.2,
          l2: float = 1e-6, seed: int = 7) -> Model:
    """Logistic regression by AdaGrad, each class weighted to count as much as the other."""
    return train_encoded([encode(d) for d in positives], [encode(d) for d in negatives], epochs, rate, l2, seed)


def train_encoded(positives: Sequence[list[int]], negatives: Sequence[list[int]], epochs: int = 4,
                  rate: float = 0.2, l2: float = 1e-6, seed: int = 7) -> Model:
    """`train` on names already turned into buckets, so experiments encode each name once."""
    rows = [(idx, 1) for idx in positives] + [(idx, 0) for idx in negatives]
    n_pos, n_neg = len(positives), len(negatives)
    if not n_pos or not n_neg:
        raise ValueError("training needs names of both kinds")
    class_weight = {1: len(rows) / (2 * n_pos), 0: len(rows) / (2 * n_neg)}
    w = array("d", bytes(8 * BUCKETS))
    g2 = array("d", bytes(8 * BUCKETS))
    bias, bias_g2 = 0.0, 0.0
    rng = random.Random(seed)
    for _ in range(epochs):
        rng.shuffle(rows)
        for idx, y in rows:
            p = _sigmoid(bias + sum(w[i] for i in idx))
            grad = (p - y) * class_weight[y]
            for i in idx:
                gi = grad + l2 * w[i]
                g2[i] += gi * gi
                w[i] -= rate * gi / math.sqrt(g2[i] + 1e-8)
            bias_g2 += grad * grad
            bias -= rate * grad / math.sqrt(bias_g2 + 1e-8)
    return Model(w, bias, {"positives": n_pos, "negatives": n_neg, "epochs": epochs})


def save(model: Model, path: Path | str) -> None:
    """One JSON header line, then the weights as int8 compressed with zlib (about 10^5 bytes)."""
    scale = max(abs(x) for x in model.weights) / 127 or 1.0
    packed = array("b", (max(-127, min(127, round(x / scale))) for x in model.weights))
    header = dict(model.meta, format=FORMAT, buckets=BUCKETS, ngrams=list(NGRAMS), scale=scale, bias=model.bias)
    Path(path).write_bytes(json.dumps(header).encode() + b"\n" + zlib.compress(packed.tobytes(), 9))


def loads(blob: bytes) -> Model:
    head, _, body = blob.partition(b"\n")
    meta = json.loads(head)
    if meta.get("format") != FORMAT or meta.get("buckets") != BUCKETS:
        raise ValueError("not a rastro scorer this version can read")
    packed = array("b")
    packed.frombytes(zlib.decompress(body))
    scale = meta["scale"]
    return Model(array("d", (x * scale for x in packed)), meta["bias"], meta)


_DEFAULT: list[Model | None] = []


def default() -> Model | None:
    """The model shipped with Rastro, or None if this copy has none."""
    if not _DEFAULT:
        try:
            _DEFAULT.append(loads(resources.files("rastro").joinpath("assets", "scorer.bin").read_bytes()))
        except (FileNotFoundError, ValueError, zlib.error):
            _DEFAULT.append(None)
    return _DEFAULT[0]


def rank(model: Model, domains: Sequence[str]) -> list[tuple[float, str]]:
    return sorted(((model.score(d), d) for d in domains), reverse=True)
