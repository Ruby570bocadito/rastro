"""Operator time-zone estimation from the hours at which a campaign acts.

People act on a daily rhythm in local time. Given the UTC hours of the
campaign's own actions (domain registrations, first certificates), each of the
24 nominal UTC offsets is scored by how well those hours fit a typical working
day. A share of the events may come from bots, which act at any hour, so the
likelihood mixes the human profile with a uniform day.

Hours alone cannot tell a crew that starts two hours late in UTC+3 from a
standard crew in UTC+1. A prior over working schedules (earlier, standard,
later) spreads the estimate accordingly, so the band stays honest.

Many domains registered in one sitting are one piece of evidence, not many.
`sessions()` collapses actions that follow each other closely before testing,
so a burst of 60 domains in three days counts as the handful of work sessions
it really is.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

# Relative activity by local hour: sleep, morning ramp, lunch dip, evening tail.
PROFILE = (1, .5, .3, .2, .2, .3, .6, 1.5, 3, 5, 6, 6, 5, 4, 5, 6, 6, 5, 4, 3.5, 3, 2.5, 2, 1.5)
OFFSETS = tuple(range(-11, 13))
BOT_SHARES = tuple(i / 10 for i in range(10))  # 0.0 … 0.9
# Hours a crew's day may be shifted from the typical profile, and how likely each shift is.
SCHEDULE_SHIFTS = {-1: 0.15, 0: 0.5, 1: 0.2, 2: 0.15}

UNIFORM_BITS = math.log2(24)  # entropy of a perfectly flat day

_P = tuple(w / sum(PROFILE) for w in PROFILE)


@dataclass(frozen=True)
class Estimate:
    offset: int                      # most probable UTC offset
    band: tuple[int, ...]            # contiguous offsets holding `band_mass` of the posterior, west to east
    band_mass: float
    posterior: dict[int, float]      # UTC offset -> probability
    bot_share: float                 # share of events best explained by round-the-clock bots
    n_events: int
    p_value: float                   # chance that uniform, bot-like activity fits a human day this well
    entropy_bits: float              # 4.58 bits means a perfectly flat day


SESSION_GAP = timedelta(minutes=30)


def sessions(times: list[datetime], gap: timedelta = SESSION_GAP) -> list[datetime]:
    """Start of each work session: actions less than `gap` apart belong to the same sitting."""
    out: list[datetime] = []
    last = None
    for t in sorted(times):
        if last is None or t - last > gap:
            out.append(t)
        last = t
    return out


def wrap_offset(o: int) -> int:
    """Map any integer offset onto -11 … +12."""
    return (o + 11) % 24 - 11


def circular_distance(a: int, b: int) -> int:
    d = abs(a - b) % 24
    return min(d, 24 - d)


def hour_counts(hours_utc) -> list[int]:
    counts = [0] * 24
    for h in hours_utc:
        counts[int(h) % 24] += 1
    return counts


def _loglik(counts, offset: int, bot_share: float) -> float:
    total = 0.0
    for h, n in enumerate(counts):
        if n:
            p = (1 - bot_share) * _P[(h + offset) % 24] + bot_share / 24
            total += n * math.log(p)
    return total


def posterior(counts, bot_share: float = 0.0) -> dict[int, float]:
    ll = {o: _loglik(counts, o, bot_share) for o in OFFSETS}
    top = max(ll.values())
    weights = {o: math.exp(v - top) for o, v in ll.items()}
    z = sum(weights.values())
    return {o: w / z for o, w in weights.items()}


def with_schedules(post: dict[int, float], shifts: dict[int, float] = SCHEDULE_SHIFTS) -> dict[int, float]:
    """Spread a standard-schedule posterior over crews that start earlier or later.

    A crew at offset o working s hours late looks like a standard crew at o - s,
    so P(o) = sum over s of P(shift s) * P_standard(o - s)."""
    spread = {o: sum(w * post[wrap_offset(o - s)] for s, w in shifts.items()) for o in OFFSETS}
    z = sum(spread.values())
    return {o: v / z for o, v in spread.items()}


def best_bot_share(counts) -> float:
    """Bot share with the highest marginal likelihood (flat prior over offsets)."""

    def marginal(b: float) -> float:
        ll = [_loglik(counts, o, b) for o in OFFSETS]
        top = max(ll)
        return top + math.log(sum(math.exp(v - top) for v in ll) / len(ll))

    return max(BOT_SHARES, key=marginal)


def credible_band(post: dict[int, float], mass: float = 0.9) -> tuple[tuple[int, ...], float]:
    """Grow a contiguous band around the best offset until it holds `mass`."""
    best = max(post, key=post.get)
    band = [best]
    acc = post[best]
    left = right = best
    while acc < mass and len(band) < 24:
        lo, hi = wrap_offset(left - 1), wrap_offset(right + 1)
        if post[lo] >= post[hi]:
            band.insert(0, lo)
            acc += post[lo]
            left = lo
        else:
            band.append(hi)
            acc += post[hi]
            right = hi
    return tuple(band), acc


def entropy_bits(counts) -> float:
    n = sum(counts)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _rhythm_stat(counts) -> float:
    """How much better the best human day explains the hours than a flat day (log-likelihood ratio)."""
    n = sum(counts)
    return max(_loglik(counts, o, 0.0) for o in OFFSETS) - n * math.log(1 / 24)


def rhythm_p_value(counts, sims: int = 2000, seed: int = 7) -> float:
    """Monte Carlo test against round-the-clock activity with the same number of events."""
    n = sum(counts)
    if n == 0:
        return 1.0
    observed = _rhythm_stat(counts)
    rng = random.Random(seed)
    hits = 0
    for _ in range(sims):
        sim = [0] * 24
        for _ in range(n):
            sim[rng.randrange(24)] += 1
        if _rhythm_stat(sim) >= observed:
            hits += 1
    return (hits + 1) / (sims + 1)


def estimate(hours_utc, mass: float = 0.9, sims: int = 2000, schedules: bool = True) -> Estimate:
    counts = hour_counts(hours_utc)
    n = sum(counts)
    if n == 0:
        raise ValueError("no events to estimate from")
    bots = best_bot_share(counts)
    post = posterior(counts, bots)
    if schedules:
        post = with_schedules(post)
    band, band_mass = credible_band(post, mass)
    return Estimate(
        offset=max(post, key=post.get),
        band=band,
        band_mass=band_mass,
        posterior=post,
        bot_share=bots,
        n_events=n,
        p_value=rhythm_p_value(counts, sims),
        entropy_bits=entropy_bits(counts),
    )


def tz_name(o: int) -> str:
    return "UTC" if o == 0 else f"UTC{'+' if o > 0 else '−'}{abs(o)}"
