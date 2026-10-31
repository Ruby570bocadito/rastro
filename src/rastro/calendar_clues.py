"""Calendar clues that narrow a crew's time zone: daylight saving time, the weekend, and holidays.

With full timestamps (not only hours), three more questions can be asked:

- Daylight saving time. A crew in Europe moves its clock an hour between the last
  Sundays of March and October; one in the United States between the second
  Sunday of March and the first of November; many places never do. The regime
  whose shifted hours fit the working day best is the most likely one.
- The weekend, in local time: Saturday and Sunday, Friday and Saturday, Sunday
  only, or no weekend at all.
- Holidays. A crew that stops for Christmas, Orthodox Christmas, Chinese New Year
  or the end of Ramadan leaves a gap. Only judged when the expected activity on
  those days is large enough to notice a gap.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from rastro import rhythm

REGIMES = ("none", "eu", "us", "south")
WEEKENDS = {"sat-sun": {5, 6}, "fri-sat": {4, 5}, "sun": {6}, "none": set()}
WEEKEND_FACTOR = 0.35        # a weekend day sees about a third of a working day's activity
MIN_EXPECTED_ON_HOLIDAYS = 5.0
# Bars set by experiment 06 (simulated crews): below them a clue is reported as inconclusive.
WEEKEND_MIN_SESSIONS, WEEKEND_MIN_WEEKS, WEEKEND_MIN_PROB = 50, 8, 0.8
DST_MIN_SESSIONS, DST_MIN_PROB = 200, 0.6

# Approximate dates, which vary by a day between countries. Chinese New Year starts a week off;
# Eid al-Fitr closes Ramadan.
CHINESE_NEW_YEAR = {2018: (2, 16), 2019: (2, 5), 2020: (1, 25), 2021: (2, 12), 2022: (2, 1), 2023: (1, 22),
                    2024: (2, 10), 2025: (1, 29), 2026: (2, 17), 2027: (2, 6)}
EID_AL_FITR = {2018: (6, 15), 2019: (6, 4), 2020: (5, 24), 2021: (5, 13), 2022: (5, 2), 2023: (4, 21),
               2024: (4, 10), 2025: (3, 30), 2026: (3, 20), 2027: (3, 10)}


def _sunday(year: int, month: int, n: int) -> int:
    """Day of the month of the n-th Sunday (n = -1 for the last one)."""
    if n > 0:
        first = date(year, month, 1)
        return 1 + (6 - first.weekday()) % 7 + 7 * (n - 1)
    nxt = date(year + (month == 12), month % 12 + 1, 1)
    last = nxt - timedelta(days=1)
    return last.day - (last.weekday() - 6) % 7


def dst_shift(t: datetime, regime: str) -> int:
    """Hours a regime adds to standard time at instant `t` (UTC)."""
    y = t.year
    if regime == "eu":       # last Sunday of March to last Sunday of October, 01:00 UTC
        start = datetime(y, 3, _sunday(y, 3, -1), 1, tzinfo=UTC)
        end = datetime(y, 10, _sunday(y, 10, -1), 1, tzinfo=UTC)
        return int(start <= t < end)
    if regime == "us":       # second Sunday of March to first Sunday of November, about 02:00 local
        start = datetime(y, 3, _sunday(y, 3, 2), 9, tzinfo=UTC)
        end = datetime(y, 11, _sunday(y, 11, 1), 8, tzinfo=UTC)
        return int(start <= t < end)
    if regime == "south":    # southern summer, as in Australia: first Sunday of October to first Sunday of April
        start = datetime(y, 10, _sunday(y, 10, 1), 16, tzinfo=UTC)
        end = datetime(y, 4, _sunday(y, 4, 1), 16, tzinfo=UTC)
        return int(t >= start or t < end)
    return 0


def local(t: datetime, offset: int, regime: str) -> datetime:
    return t + timedelta(hours=offset + dst_shift(t, regime))


def holidays(year: int) -> dict[str, list[date]]:
    out = {
        "Christmas and New Year": [date(year, 12, d) for d in range(24, 32)] + [date(year, 1, 1)],
        "Orthodox Christmas": [date(year, 1, d) for d in (6, 7, 8)],
    }
    if year in CHINESE_NEW_YEAR:
        m, d = CHINESE_NEW_YEAR[year]
        out["Chinese New Year"] = [date(year, m, d) + timedelta(days=k) for k in range(7)]
    if year in EID_AL_FITR:
        m, d = EID_AL_FITR[year]
        out["Eid al-Fitr"] = [date(year, m, d) + timedelta(days=k) for k in range(3)]
    return out


@dataclass
class Clues:
    offset: int
    band: tuple[int, ...]
    band_mass: float
    p_value: float | None
    sessions: int
    dst: str                       # a regime, or "inconclusive" below the bars of experiment 06
    dst_probs: dict[str, float]
    weekend: str                   # a weekend, or "inconclusive"
    weekend_probs: dict[str, float]
    holidays: list[tuple[str, int, float, str]] = field(default_factory=list)   # name, seen, expected, verdict
    posterior: dict[int, float] = field(default_factory=dict)                     # UTC offset -> probability


def _normalise(logs: dict[str, float]) -> dict[str, float]:
    top = max(logs.values())
    w = {k: math.exp(v - top) for k, v in logs.items()}
    z = sum(w.values())
    return {k: v / z for k, v in w.items()}


def _regime_evidence(starts: list[datetime], regime: str) -> tuple[float, list[int], float]:
    """Marginal log-likelihood of a DST regime over all offsets, with its hour counts and bot share."""
    counts = rhythm.hour_counts([t.hour + t.minute / 60 + dst_shift(t, regime) for t in starts])
    bots = rhythm.best_bot_share(counts)
    ll = [rhythm._loglik(counts, o, bots) for o in rhythm.OFFSETS]
    top = max(ll)
    return top + math.log(sum(math.exp(v - top) for v in ll) / len(ll)), counts, bots


def weekend_probs(local_days: list[int]) -> dict[str, float]:
    logs = {}
    for name, days in WEEKENDS.items():
        weights = [WEEKEND_FACTOR if d in days else 1.0 for d in range(7)]
        z = sum(weights)
        logs[name] = sum(math.log(weights[d] / z) for d in local_days)
    return _normalise(logs)


def analyse(times: list[datetime], sims: int = 20000, mass: float = 0.9) -> Clues:
    """Time zone, DST regime, weekend and holiday gaps from the moments a crew acted."""
    starts = rhythm.sessions(times)
    if not starts:
        raise ValueError("no events to analyse")
    evidence = {r: _regime_evidence(starts, r) for r in REGIMES}
    dst_probs = _normalise({r: e[0] for r, e in evidence.items()})
    regime = max(dst_probs, key=dst_probs.get)
    _, counts, bots = evidence[regime]
    post = rhythm.with_schedules(rhythm.posterior(counts, bots))
    band, band_mass = rhythm.credible_band(post, mass)
    offset = max(post, key=post.get)
    p_value = rhythm.rhythm_p_value(counts, sims) if sims else None
    local_times = [local(t, offset, regime) for t in starts]
    weekends = weekend_probs([t.weekday() for t in local_times])
    weekend = max(weekends, key=weekends.get)
    weeks = len({t.isocalendar()[:2] for t in local_times})
    if len(starts) < WEEKEND_MIN_SESSIONS or weeks < WEEKEND_MIN_WEEKS or weekends[weekend] < WEEKEND_MIN_PROB:
        weekend = "inconclusive"     # e.g. a four-day launch says nothing about weekends
    shown_regime = regime if len(starts) >= DST_MIN_SESSIONS and dst_probs[regime] >= DST_MIN_PROB else "inconclusive"
    return Clues(offset, band, band_mass, p_value, len(starts), shown_regime, dst_probs,
                 weekend, weekends, holiday_gaps(local_times), post)


def simulate_crew(offset: int, regime: str, weekend: str, n: int, seed: int = 1,
                  start: datetime = datetime(2024, 1, 1, tzinfo=UTC), days: int = 730) -> list[datetime]:
    """UTC times of `n` sittings by a made-up crew with a typical working day, its DST regime and its weekend."""
    rng = random.Random(seed)
    off_days = WEEKENDS[weekend]
    out: list[datetime] = []
    while len(out) < n:
        day = start + timedelta(days=rng.randrange(days))
        local_clock = day + timedelta(hours=rng.choices(range(24), weights=rhythm.PROFILE)[0] + rng.random())
        if local_clock.weekday() in off_days and rng.random() > WEEKEND_FACTOR:
            continue
        guess = local_clock - timedelta(hours=offset)
        out.append(guess - timedelta(hours=dst_shift(guess, regime)))
    return out


def holiday_gaps(local_times: list[datetime]) -> list[tuple[str, int, float, str]]:
    """Activity seen on each holiday against what an ordinary day would give."""
    if len(local_times) < 2:
        return []
    days = [t.date() for t in local_times]
    first, last = min(days), max(days)
    span = (last - first).days + 1
    per_day = len(days) / span
    out = []
    names = {name for y in range(first.year, last.year + 1) for name in holidays(y)}
    for name in sorted(names):
        dates = {d for y in range(first.year, last.year + 1) for d in holidays(y).get(name, []) if first <= d <= last}
        expected = per_day * len(dates)
        seen = sum(d in dates for d in days)
        if expected < MIN_EXPECTED_ON_HOLIDAYS:
            verdict = "not enough data"
        else:
            p_gap = sum(math.exp(-expected) * expected ** k / math.factorial(k) for k in range(seen + 1))
            verdict = f"gap (p = {p_gap:.3f})" if p_gap < 0.05 else "no gap"
        out.append((name, seen, round(expected, 1), verdict))
    return out
