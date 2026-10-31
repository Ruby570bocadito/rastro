import random
from datetime import UTC

from rastro import rhythm


def synth(offset, n, bot_share=0.0, seed=1):
    """UTC hours of `n` actions by people working at `offset`, with some bots mixed in."""
    rng = random.Random(seed)
    hours = []
    for _ in range(n):
        if rng.random() < bot_share:
            hours.append(rng.uniform(0, 24))
        else:
            local = rng.choices(range(24), weights=rhythm.PROFILE)[0] + rng.random()
            hours.append((local - offset) % 24)
    return hours


def test_recovers_offset_from_human_activity():
    est = rhythm.estimate(synth(3, 200), sims=300)
    assert rhythm.circular_distance(est.offset, 3) <= 1
    assert est.p_value < 0.01


def test_round_the_clock_activity_is_not_called_human():
    rng = random.Random(5)
    est = rhythm.estimate([rng.uniform(0, 24) for _ in range(200)], sims=300)
    assert est.p_value > 0.01


def test_bots_mixed_in_are_tolerated():
    est = rhythm.estimate(synth(-5, 300, bot_share=0.4, seed=3), sims=300)
    assert rhythm.circular_distance(est.offset, -5) <= 1
    assert est.bot_share >= 0.2


def test_band_contains_best_offset_and_reaches_mass():
    est = rhythm.estimate(synth(8, 100, seed=9), sims=200)
    assert est.offset in est.band
    assert est.band_mass >= 0.9


def test_band_wraps_across_the_date_line():
    est = rhythm.estimate(synth(12, 150, seed=4), sims=200)
    assert rhythm.circular_distance(est.offset, 12) <= 1
    assert all(-11 <= o <= 12 for o in est.band)


def test_schedule_prior_widens_the_band_without_moving_the_peak():
    hours = synth(3, 120, seed=11)
    strict = rhythm.estimate(hours, sims=100, schedules=False)
    honest = rhythm.estimate(hours, sims=100)
    assert honest.offset == strict.offset
    assert len(honest.band) >= len(strict.band)


def test_a_late_crew_is_still_inside_the_band():
    # crew in UTC+3 starting two hours late: the hours alone point to UTC+1
    hours = [(h + 2) % 24 for h in synth(3, 300, seed=12)]
    est = rhythm.estimate(hours, sims=100)
    assert 3 in est.band


def test_sessions_collapse_actions_in_one_sitting():
    from datetime import datetime, timedelta
    t0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
    burst = [t0 + timedelta(minutes=m) for m in (0, 5, 12, 50, 51, 200)]
    assert rhythm.sessions(burst) == [t0, t0 + timedelta(minutes=50), t0 + timedelta(minutes=200)]


def test_offsets_wrap_onto_the_nominal_range():
    assert rhythm.wrap_offset(13) == -11
    assert rhythm.wrap_offset(-12) == 12
    assert rhythm.tz_name(-5) == "UTC−5"
