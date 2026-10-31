from datetime import UTC, date, datetime, timedelta

from rastro import calendar_clues as cc
from rastro import rhythm


def test_dst_dates_follow_the_rules():
    # 2026: EU from 29 March to 25 October, US from 8 March to 1 November
    assert cc._sunday(2026, 3, -1) == 29 and cc._sunday(2026, 10, -1) == 25
    assert cc._sunday(2026, 3, 2) == 8 and cc._sunday(2026, 11, 1) == 1
    assert cc.dst_shift(datetime(2026, 7, 1, tzinfo=UTC), "eu") == 1
    assert cc.dst_shift(datetime(2026, 10, 30, tzinfo=UTC), "eu") == 0
    assert cc.dst_shift(datetime(2026, 10, 30, tzinfo=UTC), "us") == 1
    assert cc.dst_shift(datetime(2026, 12, 15, tzinfo=UTC), "south") == 1
    assert cc.dst_shift(datetime(2026, 7, 1, tzinfo=UTC), "none") == 0


crew = cc.simulate_crew


def test_recovers_offset_dst_and_weekend_with_plenty_of_data():
    clues = cc.analyse(crew(1, "eu", "sat-sun", 600, seed=3), sims=0)
    assert rhythm.circular_distance(clues.offset, 1) <= 1
    assert max(clues.dst_probs, key=clues.dst_probs.get) == "eu"   # DST is the weakest clue; it may stay unreported
    assert clues.dst in ("eu", "inconclusive")
    assert clues.weekend == "sat-sun"


def test_tells_a_friday_saturday_weekend_apart():
    clues = cc.analyse(crew(3, "none", "fri-sat", 600, seed=4), sims=0)
    assert clues.weekend == "fri-sat"
    assert max(clues.dst_probs, key=clues.dst_probs.get) == "none"


def test_a_short_launch_says_nothing_about_weekends_or_dst():
    launch = crew(2, "eu", "sat-sun", 60, seed=5, start=datetime(2025, 10, 5, tzinfo=UTC), days=4)
    clues = cc.analyse(launch, sims=0)
    assert clues.weekend == "inconclusive"
    assert clues.dst == "inconclusive"


def test_holidays_need_enough_data_before_judging():
    few = cc.holiday_gaps([datetime(2025, 3, d, 10, tzinfo=UTC) for d in range(1, 20)])
    assert all(verdict == "not enough data" for *_, verdict in few)


def test_a_crew_that_stops_for_christmas_shows_a_gap():
    days = [date(2024, 1, 1) + timedelta(days=k) for k in range(730)]
    busy = [datetime(d.year, d.month, d.day, 10, tzinfo=UTC) + timedelta(minutes=m)
            for d in days if not (d.month == 12 and d.day >= 24) and d != date(d.year, 1, 1) for m in (0, 300)]
    result = dict((name, verdict) for name, _, _, verdict in cc.holiday_gaps(busy))
    assert result["Christmas and New Year"].startswith("gap")
