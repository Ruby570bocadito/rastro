import json
import re
from datetime import UTC, datetime, timedelta

import pytest

from rastro import track
from rastro.__main__ import main
from rastro.sources.rdap import Registration

T0 = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)


def reg(domain, registrar="Fast Names, Inc.", status=("client transfer prohibited",), expires=T0 + timedelta(days=300)):
    return Registration(domain, T0 - timedelta(days=1), expires, registrar, None, "abuse@fast.example", None, status,
                        "https://rdap.example/")


class World:
    """A made-up registry and resolver whose answers change as the clock moves."""

    def __init__(self):
        self.now = T0
        self.events = {   # domain -> list of (from hours, registry outcome, registration, resolver verdict, addresses)
            "fast-1.test": [(0, "found", reg("fast-1.test"), "noerror", {"192.0.2.1"}),
                            (20, "found", reg("fast-1.test", status=("client hold",)), "nxdomain", set())],
            "fast-2.test": [(0, "found", reg("fast-2.test"), "noerror", {"192.0.2.2"}),
                            (40, "not-found", None, "nxdomain", set())],
            "slow-1.test": [(0, "found", reg("slow-1.test", "Slow Names Ltd."), "noerror", {"192.0.2.3"})],
            "slow-2.test": [(0, "found", reg("slow-2.test", "Slow Names Ltd.", expires=T0 + timedelta(hours=50)),
                             "noerror", {"192.0.2.4"}),
                            (60, "not-found", None, "nxdomain", set())],
            "nordap.test": [(0, "no-server", None, "noerror", {"192.0.2.5"}),
                            (30, "no-server", None, "nxdomain", set())],
        }

    def _at(self, domain):
        hours = (self.now - T0).total_seconds() / 3600
        return [e for e in self.events[domain] if e[0] <= hours][-1]

    def sources(self):
        return track.Sources(lambda d: self._at(d)[1:3], lambda d: (self._at(d)[3], frozenset(self._at(d)[4])))


def test_states_come_from_the_registry_and_the_resolver():
    assert track.classify("found", reg("a.test", status=("client hold",)), "nxdomain", set()) == "held"
    assert track.classify("found", reg("a.test", status=("pending delete",)), "noerror", set()) == "deleting"
    assert track.classify("not-found", None, "nxdomain", set()) == "gone"
    assert track.classify("no-server", None, "nxdomain", set()) == "gone"       # no RDAP: the zone says it
    assert track.classify("found", reg("a.test"), "noerror", {"192.0.2.1"}) == "live"
    assert track.classify("found", reg("a.test"), "noerror", set()) == "offline"
    assert track.classify("no-answer", None, None, set()) == "unknown"


def test_kaplan_meier_keeps_the_domains_still_up():
    curve = track.kaplan_meier([(10, True), (20, False), (30, True), (40, True), (50, False)])
    assert curve == [(0.0, 1.0), (10, 0.8), (30, pytest.approx(0.8 * 2 / 3)), (40, pytest.approx(0.8 * 2 / 3 / 2))]
    assert track.median_hours(curve) == 40
    assert track.standing_after(curve, 35) == pytest.approx(0.8 * 2 / 3)
    assert track.median_hours(track.kaplan_meier([(5, False), (9, True), (12, False)])) == 9   # 1 of 2 at risk
    assert track.median_hours(track.kaplan_meier([(5, False), (9, True), (12, False), (15, False)])) is None


def test_checks_find_takedowns_and_the_scoreboard_ranks_registrars(tmp_path):
    conn = track.connect(tmp_path / "track.sqlite")
    world = World()
    assert track.add(conn, list(world.events), T0, source="manual") == 5
    assert track.add(conn, ["fast-1.test"], T0 + timedelta(hours=5)) == 0       # the first clock stays
    for hours in (0, 12, 24, 36, 48, 72):
        world.now = T0 + timedelta(hours=hours)
        track.check(conn, world.sources(), now=world.now)
    assert track.standing(conn) == ["slow-1.test"]    # nordap went out of its zone, so it is gone too
    by = {c.domain: c for c in track.courses(conn)}
    assert by["fast-1.test"].down_at == T0 + timedelta(hours=24) and by["fast-1.test"].taken_down
    assert by["fast-2.test"].hours == 48
    assert by["slow-2.test"].expired and not by["slow-2.test"].taken_down    # gone after its expiry date
    assert by["slow-1.test"].hours == 72 and by["slow-1.test"].down_at is None
    assert by["nordap.test"].registrar == track.UNKNOWN_REGISTRAR
    rows = {r.registrar: r for r in track.scoreboard(conn)}
    fast, slow = rows["Fast Names, Inc."], rows["Slow Names Ltd."]
    assert (fast.domains, fast.taken_down, fast.median_hours) == (2, 2, 24)      # half were down after a day
    assert fast.after[24] == 0.5 and fast.after[72] == 0
    assert (slow.domains, slow.taken_down, slow.still_up, slow.median_hours) == (2, 0, 1, None)
    assert [r.registrar for r in track.scoreboard(conn)][0] == "Fast Names, Inc."


def test_track_commands_add_and_report(tmp_path, capsys):
    db = tmp_path / "track.sqlite"
    alerts = tmp_path / "alerts.jsonl"
    alerts.write_text(json.dumps({"logged_at": "2026-11-01 08:00:00", "domain": "slow-1.test", "pattern": "x",
                                  "log": "l", "index": 1}) + "\n", encoding="utf-8")
    case = tmp_path / "case.json"
    case.write_text(json.dumps({"reports": [{"domains": ["fast-1.test", "fast-2.test"]}]}), encoding="utf-8")
    assert main(["track", "add", "hxxps://slow-2[.]test/x", "nordap.test", "--alerts", str(alerts), "--case", str(case),
                 "--reported", "--db", str(db)]) == 0
    assert "5 new domains followed, 5 in" in capsys.readouterr().out
    assert main(["track", "report", "--db", str(db)]) == 1                  # nothing checked yet
    world, conn = World(), track.connect(db)
    for hours in (0, 24, 48):
        world.now = T0 + timedelta(hours=hours)
        track.check(conn, world.sources(), now=world.now)
    page = tmp_path / "board.html"
    assert main(["track", "report", "--db", str(db), "--html", str(page), "--lang", "es"]) == 0
    out = capsys.readouterr().out
    assert "TAKEDOWN SCOREBOARD · 5 domains" in out and "Fast Names, Inc." in out
    html = page.read_text(encoding="utf-8")
    data = json.loads(re.search(r'<script type="application/json" id="board">(.*?)</script>', html, re.S).group(1))
    assert data["lang"] == "es" and data["counts"]["domains"] == 5
    assert data["rows"][0]["registrar"] == "Fast Names, Inc."
    assert "default-src 'none'" in html


def test_the_clock_can_start_at_the_abuse_report(tmp_path):
    conn = track.connect(tmp_path / "track.sqlite")
    world = World()
    track.add(conn, ["fast-1.test", "fast-2.test", "slow-1.test"], T0)
    track.add(conn, ["fast-1.test", "fast-2.test"], T0 + timedelta(hours=12), reported=True)   # reports go out later
    for hours in (0, 12, 24, 36, 48):
        world.now = T0 + timedelta(hours=hours)
        track.check(conn, world.sources(), now=world.now)
    (row,) = track.scoreboard(conn, from_report=True)                 # slow-1 was never reported
    assert (row.registrar, row.domains, row.median_hours) == ("Fast Names, Inc.", 2, 12)
    assert track.scoreboard(conn)[0].median_hours == 24               # timed from when they were followed
    data = track.page_data(conn, from_report=True)
    assert data["from_report"] and [d["hours"] for d in data["domains"]] == [12, 36]
