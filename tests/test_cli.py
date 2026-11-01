from datetime import UTC

from rastro.__main__ import main


def test_pattern_command_prints_the_template(tmp_path, capsys):
    f = tmp_path / "domains.txt"
    f.write_text("\n".join([
        "paqexpres-entrega-4821.top", "paqexpres-envio-3318.top", "paqexpres-entrega-1180.icu",
        "paqexpres-envio-7710.icu",
    ]), encoding="utf-8")
    assert main(["pattern", str(f)]) == 0
    assert r"paqexpres-(entrega|envio)-\d{4}\.(icu|top)" in capsys.readouterr().out


def test_campaigns_command_groups_lookalikes_from_the_store(tmp_path, capsys):
    from datetime import datetime, timedelta

    from rastro import store
    from rastro.sources.ctlog import Entry

    t0 = datetime.now(UTC) - timedelta(hours=3)
    entries = [Entry(i, t0 + timedelta(minutes=4 * i), False, (f"paypal-verify-{n}.top",), "Let's Encrypt")
               for i, n in enumerate([1101, 2202, 3303])]
    # a different layout, so only the shared certificate can join these two
    entries.append(Entry(9, t0, False, ("apple-id-portal-77.top", "paypal-login-portal-77.top"), "Let's Encrypt"))
    db = tmp_path / "ct.sqlite"
    store.save(store.connect(db), "test", entries)
    assert main(["campaigns", "--db", str(db), "--hours", "24"]) == 0
    out = capsys.readouterr().out
    assert "CAMPAIGN 1 · 3 domains · paypal 3" in out
    assert "arm: paypal-verify-\\d{4}\\.top" in out
    assert "CAMPAIGN 2 · 2 domains · apple 1, paypal 1" in out
    assert "joined by: certificate 1" in out


def test_rhythm_command_reads_iso_times(tmp_path, capsys):
    f = tmp_path / "times.txt"
    f.write_text("\n".join(f"2026-10-{d:02d}T{h:02d}:15:00Z" for d in range(1, 11) for h in (6, 7, 8, 9, 11, 12, 13)),
                 encoding="utf-8")
    assert main(["rhythm", str(f), "--sims", "100"]) == 0
    out = capsys.readouterr().out
    assert "human rhythm: yes" in out
    assert "weekend: inconclusive" in out          # ten days are not enough to judge a weekend
    assert "daylight saving: inconclusive" in out


def test_brands_option_teaches_new_brands_to_any_command(tmp_path, capsys):
    mine = tmp_path / "brands.txt"
    mine.write_text("bancoeste | Banco Este | bancoeste.es\n", encoding="utf-8")
    args = ["investigate", "hxxps://bancoeste-verifica-4821[.]top/x", "--offline", "--no-crtsh", "--no-rdap",
            "--no-dns", "--sims", "100", "--cache", str(tmp_path / "cache"), "--report", str(tmp_path / "case.html")]
    assert main(["--brands", str(mine), *args]) == 0
    assert "imitating bancoeste" in capsys.readouterr().out
    assert main(args) == 0
    assert "no known brand" in capsys.readouterr().out


def test_a_broken_brands_file_stops_before_running(tmp_path, capsys):
    bad = tmp_path / "brands.txt"
    bad.write_text("not a key\n", encoding="utf-8")
    assert main(["--brands", str(bad), "pattern", str(bad)]) == 2
    assert "line 1" in capsys.readouterr().out


def test_rhythm_explains_an_empty_file_and_a_line_that_is_not_a_time(tmp_path, capsys):
    empty, bad = tmp_path / "empty.txt", tmp_path / "bad.txt"
    empty.write_text("# nothing yet\n", encoding="utf-8")
    bad.write_text("2026-10-30T09:15:00Z\nnot a time\n", encoding="utf-8")
    assert main(["rhythm", str(empty)]) == 1
    assert "No times in" in capsys.readouterr().out
    assert main(["rhythm", str(bad)]) == 2
    assert "'not a time' is neither a UTC time" in capsys.readouterr().out


def test_track_add_refuses_a_vague_since_and_skips_lines_that_are_not_alerts(tmp_path, capsys):
    db = str(tmp_path / "t.sqlite")
    assert main(["track", "add", "x.test", "--since", "yesterday", "--db", db]) == 2
    assert "--since needs a date and time in ISO 8601" in capsys.readouterr().out
    alerts = tmp_path / "alerts.jsonl"
    alerts.write_text('{"domain": "a.test", "logged_at": "2026-10-30 09:00:00"}\nnot json\n{"domain": 3}\n[1]\n'
                      '{"domain": "b.test", "logged_at": "soon"}\n'
                      '{"domain": "c.vercel.app", "logged_at": "2026-10-30 09:00:00"}\n', encoding="utf-8")
    assert main(["track", "add", "--alerts", str(alerts), "--db", db]) == 0
    out = capsys.readouterr().out
    assert "1 new domains followed" in out and "4 lines were not alerts" in out
    assert "Not followed: c.vercel.app" in out
    case = tmp_path / "case.json"
    case.write_text("[1, 2, 3]", encoding="utf-8")
    assert main(["track", "add", "--case", str(case), "--db", db]) == 2
    assert "is not case data" in capsys.readouterr().out


def test_a_missing_file_is_named_instead_of_a_traceback(tmp_path, capsys):
    missing = str(tmp_path / "no-such-file.txt")
    for argv in (["pattern", missing], ["rhythm", missing], ["watch", "--learn", missing],
                 ["investigate", "x.test", "--list", missing, "--offline", "--no-crtsh", "--no-rdap", "--no-dns"]):
        assert main(argv) == 2
        assert "no-such-file.txt: No such file or directory" in capsys.readouterr().out
