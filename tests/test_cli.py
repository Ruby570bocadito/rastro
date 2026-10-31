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
