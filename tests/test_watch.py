from datetime import UTC, datetime, timedelta

from rastro import bursts, store, watch
from rastro.sources.ctlog import Entry

T0 = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)
CAMPAIGN = [f"paqexpres-{w}-{n}.top" for w, n in
            [("entrega", 4821), ("envio", 3318), ("pago", 7710), ("entrega", 5541), ("envio", 8802), ("pago", 3019)]]


def entry(i, *names, minutes=0, precert=False):
    return Entry(i, T0 + timedelta(minutes=minutes), precert, tuple(names), "Let's Encrypt")


def test_only_narrow_learned_patterns_are_armed():
    w = watch.Watcher("test")
    random_words = ["secure-qwhzkmnbvc.top", "secure-plmzaqxtyuw.top", "secure-vbtrexjfgho.top"]
    w.arm_learned(CAMPAIGN + random_words, min_support=3)
    assert [a.regex for a in w.armed] == [r"paqexpres-(entrega|envio|pago)-\d{4}\.top"]
    assert w.skipped and w.skipped[0][0].startswith(r"secure-[a-z]")


def test_broad_patterns_can_be_forced():
    w = watch.Watcher("test", allow_broad=True)
    w.arm_learned(["secure-qwhzk.top", "secure-plmzaq.top", "secure-vbtrex.top"])
    assert len(w.armed) == 1 and not w.skipped


def test_alerts_once_per_domain_and_never_on_official_domains():
    w = watch.Watcher("test", allow={"paqexpres-envio-1111.top"})
    w.arm_learned(CAMPAIGN)
    w.arm_regex([r"[a-z]*microsoft[a-z]*\.com"])
    alerts = w.handle([
        entry(1, "paqexpres-aduana-0000.top"),                         # word outside the vocabulary
        entry(2, "paqexpres-pago-9090.top", "www.paqexpres-pago-9090.top", precert=True),
        entry(3, "paqexpres-pago-9090.top"),                            # the certificate after its pre-certificate
        entry(4, "paqexpres-envio-1111.top"),                           # on the user's allowlist
        entry(5, "login.microsoftonline.com"),                          # the brand's own domain
    ])
    assert [a.domain for a in alerts] == ["paqexpres-pago-9090.top"]
    assert w.suppressed == 2
    assert '"domain": "paqexpres-pago-9090.top"' in alerts[0].json()


def test_progress_is_remembered(tmp_path):
    conn = store.connect(tmp_path / "ct.sqlite")
    assert store.get_progress(conn, "log") is None
    store.set_progress(conn, "log", 41)
    store.set_progress(conn, "log", 42)
    assert store.get_progress(conn, "log") == 42


def test_bursts_find_a_campaign_being_born(tmp_path):
    conn = store.connect(tmp_path / "ct.sqlite")
    usps = [f"usps-redelivery-{n}.top" for n in (1023, 4410, 5821, 6634, 7702, 8915)]
    noise = ["pineapple-shop.com", "my-blog.net", "apple.com", "usps.com", "steam-tips.org"]
    entries = [entry(i, d, minutes=i * 7) for i, d in enumerate(usps + noise)]
    store.save(conn, "test", entries)
    found = bursts.find_bursts(conn, hours=6, min_domains=5, now=T0 + timedelta(hours=2))
    assert len(found) == 1
    b = found[0]
    assert b.brand == "usps" and len(b.domains) == 6
    assert b.regex == r"usps-redelivery-\d{4}\.top"
    assert bursts.find_bursts(conn, hours=6, min_domains=7, now=T0 + timedelta(hours=2)) == []


def test_bursts_group_a_distinctive_word_across_layouts(tmp_path):
    conn = store.connect(tmp_path / "ct.sqlite")
    names = ["call-microsofterrorfound-24h.ph",          # two layouts, one unusual word around the brand
             "microsofterrorfound-help-desk-1.ph",
             "secure-microsoft-1.ph"]
    store.save(conn, "test", [entry(i, d, minutes=i) for i, d in enumerate(names)])
    (b,) = bursts.find_bursts(conn, hours=6, min_domains=2, now=T0 + timedelta(hours=1))
    assert b.brand == "microsoft" and b.breadth_log10 is None
    assert b.domains == tuple(sorted(names[:2]))
    assert b.regex == r"(?=.*microsofterrorfound)[a-z0-9.-]+\.ph"


def test_only_lookalikes_and_alerts_are_kept_and_everything_is_counted(tmp_path):
    w = watch.Watcher("test")
    w.arm_regex([r"zz-\d+\.top"])
    entries = [entry(1, "my-blog.net"), entry(2, "paypal-verify-1101.top", "my-shop.com"), entry(3, "paypal.com"),
               entry(4, "zz-77.top"), entry(5, "cdn.example.org", minutes=70)]
    w.handle(entries)
    kept = w.keep(entries)
    assert [e.index for e in kept] == [2, 4]       # a lookalike, kept whole, and an alert; not the brand's own site
    conn = store.connect(tmp_path / "ct.sqlite")
    assert store.record(conn, "test", 7, entries, kept)
    assert not store.record(conn, "test", 7, entries, kept)       # a tile read twice is stored and counted once
    assert store.get_progress(conn, "test") == 8
    assert store.coverage(conn) == (5, 2, "2026-10-30T09", "2026-10-30T10")
    assert {r for (r,) in conn.execute("SELECT registrable FROM names")} == {
        "paypal-verify-1101.top", "my-shop.com", "zz-77.top"}
