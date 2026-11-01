"""Sites on hosting platforms, end to end: what DNS can and cannot say about them, who gets the abuse report,
and what Husmo, the case file and the tracker tell the user. Made-up campaigns, no network."""

from datetime import UTC, datetime, timedelta

from rastro import husmo, investigate, report, track
from rastro.domains import ABUSE_FORMS, PLATFORMS, WILDCARD_DNS, dns_hides_takedown, host_label

T0 = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)
NOW = datetime(2026, 11, 1, tzinfo=UTC)


def case(suffix: str, live: int = 3, siblings: int = 8):
    """A crew of correos-envio-NNNN sites on one platform: the seed and the first `live` - 1 siblings resolve."""
    seed = f"correos-envio-4821.{suffix}"
    names = [f"correos-envio-{n}.{suffix}" for n in range(4822, 4822 + siblings)]
    first = {d: T0 + timedelta(hours=3 * k) for k, d in enumerate([seed, *names])}
    up = {seed, *names[:live - 1]}
    sources = investigate.Sources(lambda d: (first.get(d), frozenset()), lambda d: None,
                                  lambda d: frozenset({"203.0.113.9"}) if d in up else frozenset(),
                                  lambda d: frozenset())
    return investigate.investigate(f"https://{seed}/s/1", sources, list_lines=names, sims=200, now=NOW)


def test_every_abuse_form_belongs_to_a_known_platform_and_wildcards_are_platforms():
    assert set(ABUSE_FORMS) <= set(PLATFORMS) and WILDCARD_DNS <= set(PLATFORMS)
    assert all(url.startswith("https://") for url in ABUSE_FORMS.values())
    assert host_label("x.vercel.app") == "Vercel (vercel.app)" and host_label("x.top") is None
    assert dns_hides_takedown("x.github.io") and not dns_hides_takedown("x.pages.dev")
    assert not dns_hides_takedown("github.io")


def test_where_dns_tells_a_site_is_gone_it_stays_out_of_the_report():
    inv = case("pages.dev")
    [rep] = inv.reports
    assert rep.hosted and rep.form == "https://abuse.cloudflare.com/" and rep.email is None
    assert len(rep.domains) == 3 and set(inv.left_out.values()) == {"unresolved"}
    assert "please check whether" not in rep.body
    assert "Their first certificates came" in rep.body              # no registrations on a platform


def test_where_dns_answers_any_name_nothing_is_ruled_out_and_the_platform_is_asked_to_check():
    inv = case("vercel.app")
    [rep] = inv.reports
    assert rep.registrar == "Vercel (vercel.app)" and rep.form == "https://vercel.com/abuse"
    assert len(rep.domains) == 9 and inv.left_out == {}            # DNS cannot tell which ones came down
    assert "please check whether they are still up" in rep.body
    assert all(m.alive for m in inv.members.values())


def shared_address_case():
    """Ten sites built from one template on one platform, no dates; only the seed and one sibling are live, so
    they alone share the platform's address. A template alone never joins two domains."""
    seed, twin = "correos-envio-4821.vercel.app", "correos-envio-5000.vercel.app"
    names = [twin] + [f"correos-envio-{n}.vercel.app" for n in range(6000, 6008)]
    sources = investigate.Sources(lambda d: (None, frozenset()), lambda d: None,
                                  lambda d: frozenset({"203.0.113.9"}) if d in (seed, twin) else frozenset(),
                                  lambda d: frozenset())
    return investigate.investigate(f"https://{seed}/", sources, list_lines=names, sims=100, now=NOW)


def test_a_platforms_shared_addresses_never_tie_two_sites_together():
    inv = shared_address_case()
    assert inv.campaign == [inv.seed]
    assert not any("ip" in kinds for *_, kinds in inv.edges)


def test_without_that_rule_the_shared_address_would_have_joined_them(monkeypatch):
    # the same case with a platform's addresses counted as the site's own, as before: proof the case can fail
    monkeypatch.setattr(investigate.Member, "infrastructure", property(lambda m: (m.ips, m.nameservers)))
    inv = shared_address_case()
    assert inv.campaign == [inv.seed, "correos-envio-5000.vercel.app"]


def test_husmo_says_where_the_site_lives_and_what_it_cannot_know():
    gone = husmo.narrate(case("pages.dev"), "en")
    blind = husmo.narrate(case("vercel.app"), "es")
    assert any("a site on Cloudflare Pages" in t for _, t in gone)
    assert not any("answers DNS for any name, so I cannot tell" in t for _, t in gone)
    assert any("one per platform" in t for _, t in gone)
    assert any("Esa plataforma responde en DNS a cualquier nombre" in t for _, t in blind)
    assert any(t.startswith("Puede que los 9 sigan en pie") for _, t in blind)


def test_the_case_file_names_the_host_and_its_form():
    data = report.case_data(case("vercel.app"), "en")
    [rep] = data["reports"]
    assert rep["hosted"] and rep["form"] == "https://vercel.com/abuse"
    assert data["counts"]["unchecked"] == data["counts"]["reported"] == 9
    seed = next(r for r in data["domains"] if r["seed"])
    assert seed["registrar"] == "Vercel (vercel.app)" and seed["alive"]
    page = report.render(case("pages.dev"), "es")
    assert "Avisa al registrador o al hosting" in page and "Formulario de abuso" in page


def test_the_tracker_skips_sites_it_could_never_see_come_down(tmp_path):
    conn = track.connect(tmp_path / "track.sqlite")
    names = ["correos-envio-1.vercel.app", "www.correos-envio-2.pages.dev", "correos-envio-3.top"]
    assert track.unfollowable(names) == ["correos-envio-1.vercel.app"]
    assert track.add(conn, names, NOW) == 2
    followed = {d for (d,) in conn.execute("SELECT domain FROM tracked")}
    assert followed == {"correos-envio-2.pages.dev", "correos-envio-3.top"}


def test_the_tracker_names_the_platform_and_sees_a_deleted_site_go():
    sources = track.Sources(lambda d: ("platform", None), lambda d: ("nxdomain", frozenset()))
    seen = track.look("correos-envio-2.pages.dev", sources)
    assert seen.state == "gone" and seen.registrar == "Cloudflare Pages (pages.dev)"


def test_track_add_says_which_domains_it_will_not_follow(tmp_path, capsys):
    from rastro.__main__ import main
    assert main(["track", "add", "correos-envio-1.vercel.app", "correos-envio-3.top",
                 "--db", str(tmp_path / "t.sqlite")]) == 0
    out = capsys.readouterr().out
    assert "1 new domains followed" in out and "Not followed: correos-envio-1.vercel.app" in out


def test_sites_that_share_the_platforms_certificate_are_never_looked_up_in_ct():
    asked = []

    def certificates(d):
        asked.append(d)
        return T0, frozenset()

    for suffix in ("vercel.app", "pages.dev"):
        seed = f"correos-envio-4821.{suffix}"
        inv = investigate.investigate(f"https://{seed}/", investigate.Sources(certificates), sims=100, now=NOW)
        said = " ".join(t for _, t in husmo.narrate(inv, "en"))
        assert ("all its sites share one certificate" in said) == (suffix == "vercel.app")
    assert asked == ["correos-envio-4821.pages.dev"]       # Vercel's sites have no certificate of their own


def test_a_platform_is_its_own_ending():
    from rastro.domains import ending
    assert ending("help-ledger-login.vercel.app") == "vercel.app" and ending("correos-envio-1.top") == "top"
    seed = "help-ledger-login.vercel.app"
    assert investigate.related(seed, "help-ledger-support.vercel.app") == 0
    assert investigate.related(seed, "help-ledger-support.web.app") == 1     # same layout, another platform
