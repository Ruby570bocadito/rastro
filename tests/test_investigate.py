from datetime import UTC, datetime, timedelta

import pytest

from rastro import calendar_clues, investigate
from rastro.sources.rdap import Registration

SEED = "correos-envio-4821.top"
CREW = [f"correos-envio-{n}.top" for n in range(1000, 1060)]          # sixty siblings on the public list
NOISE = ["correos-blog.com", "my-site.top", "paypal-envio-1234.top", "correos.es"]
TIMES = calendar_clues.simulate_crew(offset=-5, regime="none", weekend="none", n=61, seed=3)
FIRST = dict(zip([SEED, *CREW], sorted(TIMES), strict=True))
FIRST["dgt-multa-4821.top"] = FIRST[SEED]


def registration(domain, registered, status=("client transfer prohibited",), registrar="Example Registrar, Inc."):
    return Registration(domain, registered, None, registrar, "9999", "abuse@registrar.example", "+1.5550100",
                        status, "https://rdap.example/")


def fake_sources():
    def certificates(d):
        co = frozenset({"dgt-multa-4821.top"}) if d == SEED else frozenset()
        return FIRST.get(d), co

    def lookup(d):
        if d in ("correos-envio-1000.top", "correos-envio-1001.top"):
            return None                                                     # expired long ago
        if d == "correos-envio-1002.top":                                   # bought again a year later
            return registration(d, FIRST[d] + timedelta(days=365))
        if d == "correos-envio-1003.top":
            return registration(d, FIRST[d] - timedelta(minutes=20), status=("client hold",))
        if d in FIRST:
            return registration(d, FIRST[d] - timedelta(minutes=20))
        return None

    def addresses(d):
        return frozenset({"203.0.113.7"}) if d in (SEED, "correos-envio-1050.top") else frozenset()

    return investigate.Sources(certificates, lookup, addresses, lambda d: frozenset())


def test_seed_domain_accepts_links_defanged_links_and_unicode():
    assert investigate.seed_domain("https://www.correos-envio-4821.top/s/7Hk2?x=1") == SEED
    assert investigate.seed_domain("hxxps://correos-envio-4821[.]top/s/7Hk2") == SEED
    assert investigate.seed_domain("cоinbase.com") == "xn--cinbase-9ig.com"       # Cyrillic о
    with pytest.raises(ValueError):
        investigate.seed_domain("not a link")


def test_guess_from_one_frees_the_digits_only():
    assert investigate.guess_from_one("paqexpres-entrega-4821.top") == r"paqexpres-entrega-\d{4}\.top"
    assert investigate.guess_from_one("secure-login.top") is None


def test_investigation_finds_the_crew_the_campaign_the_clock_and_the_registrar():
    inv = investigate.investigate("hxxps://correos-envio-4821[.]top/s/7Hk2", fake_sources(),
                                  list_lines=CREW + NOISE, sims=500, now=datetime(2026, 10, 30, tzinfo=UTC))
    assert inv.seed == SEED and inv.brand == "correos"
    assert inv.crew_pattern.regex == r"correos-envio-\d{4}\.top"
    assert len(inv.crew) == 61 and "paypal-envio-1234.top" not in inv.members
    # the shared certificate pulls in another brand; the shared rare address joins one sibling
    assert {"dgt-multa-4821.top", "correos-envio-1050.top"} <= set(inv.campaign)
    assert inv.rhythm_found and inv.clues.offset in (-6, -5, -4)
    assert inv.clock_events > 61                    # registrations add a second clock
    (report,) = inv.reports
    assert report.email == "abuse@registrar.example"
    assert SEED in report.domains and "[Say how you received" in report.body
    assert "correos-envio-\\d{4}\\.top" in report.body
    assert inv.left_out["correos-envio-1000.top"] == "unregistered"
    assert inv.left_out["correos-envio-1002.top"] == "reregistered"
    assert inv.left_out["correos-envio-1003.top"] == "suspended"
    assert inv.guess is None


def test_a_lonely_seed_gets_a_guess_and_an_honest_note():
    inv = investigate.investigate("paqexpres-entrega-4821.top", investigate.Sources(), sims=0)
    assert inv.campaign == ["paqexpres-entrega-4821.top"] and inv.crew == []
    assert inv.guess == r"paqexpres-entrega-\d{4}\.top"
    assert inv.clues is None and not inv.rhythm_found
    assert ("lonely", {}) in inv.notes


def test_addresses_and_shorteners_are_refused_with_a_reason():
    with pytest.raises(ValueError, match="address"):
        investigate.seed_host("http://192.0.2.4/login")
    with pytest.raises(ValueError, match="shortener"):
        investigate.seed_host("https://bit.ly/3abc")


def test_a_brand_in_a_subdomain_names_the_target_but_not_the_template():
    inv = investigate.investigate("https://amazon.co.uk.login-check.top/x", investigate.Sources(), sims=100)
    assert inv.seed == "login-check.top" and inv.brand == "amazon"
    assert inv.members[inv.seed].brand is None
    assert ("brand_in_subdomain", {"brand": "Amazon", "seed": "login-check.top"}) in inv.notes


def test_platform_sites_are_reported_to_the_platform_not_a_registrar():
    seed, gone = "correos-envio-4821.pages.dev", "correos-envio-4822.pages.dev"

    def addresses(d):
        return frozenset({"203.0.113.9"}) if d == seed else frozenset()

    sources = investigate.Sources(lambda d: (None, frozenset()), lambda d: None, addresses, lambda d: frozenset())
    inv = investigate.investigate(f"https://{seed}/s/1", sources, list_lines=[gone, "correos-envio-4823.pages.dev"],
                                  sims=100)
    assert inv.seed == seed and inv.brand == "correos"
    [report] = inv.reports
    assert report.registrar == "Cloudflare Pages (pages.dev)" and report.email is None
    assert report.domains == [seed] and "hosted on your platform" in report.body
    assert inv.left_out == {gone: "unresolved", "correos-envio-4823.pages.dev": "unresolved"}
