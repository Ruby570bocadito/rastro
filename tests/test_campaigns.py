import json
from datetime import UTC, datetime, timedelta

from rastro.campaigns import Domain, cluster
from rastro.sources import dns

T0 = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)
CF = frozenset({"cloudflare.com"})


def at(minutes):
    return T0 + timedelta(minutes=minutes)


def background(n=60):
    """Unrelated domains that share the same big DNS provider, to give rarity something to measure."""
    return [Domain(f"site{i}-shop.com", nameservers=CF, ips=frozenset({"104.21.0.1"})) for i in range(n)]


def names(campaigns):
    return [c.domains for c in campaigns]


def test_template_plus_session_makes_a_campaign():
    crew = [Domain(f"usps-redelivery-{n}.top", "usps", at(m), nameservers=CF)
            for n, m in [(1023, 0), (4410, 6), (5821, 12), (6634, 20)]]
    found = cluster(crew + background())
    assert names(found) == [sorted(d.name for d in crew)]
    assert found[0].links["template"] and found[0].links["session"]
    assert found[0].patterns == [r"usps-redelivery-\d{4}\.top"]


def test_sittings_of_one_launch_join_through_the_burst():
    launch = [Domain(f"grup-wa-{n}.top", "whatsapp", at(m), nameservers=CF)
              for n, m in [(11, 0), (12, 5), (13, 60 * 20), (14, 60 * 20 + 3), (15, 60 * 50)]]
    (c,) = cluster(launch + background())
    assert c.size == 5 and c.links["burst"]


def test_template_alone_does_not_join_domains_months_apart():
    copies = [Domain(f"usps-redelivery-{n}.top", "usps", at(m), nameservers=CF)
              for n, m in [(1023, 0), (4410, 60 * 24 * 40), (5821, 60 * 24 * 90)]]
    assert cluster(copies + background()) == []


def test_a_shared_certificate_joins_different_brands():
    a = Domain("paypal-login-77.top", "paypal", co_certified=frozenset({"apple-id-77.top"}))
    b = Domain("apple-id-77.top", "apple", co_certified=frozenset({"paypal-login-77.top"}))
    (c,) = cluster([a, b] + background())
    assert c.domains == ["apple-id-77.top", "paypal-login-77.top"]
    assert c.brands == {"paypal": 1, "apple": 1}
    assert c.links["certificate"] == 1


def test_dns_answers_are_read_from_the_cache(tmp_path):
    payload = {"Status": 0, "Answer": [
        {"name": "x.top.", "type": 2, "data": "NS1.Evil-NS.ru."},
        {"name": "x.top.", "type": 2, "data": "ns2.evil-ns.ru."},
        {"name": "x.top.", "type": 46, "data": "signature"},
    ]}
    (tmp_path / "dns_NS_x.top.json").write_text(json.dumps(payload), encoding="utf-8")
    assert dns.nameservers("x.top", tmp_path) == frozenset({"evil-ns.ru"})


def test_a_rare_server_joins_a_template_but_a_common_one_does_not():
    rare = frozenset({"evil-ns.ru"})
    crew = [Domain(f"chase-alert-{n}.com", "chase", at(60 * 24 * k), nameservers=rare)
            for n, k in [(11, 0), (12, 30), (13, 60)]]
    (c,) = cluster(crew + background())
    assert c.size == 3 and c.links["nameserver"] == 3
    common = [Domain(d.name, d.brand, d.first_seen, nameservers=CF) for d in crew]
    assert cluster(common + background()) == []
