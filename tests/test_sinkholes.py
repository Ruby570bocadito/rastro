"""Dynamic DNS names and sinkholes: which addresses are clues, and which names are already neutralized.
Made-up names and documentation addresses, no network."""

import io
import json
import urllib.parse

from rastro import husmo, investigate, report
from rastro.sources import dns

SERVER, HOLE = "203.0.113.50", "192.0.2.66"
REVERSE = {SERVER: frozenset({"vps-50.hosting.example"}), HOLE: frozenset({"sinkhole.security.example"})}


def crew_case(suffix: str, address: str):
    """Ten names from one template; only the seed and one twin resolve, both to `address`. A template alone
    never joins two names, so they join only if the shared address counts."""
    seed, twin = f"paypal-verify-4821.{suffix}", f"paypal-verify-5000.{suffix}"
    names = [twin] + [f"paypal-verify-{n}.{suffix}" for n in range(6000, 6008)]
    sources = investigate.Sources(None, lambda d: None,
                                  lambda d: frozenset({address}) if d in (seed, twin) else frozenset(),
                                  lambda d: frozenset(), lambda ip: REVERSE.get(ip, frozenset()))
    return investigate.investigate(f"https://{seed}/", sources, list_lines=names, sims=100)


def test_a_dynamic_dns_address_is_its_owners_server_and_ties_names_together():
    inv = crew_case("duckdns.org", SERVER)
    assert inv.campaign == ["paypal-verify-4821.duckdns.org", "paypal-verify-5000.duckdns.org"]
    assert any("ip" in kinds for *_, kinds in inv.edges)
    assert inv.reports and inv.reports[0].registrar == "Duck DNS (duckdns.org)"


def test_the_same_shared_address_on_a_hosting_platform_ties_nothing():
    inv = crew_case("vercel.app", SERVER)
    assert inv.campaign == ["paypal-verify-4821.vercel.app"]


def test_a_sinkhole_ties_nothing_and_its_names_need_no_report():
    inv = crew_case("duckdns.org", HOLE)
    seed = inv.members[inv.seed]
    assert seed.sinkhole == "sinkhole.security.example" and not seed.alive
    assert inv.campaign == [inv.seed] and not any("ip" in kinds for *_, kinds in inv.edges)
    assert inv.left_out[inv.seed] == "sinkholed" and inv.reports == []
    told = " ".join(t for _, t in husmo.narrate(inv, "es"))
    assert "ya es un sumidero (sinkhole.security.example)" in told and "ya apuntan a sumideros" in told
    assert "already points at a sinkhole: someone neutralized it" in report.render(inv, "en")


def test_a_registered_domain_at_a_sinkhole_is_not_reported_either():
    from rastro.sources.rdap import Registration
    reg = Registration("paypal-verify-4821.top", None, None, "Example Registrar, Inc.", "9999",
                       "abuse@registrar.example", None, ("client transfer prohibited",), "https://rdap.example/")
    sources = investigate.Sources(None, lambda d: reg, lambda d: frozenset({HOLE}), lambda d: frozenset(),
                                  lambda ip: REVERSE[ip])
    inv = investigate.investigate("https://paypal-verify-4821.top/", sources, sims=100)
    assert inv.left_out == {"paypal-verify-4821.top": "sinkholed"} and inv.reports == []


def test_husmo_explains_a_dynamic_dns_seed():
    told = " ".join(t for _, t in husmo.narrate(crew_case("duckdns.org", SERVER), "en"))
    assert "free dynamic DNS" in told and "their own server and counts as a clue" in told


def test_reverse_dns_asks_for_the_arpa_name_and_reads_the_answer(monkeypatch, tmp_path):
    asked = []

    class Answer(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def urlopen(req, timeout):
        asked.append(urllib.parse.parse_qs(urllib.parse.urlsplit(req.full_url).query)["name"][0])
        return Answer(json.dumps({"Status": 0, "Answer": [{"type": 12, "data": "sinkhole.security.example."}]})
                      .encode())

    monkeypatch.setattr(dns.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(dns.time, "sleep", lambda s: None)
    assert dns.reverse(HOLE, tmp_path) == {"sinkhole.security.example"}
    dns.reverse("2001:db8::1", tmp_path)
    assert asked == ["66.2.0.192.in-addr.arpa",
                     "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"]
    assert dns.reverse("not an address", tmp_path) == frozenset() and len(asked) == 2


def test_a_sinkholed_seed_is_told_plainly():
    inv = investigate.investigate("https://paypal-verify-4821.duckdns.org/", investigate.Sources(
        None, lambda d: None, lambda d: frozenset({HOLE}), lambda d: frozenset(), lambda ip: REVERSE[ip]), sims=100)
    en = [t for _, t in husmo.narrate(inv, "en")]
    es = [t for _, t in husmo.narrate(inv, "es")]
    assert not any("their own server" in t for t in en)             # it is a sinkhole now, not their server
    assert "The only attributed domain is the seed, and it already points at a sinkhole." in en
    assert "El único dominio atribuido es la semilla, y ya apunta a un sumidero." in es
