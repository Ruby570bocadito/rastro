from datetime import UTC, datetime

from rastro.sources import rdap


def vcard(**fields):
    return ["vcard", [["version", {}, "text", "4.0"]] + [[k, {}, "text", v] for k, v in fields.items()]]


PAYLOAD = {
    "objectClassName": "domain",
    "ldhName": "paqexpres-entrega-4821.top",
    "status": ["client transfer prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "2026-10-29T14:03:12Z"},
               {"eventAction": "expiration", "eventDate": "2027-10-29T14:03:12Z"}],
    "entities": [
        {"roles": ["registrant"], "vcardArray": vcard(fn="A Private Person", email="person@example.com")},
        {"roles": ["registrar"], "vcardArray": vcard(fn="Example Registrar, Inc."),
         "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
         "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"],
                                                                     ["tel", {}, "uri", "tel:+1.5550100"]]]}]},
    ],
}


def test_parse_keeps_the_registrar_and_its_abuse_desk_and_never_people():
    r = rdap.parse(PAYLOAD, "paqexpres-entrega-4821.top", "https://rdap.example/")
    assert r.registered == datetime(2026, 10, 29, 14, 3, 12, tzinfo=UTC)
    assert (r.registrar, r.registrar_id) == ("Example Registrar, Inc.", "9999")
    assert (r.abuse_email, r.abuse_phone) == ("abuse@registrar.example", "+1.5550100")
    assert "Private Person" not in repr(r) and "person@example.com" not in repr(r)


def test_a_bare_date_says_nothing_about_the_hour():
    payload = dict(PAYLOAD, events=[{"eventAction": "registration", "eventDate": "2026-10-29T00:00:00Z"}])
    assert rdap.parse(payload, "x.top", "").registered is None


def test_servers_prefer_https():
    boot = {"services": [[["top", "xyz"], ["http://rdap.example/", "https://rdap.example/"]], [["com"], [
        "https://rdap.verisign.com/com/v1"]]]}
    assert rdap.servers(boot) == {"top": "https://rdap.example/", "xyz": "https://rdap.example/",
                                  "com": "https://rdap.verisign.com/com/v1/"}
