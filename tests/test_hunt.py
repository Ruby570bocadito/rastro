import csv
import io
import json
import re

from rastro import hunt
from rastro.__main__ import main

SEED = "applesupport-login-4821.test"


def row(name, **more):
    base = {"id": name, "seed": False, "campaign": False, "crew": False, "attributed": False, "alive": False,
            "first": "2026-10-01T08:00:00Z", "registered": None, "registrar": "Example Registrar, Inc.",
            "sources": ["list"], "score": None, "status": None, "ips": []}
    return {**base, **more}


def case():
    return {
        "seed": SEED, "brand_name": "Apple", "generated": "2026-10-30T09:30:00Z", "version": "0.0.0",
        "patterns": [{"regex": r"(?=.*apple)[a-z]{5,12}-login-\d{4}\.test", "breadth": 8.1, "kind": "crew",
                      "support": 5}],
        "domains": [
            row(SEED, seed=True, campaign=True, crew=True, attributed=True, alive=True, ips=["203.0.113.7"]),
            row("applesupport-login-5510.test", campaign=True, crew=True, attributed=True, alive=True),
            row("myappleid-login-0042.test", crew=True, attributed=True, status="unregistered"),
            row("appleverify-login-7777.test", crew=True, attributed=True, alive=True, status="reregistered"),
            row("applecare-login-1234.test", crew=True, attributed=True, alive=True, status="defensive"),
            row("pineapple-farm.test", alive=True),                                  # a lookalike nobody attributed
            row('bad"; drop-login-0001.test', crew=True, attributed=True, alive=True),   # not a host name
        ],
    }


def test_indicators_keep_only_what_is_still_the_crews():
    found = hunt.indicators(case())
    assert [(i.value, i.kind, i.role) for i in found] == [
        (SEED, "domain", "seed"), ("203.0.113.7", "ip", "seed"),
        ("applesupport-login-5510.test", "domain", "campaign"), ("myappleid-login-0042.test", "domain", "crew")]
    assert found[0].confidence > found[3].confidence > found[1].confidence      # clues, template alone, an address
    assert not found[1].detect and found[1].of == SEED


def test_a_pattern_becomes_a_search_other_tools_can_run():
    (s,) = hunt.searches(case())
    assert "(?=" not in s.regex and s.contains == ("apple",)        # RE2 has no look-ahead: the core goes aside
    hit = re.compile(s.regex)
    assert hit.search("applesupport-login-9999.test") and hit.search("www.applesupport-login-9999.test")
    assert not hit.search("applesupport-login-9999.test.example") and not hit.search("xapplesupport-login-99.test")
    guess = {**case(), "patterns": [{"regex": r"only-a-guess-\d{4}\.test", "breadth": 4.0, "kind": "guess",
                                     "support": 1}]}
    assert [s.kind for s in hunt.searches(guess)] == ["guess"]      # used only when nothing better was learned
    both = {**case(), "patterns": case()["patterns"] + guess["patterns"]}
    assert [s.kind for s in hunt.searches(both)] == ["crew"]


def test_the_blocklist_holds_live_domains_only():
    lines = hunt.blocklist(case()).splitlines()
    assert [n for n in lines if not n.startswith("#")] == [SEED, "applesupport-login-5510.test"]
    assert all("203.0.113.7" not in n for n in lines)


def test_csv_says_what_is_for_detection():
    rows = list(csv.DictReader(io.StringIO(hunt.csv_text(case()))))
    assert [r["indicator"] for r in rows if r["for_detection"] == "yes"] == [
        SEED, "applesupport-login-5510.test", "myappleid-login-0042.test"]
    assert next(r for r in rows if r["type"] == "ip")["address_of"] == SEED


def test_stix_is_a_bundle_with_stable_ids_and_a_report_over_everything():
    bundle = json.loads(hunt.stix(case()))
    assert bundle["type"] == "bundle" and json.loads(hunt.stix(case())) == bundle        # the same every time
    objects = bundle["objects"]
    ids = [o["id"] for o in objects]
    assert len(ids) == len(set(ids)) and all(o["spec_version"] == "2.1" for o in objects)
    report = objects[-1]
    assert report["type"] == "report" and report["object_refs"] == ids[:-1]
    by_name = {o["name"]: o for o in objects}
    assert by_name[SEED]["pattern"] == f"[domain-name:value = '{SEED}']"
    assert by_name["203.0.113.7"]["pattern"] == "[ipv4-addr:value = '203.0.113.7']"
    assert by_name["203.0.113.7"]["indicator_types"] == ["anomalous-activity"]
    learned = next(o for o in objects if o["name"].startswith("Naming pattern"))
    assert r"MATCHES '^(?=.*apple)[a-z]{5,12}-login-\\d{4}\\.test$'" in learned["pattern"]   # backslashes doubled


def test_misp_marks_addresses_and_dead_domains_as_not_for_detection():
    attributes = json.loads(hunt.misp(case()))["Event"]["Attribute"]
    flags = {a["value"]: (a["type"], a["to_ids"]) for a in attributes}
    assert flags[SEED] == ("domain", True)
    assert flags["203.0.113.7"] == ("ip-dst", False)
    assert flags["myappleid-login-0042.test"] == ("domain", False)


def test_the_searches_name_the_domains_and_the_pattern_and_never_an_address():
    for fmt in ("sigma", "kql", "spl"):
        text = hunt.build(case(), fmt, days=7)
        assert SEED in text and "myappleid-login-0042.test" in text          # a dead domain is still worth hunting
        assert r"[a-z]{5,12}-login-\d{4}\.test$" in text and "apple" in text
        assert "203.0.113.7" not in text and "drop" not in text and "applecare" not in text
    assert "query|re: '(^|\\.)[a-z]{5,12}-login-\\d{4}\\.test$'" in hunt.sigma(case())
    assert "query|contains: 'apple'" in hunt.sigma(case())
    assert "ago(7d)" in hunt.kql(case(), 7) and "earliest=-7d" in hunt.spl(case(), 7)


def test_hunt_command_writes_the_pack_from_the_demo(tmp_path, capsys):
    data = tmp_path / "case.json"
    assert main(["demo", "--sims", "100", "--report", str(tmp_path / "demo.html"), "--json", str(data)]) == 0
    assert main(["hunt", str(data), "--out", str(tmp_path / "pack")]) == 0
    assert sorted(p.name for p in (tmp_path / "pack").iterdir()) == sorted(hunt.FORMATS.values())
    assert "HUNT PACK" in capsys.readouterr().out
    assert main(["hunt", str(data), "--format", "blocklist"]) == 0
    assert ".test\n" in capsys.readouterr().out
    json.loads((tmp_path / "pack" / "stix.json").read_text(encoding="utf-8"))


def test_hunt_command_refuses_what_is_not_a_case(tmp_path, capsys):
    other = tmp_path / "other.json"
    other.write_text('{"hello": 1}', encoding="utf-8")
    assert main(["hunt", str(other)]) == 2
    assert "not case data" in capsys.readouterr().out


def test_an_address_shared_by_several_domains_is_exported_once():
    shared = case()
    shared["domains"][1]["ips"] = ["203.0.113.7"]                 # the campaign domain sits on the seed's address
    objects = json.loads(hunt.stix(shared))["objects"]
    ids = [o["id"] for o in objects]
    assert len(ids) == len(set(ids))                               # a duplicate id makes the bundle ambiguous
    (address,) = [o for o in objects if o["name"] == "203.0.113.7"]
    assert SEED in address["description"] and "applesupport-login-5510.test" in address["description"]
    values = [a["value"] for a in json.loads(hunt.misp(shared))["Event"]["Attribute"]]
    assert values.count("203.0.113.7") == 1
    assert hunt.csv_text(shared).count("203.0.113.7,ip") == 2      # the table keeps one row per domain it answers for


def test_a_tampered_case_cannot_write_into_the_searches(tmp_path, capsys):
    bad = case()
    bad["seed"] = "x.test\n| project secret"
    bad["brand_name"] = "A```B\r\nDeviceEvents | take 1"
    bad["patterns"].append({"regex": "a\"; DROP|x') or true //", "breadth": 1.0, "kind": "crew", "support": 2})
    bad["patterns"].append({"regex": r"(?<=x)evil-\d{2}\.test", "breadth": 1.0, "kind": "crew", "support": 2})
    bad["domains"][0]["ips"] = ['1.2.3.4"); evil', "203.0.113.7"]
    bad["domains"][1]["registrar"] = "=HYPERLINK(1)"
    assert hunt.dropped(bad) == {"domains": 1, "addresses": 1, "patterns": 2}
    for fmt in ("sigma", "kql", "spl"):
        text = hunt.build(bad, fmt)
        assert "DROP" not in text and "evil" not in text and "```B" not in text
        lines = text.splitlines()
        assert not any(n.startswith("| project secret") or n.startswith("DeviceEvents | take") for n in lines)
    assert "(?<=" not in hunt.kql(bad)                       # a look-behind is not something Rastro writes
    assert "'=HYPERLINK(1)" in hunt.csv_text(bad)            # a spreadsheet will not run it
    json.loads(hunt.stix(bad)), json.loads(hunt.misp(bad))
    data = tmp_path / "bad.json"
    data.write_text(json.dumps(bad), encoding="utf-8")
    assert main(["hunt", str(data), "--out", str(tmp_path / "pack")]) == 0
    assert "Left out" in capsys.readouterr().out


def test_a_guess_or_no_pattern_still_gives_a_search_for_the_known_domains():
    alone = {**case(), "patterns": []}
    for fmt in ("sigma", "kql", "spl"):
        assert SEED in hunt.build(alone, fmt)
    assert "pattern_1" not in hunt.sigma(alone) and "condition: known or under_known" in hunt.sigma(alone)
