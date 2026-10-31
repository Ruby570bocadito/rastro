import ipaddress
import socket

from rastro import brands, demo
from rastro.__main__ import main

DOCUMENTATION = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_the_demo_world_uses_only_reserved_names_and_addresses():
    made = demo.world()
    assert all(m.name.endswith(".test") for m in made.values())
    assert all(ns.endswith(".test") for m in made.values() for ns in m.nameservers)
    assert all(any(ipaddress.ip_address(ip) in net for net in DOCUMENTATION) for m in made.values() for ip in m.ips)
    assert all(m.registration.abuse_email.endswith(".example") for m in made.values() if m.registration)
    assert all(d.endswith(".test") for d in demo.public_list(made))


def test_the_demo_runs_offline_and_finds_what_was_hidden(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("the demo must not touch the network")

    monkeypatch.setattr(socket, "socket", no_network)
    with brands.extra(demo.BRANDS):
        inv = demo.investigation(sims=500)
        assert brands.display(inv.brand) == "PaqExpres"
    assert brands.brand_of(demo.SEED) is None                 # the made-up brands are gone afterwards
    assert inv.crew_pattern.regex == r"paqexpres-(aduana|entrega|envio|pago)-\d{4}\.test"
    assert demo.PARTNER in inv.campaign                         # the bank on the seed's certificate
    assert inv.rhythm_found and demo.OFFSET in inv.clues.band
    assert inv.clues.weekend == demo.TRUTH["weekend"]
    assert {r.email for r in inv.reports} == {"abuse@registrar.example", "abuse@names.example"}
    assert set(inv.left_out.values()) == {"unregistered", "suspended", "reregistered"}


def test_demo_command_writes_a_labelled_case_file(tmp_path, capsys):
    out = tmp_path / "demo.html"
    assert main(["demo", "--lang", "es", "--report", str(out), "--sims", "500"]) == 0
    assert "que imita a PaqExpres" in capsys.readouterr().out
    page = out.read_text(encoding="utf-8")
    assert '"demo":{"offset":3,"weekend":"sat-sun"}' in page and '"brand_name":"PaqExpres"' in page
