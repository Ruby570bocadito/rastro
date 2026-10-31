import base64
import hashlib
import json
import re
from datetime import UTC, datetime

from rastro import investigate, report
from rastro.__main__ import main
from rastro.sources.rdap import Registration

EVIL = "</script><script>alert(1)</script>&<b>"


def evil_sources():
    def lookup(d):
        return Registration(d, datetime(2026, 10, 29, 14, 3, tzinfo=UTC), None, EVIL, "1", "abuse@x.example", None,
                            (), "https://rdap.example/")

    return investigate.Sources(registration=lookup)


def test_attacker_controlled_text_cannot_escape_the_data_block():
    inv = investigate.investigate("paqexpres-entrega-4821.top", evil_sources(), sims=0)
    page = report.render(inv, "es")
    assert len(re.findall(r"<script", page)) == 3                  # the two data blocks and the page's own script
    assert EVIL not in page
    data = json.loads(re.search(r'<script type="application/json" id="case">(.*?)</script>', page, re.S).group(1))
    assert data["reports"][0]["registrar"] == EVIL
    assert data["lang"] == "es" and data["seed"] == "paqexpres-entrega-4821.top"


def test_the_page_may_run_only_its_own_script_and_reach_nothing():
    page = report.render(investigate.investigate("paqexpres-entrega-4821.top", investigate.Sources(), sims=0))
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
    assert "default-src 'none'" in csp and "connect-src" not in csp
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()
    assert f"'sha256-{digest}'" in csp


def test_investigate_command_writes_a_case_file_offline(tmp_path, capsys):
    empty = tmp_path / "list.txt"
    empty.write_text("", encoding="utf-8")
    out = tmp_path / "case.html"
    data = tmp_path / "case.json"
    assert main(["investigate", "hxxps://paqexpres-entrega-4821[.]top/s/7Hk2", "--offline", "--list", str(empty),
                 "--cache", str(tmp_path / "cache"), "--report", str(out), "--json", str(data), "--sims", "0"]) == 0
    text = capsys.readouterr().out
    assert "1. The link leads to paqexpres-entrega-4821.top." in text
    assert r"paqexpres-entrega-\d{4}\.top" in text
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "7Hk2" not in out.read_text(encoding="utf-8")            # the link's path never reaches the case file
    assert json.loads(data.read_text(encoding="utf-8"))["host"] == "paqexpres-entrega-4821.top"
