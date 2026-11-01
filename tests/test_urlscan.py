"""The urlscan client against a scripted urlscan: made-up scans, no network, no real key."""

import io
import json
import urllib.error
import urllib.parse

import pytest

from rastro.sources import urlscan

KIT = "a" * 64          # a file only the campaign's pages load
JQUERY = "b" * 64       # a library half the web loads


def scan(domain, uuid, when="2026-10-30T10:00:00.000Z"):
    return {"_id": uuid, "task": {"uuid": uuid, "time": when, "domain": domain}, "page": {"domain": domain}}


class Urlscan:
    """Answers searches and results from tables, and records every request and the key it carried."""

    def __init__(self):
        self.searches = {
            "page.domain:paqexpres-entrega-4821.top": [scan("paqexpres-entrega-4821.top", "old-1",
                                                             "2026-10-01T10:00:00.000Z"),
                                                        scan("paqexpres-entrega-4821.top", "new-2")],
            f"hash:{KIT}": [scan("paqexpres-entrega-4821.top", "new-2"), scan("www.envios-rapidos.icu", "s-3"),
                            scan("seguimiento-paq.top", "s-4"), scan("seguimiento-paq.top", "s-5")],
        }
        self.totals = {f"hash:{KIT}": 4, f"hash:{JQUERY}": 90000}
        self.results = {"new-2": {"lists": {"hashes": [JQUERY, KIT, KIT, "not-a-hash"]}}}
        self.urls, self.keys = [], []

    def urlopen(self, req, timeout):
        class Answer(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        self.urls.append(req.full_url)
        self.keys.append(req.get_header("Api-key"))
        url = urllib.parse.urlsplit(req.full_url)
        if url.path.startswith("/api/v1/search/"):
            q = urllib.parse.parse_qs(url.query)["q"][0]
            body = {"results": self.searches.get(q, []), "total": self.totals.get(q, len(self.searches.get(q, [])))}
        else:
            uuid = url.path.rstrip("/").rsplit("/", 1)[-1]
            if uuid not in self.results:
                raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, None)
            body = self.results[uuid]
        return Answer(json.dumps(body).encode())


@pytest.fixture
def fake(monkeypatch):
    u = Urlscan()
    monkeypatch.setattr(urlscan.urllib.request, "urlopen", u.urlopen)
    monkeypatch.setattr(urlscan.time, "sleep", lambda s: None)
    return u


def test_a_key_is_required_and_comes_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.delenv(urlscan.KEY_VARIABLE, raising=False)
    with pytest.raises(urlscan.NoKey):
        urlscan.Client(tmp_path)
    monkeypatch.setenv(urlscan.KEY_VARIABLE, "test-key")
    assert urlscan.Client(tmp_path).key == "test-key"


def test_one_scan_expands_to_the_sites_that_loaded_the_same_kit(fake, tmp_path):
    client = urlscan.Client(tmp_path, key="test-key")
    e = urlscan.expand(client, "paqexpres-entrega-4821.top")
    assert e.scan == "new-2"                                         # the newest scan of the seed
    assert e.hashes == 3 and e.common == 1                           # jQuery is left out
    assert e.siblings == {"envios-rapidos.icu": {KIT}, "seguimiento-paq.top": {KIT}}
    assert e.requests == 4 and set(fake.keys) == {"test-key"}
    assert not any("/scan/" in u for u in fake.urls)                 # nothing is ever submitted


def test_answers_are_cached_without_the_key(fake, tmp_path):
    client = urlscan.Client(tmp_path, key="test-key")
    urlscan.expand(client, "paqexpres-entrega-4821.top")
    again = urlscan.expand(urlscan.Client(tmp_path, key="test-key"), "paqexpres-entrega-4821.top")
    assert again.requests == 0 and len(again.siblings) == 2
    assert not any("test-key" in p.read_text(encoding="utf-8") for p in tmp_path.iterdir())


def test_a_domain_urlscan_never_saw_expands_to_nothing(fake, tmp_path):
    e = urlscan.expand(urlscan.Client(tmp_path, key="test-key"), "nunca-visto.top")
    assert e.scan is None and e.siblings == {} and e.requests == 1


def test_a_refused_key_stops_at_once(monkeypatch, tmp_path):
    calls = []

    def urlopen(req, timeout):
        calls.append(req.full_url)
        raise urllib.error.HTTPError(req.full_url, 401, "unauthorized", {}, None)

    monkeypatch.setattr(urlscan.urllib.request, "urlopen", urlopen)
    with pytest.raises(RuntimeError, match="HTTP 401"):
        urlscan.Client(tmp_path, key="wrong").search("page.domain:x.top")
    assert len(calls) == 1


def test_scan_ids_cannot_leave_the_result_path(tmp_path):
    with pytest.raises(ValueError):
        urlscan.Client(tmp_path, key="k").result("../../search/?q=x")


def test_the_richest_live_scan_is_chosen_over_the_newest_dead_one():
    def hit(uuid, when, status, requests):
        return {"_id": uuid, "task": {"time": when}, "page": {"domain": "x.top", "status": status},
                "stats": {"requests": requests}}
    payload = {"results": [hit("dead", "2026-10-30", "451", 2), hit("live", "2026-09-01", "200", 115),
                           hit("thin", "2026-09-05", "200", 3), {"_id": "other", "page": {"domain": "y.top"}}]}
    assert urlscan.live_first(payload, "x.top") == ["live", "thin", "dead"]
