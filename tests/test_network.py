"""The network clients against scripted servers: what they retry, what they give up on, and what they cache.
No real network: every answer below is made up."""

import email.message
import io
import json
import os
import time
import urllib.error
from datetime import UTC, datetime

import pytest

from rastro import sources
from rastro.sources import crtsh, ctlog, dns, rdap


class Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = email.message.Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("https://server.example/", code, "error", headers, None)


class Server:
    """Plays its answers in order, one per request: bytes are a 200 answer, exceptions are raised."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.urls: list[str] = []
        self.sleeps: list[float] = []

    def urlopen(self, req, timeout):
        self.urls.append(req.full_url)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return Answer(answer)


@pytest.fixture
def server(monkeypatch):
    def install(*answers):
        s = Server(*answers)
        for module in (crtsh, ctlog, dns, rdap):
            monkeypatch.setattr(module.urllib.request, "urlopen", s.urlopen)
            monkeypatch.setattr(module.time, "sleep", s.sleeps.append)
        return s
    return install


def test_only_busy_or_failing_servers_are_asked_again():
    assert sources.retryable(OSError("connection reset"))
    assert sources.retryable(http_error(429)) and sources.retryable(http_error(503))
    assert not sources.retryable(http_error(404)) and not sources.retryable(http_error(400))


def test_retry_after_is_honoured_within_limits():
    assert sources.wait(http_error(429, "30"), 2) == 30
    assert sources.wait(http_error(429, "1"), 5) == 5                  # never sooner than our own backoff
    assert sources.wait(http_error(429, "86400"), 2) == sources.MAX_WAIT
    assert sources.wait(http_error(503, "Wed, 21 Oct 2026 07:28:00 GMT"), 4) == 4
    assert sources.wait(OSError(), 8) == 8


def test_crtsh_retries_a_502_and_caches_the_answer(server, tmp_path):
    rows = [{"id": 1, "name_value": "a.top", "not_before": "2026-10-30T10:00:00"}]
    s = server(http_error(502), json.dumps(rows).encode())
    assert crtsh.fetch("a.top", tmp_path) == rows
    assert len(s.urls) == 2 and s.sleeps == [5.0]
    assert crtsh.fetch("a.top", tmp_path) == rows                     # from the cache, no third request
    assert len(s.urls) == 2


def test_crtsh_gives_up_at_once_on_a_bad_request(server, tmp_path):
    s = server(http_error(400))
    with pytest.raises(RuntimeError, match="crt.sh did not answer"):
        crtsh.fetch("a.top", tmp_path)
    assert len(s.urls) == 1 and s.sleeps == []


def test_crtsh_log_time_is_fetched_once_and_a_missing_page_is_not_retried(server, tmp_path):
    page = (b"<TH>Timestamp</TH><TH>Entry&nbsp;#</TH><TR><TD>2025-11-05&nbsp;07:26:02&nbsp;UTC</TD>"
            b"<TD>710968200</TD></TR>")
    s = server(page, http_error(404))
    when = datetime(2025, 11, 5, 7, 26, 2, tzinfo=UTC)
    assert crtsh.log_time(42, tmp_path) == when
    assert crtsh.log_time(42, tmp_path) == when                       # cached page
    assert crtsh.log_time(43, tmp_path) is None
    assert len(s.urls) == 2 and s.sleeps == []


def test_crtsh_profile_offline_never_asks(server, tmp_path):
    s = server()
    assert crtsh.profile("a.top", tmp_path, offline=True) == (None, frozenset())
    assert s.urls == []


def dns_answer(status=0, *records):
    return json.dumps({"Status": status, "Answer": [{"type": t, "data": d} for t, d in records]}).encode()


def test_dns_answers_are_cached_for_a_day(server, tmp_path):
    s = server(dns_answer(0, (1, "203.0.113.7")), dns_answer(0, (1, "203.0.113.8")))
    assert dns.addresses("a.top", tmp_path) == {"203.0.113.7"}
    assert dns.addresses("a.top", tmp_path) == {"203.0.113.7"}        # fresh cache
    assert len(s.urls) == 1
    path = tmp_path / "dns_A_a.top.json"
    old = time.time() - 25 * 3600
    os.utime(path, (old, old))
    assert dns.addresses("a.top", tmp_path) == {"203.0.113.8"}        # a day later it asks again
    assert len(s.urls) == 2


def test_dns_keeps_a_stale_answer_when_the_resolver_fails(server, tmp_path):
    s = server(dns_answer(0, (1, "203.0.113.7")), OSError(), OSError(), OSError())
    dns.addresses("a.top", tmp_path)
    old = time.time() - 25 * 3600
    os.utime(tmp_path / "dns_A_a.top.json", (old, old))
    assert dns.addresses("a.top", tmp_path) == {"203.0.113.7"}
    assert len(s.urls) == 4


def test_dns_verdicts_and_name_servers(server, tmp_path):
    server(dns_answer(3), dns_answer(0, (2, "ns1.evil-ns.ru."), (2, "ns2.evil-ns.ru.")), http_error(400))
    assert dns.resolve("gone.top", tmp_path, fresh=True) == ("nxdomain", frozenset())
    assert dns.nameservers("a.top", tmp_path) == {"evil-ns.ru"}
    assert dns.resolve("b.top", tmp_path, fresh=True) == (None, frozenset())   # a 400 is not asked again


def test_ctlog_gives_up_on_a_missing_tile_and_waits_when_rate_limited(server):
    s = server(http_error(404))
    with pytest.raises(RuntimeError, match="did not answer"):
        ctlog._get("https://log.example/tile/data/000")
    assert len(s.urls) == 1
    s = server(http_error(429, "20"), b"log.example/2027h1\n4242\nhash\n")
    assert ctlog.tree_size("https://log.example") == 4242
    assert s.sleeps == [20.0]


def test_ctlog_lists_only_usable_logs_for_the_date(monkeypatch):
    lists = {"operators": [{"tiled_logs": [
        {"description": "now", "monitoring_url": "https://now.example/", "state": {"usable": {}},
         "temporal_interval": {"start_inclusive": "2026-01-01T00:00:00Z", "end_exclusive": "2099-01-01T00:00:00Z"}},
        {"description": "retired", "monitoring_url": "https://old.example/", "state": {"retired": {}},
         "temporal_interval": {"start_inclusive": "2026-01-01T00:00:00Z", "end_exclusive": "2099-01-01T00:00:00Z"}},
        {"description": "past", "monitoring_url": "https://past.example/", "state": {"usable": {}},
         "temporal_interval": {"start_inclusive": "2020-01-01T00:00:00Z", "end_exclusive": "2021-01-01T00:00:00Z"}},
    ]}]}
    monkeypatch.setattr(ctlog, "_get", lambda url: json.dumps(lists).encode())
    assert ctlog.tiled_logs() == [("now", "https://now.example")]


def test_rdap_checks_ask_the_right_registry_and_cache_what_it_says(server, tmp_path):
    boot = {"services": [[["top"], ["https://rdap.example/"]]]}
    (tmp_path / "iana-dns.json").write_text(json.dumps(boot), encoding="utf-8")
    rdap._SERVERS.clear()
    reg = {"ldhName": "a.top", "events": [{"eventAction": "registration", "eventDate": "2026-10-29T14:03:12Z"}]}
    s = server(http_error(429, "10"), json.dumps(reg).encode(), http_error(404))
    outcome, found = rdap.check("a.top", tmp_path)
    assert outcome == "found" and found.registered == datetime(2026, 10, 29, 14, 3, 12, tzinfo=UTC)
    assert s.urls[0] == "https://rdap.example/domain/a.top" and s.sleeps[0] == 10
    assert rdap.check("a.top", tmp_path)[0] == "found"                # cached
    assert rdap.check("b.top", tmp_path) == ("not-found", None)
    assert rdap.check("a.zz", tmp_path) == ("no-server", None)
    assert len(s.urls) == 3
    rdap._SERVERS.clear()
