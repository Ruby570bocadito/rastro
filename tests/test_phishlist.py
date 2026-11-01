"""`rastro list update` against a scripted GitHub: made-up lists, no network."""

import email.message
import io
import urllib.error

import pytest

from rastro.__main__ import main
from rastro.sources import phishlist

LIST = "\n".join(["# made up"] + [f"paqexpres-envio-{n}.test" for n in range(1200)]).encode()
ETAG = '"abc123"'


def http_error(code, retry_after=None):
    headers = email.message.Message()
    if retry_after:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError(phishlist.URL, code, "error", headers, None)


class GitHub:
    """Plays its answers in order: bytes are a 200 with the ETag, exceptions are raised."""

    def __init__(self, *answers):
        self.answers, self.requests, self.sleeps = list(answers), [], []

    def urlopen(self, req, timeout):
        self.requests.append(dict(req.header_items()))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        resp = io.BytesIO(answer)
        resp.headers = email.message.Message()
        resp.headers["ETag"] = ETAG
        resp.__enter__ = lambda: resp
        return _Context(resp)


class _Context:
    def __init__(self, resp):
        self.resp = resp

    def __enter__(self):
        return self.resp

    def __exit__(self, *exc):
        return False


@pytest.fixture
def github(monkeypatch):
    def install(*answers):
        g = GitHub(*answers)
        monkeypatch.setattr(phishlist.urllib.request, "urlopen", g.urlopen)
        monkeypatch.setattr(phishlist.time, "sleep", g.sleeps.append)
        return g
    return install


def test_the_list_is_downloaded_then_only_asked_for_again_if_it_changed(github, tmp_path):
    path = tmp_path / "lists" / "phishing-domains-ACTIVE.txt"
    g = github(LIST, http_error(304))
    first = phishlist.update(path)
    assert first.changed and first.domains == 1200 and path.read_bytes() == LIST
    assert (tmp_path / "lists" / "phishing-domains-ACTIVE.txt.etag").read_text(encoding="utf-8") == ETAG
    again = phishlist.update(path)
    assert not again.changed and again.domains == 1200
    assert g.requests[1].get("If-none-match") == ETAG and "If-none-match" not in g.requests[0]


def test_an_error_page_never_replaces_a_good_list(github, tmp_path):
    path = tmp_path / "phishing-domains-ACTIVE.txt"
    path.write_bytes(LIST)
    github(b"<html><body>Rate limit exceeded</body></html>")
    with pytest.raises(ValueError, match="not a list of domains"):
        phishlist.update(path)
    assert path.read_bytes() == LIST and list(tmp_path.iterdir()) == [path]


def test_a_missing_list_is_not_asked_for_again_and_a_busy_server_is(github, tmp_path):
    g = github(http_error(404))
    with pytest.raises(RuntimeError, match="did not give the list"):
        phishlist.update(tmp_path / "l.txt")
    assert len(g.requests) == 1 and g.sleeps == []
    g = github(http_error(503, "12"), LIST)
    assert phishlist.update(tmp_path / "l.txt").changed and g.sleeps == [12.0]


def test_list_update_command_and_the_hint_when_there_is_no_list(github, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    args = ["investigate", "hxxps://paqexpres-envio-4821[.]test/x", "--offline", "--no-crtsh", "--no-rdap",
            "--no-dns", "--sims", "100", "--report", "case.html"]
    assert main(args) == 0
    assert "No phishing list" in capsys.readouterr().out
    github(LIST)
    assert main(["list", "update"]) == 0
    assert "Downloaded 1,200 domains" in capsys.readouterr().out
    assert main(args) == 0
    out = capsys.readouterr().out
    assert "No phishing list" not in out
