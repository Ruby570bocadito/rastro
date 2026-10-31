from datetime import UTC, datetime

from rastro.sources import crtsh

LE = "C=US, O=Let's Encrypt, CN=R11"


def utc(*args):
    return datetime(*args, tzinfo=UTC)


ROWS = [
    # logged first certificate, plus an automatic renewal months later
    {"id": 1, "entry_timestamp": "2026-10-01T08:15:00.123", "not_before": "2026-10-01T07:15:00",
     "name_value": "paqexpres-envio-1234.top\n*.paqexpres-envio-1234.top", "issuer_name": LE},
    {"id": 2, "not_before": "2026-12-30T02:00:00", "name_value": "paqexpres-envio-1234.top", "issuer_name": LE},
    # wildcard-search rows carry no log time: Let's Encrypt notBefore is backdated one hour
    {"id": 3, "not_before": "2026-10-02T10:40:00",
     "name_value": "www.shop.example.co.uk\nadmin@example.org\nShop Example Ltd", "issuer_name": LE},
    # a CA that rounds notBefore to midnight gives no usable hour
    {"id": 4, "not_before": "2026-10-03T00:00:00", "name_value": "paqexpres-pago-7710.xyz",
     "issuer_name": "C=GB, O=Sectigo Limited, CN=X"},
    # ... and its first timed certificate a month later is probably a renewal
    {"id": 5, "not_before": "2026-11-03T09:00:00", "name_value": "paqexpres-pago-7710.xyz", "issuer_name": LE},
]


def test_parse_keeps_hostnames_only():
    entries = crtsh.parse(ROWS)
    assert entries[0].names == ("paqexpres-envio-1234.top",)
    assert entries[2].names == ("www.shop.example.co.uk",)


def test_issuance_time_comes_from_log_or_lets_encrypt_backdate():
    entries = {e.cert_id: e for e in crtsh.parse(ROWS)}
    assert entries[1].issued_at == utc(2026, 10, 1, 8, 15, 0, 123000)
    assert entries[3].issued_at == utc(2026, 10, 2, 11, 40)
    assert entries[4].issued_at is None


def test_registrable_handles_two_label_suffixes():
    assert crtsh.registrable("www.shop.example.co.uk") == "example.co.uk"
    assert crtsh.registrable("a.b.paqexpres-pago-1.xyz") == "paqexpres-pago-1.xyz"


def test_log_time_reads_the_earliest_log_timestamp(tmp_path):
    page = ("<TH>Timestamp</TH><TH>Entry&nbsp;#</TH><TH>Log Operator</TH>"
            "<TR><TD>2025-11-05&nbsp;07:26:24&nbsp;UTC</TD><TD>233001570</TD></TR>"
            "<TR><TD>2025-11-05&nbsp;07:26:02&nbsp;UTC</TD><TD>710968200</TD></TR>"
            "<TH>Revocation</TH><TD>2026-01-01&nbsp;00:00:00&nbsp;UTC</TD>")
    crtsh.cert_page_path(42, tmp_path).write_text(page, encoding="utf-8")
    assert crtsh.log_time(42, tmp_path) == utc(2025, 11, 5, 7, 26, 2)


def test_first_cert_finds_the_earliest_certificate_of_any_ca():
    first = crtsh.first_cert(crtsh.parse(ROWS), "paqexpres-pago-7710.xyz")
    assert first.cert_id == 4


def test_first_seen_ignores_renewals_and_late_timed_certificates():
    seen = crtsh.first_seen(crtsh.parse(ROWS), keep=lambda d: d.startswith("paqexpres"))
    assert seen == {"paqexpres-envio-1234.top": utc(2026, 10, 1, 8, 15, 0, 123000)}
