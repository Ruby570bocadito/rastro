"""Just enough DER to read the names out of a certificate, with no dependencies."""

from __future__ import annotations

from collections.abc import Iterator

OID = 0x06
EXPLICIT_VERSION = 0xA0
EXPLICIT_EXTENSIONS = 0xA3
DNS_NAME = 0x82

SAN = bytes.fromhex("551d11")       # 2.5.29.17 subjectAltName
COMMON_NAME = bytes.fromhex("550403")
ORGANIZATION = bytes.fromhex("55040a")


def tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    """Tag, start and end of the value of the element at `pos`."""
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if pos + length > len(buf):
        raise ValueError("truncated DER element")
    return tag, pos, pos + length


def children(buf: bytes, start: int, end: int) -> Iterator[tuple[int, int, int]]:
    pos = start
    while pos < end:
        tag, value_start, value_end = tlv(buf, pos)
        yield tag, value_start, value_end
        pos = value_end


def _attributes(buf: bytes, start: int, end: int) -> dict[bytes, str]:
    """A Name as {attribute OID: value}, first value wins."""
    out: dict[bytes, str] = {}
    for _, rdn_start, rdn_end in children(buf, start, end):
        for _, atv_start, atv_end in children(buf, rdn_start, rdn_end):
            parts = list(children(buf, atv_start, atv_end))
            if len(parts) >= 2 and parts[0][0] == OID:
                key = bytes(buf[parts[0][1]:parts[0][2]])
                out.setdefault(key, bytes(buf[parts[1][1]:parts[1][2]]).decode("utf-8", "replace"))
    return out


def tbs_fields(tbs: bytes) -> tuple[list[str], str]:
    """DNS names (subjectAltName, else the subject's common name) and the issuer's organisation."""
    _, start, end = tlv(tbs, 0)
    fields = list(children(tbs, start, end))
    i = 1 if fields[0][0] == EXPLICIT_VERSION else 0
    issuer = _attributes(tbs, fields[i + 2][1], fields[i + 2][2])
    subject = _attributes(tbs, fields[i + 4][1], fields[i + 4][2])
    names: list[str] = []
    for tag, value_start, _ in fields[i + 6:]:
        if tag != EXPLICIT_EXTENSIONS:
            continue
        _, seq_start, seq_end = tlv(tbs, value_start)
        for _, ext_start, ext_end in children(tbs, seq_start, seq_end):
            parts = list(children(tbs, ext_start, ext_end))
            if parts and parts[0][0] == OID and bytes(tbs[parts[0][1]:parts[0][2]]) == SAN:
                _, octets_start, _ = parts[-1]
                _, gn_start, gn_end = tlv(tbs, octets_start)
                for gtag, n_start, n_end in children(tbs, gn_start, gn_end):
                    if gtag == DNS_NAME:
                        names.append(bytes(tbs[n_start:n_end]).decode("ascii", "replace").lower())
    if not names and COMMON_NAME in subject:
        names.append(subject[COMMON_NAME].lower())
    return names, issuer.get(ORGANIZATION, issuer.get(COMMON_NAME, ""))
