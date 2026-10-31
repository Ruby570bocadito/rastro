from datetime import UTC, datetime

from rastro import store
from rastro.sources import ctlog, der


def enc(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


def seq(*parts: bytes) -> bytes:
    return enc(0x30, b"".join(parts))


def oid(hexstr: str) -> bytes:
    return enc(0x06, bytes.fromhex(hexstr))


def name(*attrs: tuple[str, str]) -> bytes:
    return seq(*[enc(0x31, seq(oid(o), enc(0x0C, v.encode()))) for o, v in attrs])


def tbs(dns_names=(), cn=None, org="Let's Encrypt") -> bytes:
    exts = []
    if dns_names:
        exts.append(enc(0xA3, seq(seq(oid("551d11"), enc(0x04, seq(*[enc(0x82, n.encode()) for n in dns_names]))))))
    return seq(
        enc(0xA0, enc(0x02, b"\x02")),                       # version 3
        enc(0x02, b"\x01"),                                  # serial
        seq(oid("2a8648ce3d040302")),                        # signature algorithm
        name(("55040a", org), ("550403", "R11")),            # issuer
        seq(enc(0x17, b"261030000000Z"), enc(0x17, b"270128000000Z")),
        name(("550403", cn)) if cn else seq(),               # subject
        seq(seq(oid("2a8648ce3d0201")), enc(0x03, b"\x00\x04")),
        *exts,
    )


def test_der_reads_san_names_and_issuer():
    names, issuer = der.tbs_fields(tbs(["paqexpres-envio-1234.top", "*.paqexpres-envio-1234.top"]))
    assert names == ["paqexpres-envio-1234.top", "*.paqexpres-envio-1234.top"]
    assert issuer == "Let's Encrypt"


def test_der_falls_back_to_common_name():
    names, _ = der.tbs_fields(tbs(cn="Example.COM"))
    assert names == ["example.com"]


def test_tile_path_follows_the_static_ct_layout():
    assert ctlog.tile_path(1234067) == "tile/data/x001/x234/067"
    assert ctlog.tile_path(5) == "tile/data/005"
    assert ctlog.tile_path(5, width=17) == "tile/data/005.p/17"


def tile_leaf(stamp_ms: int, the_tbs: bytes, precert: bool) -> bytes:
    u = lambda v, size: v.to_bytes(size, "big")  # noqa: E731
    ext = b"\x00\x00\x00\x00\x2a"
    chain = b"\x11" * 32
    if precert:
        body = u(1, 2) + b"\x22" * 32 + u(len(the_tbs), 3) + the_tbs + u(len(ext), 2) + ext
        pre = seq(the_tbs, seq(oid("2a8648ce3d040302")), enc(0x03, b"\x00"))
        body += u(len(pre), 3) + pre
    else:
        cert = seq(the_tbs, seq(oid("2a8648ce3d040302")), enc(0x03, b"\x00"))
        body = u(0, 2) + u(len(cert), 3) + cert + u(len(ext), 2) + ext
    return u(stamp_ms, 8) + body + u(len(chain), 2) + chain


def test_parse_tile_reads_both_entry_types():
    data = tile_leaf(1793380000123, tbs(["a.example.com"]), precert=False) + \
        tile_leaf(1793380000456, tbs(["*.b.example.org", "b.example.org"]), precert=True)
    first, second = ctlog.parse_tile(data, first_index=512)
    assert (first.index, first.precert, first.names) == (512, False, ("a.example.com",))
    assert (second.index, second.precert, second.names) == (513, True, ("b.example.org",))
    assert first.logged_at == datetime.fromtimestamp(1793380000.123, UTC)


def test_store_keeps_each_entry_once(tmp_path):
    entries = ctlog.parse_tile(tile_leaf(1793380000123, tbs(["shop.paqexpres-pago-7710.xyz"]), False), 7)
    conn = store.connect(tmp_path / "ct.sqlite")
    assert store.save(conn, "test", entries) == 1
    assert store.save(conn, "test", entries) == 0
    assert conn.execute("SELECT registrable FROM names").fetchall() == [("paqexpres-pago-7710.xyz",)]
