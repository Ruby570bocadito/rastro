"""Domain name helpers shared by every source."""

from __future__ import annotations

# Public suffixes with two labels that show up in this kind of data; enough for a first pass.
TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "com.es", "org.es", "gob.es", "com.mx", "gob.mx", "com.ar", "gob.ar", "com.br",
    "gov.br", "com.co", "gov.co", "com.pe", "gob.pe", "go.cr", "com.ve", "gob.ve", "com.ec", "gob.ec",
    "com.uy", "com.py", "com.bo", "com.gt", "com.do", "com.pa", "com.sv", "com.hn", "com.ni", "co.cr",
    "com.au", "co.nz", "co.jp", "co.in", "com.cn", "com.tr", "co.za",
}
# Second-level labels that country registries keep for the public (co.id, com.my, ac.th...). Without
# them, every name under such a suffix would look like one domain.
GENERIC_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "gob", "mil", "nom", "or", "ne", "go",
                        "sch", "ltd", "plc"}


def registrable(name: str) -> str:
    """Registrable domain of a host name (approximate public-suffix handling)."""
    parts = name.strip(".").lower().split(".")
    if len(parts) >= 3 and (".".join(parts[-2:]) in TWO_LABEL_SUFFIXES
                            or (len(parts[-1]) == 2 and parts[-2] in GENERIC_SECOND_LEVEL)):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
