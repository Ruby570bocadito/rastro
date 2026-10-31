"""A made-up case to try Rastro offline: `rastro demo`.

Everything in it is invented, so it is safe to show anywhere:

- the brands, PaqExpres (parcels) and BancoNorte (a bank), do not exist;
- every domain ends in .test, a top-level domain reserved for testing (RFC 6761) that nobody
  can register;
- server addresses come from the ranges reserved for documentation (RFC 5737), and
  registrars and abuse desks live under .example (RFC 2606).

The crew is simulated with the working-day model the map uses: it sits at UTC+3, works
Monday to Friday and puts its domains out in ten launches between January and October.
The investigation then runs exactly as on real data, through sources that answer from
this made-up world instead of the network.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from rastro import investigate, rhythm, store
from rastro.investigate import Investigation, Sources
from rastro.sources.ctlog import Entry
from rastro.sources.rdap import Registration

BRANDS = {"paqexpres": "PaqExpres", "banconorte": "BancoNorte"}
LINK = "hxxps://paqexpres-entrega-4821[.]test/s/7Hk2"
SEED = "paqexpres-entrega-4821.test"
PARTNER = "banconorte-acceso-4821.test"      # on the seed's certificate: the crew imitates a bank too
NOW = datetime(2026, 10, 30, 9, 30, tzinfo=UTC)
OFFSET = 3
TRUTH = {"offset": OFFSET, "weekend": "sat-sun"}     # what the case file may check its answer against
WORDS = ("entrega", "envio", "aduana", "pago")
REGISTRAR = ("Example Registrar, Inc.", "abuse@registrar.example", "+1.5550100")
OTHER_REGISTRAR = ("Sample Names Ltd.", "abuse@names.example", "+44.5550200")
PARKING = ("Parked Names LLC", "abuse@parked.example", None)
# first day (Monday to Thursday), working days, and how the launch stands today
LAUNCHES = [
    (date(2026, 1, 13), 2, "gone"), (date(2026, 2, 10), 2, "gone"), (date(2026, 3, 9), 3, "gone"),
    (date(2026, 4, 15), 3, "gone"), (date(2026, 5, 19), 2, "gone"), (date(2026, 6, 22), 3, "gone"),
    (date(2026, 7, 28), 2, "gone"), (date(2026, 8, 26), 3, "held"), (date(2026, 9, 22), 2, "live"),
    (date(2026, 10, 28), 2, "live"),
]
NOISE = ["paqexpres.test", "paqexpres-seguimiento.test", "banconorte-clientes.test", "envio-paquete-online.test",
         "tienda-ejemplo.test"]


@dataclass
class Made:
    name: str
    launch: int
    registered: datetime
    first_cert: datetime
    co_certified: frozenset[str] = frozenset()
    registration: Registration | None = None
    ips: frozenset[str] = frozenset()
    nameservers: frozenset[str] = frozenset()


def _registration(name: str, when: datetime, who: tuple, status=("client transfer prohibited",)) -> Registration:
    return Registration(name, when, when + timedelta(days=365), who[0], None, who[1], who[2], status,
                        "https://rdap.example/")


def world(seed: int = 3) -> dict[str, Made]:
    """The crew's domains, deterministic for a given seed."""
    rng = random.Random(seed)
    numbers = rng.sample([n for n in range(1000, 10000) if n != 4821], 200)
    out: dict[str, Made] = {}
    for k, (first_day, days, state) in enumerate(LAUNCHES):
        day, worked = first_day, 0
        while worked < days:
            if day.weekday() < 5:
                worked += 1
                sittings = ["seed", None, None] if (k, worked) == (9, 2) else [None] * rng.randint(2, 4)
                for sitting in sittings:
                    hour = 10 + 12 / 60 if sitting == "seed" else (
                        rng.choices(range(24), weights=rhythm.PROFILE)[0] + rng.random())
                    start = datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(hours=hour - OFFSET)
                    names = [SEED, PARTNER] if sitting == "seed" else [
                        f"paqexpres-{rng.choice(WORDS)}-{numbers.pop()}.test" for _ in range(rng.choice((1, 1, 2)))]
                    for j, name in enumerate(names):
                        registered = start + timedelta(minutes=2 * j)
                        out[name] = Made(name, k, registered, registered + timedelta(minutes=rng.randint(3, 25)))
                    if len(names) == 2:                     # one certificate for both names of the sitting
                        a, b = names
                        out[a].co_certified, out[b].co_certified = frozenset({b}), frozenset({a})
                        out[b].first_cert = out[a].first_cert
            day += timedelta(days=1)
        _today(rng, [m for m in out.values() if m.launch == k], state)
    return out


def _today(rng: random.Random, launch: list[Made], state: str) -> None:
    """How a launch stands now: taken down long ago, partly suspended, or still live."""
    if state == "gone":
        if launch[0].launch == 5:                          # one name bought again later by somebody else
            m = launch[-1]
            m.registration = _registration(m.name, datetime(2026, 9, 2, 14, 20, tzinfo=UTC), PARKING)
            m.ips, m.nameservers = frozenset({"192.0.2.80"}), frozenset({"parkingdns.test"})
        return
    if state == "held":
        for m in launch[:3]:
            m.registration = _registration(m.name, m.registered, REGISTRAR, ("client hold",))
        return
    who = REGISTRAR if launch[0].launch == 9 else OTHER_REGISTRAR
    address = "203.0.113.7" if launch[0].launch == 9 else "198.51.100.23"
    for n, m in enumerate(launch):
        held = who is OTHER_REGISTRAR and n == 1
        m.registration = _registration(m.name, m.registered, who, ("server hold",) if held else
                                       ("client transfer prohibited",))
        if not held:
            m.ips, m.nameservers = frozenset({address}), frozenset({"pqxdns.test"})


def sources(made: dict[str, Made]) -> Sources:
    """Lookups that answer from the made-up world and never touch the network."""
    def certificates(d):
        m = made.get(d)
        return (m.first_cert, m.co_certified) if m else (None, frozenset())

    return Sources(certificates=certificates,
                   registration=lambda d: made[d].registration if d in made else None,
                   addresses=lambda d: made[d].ips if d in made else frozenset(),
                   nameservers=lambda d: made[d].nameservers if d in made else frozenset())


def public_list(made: dict[str, Made]) -> list[str]:
    """A made-up public phishing list: every launch but the last one was reported, plus unrelated names."""
    return sorted(m.name for m in made.values() if m.launch < len(LAUNCHES) - 1 and m.name != PARTNER) + NOISE


def watcher(made: dict[str, Made]):
    """A watcher store in memory that saw the last launch's certificates."""
    conn = store.connect(":memory:")
    last = sorted((m for m in made.values() if m.launch == len(LAUNCHES) - 1), key=lambda m: m.first_cert)
    entries, done = [], set()
    for i, m in enumerate(last):
        if m.name in done:
            continue
        names = (m.name, f"www.{m.name}", *sorted(m.co_certified))
        done |= set(names)
        entries.append(Entry(9_000_000 + i, m.first_cert, False, names, "Example CA"))
    store.save(conn, "https://ct.example/demo", entries)
    return conn


def investigation(sims: int = 5000) -> Investigation:
    """The made-up case, investigated. Call it, and render it, inside `brands.extra(BRANDS)`."""
    made = world()
    return investigate.investigate(LINK, sources(made), list_lines=public_list(made), conn=watcher(made),
                                   sims=sims, now=NOW)
