"""Husmo, the detective ferret: tells an investigation in plain words, and says how sure it is.

Each line is (kind, text). Kinds: "fact" (read from a public source), "deduction" (what the
clues add up to), "caution" (what the data cannot say) and "action" (what to do next).
"""

from __future__ import annotations

import re
from collections import Counter

from rastro import brands, calendar_clues, rhythm
from rastro.domains import PLATFORMS, dns_hides_takedown, platform
from rastro.investigate import Investigation

KIND_LABELS = {
    "certificate": ("a shared certificate", "un certificado compartido"),
    "word": ("the same unusual word", "la misma palabra rara"),
    "session": ("the same work session", "la misma sesión de trabajo"),
    "burst": ("the same launch", "el mismo lanzamiento"),
    "ip": ("the same server address", "la misma dirección de servidor"),
    "nameserver": ("the same name servers", "los mismos servidores de nombres"),
    "template": ("the same template", "la misma plantilla"),
}
WEEKENDS = {
    "sat-sun": ("They rest on Saturdays and Sundays.", "Descansan sábado y domingo."),
    "fri-sat": ("They rest on Fridays and Saturdays.", "Descansan viernes y sábado."),
    "sun": ("They rest on Sundays only.", "Solo descansan el domingo."),
    "none": ("They work all seven days.", "Trabajan los siete días de la semana."),
}
DST = {
    "eu": ("Their clock jumps with European summer time.", "Su reloj salta con el horario de verano europeo."),
    "us": ("Their clock jumps with US daylight saving time.", "Su reloj salta con el horario de verano de EE. UU."),
    "south": ("Their clock jumps with southern-hemisphere summer time.",
              "Su reloj salta con el horario de verano del hemisferio sur."),
    "none": ("Their clock does not change in summer.", "Su reloj no cambia en verano."),
}


GONE = {   # (English one, English many), (Spanish one, Spanish many)
    "unregistered": (("{n} is no longer registered", "{n} are no longer registered"),
                     ("{n} ya no está registrado", "{n} ya no están registrados")),
    "suspended": (("{n} is already suspended", "{n} are already suspended"),
                  ("{n} ya está suspendido", "{n} ya están suspendidos")),
    "defensive": (("{n} is held by a brand-protection registrar", "{n} are held by brand-protection registrars"),
                  ("{n} lo tiene un registrador de protección de marca",
                   "{n} los tienen registradores de protección de marca")),
    "reregistered": (("{n} was registered again, maybe by somebody else",
                      "{n} were registered again, maybe by somebody else"),
                     ("{n} se ha vuelto a registrar, quizá por otra persona",
                      "{n} se han vuelto a registrar, quizá por otra persona")),
    "unresolved": (("{n} was on a hosting platform and no longer resolves",
                    "{n} were on hosting platforms and no longer resolve"),
                   ("{n} estaba en una plataforma de hosting y ya no resuelve",
                    "{n} estaban en plataformas de hosting y ya no resuelven")),
}
REASONS = {   # what made a name look like known phishing: (English, Spanish)
    "brand": ("the brand {brand}", "la marca {brand}"),
    "brand+more": ("the brand with other words around it", "la marca con otras palabras alrededor"),
    "w": ('the word "{value}"', "la palabra «{value}»"),
    "tld": ("the .{value} ending", "la terminación .{value}"),
    "g": ('the letters "{value}"', "las letras «{value}»"),
    "digits": ("{value} digits", "{value} cifras"),
    "hyphens": ("{value} hyphens", "{value} guiones"),
    "length": ("a long name", "un nombre largo"),
    "punycode": ("non-Latin letters", "letras no latinas"),
    "digits+hyphens": ("digits and hyphens together", "cifras y guiones juntos"),
    "brand-only": ("just the brand's name", "solo el nombre de la marca"),
}


def reason(kind: str, value: str, lang: str = "en") -> str:
    """One of the scorer's reasons, in words."""
    template = REASONS.get(kind)
    if template is None:
        return f"{kind} {value}".strip()
    return template[1 if lang == "es" else 0].format(value=value, brand=brands.display(value) if value else "")


NOTES = {
    "shared_hosting": ("The seed's certificates also cover {n} other domains: shared hosting, so they say nothing "
                       "about its owner and were left out.",
                       "Los certificados de la semilla cubren además {n} dominios: es hosting compartido, así que no "
                       "dicen nada de su dueño y se han dejado fuera."),
    "capped": ("{n} lookalikes looked related; only the closest {max} were checked.",
               "{n} dominios parecidos parecían relacionados; solo se han revisado los {max} más cercanos."),
    "brand_in_subdomain": ("The link imitates {brand} only in a subdomain, which the crew can change at will; its "
                           "siblings are looked for by the name of {seed}.",
                           "El enlace imita a {brand} solo en un subdominio, que la banda puede cambiar a su antojo; "
                           "sus hermanos se buscan por el nombre de {seed}."),
    "lonely": ("No sibling joined the seed yet: the pattern to watch is a guess from its name alone.",
               "Ningún hermano se ha unido aún a la semilla: el patrón que vigilar es una apuesta a partir de su "
               "nombre."),
}


def note(code: str, values: dict, lang: str = "en") -> str:
    return NOTES[code][1 if lang == "es" else 0].format(**values)


def _list(items: list[str], lang: str) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + (" and " if lang == "en" else " y ") + items[-1]


def _p(p: float) -> str:
    return "< 0.0001" if p < 0.0001 else f"= {p:.4f}"


# The pieces of the regular expressions Rastro learns, in the order they are tried.
_PIECES = re.compile(r"\(\?=\.\*(?P<look>[^)]*)\)"
                     r"|\\d\{(?P<d1>\d+)(?:,(?P<d2>\d+))?\}|\[a-z\]\{(?P<a1>\d+)(?:,(?P<a2>\d+))?\}"
                     r"|\[a-z0-9\.-\]\+(?P<any>)|\((?P<alt>[^()]*)\)|\\(?P<esc>.)|(?P<dash>-)|(?P<lit>[^\\()\[\]-]+)")
_SAID = {
    "en": {"digits": "{a} digits", "digits_range": "{a} to {b} digits", "letters": "{a} letters",
           "letters_range": "{a} to {b} letters", "look": "any name with {x} in it", "or": " or ",
           "dot": "dot", "dash": "dash"},
    "es": {"digits": "{a} cifras", "digits_range": "de {a} a {b} cifras", "letters": "{a} letras",
           "letters_range": "de {a} a {b} letras", "look": "cualquier nombre con {x} dentro", "or": " o ",
           "dot": "punto", "dash": "guion"},
}


def spoken_pattern(regex: str, lang: str = "en") -> str:
    """A learned regular expression as Husmo would say it:
    paqexpres-\\d{4}\\.top -> "paqexpres dash 4 digits dot top"."""
    say = _SAID["es" if lang == "es" else "en"]
    words = []
    for m in _PIECES.finditer(regex):
        if m["look"] is not None:
            words.append(say["look"].format(x=m["look"].replace("\\", "")))
        elif m["d1"]:
            words.append(say["digits_range" if m["d2"] else "digits"].format(a=m["d1"], b=m["d2"]))
        elif m["a1"]:
            words.append(say["letters_range" if m["a2"] else "letters"].format(a=m["a1"], b=m["a2"]))
        elif m["alt"] is not None:
            options = [o.replace("\\", "") for o in m["alt"].split("|")]
            words.append(", ".join(options[:-1]) + say["or"] + options[-1] if len(options) > 1 else options[0])
        elif m["esc"]:
            words.append(say["dot"] if m["esc"] == "." else m["esc"])
        elif m["dash"]:
            words.append(say["dash"])
        elif m["lit"]:
            words.append(m["lit"])
    return " ".join(w for w in words if w)


def spoken(text: str, lang: str = "en") -> str:
    """What Husmo says for a line: patterns, time zones and numbers turned into words a voice reads well."""
    es = lang == "es"
    out = []
    for token in text.split(" "):
        core, tail = (token[:-1], token[-1]) if token[-1:] in ".,:;" else (token, "")
        if "\\" in core or "{" in core or "(?=" in core:
            token = spoken_pattern(core, lang) + tail
        out.append(token)
    said = " ".join(out)
    plus, minus = ("más", "menos") if es else ("plus", "minus")
    said = re.sub(r"UTC([+−-])(\d+)", lambda m: f"UTC {plus if m[1] == '+' else minus} {m[2]}", said)
    said = re.sub(r"10\^(\d+(?:\.\d+)?)", (r"10 elevado a \1" if es else r"10 to the power of \1"), said)
    said = said.replace("p = ", "p igual a " if es else "p equals ")
    said = said.replace("p < ", "p menor que " if es else "p below ")
    if es:
        said = re.sub(r"(?<![\w.])(\d+)\.(\d+)(?![\w.])", r"\1,\2", said)
    return said


def narrate(inv: Investigation, lang: str = "en") -> list[tuple[str, str]]:
    es = lang == "es"
    out: list[tuple[str, str]] = []
    seed = inv.members[inv.seed]
    brand = brands.display(inv.brand) if inv.brand else None
    if es:
        out.append(("fact", f"El enlace lleva a {inv.seed}" + (f", que imita a {brand}." if brand else ".")))
    else:
        out.append(("fact", f"The link leads to {inv.seed}" + (f", a lookalike of {brand}." if brand else ".")))
    if inv.name_score is not None:
        why = _list([reason(k, v, lang) for k, v in inv.name_reasons], lang)
        shown = min(inv.name_score, 0.99)      # a model of the name alone never gets to certainty
        if es:
            out.append(("deduction", f"Solo por su nombre, mi modelo le da un {shown:.2f} sobre 1 de parecido "
                                     "con el phishing conocido" + (f": {why}." if why else ".")))
        else:
            out.append(("deduction", f"By its name alone, my model gives it {shown:.2f} out of 1 for looking "
                                     "like known phishing" + (f": {why}." if why else ".")))
    r = seed.registration
    registrar = r.registrar.rstrip(".") if r and r.registrar else None
    if r and (r.registered or registrar):
        when = f"{r.registered:%Y-%m-%d %H:%M} UTC" if r.registered else None
        if es:
            out.append(("fact", "Se registró" + (f" el {when}" if when else "")
                        + (f" en {registrar}." if registrar else ".")))
        else:
            out.append(("fact", "It was registered" + (f" on {when}" if when else "")
                        + (f" through {registrar}." if registrar else ".")))
    if suffix := platform(inv.seed):
        host, blind = PLATFORMS[suffix], dns_hides_takedown(inv.seed)
        if es:
            out.append(("fact", f"Es un sitio en {host}, que regala subdominios: nadie lo registró en un registro, así "
                                "que el aviso va a la plataforma."
                        + (" Esa plataforma responde en DNS a cualquier nombre, así que no puedo saber si sigue en pie "
                           "sin visitarlo, y nunca visito." if blind else "")))
        else:
            out.append(("fact", f"It is a site on {host}, which gives out free subdomains: nobody registered it at a "
                                "registry, so the abuse report goes to the platform."
                        + (" That platform answers DNS for any name, so I cannot tell whether it is still up without "
                           "visiting it, and I never visit." if blind else "")))

    crew = inv.crew
    listed = sum(1 for d in crew if "list" in inv.members[d].sources)
    if inv.crew_pattern:
        times = [t for d in crew if (t := inv.members[d].first_seen)]
        span = f"{min(times):%Y-%m-%d}", f"{max(times):%Y-%m-%d}"
        if es:
            text = f"Su nombre sigue una plantilla: {inv.crew_pattern.regex}. La comparten {len(crew)} dominios"
            text += f", {listed} de ellos en la lista pública de phishing" if listed else ""
            text += f", de {span[0]} a {span[1]}." if times else "."
        else:
            text = f"Its name follows a template: {inv.crew_pattern.regex}. {len(crew)} domains share it"
            text += f", {listed} of them on the public phishing list" if listed else ""
            text += f", from {span[0]} to {span[1]}." if times else "."
        out.append(("deduction", text))
    else:
        out.append(("caution", "Aún no encuentro hermanos construidos igual." if es
                    else "I found no siblings built like it yet."))

    if len(inv.campaign) > 1:
        kinds: dict[str, int] = {}
        for a, b, _, ks in inv.edges:
            if a in inv.campaign and b in inv.campaign:
                for k in ks:
                    kinds[k] = kinds.get(k, 0) + 1
        labels = [KIND_LABELS[k][1 if es else 0] for k in sorted(kinds, key=lambda k: -kinds[k])
                  if k in KIND_LABELS and k != "template"]
        n = len(inv.campaign) - 1
        if es:
            out.append(("deduction", f"{n} dominio{'s' if n > 1 else ''} se le une{'n' if n > 1 else ''} por pistas "
                                     f"que suman: {_list(labels, lang)}."))
        else:
            out.append(("deduction", f"{n} domain{'s are' if n > 1 else ' is'} tied to it by clues that add up: "
                                     f"{_list(labels, lang)}."))
    elif inv.crew_pattern:
        out.append(("caution", "Ninguna pista lo ata a un lanzamiento concreto: la banda lo sacó suelto, días lejos de "
                               "sus otros dominios." if es else
                    "No clue ties it to a particular launch: the crew put it out on its own, days away from its "
                    "other domains."))
    else:
        out.append(("caution", "Ninguna pista lo une con fuerza a otro dominio todavía." if es
                    else "No clue ties it strongly to another domain yet."))

    c = inv.clues
    if c and inv.rhythm_found:
        tz, west, east = rhythm.tz_name(c.offset), rhythm.tz_name(c.band[0]), rhythm.tz_name(c.band[-1])
        if es:
            out.append(("deduction", f"Sus {inv.clock_events} actos con hora caen en una jornada laboral: lo más "
                                     f"probable, {tz}; entre {west} y {east} con un {c.band_mass:.0%} de probabilidad "
                                     f"(test de ritmo p {_p(c.p_value)})."))
        else:
            out.append(("deduction", f"Their {inv.clock_events} timed actions fall into a working day: most likely "
                                     f"{tz}, between {west} and {east} with {c.band_mass:.0%} probability "
                                     f"(rhythm test p {_p(c.p_value)})."))
        if c.weekend in WEEKENDS:
            out.append(("deduction", WEEKENDS[c.weekend][1 if es else 0]))
        if c.dst in DST:
            out.append(("deduction", DST[c.dst][1 if es else 0]))
        if c.weekend == "inconclusive" and c.dst == "inconclusive":
            out.append(("caution", "Para saber su fin de semana o su horario de verano hacen falta más sesiones." if es
                        else "Their weekend and summer time need more sessions to tell."))
        elif c.dst == "inconclusive":
            out.append(("caution", f"Para saber si cambia la hora en verano hacen falta más sesiones (unas "
                                   f"{calendar_clues.DST_MIN_SESSIONS})." if es else
                        f"Whether their clock changes in summer needs more sessions to tell (about "
                        f"{calendar_clues.DST_MIN_SESSIONS})."))
        elif c.weekend == "inconclusive":
            out.append(("caution", f"Para saber qué días descansa hacen falta más sesiones (unas "
                                   f"{calendar_clues.WEEKEND_MIN_SESSIONS} en {calendar_clues.WEEKEND_MIN_WEEKS} "
                                   "semanas)." if es else
                        f"Their days off need more sessions to tell (about {calendar_clues.WEEKEND_MIN_SESSIONS} "
                        f"over {calendar_clues.WEEKEND_MIN_WEEKS} weeks)."))
    elif c:
        p = f"p {_p(c.p_value)}" if c.p_value is not None else ""
        out.append(("caution", f"Sus {inv.clock_events} actos con hora aún no dibujan una jornada laboral ({p}): "
                               "no me atrevo con el mapa." if es else
                    f"Their {inv.clock_events} timed actions do not draw a working day yet ({p}): no map."))
    else:
        out.append(("caution", "No tengo actos con hora: sin mapa." if es else "No timed actions: no map."))

    if inv.crew_pattern:
        b = inv.crew_pattern.breadth_log10
        out.append(("action", f"Para cazar el siguiente, vigila {inv.crew_pattern.regex}: unos 10^{b:.1f} nombres "
                              "posibles, lo bastante estrecho para no dar falsas alarmas." if es else
                    f"To catch the next one, watch {inv.crew_pattern.regex}: about 10^{b:.1f} possible names, "
                    "narrow enough to stay quiet."))
    elif inv.guess:
        out.append(("action", f"Una apuesta a partir de su nombre: vigila {inv.guess}." if es else
                    f"A guess from its name alone: watch {inv.guess}."))

    gone = Counter(inv.left_out.values())
    if gone:
        parts = [GONE[code][1 if es else 0][gone[code] > 1].format(n=gone[code]) for code in GONE if gone[code]]
        total = len(set(inv.attributed) | {inv.seed})
        out.append(("fact", f"De los {total} dominios atribuidos, {_list(parts, lang)}." if es else
                    f"Of the {total} attributed domains, {_list(parts, lang)}."))
    live = sum(len(r.domains) for r in inv.reports)
    n = len(inv.reports)
    blind = sum(dns_hides_takedown(d) for r in inv.reports for d in r.domains)
    hosts = {r.hosted for r in inv.reports}
    per = {frozenset({False}): ("uno por registrador", "one per registrar"),
           frozenset({True}): ("uno por plataforma", "one per platform")}.get(
        frozenset(hosts), ("uno por registrador o plataforma", "one per registrar or platform"))[0 if es else 1]
    if live == 1 and blind:
        out.append(("action", "Puede que siga en pie, hasta donde deja ver el DNS: abajo tienes el borrador de aviso a "
                              "su plataforma, para que lo revises y lo envíes tú." if es else
                    "It may still be up, as far as DNS can tell: the abuse report draft for its platform is below, "
                    "for you to review and send."))
    elif live == 1:
        who = ("su plataforma" if inv.reports[0].hosted else "su registrador") if es else (
            "its platform" if inv.reports[0].hosted else "its registrar")
        out.append(("action", f"Solo queda uno activo: abajo tienes el borrador de aviso a {who}, para que lo "
                              "revises y lo envíes tú." if es else
                    f"Only one is still live: the abuse report draft for {who} is below, for you to review "
                    "and send."))
    elif live and blind == live:
        out.append(("action", f"Puede que los {live} sigan en pie, hasta donde deja ver el DNS: abajo tienes {n} "
                              f"borrador{'es' if n > 1 else ''} de aviso, {per}, para que los revises y envíes tú."
                    if es else
                    f"All {live} may still be up, as far as DNS can tell: {n} abuse report draft{'s' if n > 1 else ''} "
                    f"below, {per}, for you to review and send."))
    elif live:
        unsure = ((f" o sin forma de comprobarlo ({blind} en plataformas que responden en DNS a cualquier nombre)"
                   if es else f" or cannot be checked ({blind} on platforms that answer DNS for any name)")
                  if blind else "")
        out.append(("action", f"Quedan {live} activos{unsure}: abajo tienes {n} borrador{'es' if n > 1 else ''} de "
                              f"aviso, {per}, para que los revises y envíes tú." if es else
                    f"{live} are still live{unsure}: {n} abuse report draft{'s' if n > 1 else ''} below, {per}, "
                    "for you to review and send."))
    else:
        out.append(("caution", "Ninguno sigue activo con un registrador que yo pueda consultar: nada que avisar."
                    if es else "None is still live with a registrar I can look up: nothing to report."))
    out.append(("caution", "No he visitado ningún dominio: me lo han contado los certificados, los registros y el DNS "
                           "público." if es else
                "I never visited the domains: certificates, registries and public DNS told me all this."))
    return out
