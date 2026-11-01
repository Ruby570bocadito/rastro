"""Command line: `rastro investigate`, `demo`, `track`, `pattern`, `rhythm`, `logs`, `watch`, `campaigns`, `bursts`
and `score`."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
import webbrowser
from datetime import UTC, datetime, timedelta
from pathlib import Path

from rastro import (
    __version__,
    brands,
    bursts,
    calendar_clues,
    campaigns,
    demo,
    husmo,
    investigate,
    pattern,
    report,
    rhythm,
    scorer,
    store,
    track,
    watch,
)
from rastro.domains import registrable
from rastro.sources import crtsh, ctlog, dns, phishlist


def _lines(path: str) -> list[str]:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8", errors="replace")
    return [s.strip() for s in text.splitlines() if s.strip() and not s.startswith("#")]


def cmd_pattern(args) -> int:
    domains = [d.lower() for d in _lines(args.file)]
    found = pattern.learn(domains, min_support=args.min_support)
    if not found:
        print(f"No layout repeats at least {args.min_support} times in {len(domains)} names.")
        return 1
    for p in found:
        print(f"{p.regex}\n    learned from {p.support} names · could match about 10^{p.breadth_log10:.1f} names")
    return 0


def _instant(value: str) -> datetime | None:
    """A UTC instant from an ISO 8601 time, or None for a bare hour; ValueError for anything else."""
    try:
        float(value)
        return None
    except ValueError:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return t.astimezone(UTC) if t.tzinfo else t.replace(tzinfo=UTC)


def _histogram(hours: list[float]) -> None:
    counts = rhythm.hour_counts(hours)
    top = max(counts) or 1
    for h, n in enumerate(counts):
        print(f"{h:02d}h UTC {'█' * round(30 * n / top):<30} {n}")


def _probs(probs: dict[str, float]) -> str:
    return ", ".join(f"{k} {v:.0%}" for k, v in sorted(probs.items(), key=lambda kv: -kv[1]))


def cmd_rhythm(args) -> int:
    values = _lines(args.file)
    if not values:
        print(f"No times in {args.file}: give one UTC time in ISO 8601 (2026-10-30T09:15Z) or UTC hour (9.25) per "
              "line.")
        return 1
    instants = []
    for v in values:
        try:
            instants.append(_instant(v))
        except ValueError:
            print(f"{v!r} is neither a UTC time in ISO 8601 (2026-10-30T09:15Z) nor a UTC hour (9.25).")
            return 2
    if values and all(instants):
        starts = rhythm.sessions(instants)
        _histogram([t.hour + t.minute / 60 for t in starts])
        c = calendar_clues.analyse(instants, sims=args.sims)
        band = f"{rhythm.tz_name(c.band[0])} to {rhythm.tz_name(c.band[-1])}"
        print(f"\n{len(instants)} events in {c.sessions} work sessions · human rhythm: "
              f"{'yes' if c.p_value < 0.01 else 'no'} (p = {c.p_value:.4f})")
        print(f"most probable {rhythm.tz_name(c.offset)} · {c.band_mass:.0%} band {band}")
        print(f"daylight saving: {c.dst} ({_probs(c.dst_probs)})")
        print(f"weekend: {c.weekend} ({_probs(c.weekend_probs)})")
        for name, seen, expected, verdict in c.holidays:
            print(f"{name}: {seen} sessions, {expected} expected on an ordinary day ({verdict})")
        return 0
    hours = [float(v) % 24 if i is None else i.hour + i.minute / 60 for v, i in zip(values, instants, strict=True)]
    _histogram(hours)
    est = rhythm.estimate(hours, sims=args.sims)
    band = f"{rhythm.tz_name(est.band[0])} to {rhythm.tz_name(est.band[-1])}"
    print(f"\n{est.n_events} events · human rhythm: {'yes' if est.p_value < 0.01 else 'no'} (p = {est.p_value:.4f})")
    print(f"most probable {rhythm.tz_name(est.offset)} · {est.band_mass:.0%} band {band} · "
          f"bots about {est.bot_share:.0%}")
    print("(give full dates and times to also test daylight saving, the weekend and holidays)")
    return 0


def cmd_list_update(args) -> int:
    print(f"Asking {args.url} for the list...", flush=True)
    try:
        got = phishlist.update(args.to, url=args.url)
    except (RuntimeError, ValueError) as err:
        print(f"No new list: {err}")
        return 1
    what = "Downloaded" if got.changed else "Already up to date:"
    print(f"{what} {got.domains:,} domains ({got.size / 1e6:.1f} MB) in {got.path}")
    return 0


def cmd_logs(args) -> int:
    for description, url in ctlog.tiled_logs(args.days_ahead):
        print(f"{description:<36} {url}")
    return 0


def _print_burst(b: bursts.Burst) -> None:
    print(f"NEW CAMPAIGN? {b.brand}: {len(b.domains)} lookalike domains with one template, "
          f"{b.first_seen[:16]} to {b.last_seen[:16]} UTC", flush=True)
    scope = f"about 10^{b.breadth_log10} names" if b.breadth_log10 is not None else "anchored on a distinctive word"
    print(f"    pattern {b.regex}  ({scope})")
    print(f"    e.g. {', '.join(b.domains[:4])}")


def cmd_watch(args) -> int:
    allow = {d.lower() for d in _lines(args.allow)} if args.allow else set()
    model = _name_model(args.name_model)
    keep_score = args.score_keep if args.score_keep is not None else (
        model.meta.get("threshold_at_fpr_0.001") if model and args.db else None)
    w = watch.Watcher(args.log, allow=allow, max_breadth=args.max_breadth, allow_broad=args.allow_broad, model=model,
                      keep_score=keep_score, alert_score=args.score_alerts)
    if args.learn:
        w.arm_learned(_lines(args.learn), min_support=args.min_support)
    w.arm_regex((args.regex or []) + (_lines(args.regex_file) if args.regex_file else []))
    for a in w.armed:
        scope = f"  (about 10^{a.breadth_log10:.1f} names)" if a.breadth_log10 is not None else ""
        print(f"armed    {a.regex}{scope}")
    for regex, breadth in w.skipped:
        print(f"skipped  {regex}  (about 10^{breadth:.1f} names: too broad, it would raise false alarms;"
              " --allow-broad arms it anyway)")
    if w.keep_score is not None:
        print(f"name model: also keeping names that score {w.keep_score:.3f} or more")
    if w.alert_score is not None:
        print(f"name model: alerting on names that score {w.alert_score:.3f} or more")
    if not w.armed and not args.bursts_every and w.alert_score is None:
        print("Nothing to watch: give --learn, --regex or --regex-file, --score-alerts, or --bursts-every with --db.")
        return 1
    conn = store.connect(args.db) if args.db else None
    out = open(args.alerts, "a", encoding="utf-8") if args.alerts else None

    followed = track.connect(args.track) if args.track else None

    def on_alert(alert: watch.Alert) -> None:
        print(alert.line(), flush=True)
        if out:
            out.write(alert.json() + "\n")
            out.flush()
        if followed:
            track.add(followed, [alert.domain], _instant(alert.logged_at.replace(" ", "T")), source="watch")

    try:
        if args.follow:
            watch.follow(w, conn, args.minutes, poll=args.poll, max_backlog=args.max_backlog,
                         bursts_every=args.bursts_every, burst_hours=args.burst_hours, burst_min=args.burst_min,
                         on_alert=on_alert, on_status=lambda s: print("  " + s, flush=True), on_burst=_print_burst,
                         keep_all=args.store_all)
        else:
            last = ctlog.tree_size(args.log) // ctlog.TILE - 1
            first = last - args.tiles + 1
            if conn:
                first = max(first, store.get_progress(conn, args.log) or 0)   # a store never reads a tile twice
            for tile, entries in enumerate(watch.read_tiles(args.log, first, last), first):
                for alert in w.handle(entries):
                    on_alert(alert)
                if conn:
                    store.record(conn, args.log, tile, entries, entries if args.store_all else w.keep(entries))
                if (tile - first + 1) % 10 == 0:
                    print(f"  {tile - first + 1}/{last - first + 1} tiles · {w.seen:,} certificates", flush=True)
    except KeyboardInterrupt:
        print("stopped")
    finally:
        if out:
            out.close()
    kept = f" · {w.kept:,} kept" if conn and not args.store_all else ""
    print(f"{w.seen:,} certificates read{kept} · {len(w.alerted)} alerts · {w.suppressed} official domains ignored")
    return 0


def _from_store(path: str, hours: float) -> list[campaigns.Domain]:
    """Throwaway brand lookalikes seen by `rastro watch --db`, with the names they shared certificates with."""
    conn = store.connect(path)
    cutoff = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
    official = brands.official_domains()
    seen = {r: t for r, t in conn.execute(
        "SELECT registrable, MIN(logged_at) FROM names WHERE logged_at >= ? GROUP BY registrable", (cutoff,))
        if r not in official and brands.suspicious(r) and brands.brand_of(r)}
    out = []
    for domain, first in seen.items():
        certs = conn.execute("SELECT DISTINCT log, idx FROM names WHERE registrable = ?", (domain,)).fetchall()
        co = {r for log, idx in certs for (r,) in conn.execute(
            "SELECT registrable FROM names WHERE log = ? AND idx = ?", (log, idx))} - {domain}
        out.append(campaigns.Domain(domain, brands.brand_of(domain), datetime.fromisoformat(first), frozenset(co)))
    return out


def cmd_campaigns(args) -> int:
    cache = Path(args.cache)
    if args.db:
        domains = _from_store(args.db, args.hours)
    else:
        names = sorted({registrable(d.lower()) for d in _lines(args.domains)})
        if not args.no_crtsh:
            print(f"Looking up {len(names)} domains on crt.sh (cached; slow the first time)…", flush=True)
        domains = []
        for d in names:
            first, co = (None, frozenset()) if args.no_crtsh else crtsh.profile(d, cache / "crtsh-domains")
            domains.append(campaigns.Domain(d, brands.brand_of(d), first, co))
    if args.dns:
        domains = [campaigns.Domain(d.name, d.brand, d.first_seen, d.co_certified,
                                    dns.addresses(d.name, cache / "dns"), dns.nameservers(d.name, cache / "dns"))
                   for d in domains]
    found = campaigns.cluster(domains)
    for k, c in enumerate(found, 1):
        span = f"{c.first_seen:%Y-%m-%d} to {c.last_seen:%Y-%m-%d}" if c.first_seen else "dates unknown"
        brand_list = ", ".join(f"{b} {n}" for b, n in c.brands.items()) or "no brand"
        print(f"CAMPAIGN {k} · {c.size} domains · {brand_list} · {span}")
        print(f"    joined by: {', '.join(f'{kind} {n}' for kind, n in c.links.most_common())}")
        for regex in c.patterns:
            print(f"    arm: {regex}")
        print(f"    e.g. {', '.join(c.domains[:4])}")
    alone = len(domains) - sum(c.size for c in found)
    print(f"{len(found)} campaigns · {alone} of {len(domains)} domains on their own")
    return 0


DEFAULT_LIST = "data/raw/lists/phishing-domains-ACTIVE.txt"
DEFAULT_TRACK = "data/raw/track.sqlite"


def cmd_investigate(args) -> int:
    try:
        investigate.seed_host(args.link)
    except ValueError as err:
        print(err)
        return 2
    list_path = args.list or (DEFAULT_LIST if Path(DEFAULT_LIST).exists() else None)
    lines = _lines(list_path) if list_path else []
    if not list_path:
        print("No phishing list: siblings will come only from shared certificates and the watcher. "
              "`rastro list update` downloads Phishing.Database's list (about 10 MB, MIT licence).\n")
    conn = store.connect(args.db) if args.db else None
    sources = investigate.Sources.public(Path(args.cache), offline=args.offline, crt=not args.no_crtsh,
                                         rdap_=not args.no_rdap, dns_=not args.no_dns)
    inv = investigate.investigate(args.link, sources, list_lines=lines, conn=conn, max_candidates=args.max_candidates,
                                  sims=args.sims, on_status=lambda s: print("  " + s, flush=True),
                                  model=_name_model(args.name_model))
    print()
    for k, (_, text) in enumerate(husmo.narrate(inv, args.lang), 1):
        print(f"{k}. {text}")
    for code, values in inv.notes:
        print(f"   note: {husmo.note(code, values, args.lang)}")
    out = Path(args.report or f"data/raw/reports/{inv.seed}.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report.render(inv, args.lang), encoding="utf-8")
    print(f"\nCase file: {out.resolve()}")
    if args.track:
        live = [d for r in inv.reports for d in r.domains]
        new = track.add(track.connect(args.track), live, inv.when, source="investigate")
        print(f"Following {new} new of {len(live)} live domains in {args.track}: run `rastro track check` "
              "every few hours to see when each registrar acts.")
        _say_unfollowable(track.unfollowable(live))
    if args.json:
        Path(args.json).write_text(json.dumps(report.case_data(inv, args.lang), ensure_ascii=False, indent=1),
                                   encoding="utf-8")
        print(f"Data: {Path(args.json).resolve()}")
    return 0


def cmd_demo(args) -> int:
    es = args.lang == "es"
    print(f"{'Caso inventado' if es else 'Made-up case'}: {demo.LINK}")
    print("Nada es real y nada sale a la red.\n" if es else "Nothing in it is real, and nothing touches the network.\n")
    with brands.extra(demo.BRANDS):
        inv = demo.investigation(sims=args.sims)
        for k, (_, text) in enumerate(husmo.narrate(inv, args.lang), 1):
            print(f"{k}. {text}")
        out = Path(args.report or "rastro-demo.html")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.render(inv, args.lang, demo=demo.TRUTH), encoding="utf-8")
    print(f"\n{'Expediente' if es else 'Case file'}: {out.resolve()}")
    if args.open:
        webbrowser.open(out.resolve().as_uri())
    return 0


NO_MODEL = ("No name model is shipped: experiment 07 found that a model of the name alone is not reliable yet. "
            "Train one with experiments/exp07_puntuador.py --save FILE and pass --name-model FILE.")


def _name_model(path: str | None) -> scorer.Model | None:
    return scorer.loads(Path(path).read_bytes()) if path else scorer.default()


def _say_unfollowable(domains: list[str]) -> None:
    if domains:
        print(f"Not followed: {', '.join(domains)}. Their platform answers DNS for any name, so a check could never "
              "see them come down without visiting them, which Rastro never does.")


def cmd_track_add(args) -> int:
    conn = track.connect(args.db)
    now = datetime.now(UTC)
    try:
        since = _instant(args.since) if args.since else now
    except ValueError:
        since = None
    if since is None:
        print(f"--since needs a date and time in ISO 8601, such as 2026-11-01T09:00Z, not {args.since!r}")
        return 2
    names, skipped = [], 0
    for raw in list(args.domains) + (_lines(args.file) if args.file else []):
        try:
            names.append(investigate.seed_domain(raw))
        except ValueError:
            skipped += 1
    new = track.add(conn, names, since, source="manual", reported=args.reported)
    asked, not_alerts = list(names), 0
    for path in args.alerts or []:
        for line in _lines(path):
            try:
                alert = json.loads(line)
                domain, at = alert["domain"], _instant(alert["logged_at"].replace(" ", "T"))
            except (ValueError, KeyError, TypeError, AttributeError):
                at = None
            if at is None:
                not_alerts += 1
                continue
            new += track.add(conn, [domain], at, source="watch")
            asked.append(domain)
    for path in args.case or []:
        try:
            case = json.loads(Path(path).read_text(encoding="utf-8"))
            reported = [d for r in case.get("reports", []) for d in r["domains"]]
        except (ValueError, KeyError, TypeError, AttributeError):
            print(f"{path} is not case data written by `rastro investigate --json`.")
            return 2
        new += track.add(conn, reported, since, source="case", reported=args.reported)
        asked += reported
    _say_unfollowable(track.unfollowable(asked))
    total = conn.execute("SELECT COUNT(*) FROM tracked").fetchone()[0]
    notes = []
    if skipped:
        notes.append(f"{skipped} lines were not domains")
    if not_alerts:
        notes.append(f"{not_alerts} lines were not alerts")
    print(f"{new} new domains followed, {total} in {args.db}" + (f" ({'; '.join(notes)})" if notes else ""))
    return 0


def cmd_track_check(args) -> int:
    conn = track.connect(args.db)
    sources = track.Sources.public(Path(args.cache))
    rounds = args.times if args.every else 1
    for k in range(rounds):
        counts = track.check(conn, sources, on_seen=lambda d, s: print(
            f"  {s.state:<9} {d}" + (f"  ({s.registrar})" if s.registrar else ""), flush=True))
        print(f"{datetime.now(UTC):%Y-%m-%d %H:%M} UTC · " + (", ".join(f"{n} {state}" for state, n in sorted(
            counts.items())) or "nothing left to check: every followed domain is down"), flush=True)
        if k < rounds - 1:
            time.sleep(args.every * 3600)
    return 0


def cmd_track_report(args) -> int:
    conn = track.connect(args.db)
    rows = track.scoreboard(conn, args.from_report)
    if not rows:
        print("Nothing to score yet: add domains with `rastro track add`" + (" --reported" if args.from_report else "")
              + " and run `rastro track check`.")
        return 1
    done, total = sum(r.taken_down for r in rows), sum(r.domains for r in rows)
    clock = "from each abuse report" if args.from_report else "from when each domain was followed"
    print(f"TAKEDOWN SCOREBOARD · {total} domain{'s' if total != 1 else ''}, {done} taken down, "
          f"{sum(r.still_up for r in rows)} still up · timed {clock}")
    print(f"{'Registrar':<42} {'Domains':>7} {'Down':>5}  {'Median':<10} Still up after 1 day · 3 days · 7 days")
    for r in rows:
        after = " · ".join(f"{r.after[m]:.0%}" for m in track.MARKS)
        median = track.hours_text(r.median_hours)
        print(f"{r.registrar[:42]:<42} {r.domains:>7} {r.taken_down:>5}  {median:<10} {after}")
    print("Kaplan-Meier estimate: a domain still up counts as up until its last check.")
    if args.html:
        page = report.fill("scoreboard.html", "Rastro · takedown scoreboard", args.lang,
                           {"/*BOARD*/": report.safe_json(track.page_data(conn, args.lang,
                                                                          from_report=args.from_report))})
        Path(args.html).parent.mkdir(parents=True, exist_ok=True)
        Path(args.html).write_text(page, encoding="utf-8")
        print(f"Scoreboard: {Path(args.html).resolve()}")
    return 0


def cmd_score(args) -> int:
    model = _name_model(args.name_model)
    if model is None:
        print(NO_MODEL)
        return 1
    names, skipped = [], 0
    for raw in list(args.domains) + (_lines(args.file) if args.file else []):
        try:
            names.append(investigate.seed_domain(raw))
        except ValueError:
            skipped += 1
    for s, d in scorer.rank(model, sorted(set(names)))[:args.top or None]:
        why = ", ".join(husmo.reason(k, v) for k, v, _ in model.reasons(d, 3))
        print(f"{min(s, 0.999):.3f}  {d}" + (f"  ({why})" if why else ""))
    if skipped:
        print(f"{skipped} lines were not domain names")
    return 0


def cmd_bursts(args) -> int:
    conn = store.connect(args.db)
    found = bursts.find_bursts(conn, args.hours, args.min, args.max_breadth)
    if not found:
        print(f"No brand bursts of {args.min}+ lookalike domains in the last {args.hours:g} hours.")
    for b in found:
        _print_burst(b)
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(prog="rastro", description="Paste a phishing link. Watch the whole campaign unfold.")
    ap.add_argument("--version", action="version", help="show Rastro's, Python's and the system's versions, as a bug "
                    "report asks for them", version=f"rastro-osint {__version__}, Python {platform.python_version()}, "
                    f"{platform.system()} {platform.release()}")
    ap.add_argument("--brands", metavar="FILE",
                    help="more brands to recognise, one per line as `key | Name | official.com` (see the built-in "
                         "list in rastro/assets/brands.txt)")
    sub = ap.add_subparsers(dest="command", required=True)
    inv = sub.add_parser("investigate", help="from one phishing link to its campaign, crew clock, next domain and "
                                             "abuse report drafts, as an HTML case file")
    inv.add_argument("link", help="the phishing link or domain (defanged forms like hxxps://evil[.]top work too)")
    inv.add_argument("--list", help=f"file of known phishing domains to find siblings in (default: {DEFAULT_LIST} "
                                    "when present)")
    inv.add_argument("--db", help="also look among the lookalikes stored by `rastro watch --db`")
    inv.add_argument("--report", help="where to write the HTML case file (default: data/raw/reports/<domain>.html)")
    inv.add_argument("--json", help="also write the case data as JSON")
    inv.add_argument("--lang", choices=["en", "es"], default="en", help="language of the case file")
    inv.add_argument("--max-candidates", type=int, default=150, help="most related domains to check")
    inv.add_argument("--sims", type=int, default=5000, help="simulations for the rhythm test")
    inv.add_argument("--offline", action="store_true", help="use cached answers only")
    inv.add_argument("--no-crtsh", action="store_true", help="skip crt.sh (no first certificates)")
    inv.add_argument("--no-rdap", action="store_true", help="skip RDAP (no registrations or abuse contacts)")
    inv.add_argument("--no-dns", action="store_true", help="skip the public DNS-over-HTTPS resolver")
    inv.add_argument("--cache", default="data/raw", help="folder for cached crt.sh, RDAP and DNS answers")
    inv.add_argument("--name-model", help="experimental: add the scores of a name model trained by experiment 07")
    inv.add_argument("--track", nargs="?", const=DEFAULT_TRACK, metavar="DB",
                     help=f"follow the live domains with `rastro track` (default database: {DEFAULT_TRACK})")
    inv.set_defaults(run=cmd_investigate)
    sc = sub.add_parser("score", help="experimental: score names with a name model trained by experiment 07")
    sc.add_argument("domains", nargs="*", help="domains or links")
    sc.add_argument("--file", help="file of domains or links, one per line (- for stdin)")
    sc.add_argument("--top", type=int, default=0, help="show only the N highest scores")
    sc.add_argument("--name-model", help="a name model trained by experiment 07 (none is shipped)")
    sc.set_defaults(run=cmd_score)
    de = sub.add_parser("demo", help="investigate a made-up case offline and write its case file")
    de.add_argument("--lang", choices=["en", "es"], default="en", help="language of the case file")
    de.add_argument("--report", help="where to write the case file (default: rastro-demo.html)")
    de.add_argument("--sims", type=int, default=5000, help="simulations for the rhythm test")
    de.add_argument("--open", action="store_true", help="open the case file in your browser")
    de.set_defaults(run=cmd_demo)
    tr = sub.add_parser("track", help="follow domains after they are found and score registrars by how fast they act")
    tsub = tr.add_subparsers(dest="track_command", required=True)
    ta = tsub.add_parser("add", help="start following domains")
    ta.add_argument("domains", nargs="*", help="domains or links")
    ta.add_argument("--file", help="file of domains or links, one per line")
    ta.add_argument("--alerts", nargs="*", help="alerts files written by `rastro watch --alerts`")
    ta.add_argument("--case", nargs="*", help="case data written by `rastro investigate --json`: its reported domains")
    ta.add_argument("--since", help="when to start the clock (ISO 8601, default now)")
    ta.add_argument("--reported", action="store_true",
                    help="their abuse reports went out at --since (default now); works on domains already followed")
    ta.add_argument("--db", default=DEFAULT_TRACK)
    ta.set_defaults(run=cmd_track_add)
    tc = tsub.add_parser("check", help="ask the registry and a public resolver about every domain still up")
    tc.add_argument("--every", type=float, help="check again every N hours")
    tc.add_argument("--times", type=int, default=28, help="with --every, how many rounds (default 28)")
    tc.add_argument("--db", default=DEFAULT_TRACK)
    tc.add_argument("--cache", default="data/raw", help="folder for RDAP and DNS answers")
    tc.set_defaults(run=cmd_track_check)
    tp = tsub.add_parser("report", help="the scoreboard: how long each registrar takes to act")
    tp.add_argument("--html", help="also write the scoreboard as a self-contained HTML page")
    tp.add_argument("--from-report", action="store_true",
                    help="only reported domains, timed from their abuse report instead of from when they were followed")
    tp.add_argument("--lang", choices=["en", "es"], default="en")
    tp.add_argument("--db", default=DEFAULT_TRACK)
    tp.set_defaults(run=cmd_track_report)
    p = sub.add_parser("pattern", help="learn naming patterns from a file of domains (one per line, - for stdin)")
    p.add_argument("file")
    p.add_argument("--min-support", type=int, default=3)
    p.set_defaults(run=cmd_pattern)
    r = sub.add_parser("rhythm", help="estimate the operators' time zone from UTC times or hours (one per line)")
    r.add_argument("file")
    r.add_argument("--sims", type=int, default=2000)
    r.set_defaults(run=cmd_rhythm)
    li = sub.add_parser("list", help="the public list of phishing domains that investigate searches for siblings")
    lsub = li.add_subparsers(dest="list_command", required=True)
    lu = lsub.add_parser("update", help="download Phishing.Database's list of active phishing domains (about 10 MB), "
                                        "or keep the copy you have if it has not changed")
    lu.add_argument("--to", default=DEFAULT_LIST, help=f"where to keep it (default: {DEFAULT_LIST}, where investigate "
                                                       "looks)")
    lu.add_argument("--url", default=phishlist.URL, help="another list in the same format, one domain per line")
    lu.set_defaults(run=cmd_list_update)
    lg = sub.add_parser("logs", help="list the tiled Certificate Transparency logs taking new certificates")
    lg.add_argument("--days-ahead", type=int, default=90, help="expiry of the certificates you want, in days")
    lg.set_defaults(run=cmd_logs)
    w = sub.add_parser("watch", help="read new certificates from a CT log and alert on names that match")
    w.add_argument("--log", default=ctlog.DEFAULT_LOG, help="monitoring URL of a tiled log (see `rastro logs`)")
    w.add_argument("--learn", help="file of a campaign's domains to learn patterns from")
    w.add_argument("--min-support", type=int, default=3)
    w.add_argument("--regex", nargs="*", help="extra patterns to watch, as regular expressions")
    w.add_argument("--regex-file", help="file of patterns to watch, one regular expression per line")
    w.add_argument("--max-breadth", type=float, default=watch.NARROW_LOG10,
                   help="arm learned patterns only up to 10^N possible names (default 9)")
    w.add_argument("--allow-broad", action="store_true", help="arm broad learned patterns too")
    w.add_argument("--allow", help="file of extra official domains that must never alert")
    w.add_argument("--alerts", help="append alerts to this file as JSON lines")
    w.add_argument("--score-alerts", type=float, help="with --name-model, also alert on names that score at least this")
    w.add_argument("--score-keep", type=float,
                   help="with --name-model and --db, also keep names that score at least this (default: the "
                        "model's threshold for 1 false positive in 1,000)")
    w.add_argument("--track", nargs="?", const=DEFAULT_TRACK, metavar="DB",
                   help=f"follow every alerted domain with `rastro track` (default database: {DEFAULT_TRACK})")
    w.add_argument("--name-model", help="experimental: a name model trained by experiment 07, for --score-alerts "
                                        "and --score-keep")
    w.add_argument("--tiles", type=int, default=20, help="read the latest N tiles of 256 certificates and stop")
    w.add_argument("--follow", action="store_true",
                   help="keep reading new tiles (Let's Encrypt's log moves about 400 KB/s)")
    w.add_argument("--minutes", type=float, default=10, help="how long --follow runs")
    w.add_argument("--poll", type=float, default=5, help="seconds between checkpoint reads in --follow")
    w.add_argument("--max-backlog", type=int, default=2000, help="tiles to catch up at most when resuming")
    w.add_argument("--db", help="SQLite file to keep brand lookalikes and alerts in, and where the watch stopped")
    w.add_argument("--store-all", action="store_true",
                   help="with --db, keep every certificate (about 6 GB a day on Let's Encrypt's log)")
    w.add_argument("--bursts-every", type=float, default=0,
                   help="with --follow and --db, look for campaigns being born every N minutes")
    w.add_argument("--burst-hours", type=float, default=48)
    w.add_argument("--burst-min", type=int, default=5)
    w.set_defaults(run=cmd_watch)
    ca = sub.add_parser("campaigns", help="group domains into campaigns from certificates, timing and infrastructure")
    src = ca.add_mutually_exclusive_group(required=True)
    src.add_argument("--domains", help="file of domains, one per line (- for stdin)")
    src.add_argument("--db", help="use the lookalikes stored by `rastro watch --db`")
    ca.add_argument("--hours", type=float, default=72, help="with --db, how far back to look")
    ca.add_argument("--dns", action="store_true",
                    help="add addresses and name servers (public DNS-over-HTTPS resolver)")
    ca.add_argument("--no-crtsh", action="store_true",
                    help="with --domains, skip crt.sh (no dates or shared certificates)")
    ca.add_argument("--cache", default="data/raw", help="folder for cached crt.sh and DNS answers")
    ca.set_defaults(run=cmd_campaigns)
    bu = sub.add_parser("bursts", help="find campaigns being born among the names stored by `rastro watch --db`")
    bu.add_argument("--db", required=True)
    bu.add_argument("--hours", type=float, default=48)
    bu.add_argument("--min", type=int, default=5, help="fewest lookalike domains with one template")
    bu.add_argument("--max-breadth", type=float, default=12.0)
    bu.set_defaults(run=cmd_bursts)
    args = ap.parse_args(argv)
    names, official = {}, {}
    if args.brands:
        try:
            names, official = brands.from_file(args.brands)
        except (OSError, ValueError) as err:
            print(f"--brands {args.brands}: {err}")
            return 2
    try:
        with brands.extra(names, official):
            return args.run(args)
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError, PermissionError) as err:
        # a path the user gave that is missing, is a folder, or cannot be read: say so instead of a traceback
        print(f"{err.filename}: {err.strerror}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
