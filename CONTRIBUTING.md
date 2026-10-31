# Contributing to Rastro

Thanks for helping. Issues and pull requests are welcome, in English or Spanish.

## Set up

```bash
git clone https://github.com/Ruby570bocadito/rastro
```

```bash
pip install -e ./rastro pytest ruff==0.16.7
```

```bash
python -m pytest rastro
```

```bash
ruff check rastro
```

CI runs the same lint and tests on Linux and Windows with Python 3.11, 3.12 and 3.13.

## Rules every change keeps

They are what make Rastro safe to run and to share, so a change that breaks one will not be merged.

- **Never connect to an investigated domain.** Ask public services instead: Certificate Transparency logs, crt.sh, RDAP registries, a public DNS-over-HTTPS resolver.
- **Never look for people.** No registrant, administrative or technical contacts, no names and no addresses of persons. Rastro stops at time zones and infrastructure.
- **Never send anything for the user.** Abuse reports are drafts.
- **Case files reach nothing.** They make no network requests, they write attacker-controlled text as text, never as HTML, and Husmo only speaks with offline system voices, because a cloud voice would send the case's text away.
- **No live names in the repository.** Tests and examples use made-up names under `.test` or `.example` and addresses from the documentation ranges. Names seen live stay in `data/raw/`, which git ignores.
- **No dependencies in the core.** The package uses the standard library only.
- **Say how sure.** A new clue needs an "inconclusive" answer below the amount of data it needs, measured in an experiment.

## Layout

- `src/rastro/investigate.py`: from one link to its crew, campaign, clock, next domain and abuse report drafts.
- `src/rastro/husmo.py`: Husmo's words for an investigation, in English and Spanish.
- `src/rastro/report.py` and `src/rastro/assets/report.html`: the self-contained HTML case file.
- `src/rastro/demo.py`: the made-up world behind `rastro demo`.
- `src/rastro/track.py` and `src/rastro/assets/scoreboard.html`: follows domains after they are found and scores registrars with Kaplan-Meier survival curves.
- `src/rastro/watch.py`: the live watcher (narrow patterns only, official-domain allowlist, one alert per domain, resume).
- `src/rastro/bursts.py`: spots campaigns being born among stored names.
- `src/rastro/campaigns.py`: groups domains into campaigns from clues that add up.
- `src/rastro/pattern.py`: learns a readable regular expression from a campaign's domains and reports how many names it could match.
- `src/rastro/scorer.py` and `src/rastro/assets/scorer.bin`: the name model (logistic regression on hashed features of the name), trained by experiment 07.
- `src/rastro/rhythm.py`: the time-zone model, with bots, early and late crews, and the rhythm test.
- `src/rastro/calendar_clues.py`: daylight saving, weekend and holiday clues, with the bars below which they stay silent.
- `src/rastro/assets/brands.txt`: imitated brands, how they are written and their official domains; `src/rastro/brands.py` reads it and decides what makes a lookalike.
- `src/rastro/store.py`: SQLite store of what the watcher kept and of where each watch stopped.
- `src/rastro/sources/`: Certificate Transparency logs (`ctlog.py`, `der.py`), crt.sh (`crtsh.py`), RDAP (`rdap.py`) and DNS over HTTPS (`dns.py`), each cached on disk.
- `src/rastro/__main__.py`: the `rastro` command line.
- `experiments/`: the validation experiments and their aggregated results.
- `tests/`: unit tests on synthetic data.
- `scripts/landmask.py`: how the map's land dots were made.

## Adding a brand

Add a line to `src/rastro/assets/brands.txt`: `key | how it is written | official domains`. Keys of four letters or fewer must match a whole word; the official domains never alert; the name can stay empty when capitalising the key is enough. Order matters, the first brand that matches wins. Add a test with made-up lookalikes. To try a brand without changing Rastro, put the same line in a file of your own and pass `rastro --brands FILE`.

## Experiments

Each experiment in `experiments/` writes its aggregated results to `experiments/results/`. Raw downloads and the names they contain stay in `data/raw/`. Ask before adding a new data source, and say in the experiment's notes what failed as well as what worked.
