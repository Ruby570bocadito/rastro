# Changelog

## Unreleased

- `rastro track`: follows domains after they are found (`add`, `check`, `report`), through RDAP and public DNS only, and scores registrars by how long their domains stay up, as Kaplan-Meier survival curves, timed from when each domain was followed or, with `--from-report`, from its abuse report. `rastro investigate --track` and `rastro watch --track` feed it. The scoreboard is a self-contained HTML page too.
- RDAP answers now tell a domain that is not registered from a TLD without an RDAP server, and DNS answers keep the resolver's verdict (NXDOMAIN means out of the zone).
- Husmo speaks: a Listen button in the case file reads the deductions aloud with an offline system voice, never a cloud one, while the ferret's mouth follows the words (each shape held at least 160 ms) and the line being read lights up. Learned patterns, time zones and numbers are turned into words a voice reads well.
- Experiment 07: a logistic-regression model of the domain name alone (`src/rastro/scorer.py`). It does not ship: on fresh certificates it would bury the alerts in false alarms, and live campaigns hide among its training negatives. `--name-model FILE` lets `rastro score`, `rastro investigate` and `rastro watch` use a model you train with `experiments/exp07_puntuador.py --save FILE`.
- Registrable domains now treat country second levels such as `co.id`, `com.my` or `ac.th` as public suffixes.

## 0.1.0 · 2026-10-31

First public release.

- `rastro investigate`: from one phishing link to its crew, its campaign, the crew's time zone, the pattern of its next domain and abuse report drafts, in one self-contained HTML case file.
- `rastro demo`: the same on a made-up case, offline.
- `rastro watch`: reads Certificate Transparency logs directly, alerts on narrow patterns, spots campaigns being born and stores only lookalikes.
- `rastro campaigns`, `bursts`, `pattern`, `rhythm` and `logs`.
- Validation experiments 01 to 06 and a live end-to-end trial, in [experiments](experiments/README.md).
