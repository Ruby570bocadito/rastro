# Changelog

## Unreleased

- Experiment 07: a logistic-regression model of the domain name alone (`src/rastro/scorer.py`). It does not ship: on fresh certificates it would bury the alerts in false alarms, and live campaigns hide among its training negatives. `--name-model FILE` lets `rastro score`, `rastro investigate` and `rastro watch` use a model you train with `experiments/exp07_puntuador.py --save FILE`.
- Registrable domains now treat country second levels such as `co.id`, `com.my` or `ac.th` as public suffixes.

## 0.1.0 · 2026-10-31

First public release.

- `rastro investigate`: from one phishing link to its crew, its campaign, the crew's time zone, the pattern of its next domain and abuse report drafts, in one self-contained HTML case file.
- `rastro demo`: the same on a made-up case, offline.
- `rastro watch`: reads Certificate Transparency logs directly, alerts on narrow patterns, spots campaigns being born and stores only lookalikes.
- `rastro campaigns`, `bursts`, `pattern`, `rhythm` and `logs`.
- Validation experiments 01 to 06 and a live end-to-end trial, in [experiments](experiments/README.md).
