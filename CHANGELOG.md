# Changelog

## 0.2.1 · 2026-11-01

- Sites on hosting platforms, end to end. 17 of the 22 known platforms answer DNS for any name (checked with random names), so for their sites an address proves nothing: they are no longer left out as gone, their draft asks the platform to check whether they are still up, and `rastro track` does not follow them, since it could never see them come down without visiting them.
- A platform's shared addresses no longer tie two of its sites into one campaign. Before, two unrelated sites on the same platform could be joined by address alone.
- Platform drafts carry the platform's abuse form for 12 of the 22 suffixes (10 operators), each checked by hand; the others have none rather than a guess.
- Husmo says when a site lives on a platform and what DNS cannot tell about it; the case file's step 5 reads "Warn the registrar or host", shows the abuse form, names the platform in the evidence table, and counts sites that cannot be checked apart from live ones. The takedown scoreboard names platforms too.

## 0.2.0 · 2026-11-01

- Experiment 02: a read-only urlscan.io client (`rastro.sources.urlscan`) expands a domain to the sites that loaded the same kit files, never submitting a scan. It failed its bar (14 of 20 seeds never scanned; the expansions found could not be confirmed), so `rastro investigate` does not use it. It needs a free API key in `URLSCAN_API_KEY`.
- The demo case file is published on GitHub Pages, in English and Spanish, by a new `pages` workflow; the README links to it.
- The brands live in a data file, `src/rastro/assets/brands.txt` (`key | Name | official domains`), and `rastro --brands FILE` adds your own to any command.
- The network clients give up at once on answers that will not change (a 404, a 400) instead of retrying them, and wait as long as a server's Retry-After asks, up to five minutes.
- Cached DNS answers expire after a day; a stale one is used only when the resolver does not answer.
- Tests for the crt.sh, CT log, DNS and RDAP clients against scripted servers, and for the live watch against a fake log that grows as a fake clock runs.
- Rastro installs from GitHub, not PyPI: `pipx install git+https://github.com/Ruby570bocadito/rastro`. Each tag publishes a GitHub release with the wheel and the source archive.

## 0.1.1 · 2026-10-31

- Links on free hosting platforms (pages.dev, web.app, github.io, vercel.app and others) are investigated as the site they are, not as the platform: each subdomain is its own registrable name, RDAP is not asked about it, and its abuse report draft goes to the platform. Siblings that no longer resolve stay out, with their reason.
- Brands written to look like the real thing are recognised: punycode homographs (Cyrillic or Greek letters), a lone digit for a letter (paypa1, app1e, 5team) and letter pairs (arnazon, vvhatsapp). A number is never read as letters.
- A brand found only in a subdomain (amazon.co.uk.login-check.top) names the target, and Husmo says the siblings are searched by the registrable name.
- `rastro investigate` refuses IP addresses and link shorteners with a reason, instead of investigating `2.4` or `bit.ly`.
- Experiment 07b: the name model with benign names checked by age through RDAP. Worse than 07 (too few benign names, 131 of them with a brand), so still no model ships; the notes say what data the next try needs.
- The RDAP, DNS, crt.sh and CT clients retry on any network failure, such as a server closing the connection without answering, instead of stopping a long run.
- RDAP keeps the registration date even when a registry gives no time of day.
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
