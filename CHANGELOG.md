# Changelog

## Unreleased

- Official domains for 30 brands that had none, most of them Spanish (Movistar, Vodafone, Iberdrola, Endesa, Naturgy, Bizum, Bankinter, Sabadell...), and for AWS: 58 of 61 brands have them now, so the watcher no longer stores the brands' own sites as lookalikes. Each was checked in DNS, the less obvious ones through RDAP.
- A live run of the watcher (experiments: live trial) found the lookalike readings added no noise; the plain substring rule's innocents (purchase, pineapple) are documented for a future experiment.
- Sinkholes. A domain whose address has reverse DNS saying "sinkhole" is already neutralized: it stays out of the abuse drafts (`sinkholed`), counts as down, and its address never ties two domains into one campaign, since a sinkhole holds names from many unrelated crews. On 2026-11-01, 22 of 28 listed duckdns.org names that resolved pointed at one security company's sinkhole.
- Duck DNS is dynamic DNS, not hosting: its name points at its owner's own server, so that address counts as a clue again, unlike a hosting platform's shared addresses. Husmo explains it.
- `dns.reverse` asks the public resolver for an address's reverse DNS name, never the address itself.
- `rastro track` records a new state, `sinkholed`, and counts it as a takedown: a name a security team took over no longer looks live forever, and the scoreboard times it like any other takedown.
- Checked live on two branded duckdns.org names from the public list: the sinkholed one gets no draft, the other gets one for Duck DNS. Husmo no longer calls a sinkhole the crew's own server, and says "the only attributed domain is the seed" instead of "of the 1 attributed domains".

## 0.2.2 · 2026-11-01

- Tested live on three real seeds (a registry domain, a pages.dev site and a vercel.app site) against crt.sh, RDAP and DNS. What it showed is fixed here:
  - 16 platforms serve every site under one certificate (crt.sh had none for two listed sites of each), so Rastro no longer asks crt.sh about their sites: the vercel.app case went from 334 to 82 seconds. Husmo says certificates cannot date such a site, and the README says the CT watcher cannot see them.
  - When there are more candidates than `--max-candidates`, the ones that share most words with the seed go first, instead of the first ones in alphabetical order.
  - A platform is its own ending: vercel.app and web.app sites no longer count as having the same TLD.
  - Husmo says one timed action in the singular.
- `rastro list update` downloads Phishing.Database's list of active phishing domains to where `rastro investigate` looks for siblings. It asks for it again only when it changed (the server's ETag), and a download that is not a list of domains, such as an error page, never replaces a good one. `rastro investigate` says when there is no list, instead of quietly finding fewer siblings.
- Fixed: `rastro investigate` crashed when it found the crew's template but no domain had a date, as with `--no-crtsh` or when crt.sh did not answer.
- Fixed, found by running every offline command with odd inputs: `rastro rhythm` crashed on an empty file or a line that is not a time, `rastro track add` on a `--since` that is not ISO 8601 and on alert or case files that are not what Rastro writes, and every command on a path that is missing or is a folder. Each now says what is wrong and exits with code 1 or 2. `rastro track add` also says which domains from alerts and cases it will not follow.

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
