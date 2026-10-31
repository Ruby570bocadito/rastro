# Validation experiments

Each experiment answers one question from the plan before we build on it. Raw downloads stay in `data/raw/` (not committed); aggregated results go to `results/`.

## 01 · Human rhythm in lookalike domains

**Question.** Do the first certificates of lookalike domains follow a human working day, or are they spread round the clock like bot activity?

**Method.** `exp01_ritmo.py` takes, for each brand, the suspicious lookalike domains, the issuance time of each one's first certificate, and tests those hours against round-the-clock activity (`rastro.rhythm`).

**Kill criterion.** Fewer than 2 brands with a rhythm (p < 0.01) → the time-zone map becomes a secondary clue and the next-domain watch becomes the star.

**First run, 2026-10-30: inconclusive, the data source fell short.**

- crt.sh wildcard searches (`%correos%`) return a small, partial sample: 1,455 certificates for "correos", only 14 of them with a usable time, and 6 suspicious domains. "tributaria" and "dhl" gave none.
- crt.sh rejects wildcards in the middle of a query (`%correos%.top` → "Unsupported use of '%'"), and TLD-wide searches answer 502.
- crt.sh JSON never includes the CT log time, and exact searches stop at 5,000 rows.
- The timing itself works. Let's Encrypt backdates notBefore by one hour; checked on two certificates (R3 in 2021, E8 in 2025), the CT log time was notBefore + 1 h within two minutes.

**Next.** Discovery needs another source. Options, in order of preference:

1. urlscan.io search API (free account and key): finds the sibling domains of one campaign by shared page files. This is experiment 02, and it also gives exp01 single-campaign clusters instead of brand-wide mixes.
2. A public list of reported phishing domains, filtered by brand, then one exact crt.sh lookup per domain.
3. crt.sh's public read-only SQL interface, which has full results and log times but needs a Postgres client.

## 01b · The same test on a public phishing list

**Why.** Experiment 01 could not find enough domains through crt.sh alone.

**Source.** `phishing-domains-ACTIVE.txt` from [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) (MIT licence, 10.5 MB, 392,178 lines, downloaded 2026-10-30 to `data/raw/lists/`, not committed). 6,474 registrable domains carry a brand name; Apple, Amazon and Facebook lead, and Santander is the top Spanish brand with 78.

**Method.** `exp01b_lista.py` groups domains by the brand in their registrable name (shared-hosting subdomains are left out because they carry the platform's certificate), samples up to 45 per brand, looks each one up on crt.sh (cached, 1.5 s between requests) and runs the rhythm test on the issuance time of each domain's first certificate.

**Run.** `python -I experiments/exp01b_lista.py --brands apple facebook metamask paypal steam santander usps`

**Partial result, 2026-10-30 (stopped after Apple).** Apple's 45 sampled domains gave 29 timed first certificates spread from 2017 to 2024, with no rhythm (p = 0.65) and a fitted bot share of 90 %. A brand group mixes years of different crews, so their days cancel out. Lookups also ran at about 14 s each, an hour for the full run. The run was stopped and replaced by 01c, which tests families that share a naming template. Cached answers stay in `data/raw/crtsh-domains/`, and `--offline` re-analyses them without network.

## 01c · Human rhythm per template family

**Why.** A family that shares a narrow naming template is much more likely to be one crew than a whole brand group.

**Method.** `exp01c_familias.py` takes families from the public list (same brand, same token layout, a learned pattern of at most 10^25 names, at most half on closed Freenom TLDs), times the first certificate of up to 50 domains each, and tests the rhythm over the whole family and inside its busiest 120-day burst.

**Families.** `\d{4,8}-coinbase.com` (94 domains), a WhatsApp group-invite family (75), `[a-z]{0,3}amazon[a-z]{0,5}\d{1,4}` (63) and a DHL tracking family (28).

**Run.** `python -I experiments/exp01c_familias.py --families 4 --min-family 25 --narrow 25 --per-family 100`

**Two fixes made along the way.**

- First certificates from CAs other than Let's Encrypt are now timed from their crt.sh certificate page, which shows the exact CT log time. In the Coinbase family this recovered 34 of 91 timed domains.
- The test now counts work sessions, not domains: first certificates less than 30 minutes apart count once. Counting domains had inflated the WhatsApp burst, 64 domains in only 11 sessions.

**Final results, 2026-10-30.** Whole families, tested by work session with 20,000 simulations. Four families are tested, so the bar is corrected to p < 0.0025.

| Family | Timed domains | Days | Sessions | p | Most probable (band) |
|---|---:|---:|---:|---:|---|
| `\d{4,8}-coinbase.com` | 92 | 80 | 88 | < 0.0001 | UTC−7 (UTC−9 to UTC−5) |
| WhatsApp group-invite family | 75 | 11 | 19 | 0.0008 | UTC+2 (UTC to UTC+4) |
| `[a-z]{0,3}amazon[a-z]{0,5}\d{1,4}` | 63 | 50 | 51 | 0.0014 | UTC+3 (UTC+1 to UTC+5) |
| DHL tracking family | 27 | 27 | 27 | 0.44 | none (looks round-the-clock) |

**Verdict.** 3 of 4 families pass the corrected test, so the time-zone map stays as a main piece, always with its "inconclusive" answer when the test fails, as it did for DHL.

**How much to trust it.**

- The interim reading earlier the same day was more pessimistic, because it had partial data and coarser p-values (2,000 simulations). Amazon went from 54 to 63 timed domains, and the finer test moved WhatsApp and Amazon under the corrected bar.
- The criterion (whole family, work sessions, corrected bar) was set after experiment 01b and after seeing part of these results. DHL, the only family judged blind, failed. It is small (27 sessions over nine years) and probably mixes crews, but it is a reminder that the rhythm does not show up everywhere.
- Bursts alone are weak evidence: WhatsApp's 68 domains in four days are only 12 sessions (p = 0.013).
- The Coinbase family registered almost one domain per sitting for two years, with a clear working day in the Americas' time zones. That is where their day falls, not proof of where anyone is.

## 03 · Learned naming patterns (offline proxy for the next-domain watch)

**Question.** After seeing 10 domains of a family, how many of its other domains does the learned pattern catch, and how many unrelated domains does it match?

**Method.** `exp03_patron.py` builds families from the public list (same imitated brand and same token layout, at least 15 domains), takes the 40 largest, learns a pattern from 10 domains of each (`rastro.pattern`) and scores it on the rest of the family and on every other domain in the list.

**Results, 2026-10-30.**

| Version | Change | Median recall | Matches outside the family |
|---|---|---:|---:|
| v1 | slots become vocabularies, digit ranges or letter classes | 49 % | 407,508 |
| v2 | a core shared inside a slot (the brand) stays literal | 53 % | 46,332 |
| v3 | a core that moves between slots is required anywhere | 53 % | 218 |

Narrow patterns (at most 10^9 possible names) appear in 5 of the 40 families. They catch a median 87 % of their siblings with no match outside the family. Template families such as `facebook-business-help-center-…` (99 %) and `\d{5,8}-coinbase.com` (96 %) are exactly what the live watcher should arm.

**Limits.** Families are grouped by brand and layout, not by confirmed campaign. There are no benign names in the test yet, so the real false-alarm rate needs a day of Certificate Transparency names from the live watcher.

## 04 · False alarms on fresh Certificate Transparency names

**Question.** How often would the 40 patterns from experiment 03 fire on real, benign traffic?

**Method.** `exp04_falsas_alarmas.py` reads Let's Encrypt's Sycamore 2027h1 log directly (`rastro.sources.ctlog`, static CT API, no crt.sh), takes 120 tiles of 256 certificates spread over the last hours, and counts matches. Matched names stay in `data/raw/ct/`, out of the repository.

**Results, 2026-10-30.** The run covered 30,720 certificates logged between 08:42 and 17:22 UTC, with 21,043 distinct registrable domains. The log takes about 16.9 million entries a day.

- The 5 narrow patterns matched **nothing**. With this sample size, the 95 % upper bound is about 1,650 alarms a day for all five together; reading a full day of the log would bring the bound to about 3.
- The 35 broad patterns matched 12 certificates, about 6,600 alarms a day. Almost all were legitimate, including the brands' own domains (`microsoftonline.com`, `chaseonline.com`) and a news site about Apple.

**What it means.** Only narrow patterns should be armed live. The watcher also needs an allowlist of each brand's official domains.

## 05 · Campaigns inside the template families

**Question.** Do the template families of 01c break into campaigns once certificates, timing and infrastructure are added?

**Method.** `exp05_campanas.py` runs `rastro.campaigns` on the 260 domains of the four families. It uses three sources: names that shared a certificate (crt.sh), the time of each domain's first certificate, and today's addresses and name servers from a public DNS-over-HTTPS resolver.

**Results, 2026-10-30.**

- Only 6 of the 260 domains still resolve, and none shared a certificate with another. For old families, infrastructure adds almost nothing; the clues that work are template and timing.
- With the session clue alone (30 minutes), the WhatsApp launch split into 10 pieces, one per sitting. A launch clue was added: same brand and template, each domain within 72 hours of the previous one, weight 0.5.
- With it, the WhatsApp family is **one campaign of 68 domains** over four days, and the 7 left are older strays.
- The Coinbase family comes in **waves**: 63 domains in 17 campaigns (the largest, 14 domains from 22 October to 3 November 2024), and 31 on their own. Without shared infrastructure the waves stay apart. Their common rhythm (01c) suggests one crew, but that is not proof.
- No campaign spans two families.

**On fresh domains it is different.** The two "microsofterrorfound" domains from the live trial join through three independent clues: the same distinctive word, the same rare address, and the same sitting.

**Reading.** Rastro has two levels: a crew, recognised by template and rhythm across months, and its launches, the campaigns. The live watcher works at the second level.

## 06 · Calendar clues for the map

**Question.** How much data do the daylight-saving, weekend and holiday clues need, and what do they say about the real families?

**Method.** `exp06_pistas_mapa.py` simulates crews with a known offset, DST regime and weekend (four kinds, 40 crews each per size, sittings spread over two years) and counts how often `rastro.calendar_clues` gets each right. Then it analyses the families of 01c.

**How often each clue is right (best guess, simulated crews).**

| Sessions | Offset ±1 h | DST regime (chance = 25 %) | Weekend |
|---:|---:|---:|---:|
| 25 | 82 % | 27 % | 65 % |
| 50 | 96 % | 38 % | 87 % |
| 100 | 99 % | 42 % | 96 % |
| 200 | 100 % | 61 % | 99 % |
| 400 | 100 % | 72 % | 100 % |

The weekend is a good clue from about 50 sessions. DST is weak and needs hundreds. Holiday gaps never had enough expected activity to judge in these families.

**A trap found and closed.** At first the WhatsApp family came out with a Friday-Saturday weekend at 96 %. Its launch ran from a Sunday to a Wednesday, so it says nothing about weekends. Each clue now has a bar, and below it Rastro answers "inconclusive":

- weekend: at least 50 sessions over 8 or more weeks, and 80 % for the best weekend;
- DST: at least 200 sessions and 60 % for the best regime.

**The real families.**

- **Coinbase** (88 sessions): about UTC−8 (band UTC−9 to UTC−6). DST is inconclusive (US 34 %, none 27 %). **No weekend at all** (93 %): they work all seven days.
- **Amazon** (51 sessions): about UTC+2 (band UTC to UTC+4). DST is inconclusive. **No weekend** (95 %).
- **WhatsApp** (19 sessions, a four-day launch): weekend and DST inconclusive.
- **DHL**: no rhythm, nothing to add.

**Reading.** Crews that work every day cannot be placed by their weekend, but that itself says they are not office workers on a timetable. To place a crew more precisely, the clue to collect is more sessions, not more kinds of clue.

## Live trial · five minutes of Let's Encrypt, 2026-10-30

`rastro watch --follow` ran for five minutes against Sycamore 2027h1 with four narrow family patterns armed and burst detection on.

- It read 46,336 certificates (26,667 distinct registrable domains) and never fell more than one tile behind the log.
- The armed family patterns raised no alert. Those families are from 2023 to 2025.
- Six fresh names carried a brand and the shape of a throwaway lookalike.
- Burst detection, with no seed, flagged two punycode domains built around the same long word, "microsoft" plus "error found", logged in the same minute. That is the usual shape of a tech-support scam. It took a second grouping rule to catch them: the same long word around the brand, even when the layout differs.
- The names are kept in `data/raw/ct/`, out of the repository, and none of them has been verified.

## Live trial · one link, end to end, 2026-10-30

A filtered watch read 10,240 fresh certificates from Sycamore 2027h1 and kept 18 of them (0.18 %, 48 KB), the ones carrying a brand lookalike. Among them was a domain built from the Coinbase crew's template of experiment 01c, `\d{4,8}-coinbase\.com`, which is not on the public list. Its certificate that day was a renewal: RDAP says the domain was registered on 2025-11-10.

`rastro investigate` on it, with crt.sh answers cached since experiment 01c, RDAP from the .com registry and public DNS:

- **Crew:** 95 domains built from the template (94 on the list, plus the seed), first seen from 2023-08-25 to 2025-12-03.
- **Campaign:** the seed alone. No other domain of the crew came within 72 hours of it, so it went out on its own.
- **Today:** 85 are no longer registered and 9 are still registered but suspended. Only the seed is live, so it gets the only abuse report draft. 5 of the 10 still registered are with the seed's registrar.
- **Clock:** 102 timed actions in 93 work sessions, first certificates plus the registrations whose first certificate followed within 30 days. Most probable UTC−7, 90 % band UTC−8 to UTC−5, p = 0.0002. Experiment 01c found UTC−7 from first certificates alone, so the second clock agrees with the first.

The seed's name and the case files stay in `data/raw/`, out of the repository.

## 07 · A model of the name alone

**Question.** Can a small machine-learning model, looking only at a domain's name, rank fresh certificate names by how much they look like phishing, so the watcher could find lookalikes without a seed, a brand or a pattern?

**Method.** `src/rastro/scorer.py`: logistic regression on 2^18 hashed features of the name (character 3- to 5-grams, words, the ending, the brand it carries, length, hyphens, digits, punycode), trained by AdaGrad in pure Python. Positives: the 116,474 registrable domains that Phishing.Database lists whole (the bare name or www), so they were registered for phishing. Left out: 1,180 hosting platforms (ten or more listed host names, such as duckdns.org or github.io) and the 39,683 domains listed only through a subdomain, a mix of tricks like amazon.x1g.top and hacked legitimate sites. Negatives: 52,838 registrable names from 160 tiles of Let's Encrypt's Sycamore log, plus the five-minute live sample. Measured three ways: five-fold cross-validation grouped by template, so no family sits on both sides; the subdomain-only names, never trained on; and a later sample of 60 tiles (15,360 certificates, 11,172 names) never trained on. `experiments/exp07_puntuador.py`, results in `results/exp07_puntuador-2026-10-31-*.json`.

**Result.**

| | ROC AUC | Recall at 1 % false positives | Recall at 0.1 % |
|---|---:|---:|---:|
| All names, grouped cross-validation | 0.79 | 22 % | 7 % |
| Names that carry a brand (167 negatives) | 0.80 | | |
| Listed only through a subdomain, never trained on | 0.70 | 12 % | 3 % |

On the later sample, every threshold strict enough to keep false alarms under about 7,000 a day caught none of the fresh names already on the list, and a threshold of 0.99 would flag about 167,000 names a day. The highest scores went to random-looking strings and to ordinary names in languages other than English.

**What went wrong, and why it matters.**

- **The negatives are not clean.** Certificate Transparency carries the live campaigns too. A batch of facebook--signup-… names on .ph sat among the training negatives, so the model learned them as normal and gave the same campaign almost 0 in the later sample, while the old rule (a brand plus a throwaway shape) flagged some of them.
- **Leaving brand names out of the negatives does not fix it.** With the brands' official domains as the only branded negatives, the campaign rose to between 0.77 and 0.999, but the model learned that any brand means phishing: microsoftonline.com scored 0.93 and ordinary businesses with a brand inside their name about 0.99. The branded AUC of 0.93 in that variant only measures brands against their own official domains.
- **Base rates.** Phishing is a tiny share of the millions of names a day in the log, so a name-only model needs a false-positive rate far below what it reaches here before its alerts mean anything.

**Decision.** No name model ships with Rastro, and Husmo gives no name score by default. The code stays for experiments: `--save FILE` keeps a trained model, and `--name-model FILE` adds its scores to `rastro score`, `rastro investigate` and `rastro watch`. The next attempt needs clean benign names, for example domains registered years ago, still alive and never listed, read through RDAP.

## 02 · Expansion from one URL

Pending. Does one URL expand to at least 10 sibling domains in 2 minutes with the free urlscan quota plus crt.sh?
