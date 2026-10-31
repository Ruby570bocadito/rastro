# Experiment 04 · false alarms of learned patterns on fresh CT names

Run on 2026-10-30. 30,720 certificates from 120 tiles of `https://mon.sycamore.ct.letsencrypt.org/2027h1`, one tile every 200, logged between 2026-10-30 08:42 and 17:22 UTC: 21,043 distinct registrable domains. This log takes about 16.9 million entries a day (pre-certificates and certificates).

- Narrow patterns (at most 10^9 names): 5. Certificates they match in the sample: **0**, about **0 alarms a day** on this log.
- Broad patterns: 35. Certificates matched: 12, about 6,592 alarms a day.

| Brand | Pattern | Breadth (log10) | Names matched | Alarms a day |
|---|---|---:|---:|---:|
| facebook | `facebook\-(form|fr|issues|metaplasform|problems)\d{1,3}\.(gq|ml|tk)` | 4.22 | 0 | 0.0 |
| amazon | `(amazon|amazoncom|amazonl|amazontfyg)\d{1,3}\.(cc|com|net|vip)` | 4.25 | 0 | 0.0 |
| facebook | `(?=.*\-checkpoint)facebook\-(business|checkpoint)\-(help|policy)\-(center|violation)\-(fanpage|social)\-(checkpoint|network)\d{1,3}\.ml` | 4.55 | 0 | 0.0 |
| facebook | `(facebook|facebookreport)\d{2,5}\.(cf|ml|tk)` | 5.82 | 0 | 0.0 |
| coinbase | `\d{5,8}\-coinbase\.com` | 8.05 | 0 | 0.0 |
| whatsapp | `(?=.*\-whatsapp)(app|lnstagram)\-[a-z]{3,8}\-(whatsapp|whatsappcc)\.(com|ml)` | 12.24 | 0 | 0.0 |
| usps | `(amazon|info|redeliverys|usps)\-[a-z]{3,8}\.(com|shop|top|xyz)` | 12.54 | 0 | 0.0 |
| icloud | `(icloud|icloudsign|iphone)\-[a-z]{2,8}\.(co|com|info|me|net|online|support)` | 12.66 | 0 | 0.0 |
| amazon | `(aft|amazon)\-[a-z]{1,9}\.(fr|ga|icu|live|shop|tk|top|xyz)` | 13.96 | 0 | 0.0 |
| telegram | `(a|auth|d|m|telegram)\-[a-z]{1,9}\.(biz|me|net|org|pro|ru|site|vip)` | 14.35 | 1 | 549.3 |
| paypal | `(au|aus|paypal)\-[a-z]{5,12}\.(com|net|org|pro|shop|site)` | 18.25 | 0 | 0.0 |
| netflix | `(aviso|netflix)\-[a-z]{3,14}\.(com|org|xyz)` | 20.6 | 0 | 0.0 |
| whatsapp | `[a-z]{0,8}whatsapp[a-z]{0,7}\.(com|live|ml|site|tk|vip)` | 22.04 | 0 | 0.0 |
| apple | `(apple|mono)\-[a-z]{3,8}\-[a-z]{4,7}\-(apple|online|portal|support)\.com` | 22.16 | 0 | 0.0 |
| ledger | `(info|ledger|recovery|validate)\-[a-z]{2,15}\.(com|live|net|org)` | 22.45 | 0 | 0.0 |
| icloud | `(?=.*icloud\-)(icloud|id|iforgo|info)\-[a-z]{2,8}\-[a-z]{2,7}\.(com|info|net|support|us|ws)` | 22.64 | 0 | 0.0 |
| instagram | `(copyrightcenter|copyrightk|instagram|instagramsupporter|m)\-[a-z]{2,15}\.(com|de|ga|live|org|ru|tk)` | 22.79 | 1 | 549.3 |
| apple | `[a-z]{0,5}apple[a-z]{4,11}\.(cc|com|live|top|us)` | 23.37 | 2 | 1,098.6 |
| ledger | `[a-z]{0,4}ledger[a-z]{0,12}\.(claims|com|help|live|us|vip)` | 23.45 | 1 | 549.3 |
| apple | `(apple|applecareconnect|appleid|depconnect|https)\-[a-z]{3,8}\-[a-z]{3,8}\.(cloud|com)` | 23.67 | 0 | 0.0 |
| facebook | `facebook\-(paymant|verifyissue)\-(meta|updates)\d{3,24}\.tk` | 24.65 | 0 | 0.0 |
| paypal | `(?=.*paypal\-)(account|paypal)\-[a-z]{4,9}\-[a-z]{2,8}\.(cf|com|net|org)` | 24.99 | 0 | 0.0 |
| apple | `(?=.*apple)[a-z]{3,11}\-[a-z]{2,7}\.(com|info|live|services|store)` | 26.2 | 0 | 0.0 |
| whatsapp | `(?=.*whatsapp)[a-z]{2,8}\-[a-z]{2,10}\.(cc|com|gq|site|xyz)` | 26.2 | 0 | 0.0 |
| amazon | `[a-z]{0,7}amazon[a-z]{0,11}\.(club|live|monster|shop|top|xyz)` | 26.28 | 0 | 0.0 |
| instagram | `instagram[a-z]{3,19}\.(com|dev|ga|ml|org|site|tk)` | 27.75 | 0 | 0.0 |
| amazon | `(amazon|identity|relay)\-[a-z]{2,13}\-[a-z]{2,6}\.(com|icu|shop|top|xyz)` | 28.09 | 0 | 0.0 |
| metamask | `(?=.*metamask)[a-z]{2,12}\-[a-z]{4,8}\.(app|co|com|net|online|org)` | 29.11 | 0 | 0.0 |
| icloud | `[a-z]{0,12}icloud[a-z]{0,10}\.(app|cn|com|info|pl|pro)` | 31.94 | 1 | 549.3 |
| microsoft | `[a-z]{0,7}microsoft[a-z]{0,15}\.(co|com|de|ml|net|ru)` | 31.94 | 1 | 549.3 |
| steam | `[a-z]{0,9}steam[a-z]{0,15}\.(com|net|ru|shop|world)` | 34.69 | 3 | 1,647.9 |
| paypal | `[a-z]{0,9}paypal[a-z]{0,15}\.(cf|co|com|ml|net|tk)` | 34.77 | 0 | 0.0 |
| whatsapp | `(?=.*whatsapp)[a-z]{3,14}\-[a-z]{1,8}\d{1,4}\.(cf|com|gq|ml|tk|xyz)` | 35.99 | 0 | 0.0 |
| metamask | `[a-z]{0,14}metamask[a-z]{0,12}\.(com|lt|navy|ro|run|top)` | 37.6 | 0 | 0.0 |
| coinbase | `(?=.*coinbase)[a-z]{4,15}\-[a-z]{2,13}\.(biz|com)` | 39.95 | 0 | 0.0 |
| chase | `[a-z]{0,14}chase[a-z]{0,15}\.(cf|com|info|ml|studio)` | 41.77 | 1 | 549.3 |
| steam | `(?=.*steam)[a-z]{2,13}\-[a-z]{4,16}\.(cfd|com|live|ru|top)` | 41.77 | 1 | 549.3 |
| netflix | `[a-z]{0,18}netflix[a-z]{0,17}\.(co|com|kr|me)` | 50.16 | 0 | 0.0 |
| facebook | `(?=.*facebook)[a-z]{2,18}\-[a-z]{3,18}\.(co|com|de|gq|tk|vn)` | 51.75 | 0 | 0.0 |
| facebook | `[a-z]{0,16}facebook[a-z]{0,22}\.(cf|co|com|ga|gq|info|net)` | 54.65 | 0 | 0.0 |

A match is not a confirmed phish: some are legitimate businesses, some may be the campaign's new domains. The matched names are kept out of the repository, in `data/raw/ct/`.
