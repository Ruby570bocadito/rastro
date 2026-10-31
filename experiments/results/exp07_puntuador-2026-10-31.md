# Experiment 07 · a model of the name alone

Run on 2026-10-31. Positives: 116,474 registrable domains listed whole on Phishing.Database (1,180 hosting platforms and 39,683 domains listed only through a subdomain left out of training). Negatives: names from Let's Encrypt's Sycamore log. Later sample: 15,360 certificates, 11,172 names, about 14.8 million log entries a day.

## Cross-validation grouped by template

| Negatives | Count | AUC, all | Recall at 1 % FP | Recall at 0.1 % FP | AUC, names with a brand | Branded negatives | AUC, subdomain-only names |
|---|---:|---:|---:|---:|---:|---:|---:|
| all | 52,838 | 0.7858 | 21.8% | 7.3% | 0.8038 | 167 | 0.696 |
| no-brand | 52,759 | 0.7874 | 23.1% | 8.9% | 0.9255 | 72 | 0.6978 |

## The later sample, never trained on

46 names carry a brand. 63 names are on the list, all of them only through a subdomain. The old rule (a brand plus a throwaway shape) flags 6 names, about 5,770 a day.

### Negatives: all

| Threshold | Names flagged | A day | Listed names caught | With a brand |
|---:|---:|---:|---:|---:|
| 0.5 | 4,191 | 4,030,183 | 12 | 21 |
| 0.8 | 2,061 | 1,981,915 | 3 | 14 |
| 0.9 | 1,233 | 1,185,687 | 1 | 9 |
| 0.95 | 677 | 651,022 | 0 | 3 |
| 0.99 | 174 | 167,323 | 0 | 2 |
| 0.996 | 76 | 73,084 | 0 | 0 |
| 0.9999 | 8 | 7,693 | 0 | 0 |

### Negatives: no-brand

| Threshold | Names flagged | A day | Listed names caught | With a brand |
|---:|---:|---:|---:|---:|
| 0.5 | 4,268 | 4,104,229 | 13 | 41 |
| 0.8 | 2,153 | 2,070,385 | 4 | 32 |
| 0.9 | 1,333 | 1,281,850 | 3 | 29 |
| 0.95 | 774 | 744,300 | 2 | 26 |
| 0.99 | 203 | 195,210 | 0 | 17 |
| 0.9958 | 101 | 97,124 | 0 | 11 |
| 0.9999 | 7 | 6,731 | 0 | 1 |

No name model ships: see [the notes](../README.md#07--a-model-of-the-name-alone). The flagged names stay in `data/raw/ct/exp07/`.
