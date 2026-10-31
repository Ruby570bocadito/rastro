# Experiment 06 · calendar clues for the map: how much data they need, and what they say

Run on 2026-10-30.

## Part 1 · simulated crews

4 kinds of crew (UTC+1 with European DST and a Saturday-Sunday weekend; UTC−6 with US DST; UTC+3 with no DST and a Friday-Saturday weekend; UTC+8 with neither), 40 crews of each per size, work sessions spread over two years. Share recovered:

| Sessions | Offset ±1 h | DST regime | Weekend |
|---:|---:|---:|---:|
| 25 | 82% | 27% | 65% |
| 50 | 96% | 38% | 87% |
| 100 | 99% | 42% | 96% |
| 200 | 100% | 61% | 99% |
| 400 | 100% | 72% | 100% |

## Part 2 · the real families

### coinbase (88 sessions, p < 0.0001)

- Most probable UTC−8, band UTC−9 to UTC−6
- Daylight saving: **inconclusive** (us 34%, none 27%, south 22%, eu 17%)
- Weekend: **none** (none 93%, sun 5%, fri-sat 2%, sat-sun 0%)
- Holidays: Chinese New Year: seen 2, expected 1.5 (not enough data); Christmas and New Year: seen 2, expected 1.9 (not enough data); Eid al-Fitr: seen 0, expected 0.6 (not enough data); Orthodox Christmas: seen 0, expected 0.6 (not enough data)

### whatsapp (19 sessions, p = 0.0006)

- Most probable UTC+1, band UTC−1 to UTC+3
- Daylight saving: **inconclusive** (south 31%, us 26%, none 24%, eu 19%)
- Weekend: **inconclusive** (fri-sat 96%, none 2%, sat-sun 1%, sun 0%)
- Holidays: Chinese New Year: seen 0, expected 0.3 (not enough data); Christmas and New Year: seen 0, expected 0.4 (not enough data); Eid al-Fitr: seen 0, expected 0.1 (not enough data); Orthodox Christmas: seen 0, expected 0.1 (not enough data)

### amazon (51 sessions, p = 0.0010)

- Most probable UTC+2, band UTC to UTC+4
- Daylight saving: **inconclusive** (eu 32%, us 29%, none 24%, south 15%)
- Weekend: **none** (none 95%, fri-sat 4%, sat-sun 0%, sun 0%)
- Holidays: Chinese New Year: seen 1, expected 1.1 (not enough data); Christmas and New Year: seen 0, expected 1.4 (not enough data); Eid al-Fitr: seen 0, expected 0.4 (not enough data); Orthodox Christmas: seen 0, expected 0.5 (not enough data)

### dhl (27 sessions, p = 0.4315)

- Most probable UTC+4, band UTC−6 to UTC−11
- Daylight saving: **inconclusive** (none 25%, eu 25%, us 25%, south 25%)
- Weekend: **inconclusive** (sun 51%, sat-sun 40%, fri-sat 5%, none 4%)
- Holidays: Chinese New Year: seen 0, expected 0.5 (not enough data); Christmas and New Year: seen 0, expected 0.7 (not enough data); Eid al-Fitr: seen 2, expected 0.2 (not enough data); Orthodox Christmas: seen 0, expected 0.2 (not enough data)
