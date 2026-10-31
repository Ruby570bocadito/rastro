# Experiment 01c · human rhythm per template family

Run on 2026-10-30. Families from Phishing.Database that share a brand, a token layout and a narrow naming template, with at most half of their domains on closed Freenom TLDs. First certificates timed through crt.sh (Let's Encrypt notBefore + 1 h).

## coinbase · `\d{4,8}\-coinbase\.com`

- Family size: 94 · looked up: 94 · timed: 92 · timed from its certificate page: 35 · no certificate: 2
- All of it: 92 domains on 80 days in 88 work sessions, 2023-08-25 to 2025-12-03: human rhythm **yes** (p < 0.0001), most probable UTC−7, 96% band UTC−9 to UTC−5, bots about 20%
- Busiest 120 days: 40 domains on 34 days in 39 work sessions, 2024-09-16 to 2025-01-12: human rhythm **yes** (p < 0.0001), most probable UTC−6, 95% band UTC−8 to UTC−4, bots about 10%

```
00h UTC █████████                      2
01h UTC █████████████                  3
02h UTC                                0
03h UTC                                0
04h UTC                                0
05h UTC                                0
06h UTC ████                           1
07h UTC                                0
08h UTC                                0
09h UTC                                0
10h UTC █████████                      2
11h UTC                                0
12h UTC                                0
13h UTC ████                           1
14h UTC ████                           1
15h UTC                                0
16h UTC █████████                      2
17h UTC █████████████                  3
18h UTC █████████████████████          5
19h UTC                                0
20h UTC ██████████████████████████     6
21h UTC ██████████████████████████████ 7
22h UTC ████                           1
23h UTC █████████████████████          5
```

## whatsapp · `(app|chat|gabung|grup|lnstagram|whatsapp)\-[a-z]{3,8}\-(aidhsoxbaox|com|group|hk|whatsapp|whatsappcc)\.(cf|com|ga|gq|ml|top)`

- Family size: 75 · looked up: 75 · timed: 75 · timed from its certificate page: 3
- All of it: 75 domains on 11 days in 19 work sessions, 2020-07-13 to 2025-10-08: human rhythm **yes** (p = 0.0008), most probable UTC+2, 95% band UTC to UTC+4, bots about 0%
- Busiest 120 days: 68 domains on 4 days in 12 work sessions, 2025-10-05 to 2025-10-08: human rhythm **no** (p = 0.0131), most probable UTC+2, 96% band UTC to UTC+5, bots about 0%

```
00h UTC                                0
01h UTC                                0
02h UTC                                0
03h UTC                                0
04h UTC                                0
05h UTC                                0
06h UTC                                0
07h UTC ██████████████████████████████ 2
08h UTC ███████████████                1
09h UTC ███████████████                1
10h UTC ███████████████                1
11h UTC ██████████████████████████████ 2
12h UTC ███████████████                1
13h UTC                                0
14h UTC ███████████████                1
15h UTC ███████████████                1
16h UTC                                0
17h UTC                                0
18h UTC                                0
19h UTC ██████████████████████████████ 2
20h UTC                                0
21h UTC                                0
22h UTC                                0
23h UTC                                0
```

## amazon · `[a-z]{0,3}amazon[a-z]{0,5}\d{1,4}\.(buzz|cc|com|net|online|shop|tokyo|top|vip|xyz)`

- Family size: 63 · looked up: 63 · timed: 63 · timed from its certificate page: 15
- All of it: 63 domains on 50 days in 51 work sessions, 2018-10-15 to 2025-03-14: human rhythm **yes** (p = 0.0014), most probable UTC+3, 95% band UTC+1 to UTC+5, bots about 30%
- Not enough timed domains in any 120-day burst (< 15).

## dhl · `(dhl|ge|mytracking|pound|qatar)\-[a-z]{2,14}\.(app|biz|cfd|com|fr|life|pl|site|support|top)`

- Family size: 28 · looked up: 28 · timed: 27 · no certificate: 1 · timed from its certificate page: 11
- All of it: 27 domains on 27 days in 27 work sessions, 2016-09-14 to 2025-06-03: human rhythm **no** (p = 0.4410), most probable UTC+5, 92% band UTC−6 to UTC−10, bots about 90%
- Not enough timed domains in any 120-day burst (< 15).

## Verdict

3 of 4 families pass the corrected test (p < 0.0025): coinbase, whatsapp, amazon. The time-zone map stays as a main piece.

This criterion (whole family, by work session, corrected for the number of families) was set after experiment 01b and after seeing part of these results. Only the families finished later were judged blind to it.

## Caveats

- The test counts work sessions (first certificates less than 30 minutes apart count once), not domains. The hour histograms above still show every domain.
- A shared template suggests one crew but does not prove it; kits are sold and copied.
- The offset is where the crew's working day falls, not proof of where anyone is.
- Domains whose first certificate came from another CA are left out.
- Daylight saving time is ignored, so offsets can blur by an hour.
