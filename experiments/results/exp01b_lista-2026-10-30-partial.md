# Experiment 01b · human rhythm in domains from a public phishing list

Run on 2026-10-30. Domains from Phishing.Database (phishing-domains-ACTIVE.txt, MIT licence), 6,474 registrable domains, grouped by the brand in their name. Each sampled domain was looked up on crt.sh and timed by its first certificate (Let's Encrypt notBefore + 1 h).

## apple

- In the list: 1,002 · looked up: 45 · timed: 29 · first certificate not from Let's Encrypt: 14 · no certificate: 2
- First certificates between 2017-06-30 and 2024-05-20
- Human rhythm: **no** (p = 0.6457)
- Most probable offset: UTC+8 · 93% band: UTC to UTC−4 · estimated bot share: 90%
- Entropy: 3.93 bits (a flat day is 4.58)

```
00h UTC                                  0
01h UTC ███████████                      1
02h UTC ███████████                      1
03h UTC ████████████████████████████████ 3
04h UTC ███████████                      1
05h UTC ███████████                      1
06h UTC █████████████████████            2
07h UTC █████████████████████            2
08h UTC ████████████████████████████████ 3
09h UTC █████████████████████            2
10h UTC                                  0
11h UTC                                  0
12h UTC ███████████                      1
13h UTC ███████████                      1
14h UTC ████████████████████████████████ 3
15h UTC ███████████                      1
16h UTC █████████████████████            2
17h UTC                                  0
18h UTC                                  0
19h UTC ███████████                      1
20h UTC                                  0
21h UTC ████████████████████████████████ 3
22h UTC ███████████                      1
23h UTC                                  0
```

Weekday (UTC): Mon 3 · Tue 3 · Wed 3 · Thu 6 · Fri 7 · Sat 3 · Sun 4

## facebook

- In the list: 953 · looked up: 45 · timed: 4 · no certificate: 8 · not looked up yet: 32 · first certificate not from Let's Encrypt: 1
- too few timed domains (< 20)

## metamask

- In the list: 279 · looked up: 45 · timed: 0 · not looked up yet: 45
- too few timed domains (< 20)

## paypal

- In the list: 253 · looked up: 45 · timed: 0 · not looked up yet: 45
- too few timed domains (< 20)

## steam

- In the list: 260 · looked up: 45 · timed: 0 · not looked up yet: 45
- too few timed domains (< 20)

## santander

- In the list: 78 · looked up: 45 · timed: 0 · not looked up yet: 45
- too few timed domains (< 20)

## usps

- In the list: 66 · looked up: 45 · timed: 0 · not looked up yet: 45
- too few timed domains (< 20)

## Verdict

Only 1 brand(s) had enough timed domains, which is not enough to apply the kill criterion.

## Caveats

- A brand group mixes every crew that imitated it. A rhythm here is a lower bound on what one campaign shows, and the offset is the dominant crew's at best.
- Domains whose first certificate came from another CA are left out, which may favour crews that use Let's Encrypt.
- Daylight saving time is ignored, so offsets can blur by an hour across the year.
- The list holds domains that were still active when it was built; some first certificates are years old.
- Brand matching is by name. A few domains may be unrelated businesses that happen to contain the word.
