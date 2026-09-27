# Blind detection check

The detection scoreboard compares ATDR's rules with the team's labels, but
those labels were made while the rules were being tuned, mostly on logs where
ATDR and the labels disagreed, and often with ATDR's verdict in view. Its
numbers (F1 94% after the label review) measure agreement, not accuracy. The
blind check measures accuracy.

## Method

1. **Unseen traffic.** ATDR's database holds 20 May 13:36:15–13:39:30. The MFU
   file continues to 13:57, and those later lines were never imported, labeled
   or used for tuning. Lines 319,644–773,551 (13:45–13:57, 453,908 logs) are
   imported into a separate database, `.tmp/blind_check/holdout.db`, with the
   same parser and storage code as a normal import. The live database is not
   touched.
2. **Current rules.** Detection runs over the whole holdout with the rules as
   they are (catalog v5.32.0). The test window is 13:50–13:55, one full
   5-minute detection window with traffic on both sides for context.
3. **Stratified random sample.** Each unique log in the window falls into one
   of three groups:

   | Group | Logs in window | Sampled |
   |---|---|---|
   | Alerted by ATDR | 21,461 | 60 |
   | Not alerted, but notable from raw fields (denied/reset, app risk 4-5, unknown app, firewall threat log) | 53,496 | 45 |
   | Everything else | 113,221 | 45 |

   The groups only decide how many logs are drawn from where; they are never
   shown. Seed 20260927.
4. **Blind labeling.** The team labels each log as Threat, Normal, Normal but
   unusual or Unsure, from the log's fields and plain context: what the same
   source did within 2.5 minutes, and how many sources hit the same
   destination and port. Rows are shuffled, and the sheet contains nothing
   from ATDR. Labelers must not look the IPs up in ATDR. The answer key
   (`key.json`) is kept apart.
5. **Scoring.** Each group's threat share is scaled up to the group's size,
   which gives window-wide estimates of precision (share of alerted logs that
   are threats), recall (share of all threats that were alerted) and the
   false-alarm rate (share of harmless logs that were alerted). 95% intervals
   come from 2,000 bootstrap resamples within the groups. "Unsure" labels are
   left out and reported.

All numbers are per log, the same unit as the detection scoreboard: a scan of
500 logs counts as 500.

## Reading the result

- Precision rests on 60 alerted samples, so its interval will be fairly tight.
- Recall depends on how many threats hide in the 113,221 "everything else"
  logs. One "Threat" label among those 45 samples stands for about 2,500 logs,
  so the recall interval will be wide. That is the real uncertainty of
  measuring rare misses with 150 labels, not a flaw in the method.
- The same labeled set will later be the test set for the MFU-trained ML
  model, so rules and ML can be compared on identical, unseen logs.

## Commands

```
python -m atdr.scripts.blind_check prepare --log-file "C:\path\paloalto-firewall(1).log"
python -m atdr.scripts.blind_check score --decisions .tmp/blind_check/decisions.csv
```

`prepare` reuses `holdout.db` if it exists. `score` reads a CSV with columns
`sample_id` and `decision` and writes `.tmp/blind_check/score.json`. The files
under `.tmp/blind_check/` contain real MFU IP addresses and stay private to
the team.
