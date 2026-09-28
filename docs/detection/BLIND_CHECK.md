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

## Official blind result (2026-09-27, rule catalog v5.32.0, model mfu_behavior_v1)

This is the official blind evaluation. Its numbers are fixed. Rules changed
after these labels were read are reported further down as post-tuning second
looks, which never replace these numbers.

**How the labels were made.** All 150 rows were labeled by ChatGPT, asked to act
as a senior SOC analyst, on behalf of the ATDR team. The reviewer saw only the
workbook: no ATDR verdicts, alerts, dashboard or model output, and no IP
reputation lookups. Borderline one-packet probes were left "Unsure". So the
labels are blind to ATDR but come from one AI reviewer; the team has not yet
checked them. Until it has, this is an **independent blind reference labeling
performed without access to ATDR verdicts**, not ground truth (see "Human
verification" below). Decisions: 102 Normal, 13 Normal but unusual, 31 Threat,
4 Unsure (left out).

| Detector | Precision | Recall | False-alarm rate | F1 |
|---|---|---|---|---|
| Rules alone | 50.9% (95% interval 38.6-64.9%) | 81.8% (61.9-100%) | 6.0% | 62.7% |
| Behaviour model alone | 74.4% | 65.5% | 1.7% | 69.7% |
| Rules or model | 53.5% | 90.9% | 6.0% | 67.4% |

Rule precision by alert type in the sample (Threat / judged):

| Alert type | Precision | What the reviewer saw in the false alarms |
|---|---|---|
| Port scan | 12/12 | |
| Horizontal scan | 13/13 | |
| Multiple denied connections | 1/1 | |
| Unusual destination port | 3/5 (3 Unsure) | normal inbound web services |
| Connection flood | 0/13 | ordinary outbound SSL, QUIC, WeChat and DNS-over-HTTPS; one SNMP monitor |
| Very high application risk | 0/9 | BitTorrent file sharing ("policy-relevant, not an attack") |
| Unknown or incomplete app | 0/3 | peer-to-peer UDP |
| Beaconing | 0/1 | one two-way SSL session on port 4433 |

The two threats the rules missed were small probing bursts from outside
(10-16 unanswered attempts over 5-8 hosts); the model caught one of them.

Reading it:

- This is the honest number. The scoreboard's F1 94% measured agreement with
  labels made while tuning; blind, the rules' F1 is about 63%.
- The scan rules are right every time. Nearly all false alarms come from two
  rules: the flood rule, which fired on campus devices' ordinary busy apps,
  and the very-high-application-risk rule, which fired on BitTorrent.
- The reviewer left single unanswered probes as Unsure rather than Threat,
  which matches treating them as background probing.
- These labels have now been seen, so any rule change made after reading them
  is reported as a second look at this window, never as a new blind result.

## Post-tuning second looks (not blind)

The changes below were made after reading the blind labels, with their false
alarms in view. Re-scoring the same 150 labels therefore shows whether a fix
did what it was meant to do and broke nothing else. It is not a new blind
result and is expected to look better than a fresh blind check would.

| Detector | Official blind (v5.32.0) | Second look v5.33.0 (flood fix) | Second look v5.34.0 (P2P policy) |
|---|---|---|---|
| Rules: precision | 50.9% | 65.9% | 80.6% (66.7-92.7%) |
| Rules: recall | 81.8% | 81.8% | 81.8% |
| Rules: false-alarm rate | 6.0% | 3.2% | 1.5% |
| Rules: F1 | 62.7% | 73.0% | 81.2% |
| Model: precision / recall / F1 | 74.4% / 65.5% / 69.7% | unchanged | 21 of 21 flags Threat / 65.5% / 79.2% |
| Rules or model: precision | 53.5% | 68.2% | 82.2% (68.8-93.5%) |
| Rules or model: recall | 90.9% | 90.9% | 90.9% |
| Rules or model: F1 | 67.4% | 78.0% | 86.3% |

Recall never moved: no sample labeled Threat lost its flag in either change.

### v5.33.0: flood fix

The flood rule was narrowed after this check (see `DETECTION_RULE_CATALOG.md`),
the fix was first confirmed on the non-blind reviewed labels (scoreboard F1
94.2% to 94.9%), then the rules were re-run on a copy of the holdout. Exactly
the 13 sampled flood false alarms stopped alerting; no other sampled verdict
changed.

| Detector | Precision | Recall | False-alarm rate | F1 |
|---|---|---|---|---|
| Rules (v5.33.0) | 65.9% (51.3-80.0%) | 81.8% | 3.2% | 73.0% |
| Rules or model | 68.2% | 90.9% | 3.2% | 78.0% |

The remaining false alarms are BitTorrent (very high application risk, 9),
peer-to-peer UDP (unknown app, 3), inbound web services on unusual ports (2)
and one two-way SSL session (beaconing, 1). Whether file sharing is an attack to
alert on or a policy matter to summarise is a policy decision for the team.

### v5.34.0: peer-to-peer file sharing is policy activity

The team decided that BitTorrent and other peer-to-peer file sharing is
policy-relevant activity, not an attack: its fan-out resembles scanning, but
that alone is not a threat. File sharing (Palo Alto technology
"peer-to-peer", subcategory "file-sharing") now alerts only with malicious
evidence: a firewall threat or malware detection, brute force, or a watchlist
match. Otherwise it is counted as policy activity and shown on the dashboard
beside background probing, outside the attack counts. The behaviour model
applies the same policy: a window that is mostly file sharing with no firewall
threat log is never flagged.

Rules re-run on a copy of the holdout, model flags recomputed with the policy:

- Exactly the 8 sampled BitTorrent logs changed; the reviewer had labeled all
  8 "Normal but unusual". They stop alerting from both the rules (very high
  application risk) and the model (it had called them port scans).
- No other sampled verdict changed, and no Threat sample lost its flag.
- All 21 samples the model still flags are labeled Threat. 21 is a small
  number, so this does not show the model never errs.
- The remaining rule false alarms: unknown UDP on port 5521 (3, which the
  reviewer called peer-to-peer; the firewall did not identify the app, so the
  policy cannot see it), web browsing on port 3000 (unusual destination port,
  2), an HTTP proxy (very high application risk, 1) and the SSL session on port
  4433 (beaconing, 1).

### v5.35.0: internet background probing is summarised

The rules now apply the background-probing policy the behaviour model already
followed: an unanswered connection from an internet host whose source stays
within 9 hosts, 4 ports and 20 connections is summarised, unless there is
stronger evidence (a firewall threat or malware log, brute force, a watchlist
match, or 5 or more denied attempts). On the same 150 labels nothing moves:
precision 80.6%, recall 81.8%, false alarms 1.5%, F1 81.2%. The 3 samples that
stop alerting were all unusual-port probes the reviewer labeled "Unsure".

### v5.36.0: informational firewall records support, malware leads

Informational firewall threat records that name no attack ("Non-RFC Compliant
SSL Traffic" and the like) no longer raise alerts on their own, and a
firewall-confirmed malware record leads its alert. On the same 150 labels
nothing moves: precision 80.6%, recall 81.8%, false alarms 1.5%, F1 81.2%; no
sample changes its flag. On the unimported 13:45-13:57 traffic alerts go from
684 to 453.

## Human verification (pending)

The team will check the AI reviewer's labels by hand: all 31 Threat labels, all
28 false alarms (logs the rules or the model flagged that the reviewer called
Normal or Normal but unusual) and the 4 Unsure rows, mixed with 20 random other
rows so the checkers cannot tell which rows ATDR flagged (83 rows,
`.tmp/blind_check/ATDR_blind_label_verification.xlsx`). The sheet shows the
reviewer's decision and note and asks Agree or Change. A second sheet asks
whether the 11 BitTorrent logs our own team labeled as threats (10 port scans,
1 unknown anomaly) are still threats under the file-sharing policy. IP addresses are anonymized consistently: the same address
always gets the same stand-in, MFU addresses stay recognisable as MFU and
subnets stay grouped, so behaviour can still be judged. Once done, this
document will report the result as AI-assisted, human-verified labeling. If a
checker changes a label, the official blind numbers above stay as they are and
the re-scored numbers are reported next to them.

## Commands

```
python -m atdr.scripts.blind_check prepare --log-file "C:\path\paloalto-firewall(1).log"
python -m atdr.scripts.blind_check score --decisions .tmp/blind_check/decisions.csv
python -m atdr.scripts.anonymized_review_files verify-blind-labels   # needs openpyxl
```

`prepare` reuses `holdout.db` if it exists. `score` reads a CSV with columns
`sample_id` and `decision` and writes `.tmp/blind_check/score.json`. The files
under `.tmp/blind_check/` contain real MFU IP addresses and stay private to
the team. The second looks are written next to it (`second_look.json` for
v5.33.0, `second_look_v5_34.json` for v5.34.0); `score.json` is the official
blind result and is not rewritten.
