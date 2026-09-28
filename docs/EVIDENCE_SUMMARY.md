# ATDR evidence summary

Every number the team quotes about ATDR, what kind of number it is, and how
much to trust it. As of 2026-09-27 (rule catalog v5.34.0, behaviour model
mfu_behavior_v2). Details are in the linked documents.

## The data

- One firewall (MFU-FW), one export: 20 May 2026, 13:36-13:57, 773,551 lines.
- The live database holds 13:36:15-13:39:30 (151,242 logs); the team's labels
  are there. The behaviour model trained on 13:36-13:45. The 13:45-13:57 part
  was never imported into the live system, labeled or tuned on; it is the
  holdout for the blind check and the model's tests.
- Everything below describes this one 21-minute export.

## Four kinds of number

| Kind | What it is | How far to trust it |
|---|---|---|
| **Blind** | Measured once, on data and labels nobody tuned on | The fair estimate |
| **Second look** | The same blind labels, re-scored after changes made with them in view | Shows a fix worked; optimistic |
| **Agreement** | Against the team's own labels, made while the rules were tuned, often with ATDR's view visible | Agreement, not accuracy |
| **Simulated** | Share of simulated attacks found, blended into real MFU traffic | Capability, not a real-world rate |

## Detection: the rules (they decide alerts)

| Measurement | Kind | Precision | Recall | False alarms | F1 |
|---|---|---|---|---|---|
| Blind check, 150 logs, rules v5.32.0 (official) | Blind | 50.9% (38.6-64.9%) | 81.8% (61.9-100%) | 6.0% | 62.7% |
| Blind check re-scored, rules v5.34.0 and v5.35.0 | Second look | 80.6% (66.7-92.7%) | 81.8% | 1.5% | 81.2% |
| Detection scoreboard, 2,132 team labels, v5.34.0 | Agreement | 95.5% | 80.4% | 1.8% | 87.3% |
| Detection scoreboard, 2,132 team labels, v5.35.0 | Agreement | 95.6% | 73.1% | 1.6% | 82.9% |
| Live alert list before the rebuild (3,676 alerts) | Agreement | 48.9% | 87.6% | 43.3% | 62.8% |
| Live alert list after the rebuild (314 alerts) | Agreement | 93.9% | 80.4% | 2.5% | 86.6% |

- The blind labels were made by an AI reviewer (ChatGPT, acting as a senior
  SOC analyst) without access to ATDR's verdicts. A second AI pass agreed with
  all 83 rows it checked; the team's own check is pending. Until then they are
  an independent blind reference labeling, not ground truth.
- Between v5.32.0 and v5.34.0: the flood rule stopped firing on campus apps'
  busy two-way traffic, and BitTorrent became policy activity. No sample
  labeled Threat lost its alert.
- Most of the scoreboard's lower recall is BitTorrent the team labeled as a
  threat; with file sharing scored as policy, F1 is 95.3%.
- v5.35.0 summarises internet background probing (isolated unanswered probes
  from a source touching at most 9 hosts, 4 ports and 20 connections) unless
  there is stronger evidence. It changed nothing on the blind labels (the 3
  samples it stops alerting on were labeled "Unsure") and cut alerts on the
  unimported 13:45-13:57 traffic by 19%. The team's labels had called 43 such
  probes port scans, so their recall drops to 73.1%; those labels are part of
  the pending human check.
- Sources: `detection/BLIND_CHECK.md`, `DETECTION_RULE_CATALOG.md`,
  `detection/ALERT_REBUILD.md`.

## Detection: the MFU behaviour model (advises)

| Measurement | Kind | Result |
|---|---|---|
| v1 alone on the blind check | Blind | precision 74.4%, recall 65.5%, F1 69.7% |
| Rules or v1, blind check | Blind | F1 67.4% vs rules 62.7%: quality-bar condition 3 holds |
| v1's extra finds, 22-row blind review | Blind (method not stated on the sign-off) | port scan 1 of 1 real, C2 1 of 7, exfiltration 0 of 3 |
| v2 alone, blind check re-scored | Second look | all 20 flags labeled Threat, recall 62.7% |
| Rules or v2, blind check re-scored | Second look | F1 86.3% vs rules 81.2% |
| v2 on fresh simulated attacks (13:45-13:50, 13:55-13:57) | Simulated | port scan 96.5%, brute force 97.5%, flood 100%, C2 88.5%, exfiltration 98.0% |
| v2's extra finds on the fresh windows | Blind review out with the team | 5 port scan, 8 C2, 2 exfiltration windows |

Every attack type is advisory. A type may raise alerts only after passing the
bar declared before training (`detection/ML_QUALITY_BAR.md`); today port scan
is the only type that still can, and only if the team's review finds all 5
windows real. The AI Governance page shows each type's standing.

The earlier models (anomaly model and supervised classifier) stay advisory.
In the pre-presentation 40-case blind review the anomaly model found none of
the malicious cases and the supervised classifier failed calibration.

## Threat intelligence

- One real finding: a campus device called 111.90.158[.]40, listed by Elastic
  Security Labs as a GHOSTENGINE C2 server, every 14 seconds over plain HTTP
  for the whole export. v1 flagged it; no rule did. It is now a Critical
  watchlist alert.
- 2,324 known-bad addresses from Feodo Tracker and ThreatFox are on the
  watchlist. No stored log contacts them, as expected for this month's
  servers and May's logs. Source: `detection/THREAT_INTEL_FEEDS.md`.

## SOC assistant

| Question set | Local model agent | Earlier rule-based router |
|---|---|---|
| Main set (85 checks, automatic) | 84 (99%) | 40 of the first 82 |
| Held-out set (27 questions written after tuning) | 26 automatic (96%); 25 by hand before the rebuild | 10 |

Measured on 2026-09-27 with qwen3:8b running locally, after the alert
rebuild. The main set gained three questions when the assistant got tools
for the watchlist and the MFU behaviour model; before that it answered "what
does the MFU behaviour model see?" with the earlier anomaly model's status.
Scores move by a question or two between runs. The held-out miss asks about "the latest Critical alert", whose
expected wording was written when that was a brute-force alert.
Source: `SOC_ASSISTANT_CONVERSATIONAL.md`.

## What these numbers do not show

- **One export.** 21 minutes of one day from one firewall. Nothing here says
  how ATDR does on another day or another network.
- **Attack types.** The real attacks in the data are mostly scans and
  probing, firewall threat and malware logs, and one C2 beacon. Brute force,
  flood and exfiltration are measured only on simulated attacks.
- **Labels.** The team's labels were AI-assisted and team-verified; the blind
  labels are an AI reviewer's. The team's own check of the blind labels is
  pending.
- **Rare misses.** Recall rests on few threats, hence intervals like 61.9-100%.

## Open items

- Team: check the blind labels (83 rows) and review v2's extra finds (30 rows).
- Another MFU export, even an hour from a different day, would allow one clean
  end-to-end test of the whole system.
