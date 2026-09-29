# ATDR evidence summary

Every number the team quotes about ATDR, what kind of number it is, and how
much to trust it. As of 2026-09-28 (rule catalog v5.36.0, behaviour model
mfu_behavior_v2). Details are in the linked documents.

**All accuracy figures come from one 21-minute MFU export (20 May 2026); treat them as low-confidence estimates until tested on more traffic.** ATDR shows this line wherever it quotes accuracy.

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
| Blind check re-scored, rules v5.34.0 to v5.36.0 | Second look | 80.6% (66.7-92.7%) | 81.8% | 1.5% | 81.2% |
| Blind check, rules v5.32.0, labels human-checked (28 Sep) | Blind, official method | 56.4% | 83.6% | 5.4% | 67.3% |
| Blind check, rules v5.36.0, labels human-checked | Second look | 93.5% | 78.2% | 0.5% | 85.2% |
| Detection scoreboard, 2,132 team labels, v5.34.0 | Agreement | 95.5% | 80.4% | 1.8% | 87.3% |
| Detection scoreboard, 2,132 team labels, v5.35.0 | Agreement | 95.6% | 73.1% | 1.6% | 82.9% |
| Detection scoreboard, 2,132 team labels, v5.36.0 | Agreement | 95.6% | 72.4% | 1.6% | 82.4% |
| Detection scoreboard, 1,489 team-labeled records, v5.36.0, misattached labels archived | Agreement | 97.0% | 79.3% | 1.5% | 87.3% |
| Same, after the team review relabeled 185 labels (28 Sep) | Agreement (circular) | 97.0% | 99.8% | 1.4% | 98.4% |
| Same, with the 74 unresolved unidentified-app labels set aside as "needs context" | Agreement (circular) | 96.0% | 99.7% | 1.6% | 97.8% |
| Live alert list before the rebuild (3,676 alerts) | Agreement | 48.9% | 87.6% | 43.3% | 62.8% |
| Live alert list after the rebuild (314 alerts) | Agreement | 93.9% | 80.4% | 2.5% | 86.6% |

- The blind labels were made by an AI reviewer (ChatGPT, acting as a senior
  SOC analyst) without access to ATDR's verdicts. On 28 Sep the team checked
  the 83 that matter (every Threat, false alarm and Unsure, plus 20 random
  others): the answers were drafted by AI and a person checked every row, so
  they are "AI-assisted, human-checked" labels, not an independent relabel. The
  check kept every Threat-or-not verdict (74 of 74) and changed 11 decisions:
  2 Unsure rows became Threats, and 5 rows the rules flag moved from Normal or
  Normal but unusual to Unsure. Unsure rows are not scored, so those 5 leave the
  false alarms: most of the rise to 93.5% precision under v5.36.0 is that move,
  not rows judged to be threats. The official row above stays as scored on 27 Sep.
- Between v5.32.0 and v5.34.0: the flood rule stopped firing on campus apps'
  busy two-way traffic, and BitTorrent became policy activity. No sample
  labeled Threat lost its alert.
- The last two rows are agreement by construction: the team review relabeled
  exactly the groups where the labels contradicted ATDR's policies (file
  sharing, isolated internet probes) or the firewall's own record (miner,
  Shellshock). It shows the labels now follow those policies, not that the
  rules are 98% accurate. The blind check is the fair estimate.
- The scoreboard rows with 2,132 labels included 794 reviewed labels made on
  23-25 May for logs that were re-imported on 27 May, so they described other
  records, and counted duplicate copies of some records. Those labels are
  archived and each record now counts once (`detection/LABEL_ARCHIVE.md`); the
  1,489-record row is the one to quote. The live-list rows used the old labels.
- Most of the scoreboard's lower recall is BitTorrent the team labeled as a
  threat; with file sharing scored as policy, F1 is 95.3%.
- v5.35.0 summarises internet background probing (isolated unanswered probes
  from a source touching at most 9 hosts, 4 ports and 20 connections) unless
  there is stronger evidence. It changed nothing on the blind labels (the 3
  samples it stops alerting on were labeled "Unsure") and cut alerts on the
  unimported 13:45-13:57 traffic by 19%. The team's labels had called 43 such
  probes port scans, so their recall drops to 73.1%; those labels are part of
  the pending human check.
- v5.36.0 stops informational firewall records that name no attack ("Non-RFC
  Compliant SSL Traffic" from VPN clients, games and tunnels) from raising
  alerts on their own; they had led 30% of the live alerts. Alerts on a full
  re-run: live 249 to 180, unimported traffic 684 to 453. Blind labels
  unchanged; on the team's labels 5 logs labeled threats stop alerting, 4 of
  whose labels were generated from ATDR's own rule scores.
- Sources: `detection/BLIND_CHECK.md`, `DETECTION_RULE_CATALOG.md`,
  `detection/ALERT_REBUILD.md`.

## Detection: what each alert says is happening

Each alert names an attack type (port scan, malware / C2, exploit attempt and
so on) with its ATT&CK technique and a response playbook. Until 2026-09-28 the
type came only from which rule fired, so 133 of the 249 live alerts (53%) said
"Unclassified", including firewall-named exploits and a known C2 server. The
type now also comes from the evidence: the firewall's threat signature, the
kind of watchlist indicator, and whether an inbound probe was answered. On the
same 249 alerts, re-run on a copy, and then on the live list after rule
catalog v5.36.0, which stops informational records that name no attack from
raising alerts alone (rebuilt 2026-09-28; the 5 analyst-worked alerts kept):

| Attack type | Before | Typed from evidence | Live, v5.36.0 (180 alerts) |
|---|---|---|---|
| Port scan | 84 | 117 | 121 |
| Unclassified | 133 | 93 | 18 |
| Malware / C2 | 6 | 11 | 11 |
| Policy violation | 9 | 8 | 10 |
| Data exfiltration (suspected) | 7 | 7 | 7 |
| Brute force | 6 | 6 | 6 |
| Flood | 4 | 4 | 4 |
| Exploit attempt (new) | 0 | 3 | 3 |

Four of the 180 (1 port scan, 2 brute force, 1 malware / C2) were built on
synthetic lab logs a test tool wrote into the live database by mistake on
27 Sep; they were archived on 29 Sep (`docs/detection/ALERT_REBUILD.md`). The
live list is now 181 alerts, 5 of them the MFU model's experimental alerts.

- 30 alerts on unanswered internet probes to uncommon ports are now port scans.
- Four alerts on campus devices whose connections the firewall identified as
  XMRig cryptocurrency-miner command and control (140 dropped connections from
  8 devices to mining pools) had been filed as port scans, because the
  retries also look like one. They are now malware / C2, as is the GHOSTENGINE
  watchlist alert.
- Shellshock (Bash remote code execution), an Apache path traversal and a
  `.env` file scan are exploit attempts; Nmap and RPC portmapper probes are port
  scans.
- Of the 93 still unclassified, 75 were firewall threat records that name no
  attack (informational "Non-RFC Compliant SSL/DNS/HTTP Traffic" and one SSLv2
  negotiation); v5.36.0 made them supporting evidence (see above). The other 18
  are alerts on campus devices using an application the firewall could not
  identify; nothing in them names a technique.
- Typing from evidence changes only the type; which logs alert, and every
  precision and recall figure, stay the same. Source:
  `detection/ATDR_DETECTION_TAXONOMY.md`.

## Detection: the MFU behaviour model (advises, and raises experimental alerts)

| Measurement | Kind | Result |
|---|---|---|
| v1 alone on the blind check | Blind | precision 74.4%, recall 65.5%, F1 69.7% |
| Rules or v1, blind check | Blind | F1 67.4% vs rules 62.7%: quality-bar condition 3 holds |
| v1's extra finds, 22-row blind review | Blind (method not stated on the sign-off) | port scan 1 of 1 real, C2 1 of 7, exfiltration 0 of 3 |
| v2 alone, blind check re-scored | Second look | all 20 flags labeled Threat, recall 62.7% |
| Rules or v2, blind check re-scored | Second look | F1 86.3% vs rules 81.2% |
| v2 on fresh simulated attacks (13:45-13:50, 13:55-13:57) | Simulated | port scan 96.5%, brute force 97.5%, flood 100%, C2 88.5%, exfiltration 98.0% |
| v2's extra finds on the fresh windows, 30-row blind review and follow-up (28 Sep) | Blind, AI-assisted and person-checked | port scan 4 of 4 judged real (1 unsure), C2 0 of 5 (3 unsure), exfiltration 0 of 1 (1 unsure) |
| Rules or v2, blind check with the human-checked labels | Second look | F1 90.1% vs rules 85.2%: condition 3 holds |

No attack type passed the bar declared before training
(`detection/ML_QUALITY_BAR.md`). With no further data, the team lead switched
every type on as a recorded exception on 28 Sep: where the model flags a device
and no rule alert covers it, ATDR raises an alert marked experimental and low
confidence (5 on the live data: 4 malware / C2, 1 port scan). Where the review
stands: port scan's 4 judged finds were all real, but
the bar needs 5 judged and one stayed Unsure; C2 fails on simulated beacons and
its finds; exfiltration has too few. The AI Governance page shows each type's
standing.

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
  probing, firewall threat and malware logs (including XMRig miner traffic from
  8 campus devices, all dropped), and one C2 beacon. Brute force,
  flood and exfiltration are measured only on simulated attacks.
- **Labels.** 1,231 early labels turned out to describe other records and were
  archived (`detection/LABEL_ARCHIVE.md`). The team's remaining labels were
  AI-assisted and team-verified, 185 of them corrected in the 28 Sep review;
  the blind
  labels are an AI reviewer's. The team's own check of the blind labels is
  pending.
- **Rare misses.** Recall rests on few threats, hence intervals like 61.9-100%.

## Open items

- Team review pack and its follow-up returned and applied on 28 Sep
  (`detection/TEAM_REVIEW_PACK.md`). 13 rows stay Unsure, among them the
  port-scan find, which the team asked not to count; the unidentified-app labels
  stay undecided and the rule that alerts on them is unchanged.
- Another MFU export, even an hour from a different day, would allow one clean
  end-to-end test of the whole system.
