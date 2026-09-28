# MFU behaviour model (current: mfu_behavior_v2)

A supervised model trained only on Mae Fah Luang University's own firewall
traffic. For each source's activity in a 5-minute window it names the attack
it looks like, explains why in plain terms, and points to the response steps.
It runs next to the rules and is **advisory**: it creates no alerts until an
attack type passes the quality bar declared before training
([ML_QUALITY_BAR.md](ML_QUALITY_BAR.md)).

## What it does

- **Unit:** one source IP's traffic in one 5-minute clock window, the same unit
  the rules use, so a model finding and a rule alert can be compared directly.
- **Classes:** normal, port scan (including horizontal scans), brute force,
  flood / denial of service, malware / C2 beaconing, possible data exfiltration.
- **Features:** numbers from raw firewall fields only: how many destinations
  and ports the source touched, how concentrated its traffic was, denied and
  unanswered shares, upload volume, app risk, direction, and how regular its
  most regular repeated connection was (30 in v1). v2 adds a 31st: how many
  sources contacted the destination of that regular connection. No rule output is used, so
  the model cannot simply copy the rules. (`atdr/app/ml/behavior_features.py`)
- **Classifier:** scikit-learn HistGradientBoostingClassifier.
- **Explanations:** each finding quotes the values that are outside what normal
  MFU sources do, for example "600 destinations tried on one port (normal MFU
  sources: at most 142 in 99.9% of windows)".
- **Response:** each finding carries the MITRE ATT&CK technique and the
  playbook's objective, containment steps and escalation rule.

## Training data (20 May 13:36-13:45 only)

| Part | Windows |
|---|---|
| Real windows used (normal, or labeled by the team) | 13,833 |
| Real windows labeled as attacks by the team | 37 port scan, 2 brute force, 1 exfiltration |
| Simulated attacks blended into real windows | 300 per attack type |
| Left out: rule-alerted windows nobody labeled (true class unknown) | 786 |
| Left out: internet background probing | 2,178 (48 of them labeled as attacks by the team) |

Simulated attacks use MFU's own zone names, real internal hosts and the field
values seen in MFU's real labeled attacks (for scans: mostly allowed, one
packet, app "incomplete", no reply). Attacks by an internal host are added to a
real host's traffic. Every attack draws its own strength, from obvious to
subtle. (`atdr/app/ml/attack_simulation.py`)

**Background probing.** Most of what the team labeled as scanning was single
unanswered connections from internet hosts, and 962 identical-looking windows
were unlabeled. Training on both would teach the model two answers for the
same behaviour. Every public network receives this probing all day, so ATDR
treats it as background: a source outside the network whose connections are
mostly inbound and unanswered, touching at most 9 hosts, 4 ports and 20
connections in five minutes. Such windows are not trained on and never
flagged; the dashboard shows how many there were instead. Whether single
probes should count as threats is a policy decision for the team, and the
blind check is scored both ways. The team has decided to keep summarising
them: a probe is escalated only with stronger evidence, such as repeated
attempts, wider host or port coverage, a known malicious indicator,
exploitation, or other correlated signals. From rule catalog v5.35.0 the rules
use the same limits (defined once, in `detection/rules.py`).

**Peer-to-peer file sharing (from catalog v5.34.0).** BitTorrent and similar
file sharing is policy activity, not an attack. A window in which at least half
of the source's connections are peer-to-peer file sharing, with no firewall
threat log, is never flagged; the dashboard shows it in its own policy summary.
This policy was added after v1 was trained. 13 training-period windows were
mostly file sharing: 11 were already left out (rule-alerted, unlabeled) and 2
were trained as port scans because the team had labeled them so. The dataset
builder now leaves such windows out. v1 has not been retrained, so the blind
evaluation and the model review still describe the same model. The policy is
applied when the model makes predictions.

**Threshold.** Chosen on a validation split grouped by source IP (no source on
both sides) so that at most 0.2% of real normal windows are flagged: 0.969.

## Results

### Validation (training period, held-back sources)

| Attack type | Simulated found | Real labeled found |
|---|---|---|
| Port scan | 96% | 6 of 8 |
| Brute force | 100% | 1 of 2 (typed wrong) |
| Flood | 100% | none labeled |
| C2 beaconing | 77% | none labeled |
| Data exfiltration | 100% | none labeled |

### Untouched test window (20 May 13:50-13:55, evaluated once)

Bar condition 2, recall on fresh simulated attacks (200 per type, a seed never
used in training):

| Attack type | Found with the right type | Condition 2 (at least 90%) |
|---|---|---|
| Port scan | 98.0% | passes |
| Brute force | 97.5% | passes |
| Flood | 100% | passes |
| C2 beaconing | 77.0% | **fails** |
| Data exfiltration | 97.0% | passes |

Real traffic: 8,995 source windows; the rules alerted on 1,055, the model
flagged 190, and 179 of those 190 are windows the rules also alerted on. The
model found 11 windows the rules did not: 1 port scan, 7 beaconing, 3
exfiltration.

With the file-sharing policy (v5.34.0), 5 of the 190 flags were file-sharing
windows the model had called port scans; they are no longer flagged (185).
The 11 model-only windows and the simulated recall above are unchanged, so the
model review below still applies.

Bar condition 1 (at least 90% of model-only alerts are real threats): one
team member reviewed the 11 model-only windows blind, mixed with 11 random
unflagged windows (`.tmp/mfu_model/ATDR_model_review_anonymized.xlsx`, MFU
addresses anonymized). The sign-off describes an independent review of the
sheet with limited public lookups of internet addresses; it does not say
whether AI assistance was used.

| Attack type | Model-only windows judged Threat | Condition 1 |
|---|---|---|
| Port scan | 1 of 1 (an outside host probing 6 MFU hosts on 6 ports) | passes |
| C2 beaconing | 1 of 7 | fails |
| Data exfiltration | 0 of 3 | fails |
| Brute force, flood | no model-only windows | cannot be shown |

- The random unflagged windows were 10 Normal and 1 Unsure: no missed attack
  among them.
- C2: six of the seven were ordinary apps (Google, LINE, CDNs) checking in at
  steady intervals. The seventh called one internet address over HTTP every
  14 seconds; the reviewer found it listed as a GHOSTENGINE C2 indicator. The
  rules did not alert on it.
- Exfiltration: all three were internet clients uploading large files into
  MFU's public web services: data coming in, not leaving.

Port scan passes all three conditions as written, but on a single window, so
it stays advisory. Every type is advisory in v1. What v2 changes in response,
and how it is tested on fresh windows, was declared before v2 was built
(`ML_QUALITY_BAR.md`, addendum).

Bar condition 3 (rules or model does not lower F1) **passes**. On the blind
check labels ([BLIND_CHECK.md](BLIND_CHECK.md)), with the rules as they were at
the time (v5.32.0):

| Detector | Precision | Recall | False-alarm rate | F1 |
|---|---|---|---|---|
| Rules alone | 50.9% | 81.8% | 6.0% | 62.7% |
| Model alone | 74.4% | 65.5% | 1.7% | 69.7% |
| Rules or model | 53.5% | 90.9% | 6.0% | 67.4% |

These are the official blind numbers and stay as they are.

The model's own false alarms in that sample were BitTorrent: peers touching
hundreds of hosts and ports look like scans. Those windows were rule-alerted
and unlabeled in training, so they were left out and the model never learned
that file sharing is not scanning. The team then decided file sharing is
policy activity (catalog v5.34.0).

Post-tuning second look (not blind; the change was made after reading these
labels), rules v5.34.0 and the model with the file-sharing policy:

| Detector | Precision | Recall | False-alarm rate | F1 |
|---|---|---|---|---|
| Rules alone | 80.6% | 81.8% | 1.5% | 81.2% |
| Model alone | 21 of 21 flags labeled Threat | 65.5% | 0.0% | 79.2% |
| Rules or model | 82.2% | 90.9% | 1.5% | 86.3% |

The only change for the model: the 8 BitTorrent samples, all labeled "Normal
but unusual", are no longer flagged. No sample labeled Threat lost its flag.
Condition 3 still holds (86.3% vs 81.2%).

## v2 (2026-09-27, current)

What changed and how it is tested was declared before it was built
(`ML_QUALITY_BAR.md`, addendum). Trained from commit 5001f9e on the same
13:36-13:45 data; threshold 0.981, chosen the same way (0.18% of real normal
validation windows flagged).

- **Destination prevalence.** For the steadiest repeated connection, how many
  sources contacted that destination in the window. Counted over the whole
  window, also when the model judges one alert's source or a simulated attack.
- **Direction.** C2 and exfiltration are flagged only when most of the
  source's traffic leaves MFU.
- **Training labels from the current rules (v5.34.0).** 25,363 rule-alerted
  training logs instead of 34,369; 13,863 real windows used. The training
  script had been keeping the older catalog's alerts; it now re-runs the rules.

Validation (training period, held-back sources), simulated attacks found:

| Attack type | v1 | v2 |
|---|---|---|
| Port scan | 96.4% (real labeled: 6 of 8) | 96.4% (real labeled: 5 of 8) |
| Brute force | 100% | 99.0% |
| Flood | 100% | 100% |
| C2 beaconing | 76.5% | 82.7% |
| Data exfiltration | 100% | 97.8% |

**Second look at 13:50-13:55** (seen before, not a clean test; rules v5.34.0):

- All 9 false alarms from the v1 review are gone: the 6 C2 ones (their
  destinations were used by 236-355 sources, or scored lower) and the 3
  exfiltration ones (data coming in). The real port scan is still flagged.
- The real C2 window is no longer flagged: v2 scores it 0.929, under its
  threshold (see Known limits).
- 170 flags, 9 of them model-only (3 port scan, 1 brute force, 5 C2).
- Blind labels (condition 3): all 20 samples v2 flags are labeled Threat;
  model recall 62.7%; rules or model F1 86.3% vs rules 81.2%, so it holds.

**Fresh windows 13:45-13:50 and 13:55-13:57** (the clean test):

| Attack type | Simulated attacks found (condition 2) | Model-only windows | Can it pass? |
|---|---|---|---|
| Port scan | 96.5% | 5 | only if a person-checked review calls all 5 threats |
| Brute force | 97.5% | 0 | no: nothing to review |
| Flood | 100% | 0 | no: nothing to review |
| C2 beaconing | 88.5% (fails) | 8 | no: condition 2 fails |
| Data exfiltration | 98.0% | 2 | no: fewer than 5 |

15,153 source windows; the rules alerted on 1,660, the model flagged 230.
The 15 model-only windows are in a blind review mixed with 15 random unflagged
windows (`.tmp/mfu_model/v2_fresh/ATDR_model_review_v2_fresh_anonymized.xlsx`,
30 rows, MFU addresses anonymized). Every type stays advisory until then.
Training labels: v1 and v2 took the team's labels by line fingerprint, including
labels later found to describe other records (`LABEL_ARCHIVE.md`): 394 normal, 21
port scan, 5 data exfiltration, 2 brute force. The model learns mostly from
simulated attacks and unlabeled normal traffic, so the effect is small, but its one
real exfiltration example came from a wrong label; the next version trains on the
cleaned labels. The review was drawn against rules v5.34.0. It came back on 28 Sep (AI-assisted,
a person checked every row): port scan 4 of 4 judged finds real with 1 Unsure,
so 4 judged against the 5 the bar needs; C2 0 of 3 judged real, 5 Unsure;
exfiltration 0 of 1, 1 Unsure. No type passes this round. Condition 3 still
holds with the human-checked blind labels (rules or model F1 90.1% against
85.2% for the rules alone). Rules v5.35.0 and v5.36.0 alert on
fewer windows (759 of the 15,153), but every window the model flagged keeps its
rule alert, so the model-only windows are the same 15 and the review stays
complete.

## Known limits

- **Traffic nobody alerted on is trained as normal.** One campus device called
  111.90.158[.]40 over HTTP about every 14 seconds for the whole file
  (13:36-13:57), with no firewall threat log and no rule alert. Elastic
  Security Labs lists that address as a GHOSTENGINE C2 server (May 2024; the
  address may have changed hands since). Because nothing flagged it in
  13:36-13:45, both models learned its windows as normal. v1 still caught it in
  the test window; v2 scores it 0.93, just under its threshold. Labeling a
  sample of unalerted training windows would stop the models learning such
  traffic as normal.

  The address is now on ATDR's watchlist (item 1, added 2026-09-27 through
  the admin API, so it is in the audit log). Re-running the current rules with
  it on a copy of the 13:45-13:57 traffic adds exactly 2 Critical
  watchlist alerts, for the beaconing device (53 connections) and a second
  device (1 connection), and changes nothing else. In the live database the
  13:36-13:39 part of the same traffic already sits in two open alerts that
  older rules raised as "application risk 4".

  Why no new behavioural rule: the beaconing rule needs extra context (an
  uncommon port, an unidentified app, a firewall threat log or a very-high-risk
  app), and this beacon was plain web browsing on port 80. Counting steady
  outbound beacons that only one device sends to a destination gives 30 in
  13:36-13:45 and 35 in 13:45-13:57, nearly all SNMP polling, NTP, ping
  monitors and app keep-alives. A rule on that pattern would bury this one C2
  under dozens of harmless alerts. Behaviour alone cannot single it out;
  threat intelligence can, which is what the watchlist is for.

- **Beaconing:** a 5-minute window often holds only 4-5 beacons, and a beacon
  hidden among a busy host's HTTPS traffic is hard to see. The model finds
  77% of simulated beacons. Looking across 15 minutes, as the rules' beacon
  rule does, is the next improvement.
- **Few real attacks:** only about 40 real labeled attack windows were
  available, almost all port scans. Brute force, flood, beaconing and
  exfiltration are learned mainly from simulation.
- **One network, one hour of one day:** results describe 20 May traffic; they
  should be re-measured on new MFU logs.

## Reproducing

```
python -m atdr.scripts.train_behavior_model --log-file "C:\path\paloalto-firewall(1).log"
python -m atdr.scripts.evaluate_behavior_model
python -m atdr.scripts.evaluate_behavior_model --review-decisions .tmp/mfu_model/review_decisions.csv
python -m atdr.scripts.evaluate_behavior_model --blind-decisions .tmp/blind_check/decisions.csv
python -m atdr.scripts.anonymized_review_files model-review   # needs openpyxl

# v2: the seen window as a second look, and the fresh windows as the clean test
python -m atdr.scripts.evaluate_behavior_model --out-dir .tmp/mfu_model/v2_second_look --rules-db .tmp/blind_check/holdout_v5_34.db --no-review
python -m atdr.scripts.evaluate_behavior_model --out-dir .tmp/mfu_model/v2_fresh --window "2026-05-20 13:45:00" "2026-05-20 13:50:00" --window "2026-05-20 13:55:00" "2026-05-20 14:00:00" --rules-db .tmp/blind_check/holdout_v5_34.db --seed 9000002 --review-seed 20260928 --review-prefix F --min-reviewed 5
python -m atdr.scripts.anonymized_review_files model-review --round-dir .tmp/mfu_model/v2_fresh

# after the review is scored: save each type's quality-bar standing in the model card (shown on AI Governance)
python -m atdr.scripts.evaluate_behavior_model --out-dir .tmp/mfu_model/v2_fresh --review-decisions review_decisions.csv --min-reviewed 5
python -m atdr.scripts.evaluate_behavior_model --out-dir .tmp/mfu_model/v2_fresh --record-bar --blind-dir .tmp/mfu_model/v2_second_look --min-reviewed 5 --review-method "<as the sign-off says>"
```

`holdout_v5_34.db` is a copy of the holdout with the current rules run over
it. The v1 model is kept as `atdr/models/mfu_behavior_model_v1.joblib`.

The model file (`atdr/models/mfu_behavior_model.joblib`) is not in git; the
first command rebuilds it. The dashboard's Overview page shows the model's
findings for any 5-minute window, and each alert shows the model's opinion
(`GET /api/ml/behavior/findings`, `GET /api/ml/behavior/alerts/{id}`).
