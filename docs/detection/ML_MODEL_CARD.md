# MFU behaviour model (mfu_behavior_v1)

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
- **Features:** 30 numbers from raw firewall fields only: how many
  destinations and ports the source touched, how concentrated its traffic was,
  denied and unanswered shares, upload volume, app risk, direction, and how
  regular its most regular repeated connection was. No rule output is used, so
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
blind check is scored both ways.

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

Bar condition 1 (at least 90% of model-only alerts are real threats) is waiting
for the team's blind review of those 11 windows
(`.tmp/mfu_model/ATDR_model_review.xlsx`, mixed with 11 random windows).
Brute force and flood made no model-only alerts in the window, so they cannot
pass condition 1 and stay advisory; the model adds nothing beyond the rules for
them here.

Bar condition 3 (rules or model does not lower F1) **passes**. On the blind
check labels ([BLIND_CHECK.md](BLIND_CHECK.md)), with the rules as they were at
the time (v5.32.0):

| Detector | Precision | Recall | False-alarm rate | F1 |
|---|---|---|---|---|
| Rules alone | 50.9% | 81.8% | 6.0% | 62.7% |
| Model alone | 74.4% | 65.5% | 1.7% | 69.7% |
| Rules or model | 53.5% | 90.9% | 6.0% | 67.4% |

The model's own false alarms in that sample were BitTorrent: peers touching
hundreds of hosts and ports look like scans. Those windows were rule-alerted
and unlabeled in training, so they were left out and the model never learned
that file sharing is not scanning. How to treat file sharing is a policy
decision for the team.

## Known limits

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
```

The model file (`atdr/models/mfu_behavior_model.joblib`) is not in git; the
first command rebuilds it. The dashboard's Overview page shows the model's
findings for any 5-minute window, and each alert shows the model's opinion
(`GET /api/ml/behavior/findings`, `GET /api/ml/behavior/alerts/{id}`).
