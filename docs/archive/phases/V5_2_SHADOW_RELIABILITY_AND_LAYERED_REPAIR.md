# v5.2 Shadow Reliability And Layered Detection Repair

Date: 2026-07-22

## Decision

v5.2 repairs the controlled rule, anomaly, and hybrid regressions, adds
privacy-safe durable shadow telemetry, and evaluates supervised SOC queue
strategies under stricter split and calibration controls.

The deterministic rule layer remains alert-authoritative. IsolationForest,
supervised output, and hybrid interpretation remain advisory. No supervised
candidate passed every required validation view, so the lifecycle remains
`shadow_observation`. No model was activated or promoted by v5.2, and response
automation and real firewall blocking remain disabled.

## Baseline Lock

Before v5.2, the configured database contained 145,232 raw logs, 145,232
normalized logs, 3,231 alerts, 31 detection runs, 2,672 labels, 45 model-run
records, and zero response actions. The governed v5.1 artifact was
`v5.1-soc-queue-20260722T102436Z` in `shadow_observation`.

The v5.1 layered matrix passed 267 of 288 runs:

| Layer | Before | False positives | False negatives |
| --- | ---: | ---: | ---: |
| Rules | 69/72 | 0 | 3 |
| IsolationForest advisory | 63/72 | 9 | 0 |
| Supervised-only diagnostic | 72/72 | 0 | 0 |
| Hybrid diagnostic | 63/72 | 3 | 6 |
| Total | 267/288 | 12 | 9 |

## Root Causes

The machine-readable failure matrix identified four concrete causes:

1. Three C2 timing false negatives came from the scenario-variant generator.
   Per-row timestamp offsets stretched a five-minute beacon sequence beyond its
   intended correlation window.
2. Nine anomaly false positives were field-poor generic, malformed, or raw
   fallback rows. Their valid anomaly score was being presented as high attack
   risk despite weak parser context.
3. Three hybrid false positives occurred when low-specificity application
   evidence and advisory anomaly evidence were added together to reach the
   alert threshold.
4. Three hybrid false negatives occurred when anomaly precedence replaced the
   more specific deterministic rare-port finding with `unknown_anomaly`.

These were runtime/validation-contract faults. They did not justify changing
human labels or weakening model gates.

## Layered Repairs

- Scenario variants now apply one uniform timestamp shift to the entire
  scenario, preserving event cadence and correlation semantics.
- Advisory anomaly evidence no longer contributes to deterministic alert
  threshold authority.
- Explicit deterministic rule matches alone select alert eligibility, score,
  severity, and primary attack type.
- Anomaly priority is below explicit rules, so it cannot replace a more
  specific deterministic finding.
- Field-poor fallback/parser-warning anomaly rows retain their raw score but
  receive a bounded advisory interpretation instead of a high-confidence
  attack claim.
- Explanations identify deterministic rule evidence as authoritative and label
  anomaly, supervised, and hybrid material as advisory or shadow evidence.

After repair, the same matrix passes 288/288 runs:

| Layer | After | False positives | False negatives |
| --- | ---: | ---: | ---: |
| Rules | 72/72 | 0 | 0 |
| IsolationForest advisory | 72/72 | 0 | 0 |
| Supervised-only diagnostic | 72/72 | 0 | 0 |
| Hybrid diagnostic | 72/72 | 0 | 0 |
| Total | 288/288 | 0 | 0 |

The separate controlled scenario corpus passes 24/24 in a temporary database,
with automatic response false, real blocking false, and no production claim.
These are controlled regression results, not real-world accuracy estimates.

## Supervised Reliability Protocol

The read-only evaluator uses 2,235 latest eligible reviewed rows. It preserves
label provenance: 1,672 manual, 529 rule-assisted, 7 ML-assisted, and 27
hybrid-assisted. Assisted provenance is never described as human-authored.
Weak or unreviewed rows are excluded, and 0 duplicate normalized-log IDs enter
evaluation.

It compares calibrated and weighted ExtraTrees, Logistic Regression,
HistGradientBoosting, binary queue, three-class, hierarchical, and existing
diagnostic baselines. Fit, calibration, threshold selection, and final test
roles are separated. Final-test and locked external labels are not used for
tuning.

Required gates on every view are:

- benign-like FPR <= 0.10;
- threat-positive F1 >= 0.85;
- suspicious recall >= 0.80;
- malicious recall >= 0.80;
- ECE <= 0.10;
- maximum confidence/accuracy gap <= 0.15;
- zero leakage and response side effects; and
- no material split collapse.

## Supervised Result

`binary_extra_trees_lower_threat_weight` is the leading comparator by the
predeclared aggregate ordering. It is **not selected** and is not eligible for
activation. It passes 0/6 required validation views and 10/30 aggregate metric
checks.

| Split | Precision | Recall | F1 | FPR | Suspicious recall | Malicious recall | ECE | Max gap |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Temporal | 0.2174 | 0.9746 | 0.3555 | 1.0000 | 0.9118 | 1.0000 | 0.4351 | 0.8288 |
| Source holdout | failed closed | - | - | - | - | - | - | - |
| Network-zone proxy | 0.9399 | 0.6475 | 0.7668 | 0.1027 | 0.4774 | 0.8419 | 0.2238 | 0.3359 |
| Random seed 7 | 0.9052 | 0.7985 | 0.8485 | 0.0743 | 0.6923 | 0.9070 | 0.0353 | 0.1413 |
| Random seed 17 | 0.9234 | 0.7338 | 0.8178 | 0.0541 | 0.6154 | 0.8682 | 0.0319 | 0.2541 |
| Random seed 42 | 0.8755 | 0.7757 | 0.8226 | 0.0980 | 0.7120 | 0.8629 | 0.0710 | 0.3643 |

Source holdout fails closed because the eligible reviewed evidence contains
fewer than two independent `source_name` groups. The network-zone split is a
proxy, not a device-disjoint substitute. Temporal label/app drift is material,
and random-split success does not repair temporal or source-transfer failure.

Direct comparison with the v5.1 governed artifact is:

| Split | F1 v5.1 -> v5.2 | FPR v5.1 -> v5.2 | Suspicious recall v5.1 -> v5.2 | Malicious recall v5.1 -> v5.2 | ECE v5.1 -> v5.2 | Max gap v5.1 -> v5.2 |
| --- | --- | --- | --- | --- | --- | --- |
| Temporal | 0.2363 -> 0.3555 | 0.2198 -> 1.0000 | 0.1176 -> 0.9118 | 0.2857 -> 1.0000 | 0.6134 -> 0.4351 | 0.7286 -> 0.8288 |
| Network-zone proxy | 0.7719 -> 0.7668 | 0.0893 -> 0.1027 | 0.4774 -> 0.4774 | 0.8541 -> 0.8419 | 0.2268 -> 0.2238 | 0.3435 -> 0.3359 |
| Random seed 7 | 0.8415 -> 0.8485 | 0.0743 -> 0.0743 | 0.6667 -> 0.6923 | 0.9147 -> 0.9070 | 0.0611 -> 0.0353 | 0.3549 -> 0.1413 |
| Random seed 17 | 0.8361 -> 0.8178 | 0.0709 -> 0.0541 | 0.6667 -> 0.6154 | 0.8992 -> 0.8682 | 0.0639 -> 0.0319 | 0.3515 -> 0.2541 |
| Random seed 42 | 0.8262 -> 0.8226 | 0.0811 -> 0.0980 | 0.7200 -> 0.7120 | 0.8387 -> 0.8629 | 0.0784 -> 0.0710 | 0.3078 -> 0.3643 |
| Source holdout | unavailable -> failed closed | - | - | - | - | - |

The v5.2 comparator improves temporal recall only by queuing nearly every
temporal-test row, producing FPR 1.0. Network-zone FPR also moves above the
gate, while suspicious recall and calibration remain unstable. This is not a
safe reliability improvement.

## Calibration And External Evidence

Sigmoid and isotonic calibration are evaluated only when partition support is
sufficient. Calibration is acceptable on some random views but collapses on
temporal and network-zone views. Selected thresholds range from 0.15 to 0.75,
which is further evidence of unstable transfer.

The locked CSE-CIC-IDS2018 result remains a final diagnostic only. Its FPR is
1.0, and its labels are not used to modify features, select a candidate,
calibrate probabilities, or tune thresholds.

## Private Shadow Evidence

The latest ignored private validation report records only safe aggregates:

- 773,551 rows processed and normalized;
- 0 parse failures;
- 2,000 deterministic sample rows scored;
- 825 rows queued (41.25% of the scored sample);
- configured database unchanged;
- model artifacts unchanged;
- model activated false and promoted false;
- zero response actions; and
- no private path, raw evidence, or secret returned.

This evidence proves parser and shadow-scoring execution on the available
private PAN-OS structure. It has no independent ground truth and therefore does
not establish FPR, precision, recall, F1, or production suitability.

## Durable Shadow Telemetry

v5.2 can persist an admin-triggered aggregate telemetry snapshot in the
existing `MLModelRun` and `AuditLog` tables. No migration was required. The
snapshot contains model version, inference/batch/failure counts, latency,
missing-feature rate, score histogram, queue rate, and drift warnings. It does
not contain raw logs, IPs, labels, alert IDs, private paths, or model binaries.

The useful snapshot endpoint is:

```text
POST /api/ml/supervised/telemetry/snapshot
```

It is admin-only and audited. Telemetry is operational monitoring, not an
accuracy metric. A CLI process has its own process-local counters, so the API
endpoint should be used to capture the running backend process.

## Dashboard And Explanation Contract

AI Governance now distinguishes lifecycle state, reliability stability,
layered validation, queue telemetry, calibration/drift blockers, and the
leading unselected comparator. It does not present that comparator as an
active or promoted model.

Alert explanations distinguish:

- **Rule Authority:** deterministic evidence that created the alert;
- **Anomaly Advisory:** IsolationForest context that cannot create the alert;
- **Supervised Shadow:** queue evidence that cannot change alert state;
- **Hybrid Interpretation:** diagnostic synthesis without response authority;
- **ATT&CK-style Mapping:** analyst context, not certified attribution.

## Safety And Rollback

- Database and active artifact state were unchanged by model evaluation.
- No labels or model-run activation records were created by the evaluator.
- No response action was created.
- `production_promoted=false`.
- `response_automation_allowed=false`.
- Real firewall blocking remains disabled.
- The existing v5.1 artifact remains shadow-only; normal rule processing fails
  safely if shadow inference is unavailable.

No rollback migration is needed. The detection repair can be reverted at the
code level, while the existing admin lifecycle disable/rollback operations
remain available for the governed shadow artifact.

## Verification

- Taskboard render and standards checks passed.
- Whole-repo Ruff and compileall passed.
- Full backend suite: 651 passed, 1 hardware-dependent skip.
- Alembic: no new upgrade operations detected.
- React lint and production build passed.
- Playwright: 26 passed, 1 hardware-dependent skip.
- Controlled scenarios: 24/24, automatic response false, real blocking false.
- Layered validation: 288/288, 0 FP, 0 FN, 0 response actions.
- SOC Assistant QA: 20/20, citation rate 1.0, unsafe refusal passed, and zero
  response/detection/label/model side effects.
- Private disposable shadow: 5,000/5,000 parsed, 1,000 scored, 47 queued,
  configured DB/artifacts unchanged, no private/raw/secret output.
- Replay dry-run parsed 2 safe rows and wrote/sent 0.
- Read-only performance smoke had no warnings: Overview 0.1530s, cached
  0.0096s, ML Governance 1.1205s, alerts 0.0309s, cases 0.0652s, and 20-row
  feature generation 0.0068s.
- Official release gate returned `ok: true` with zero failed required checks.

## Remaining Evidence Requirements

1. Independently reviewed evidence from at least two real source devices and
   multiple time windows.
2. A new untouched, schema-compatible external firewall/syslog benchmark.
3. Stable temporal, source-disjoint, and calibration performance under the
   unchanged gates.
4. Advisor/organization approval for any change beyond shadow observation.
5. Real device forwarding and hardware validation when equipment is available.

The final v5.2 decision is `shadow_observation`, with no supervised candidate
selected. Rules remain the authoritative detection mechanism.
