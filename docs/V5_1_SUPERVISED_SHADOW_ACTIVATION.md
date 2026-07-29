# v5.1 Governed Supervised SOC Queue Activation

Date: 2026-07-22

## Decision

ATDR now has a fresh, reproducible supervised SOC review-queue model registered
and operationally active in `shadow_observation` mode. Deterministic rules remain
the only alert-authoritative detector. The model cannot create or suppress an
alert, change severity, execute a response, or authorize firewall action.

The model is **not** eligible for `decision_support` influence because it passed
0 of 5 strict validation splits and failed the locked external benchmark.
Production promotion and response automation remain false.

## Selected Model

| Field | Value |
| --- | --- |
| Model | Calibrated ExtraTrees binary SOC queue |
| Target | `benign_like` / `needs_review` |
| Version | `v5.1-soc-queue-20260722T102436Z` |
| Feature set | `v5.1-causal-soc-queue-features-v1` |
| Calibration | Sigmoid on a dedicated calibration partition |
| Queue threshold | `0.85` |
| Lifecycle | `shadow_observation` |
| Decision-support eligible | false |
| Production promoted | false |
| Response automation allowed | false |

The binary queue target was selected because the current evidence is more
suitable for prioritizing analyst review than for asserting an exact attack
class. Suspicious, malicious, and attack-type labels remain evaluation and
explanation context, not runtime truth.

## Training Evidence

- Latest eligible reviewed rows: 2,235.
- Artifact fit rows in the temporal partition: 957.
- Dataset fingerprint:
  `8df91a6cfaa1f2b1a7206ea1bf0d1c0dafaf8efa13a1dc1639b6e3cf6ed48970`.
- Label-source provenance: 1,672 manual, 529 rule-assisted, 7 ML-assisted,
  and 27 hybrid-assisted.
- Weak or unreviewed labels were excluded from the canonical run.
- Assisted-source provenance is retained and is not described as human-authored.
- Exact, near-pattern, used-feature, and normalized-log grouping prevents a
  duplicate group from crossing a split boundary.
- Target, future, alert-result, response, and post-detection leakage fields are
  excluded from the feature schema.

The runtime target is derived directly from the latest reviewed original label:

- `benign` and `benign_unusual` -> `benign_like`
- `needs_context`, `suspicious`, and `malicious` -> `needs_review`

No labels were created, changed, or reclassified by v5.1.

## Validation Result

Required gates on every split are FPR <= 0.10, threat F1 >= 0.85,
suspicious recall >= 0.80, malicious recall >= 0.80, ECE <= 0.10, and maximum
confidence/accuracy gap <= 0.15.

| Split | Precision | Recall | F1 | FPR | Suspicious recall | Malicious recall | ECE | Max gap |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Temporal holdout | 0.2353 | 0.2373 | 0.2363 | 0.2198 | 0.1176 | 0.2857 | 0.6134 | 0.7286 |
| Network-zone proxy | 0.9476 | 0.6511 | 0.7719 | 0.0893 | 0.4774 | 0.8541 | 0.2268 | 0.3435 |
| Random seed 7 | 0.9039 | 0.7871 | 0.8415 | 0.0743 | 0.6667 | 0.9147 | 0.0611 | 0.3549 |
| Random seed 17 | 0.9067 | 0.7757 | 0.8361 | 0.0709 | 0.6667 | 0.8992 | 0.0639 | 0.3515 |
| Random seed 42 | 0.8938 | 0.7681 | 0.8262 | 0.0811 | 0.7200 | 0.8387 | 0.0784 | 0.3078 |

Strict passing splits: **0 / 5**. All leakage audits passed, but temporal
generalization, suspicious recall, and calibration are unstable. The locked
CSE-CIC-IDS2018 evidence also remains failed, including FPR 1.0. These failures
are why activation is limited to shadow observation.

## Artifact And Registry

The ignored candidate artifact is stored under
`atdr/models/supervised_candidates/`. Its binary is not committed.

| Check | Result |
| --- | --- |
| Serialization round trip | passed |
| Metadata digest present | passed |
| Binary checksum verified | passed |
| Probability bounds | passed |
| Single-row p95 latency | 14.7438 ms |
| Shadow latency budget | 250 ms |
| Artifact size | 13,812,490 bytes |
| SHA-256 | `f6109f74f570a639d2048ac97c42d2cd2ea9c7c380a983ccbbed1e79f32b442f` |

The governed model is registry run 44 and its shadow activation is lifecycle run
45 in the current local database. These IDs are local operational evidence, not
portable release identifiers.

The older `supervised_classifier.joblib` artifact remains untouched. Its model
and feature metadata are unknown, and the governed registry marks it as an
unselected legacy reference.

## Runtime Contract

Lifecycle states are:

| State | Allowed influence |
| --- | --- |
| `inactive` | No governed supervised inference. Rules continue normally. |
| `shadow_observation` | Score and expose queue evidence only. No alert, severity, suppression, or response influence. |
| `decision_support` | A future bounded hybrid contribution, only after every strict and external gate passes. Rules remain authoritative. |
| `production_promoted` | Not implemented and rejected by the lifecycle API. |

Runtime inference exposes model version, feature version, queue probability,
threshold, calibration method, observed signals, missing context, and confidence
limitations. Model failure returns a safe unavailable result and rule detection
continues.

Telemetry is process-local and includes inference count, batch count, failures,
latency, missing-feature rate, score distribution, queue rate, and model version.
It is operational visibility, not durable production monitoring.

## Private Palo Alto Shadow Validation

The private file was inspected and scored without importing it into the
configured database. Only safe aggregates are recorded here.

Full preflight:

- 773,551 nonblank PAN-OS rows;
- 0 parser failures;
- 0 exact duplicates;
- 54,909 unknown/incomplete applications (7.0983%);
- 120,000 rows already overlapped the current database by fingerprint
  multiplicity (15.5129%); and
- no raw rows, IPs, private identifiers, secrets, or private path were returned.

Disposable 5,000-row shadow run:

- 5,000 raw and 5,000 normalized rows;
- 0 parse failures and 0 duplicates;
- 1,000 deterministic rows scored by the governed model;
- 47 `needs_review` rows (4.7% queue rate);
- supervised scoring time about 0.68 seconds for the 1,000-row batch;
- model output was not used for hybrid or alert creation;
- configured database unchanged;
- model artifacts unchanged; and
- 0 response actions, 0 labels, and 0 model activations created by validation.

The private run has no independent ground truth. Its queue rate is an
operational observation, not precision, recall, F1, or false-positive evidence.

## Closure Verification

- Taskboard render and standards checks passed.
- Ruff and compileall passed.
- Backend tests passed: 640 passed, 1 skipped. The skip is hardware-dependent.
- Alembic reported no schema drift.
- React lint and production build passed; Playwright passed 26 tests with one
  hardware-dependent skip.
- The controlled detection corpus passed 24/24 scenarios with zero response
  actions.
- The layered diagnostic passed 267/288 mode/variant runs. Supervised-only
  passed 72/72; the remaining 21 rule/anomaly/hybrid failures are retained as
  false-positive/false-negative evidence, not hidden as a release success.
- SOC Assistant QA passed 20/20 and created no response, detection, label,
  model, alert, log, or feedback side effects.
- Replay dry-run parsed the two bundled safe rows and wrote zero database rows.
- Performance smoke was read-only and passed overall. Overview was 0.7637 s,
  cached Overview was 0.0120 s, alerts were 0.0660 s, cases were 0.0737 s, and
  feature generation was 0.0120 s. ML Governance was 2.1246 s against its
  2.0-second local advisory budget and remains a narrow performance warning.
- The official release gate returned `ok: true` with no failed required checks.

An initial release-gate compile scan encountered intentionally malformed test
fixture copies left by an earlier ignored pytest temp directory under processed
data. Moving that ignored generated directory to the repository's `.tmp`
boundary restored the intended compile scope; no application source, database,
or evidence changed.

## API And Dashboard

Authenticated analyst/admin read:

```text
GET /api/ml/supervised/lifecycle
GET /api/ml/supervised/models
```

Admin-only controls:

```text
POST /api/ml/supervised/models/{model_id}/activate?mode=shadow_observation
POST /api/ml/supervised/models/{model_id}/activate?mode=decision_support
POST /api/ml/supervised/models/disable
POST /api/ml/supervised/models/rollback
```

The `decision_support` request fails closed while strict gates fail. AI
Governance shows lifecycle, model/version, feature set, calibration, validation,
and disabled response state. Explanations and the SOC Assistant may report the
shadow score as bounded evidence but cannot act on it.

## Operations

Inspect status:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.manage_supervised_lifecycle --status --pretty
```

Train/register and activate a fresh shadow candidate:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v51_supervised_shadow_activation --activation-mode shadow_observation --pretty
```

Disable immediately:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.manage_supervised_lifecycle --disable --pretty
```

Rollback to the previous governed activation, or disable if none is available:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.manage_supervised_lifecycle --rollback --pretty
```

Disabling or rolling back does not delete labels, logs, alerts, or evidence.

## Remaining Gates

1. Collect independently reviewed multi-device and multi-period firewall/syslog
   evidence.
2. Add one untouched schema-compatible external benchmark that is not used for
   model, feature, calibration, or threshold selection.
3. Repair temporal and source-transfer stability, especially suspicious recall.
4. Reduce maximum calibration gap on every required split.
5. Validate durable inference monitoring and drift on an approved shared host.
6. Re-run the same predeclared gates. Until every gate passes, keep the model in
   `shadow_observation`.

ATDR remains AI-assisted SOC decision support. This activation is not a
production-accuracy, production-readiness, or autonomous-response claim.
