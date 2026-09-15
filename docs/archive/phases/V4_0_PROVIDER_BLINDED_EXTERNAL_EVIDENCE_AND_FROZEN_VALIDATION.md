# v4.0 Provider-Blinded External Evidence And Frozen Validation

## Status

Implemented and evaluated as a read-only diagnostic phase on 2026-07-14. ATDR sampled 4,000 rows from an official public provider dataset without consulting label values, quarantined seven duplicate flow records, froze predictions for 3,993 independent rows, and only then reopened the provider files to reveal labels for scoring.

The result is a failed external generalization gate. The frozen supervised queue caught all sampled threat-positive flows but also queued every benign flow. Readiness remains `candidate_only`. No model was activated or promoted, no model artifact was written, no provider label was imported, no response action was created, and real firewall blocking remains disabled.

## Official Dataset And Terms

Selected dataset: **CSE-CIC-IDS2018 on AWS**, published by the Canadian Institute for Cybersecurity at the University of New Brunswick.

- Official dataset page: <https://www.unb.ca/cic/datasets/ids-2018.html>
- Official AWS catalog: <https://registry.opendata.aws/cse-cic-ids2018/>
- Dataset version: 2018 processed traffic data for ML algorithms.
- Download date: 2026-07-14.
- Usage terms: the official page permits redistribution, republication, and mirroring and requires citation of the dataset and AWS page.
- Required citation: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization* (2018).

CICIDS2017 was considered, but its current official download path requires a researcher form. UNSW-NB15 was also considered, but its official files currently require authenticated SharePoint access. CSE-CIC-IDS2018 was selected because its official terms are explicit and its public S3 objects were accessible without bypassing an access gate.

## Provider File Identity

| Provider day | Original rows | Bytes | Local SHA-256 | Provider scenario |
| --- | ---: | ---: | --- | --- |
| 2018-02-14 | 1,048,575 | 358,223,333 | `acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147` | FTP and SSH brute force |
| 2018-03-01 | 331,125 | 107,842,858 | `b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf` | Infiltration |

The local SHA-256 values were calculated after download. S3 object sizes, ETags, and last-modified values are retained in the ignored immutable manifest. Raw provider files and all generated evidence remain under ignored `.tmp/external_evidence/` and are not source-controlled.

## Immutable Sampling And Manifest

The evaluator selected 2,000 rows per provider day using the minimum SHA-256 rank of:

```text
sampling_seed | verified_provider_file_sha256 | provider_row_number
```

Seed: `400`. The rank does not include or inspect the provider label. The feature-only CSV excludes `Label` entirely.

Two self-hashed manifests prove the state transition:

- pre-label manifest hash: `d3f1f17b423cd5e66a3383c6f4865c3b47382680f6b367c83a9f36239db94994`;
- final manifest hash: `6f597005696cac8ea8a421bb2aafe0545b7093bbd07df7fb706791832d382d4f`.

Both manifests use `atdr_v400_external_evidence_manifest_v1`, declare `human_reviewed=false` and `import_ready=false`, and contain no private local path.

## Prediction-Before-Label Ordering

The protocol is enforced in code and tests:

1. Verify provider file size and SHA-256.
2. Select rows using provider row identity only.
3. Write a feature-only sample without the label column.
4. Map available provider fields to the frozen ATDR feature contract.
5. Audit exact, near-pattern, and used-feature overlap.
6. Freeze internal fit/calibration/threshold roles.
7. Write and hash all external predictions.
8. Verify the prediction artifact hash.
9. Reopen the provider files and read selected labels.
10. Score the already-frozen predictions.

Measured ordering:

- prediction frozen: `2026-07-14T04:26:01.025312+00:00`;
- label read started: `2026-07-14T04:26:01.046208+00:00`;
- prediction SHA-256: `84d7a0bc9a85e9cd7094f8f9289f63e349185be7e4f3409ce3a398beb99ec2bf`.

External rows used for fitting, probability calibration, or threshold selection: `0/0/0`.

## Honest Feature Adapter

Mapping version: `cse_cic_ids2018_to_atdr_flow_v1`.

Direct provider mappings:

- `Timestamp` to event ordering time;
- `Dst Port` to destination port;
- protocol number `6` to TCP and `17` to UDP;
- forward/backward total packet bytes to sent/received/total bytes;
- forward/backward packet counts to total packets;
- flow duration microseconds to seconds.

Unavailable fields are not invented:

- source and destination IP;
- source port;
- firewall action;
- application and application risk/category/characteristics;
- source and destination zone.

Provider file/day is used only as collection-source identity. It is not represented as a network source IP. Timezone-unqualified provider timestamps are used for deterministic ordering; they are not claimed to be verified UTC event time.

The frozen internal preprocessing pipeline handles missing numerical fields, and categorical fields use the explicit `unavailable` sentinel. This creates a real domain shift and is intentionally not repaired using final labels.

## Rule Applicability

Only `high_bytes_outlier` and `high_packets_outlier` can be evaluated from available fields. Their thresholds were frozen from internal fit-partition features. IP-, direction-, action-, application-, Palo Alto threat-type-, and source-frequency-dependent rules are reported unavailable.

This partial rule baseline detected no sampled provider attacks because no row exceeded the frozen internal byte/packet thresholds. That result is not evidence that the full ATDR rule engine failed; most rule families cannot be evaluated on this flow schema.

## Overlap And Quarantine

| Check | Result |
| --- | ---: |
| Attempted sample rows | 4,000 |
| Accepted and scored | 3,993 |
| Duplicate external exact flows quarantined | 7 |
| Exact overlap with 2,235 internal reviewed rows | 0 |
| Near-pattern overlap with internal reviewed rows | 0 |
| Used-feature overlap with internal reviewed rows | 0 |
| Exact/near/feature overlap with 720 v3.99 synthetic rows | 0 / 0 / 0 |

## Provider Label Provenance

| ATDR diagnostic mapping | Provider labels | Rows |
| --- | --- | ---: |
| benign | `Benign` | 2,727 |
| suspicious | `FTP-BruteForce`, `SSH-Bruteforce` | 708 |
| malicious | `Infilteration` | 558 |

These are provider ground-truth labels. They are not ATDR analyst labels, are not marked human-reviewed, are not import-ready, and were not inserted into `ml_labels`.

## All-External Metrics

| Strategy | Precision | Recall | F1 | Benign FPR | Suspicious recall | Malicious recall | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Frozen calibrated ExtraTrees SOC queue | 0.3171 | 1.0000 | 0.4815 | 1.0000 | 1.0000 | 1.0000 | 0.6538 | 0.6614 |
| Logistic Regression baseline | 0.2179 | 0.1880 | 0.2019 | 0.3132 | 0.0000 | 0.4265 | 0.2979 | 0.1604 |
| IsolationForest baseline | 0.3171 | 1.0000 | 0.4815 | 1.0000 | 1.0000 | 1.0000 | 0.2330 | 0.1149 |
| Applicable deterministic rules | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.3171 | 0.3171 |
| Frozen hybrid decision support | 0.3171 | 1.0000 | 0.4815 | 1.0000 | 1.0000 | 1.0000 | 0.2237 | 0.0750 |
| Internal-fit majority baseline | 0.3171 | 1.0000 | 0.4815 | 1.0000 | 1.0000 | 1.0000 | 0.6829 | 0.6829 |

Primary 95% bootstrap intervals:

- precision: `0.3033-0.3293`;
- recall: `1.0000-1.0000`;
- F1: `0.4654-0.4955`;
- benign-like FPR: `1.0000-1.0000`.

The primary F1 ranges from `0.4363` to `0.5243` across provider-day, temporal, and repeated random views. FPR is `1.0000` in every view. The worst view is the 2018-03-01 provider day: precision `0.2790`, recall `1.0000`, and F1 `0.4363`.

## Error And Calibration Diagnosis

The frozen supervised score is approximately `0.98` for nearly every external row. All 2,727 benign rows become false positives. Dominant benign destinations are ports 53, 443, 3389, 80, and 445, across both TCP and UDP.

Root cause: the internal candidate was trained around Palo Alto categorical context and source/destination behavior windows. The provider flow files omit those identities and firewall semantics. Frozen imputation plus unfamiliar categorical values places almost every flow in the review region. The same missing-domain issue makes IsolationForest and the hybrid queue all-positive at their frozen thresholds.

Confidence calibration is weak. High-confidence review scores do not represent reliable external probabilities. No threshold, guard, feature, or model was adjusted after labels were revealed.

## Known Limitations

- This evaluates two selected attack days, not the full CSE-CIC-IDS2018 corpus.
- Row sampling is deterministic and label-independent but not a device-stratified capture sample.
- Provider labels are dataset ground truth, not independent ATDR analyst review.
- The processed CSV schema omits network identities and firewall semantics described by richer source captures.
- Source-aware rules, cases, and source-window features cannot be fairly assessed.
- The dataset is from 2018 and does not represent current traffic prevalence or all modern attacks.
- A public benchmark cannot replace authorized real-device and long-duration drift validation.

## Readiness And Next Gate

Decision: `candidate_only`.

The v4.0 sample is now locked final evidence and must not be used to select a new threshold, guard, feature, or model. The next model-development work should use a separate declared development corpus to build schema-aware missingness handling or a provider-flow feature branch, then use a new untouched provider dataset for final validation.

Regardless of future metrics:

- `production_promoted=false`;
- `model_activated=false`;
- `model_artifact_written=false`;
- `response_automation_allowed=false`;
- `real_firewall_blocking_enabled=false`.

## Verification Closure

All verification used the migrated ignored disposable SQLite database with MFU IAM and the external assistant provider disabled through process-local overrides. The configured database was not migrated or written.

- Task-board render and standards check: passed.
- Ruff and `compileall`: passed.
- Backend: `556 passed, 1 skipped`; the skip is hardware-dependent.
- Disposable Alembic check: no drift at `b4c5d6e7f8a9 (head)`.
- React lint and production build: passed.
- Playwright: `21 passed, 1 skipped`; the skip is the live hardware-dependent scenario.
- Replay dry-run: two safe rows parsed, zero rows sent or imported.
- Read-only performance smoke: no warnings; Overview `0.4683s`, cached Overview `0.0069s`, ML Governance `1.2817s`, alerts `0.0355s`, cases `0.0923s`.
- Release gate: `ok: true`; no required checks failed.
- The v4.0 evaluation was repeated with an identical prediction hash, `84d7a0bc9a85e9cd7094f8f9289f63e349185be7e4f3409ce3a398beb99ec2bf`, and identical metrics.

## Command

Run only against a migrated disposable validation database:

```powershell
$env:DATABASE_URL='sqlite:///C:/path/to/disposable-validation.sqlite3'
.\.venv\Scripts\python.exe -m atdr.scripts.run_v400_provider_blinded_external_validation --rows-per-file 2000 --seed 400 --summary-only --pretty
```

The official files must already exist beneath ignored `.tmp/external_evidence/cse_cic_ids2018/` with the exact names and checksums above.
