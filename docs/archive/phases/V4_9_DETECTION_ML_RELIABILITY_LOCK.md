# v4.9 Detection and ML Decision-Support Reliability Lock

Date: 2026-07-18

## Decision

v4.9 is implemented as a read-only reliability and governance phase. Controlled rule scenarios pass, parser/rule provenance is stronger, and supervised feature generation is source-scoped and causal. No supervised candidate is stable enough across every internal split, and the locked external benchmark still fails. Readiness remains `candidate_only`.

No model was activated or promoted, no active artifact was written, no label was authored, no response action was created, and real firewall blocking remains disabled.

## What Changed

- Added versioned catalog `atdr_rule_catalog_v4.9.0` with stable IDs, required fields, source/window scope, false positives, references, MITRE context, explanation templates, and claim boundaries.
- Corrected overclaims: generic Palo Alto `THREAT`, app risk, and directionless byte/packet outliers no longer imply C2, exfiltration, or DoS.
- Made repeated-behavior correlation source-scoped and five-minute bounded.
- Anchored Palo Alto app metadata to documented field positions with validation and safe fallback.
- Added feature set `behavior_windows_v3_leakage_safe`: prior-only history, source-scoped windows, parser missingness/confidence, repeat-count, and behavior diversity signals.
- Repaired bulk feature generation so it matches scalar causal features while avoiding thousands of SQL queries.
- Separated stored alert evidence from current diagnostic scores in `Why flagged?` explanations.
- Added one unified read-only evaluator with dedicated fit, calibration, threshold-selection, and final-test roles.
- Clarified the model registry: an active legacy artifact exists, but classifier/feature metadata are unavailable; diagnostic candidates are not active.

## Source Research

Primary sources accessed 2026-07-18:

- Palo Alto Networks [Traffic Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields) and [Threat Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields).
- [Sigma Rules Specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html).
- MITRE ATT&CK [T1046](https://attack.mitre.org/techniques/T1046/), [T1110](https://attack.mitre.org/techniques/T1110/), [T1498](https://attack.mitre.org/techniques/T1498/), [T1071](https://attack.mitre.org/techniques/T1071/), and [T1048](https://attack.mitre.org/techniques/T1048/).
- University of New Brunswick [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html).
- scikit-learn [Probability Calibration](https://scikit-learn.org/stable/modules/calibration.html), [TimeSeriesSplit](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.TimeSeriesSplit.html), and [GroupKFold](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupKFold.html).

These sources define field meaning, rule/evidence structure, behavior context, dataset provenance, and validation methods. They do not certify ATDR's thresholds or accuracy.

### Primary Source Evidence Register

Rechecked 2026-07-22. ATDR references these sources; it does not redistribute vendor documentation, Sigma rules, ATT&CK content, or external benchmark rows in Git.

| Primary source | License or permitted use | ATDR mapping | Limitation |
| --- | --- | --- | --- |
| Palo Alto Networks [Traffic Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields) and [Threat Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields) | Copyrighted vendor documentation; reference-only use. No reuse license is asserted and no documentation content is redistributed. | Anchors parser field positions, event families, action/application context, and missing-field behavior. | Field availability varies by PAN-OS version, log subtype, export profile, and custom syslog format. A generic `THREAT` row does not prove a particular attack. |
| SigmaHQ [Sigma Rules Specification](https://github.com/SigmaHQ/sigma-specification) and [official rule repository](https://github.com/SigmaHQ/sigma) | The specification is public domain; official repository rules are under Detection Rule License 1.1. ATDR copied no Sigma rule content. | Informs the versioned rule metadata contract: stable ID, status, log source, fields, condition, false positives, level, references, and tests. | Sigma structure is an inspiration, not direct rule compatibility. ATDR uses normalized firewall-flow evidence and its own thresholds/catalog. |
| [MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/) and techniques T1046, T1110, T1498, T1071, and T1048 | Non-exclusive, royalty-free research, development, and commercial use with MITRE's required copyright/license attribution for copies. | Provides behavioral context for service discovery, brute force, network denial of service, application-layer protocol, and exfiltration hypotheses. | ATT&CK mappings are hypotheses and vocabulary, not proof of intent, attribution, compromise, impact, or complete defensive coverage. |
| University of New Brunswick [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) and [AWS registry](https://registry.opendata.aws/cse-cic-ids2018/) | Redistribution, republication, and mirroring are permitted when the dataset and official AWS page/paper are cited. | Supplies locked external provider labels and CICFlowMeter flow evidence for a no-tuning generalization check. Files stay outside Git; tracked evidence is limited to a manifest, checksums, schema mapping, citations, and aggregates. | CICFlowMeter bidirectional flows are not Palo Alto logs. Action, application, zones, source identity, and source-history fields are unavailable and must not be fabricated. |
| scikit-learn [calibration](https://scikit-learn.org/stable/modules/calibration.html), [TimeSeriesSplit](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.TimeSeriesSplit.html), [GroupKFold](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupKFold.html), and [source license](https://github.com/scikit-learn/scikit-learn/blob/main/COPYING) | BSD 3-Clause License. | Implements candidate estimators, held-out split mechanics, probability calibration, and diagnostic metrics. | Library APIs and calibration methods do not certify dataset quality, threshold validity, cross-device generalization, or production readiness. |

## Controlled Rule Validation

The disposable scenario matrix passed 24 of 24 scenarios:

| Measure | Result |
| --- | ---: |
| Expected scenarios passed | 24 / 24 |
| Scenario-level false positives | 0 |
| Scenario-level false negatives | 0 |
| Unexpected attack types | 0 |
| Expected/actual alerts | 15 / 15 |
| Response actions | 0 |

This proves controlled regression behavior only. It does not measure prevalence-weighted or real-device accuracy.

## Label Evidence

The evaluator selected 2,235 latest label rows whose `reviewed` flag is true and preserved original `label_source`:

| Source | Rows |
| --- | ---: |
| `manual` | 1,672 |
| `assisted_rule` | 529 |
| `assisted_ml` | 7 |
| `assisted_hybrid` | 27 |

Class counts are benign 522, benign-unusual 662, needs-context 103, suspicious 536, and malicious 412. Another 437 latest weak/unreviewed rows were excluded. v4.9 authored zero AI labels and marked zero AI labels human-reviewed. The reviewed flag must not be presented as proof that every included label was human-authored; original provenance remains visible.

## Leakage And Duplicate Audit

- Duplicate normalized-log IDs in evaluation: 0.
- Leakage groups: 1,749; largest group: 43 rows.
- Multi-row groups: 190, containing 676 rows.
- Exact-fingerprint groups: 126.
- Near-fingerprint groups: 190.
- Used-feature fingerprint groups: 10.
- Duplicate/near-duplicate groups remain inside one partition.
- All five split leakage audits passed.
- Final-test labels were excluded from fit, calibration, threshold selection, and candidate selection.

The current label evidence represents one physical firewall. A true device-disjoint source holdout is therefore impossible; `network_zone_holdout` is explicitly a proxy, not independent device validation.

## Evaluation Protocol

Required views:

- strict temporal holdout;
- network-zone group holdout proxy;
- random seeds 7, 17, and 42.

Compared strategies:

- deterministic rules;
- IsolationForest;
- flat five-class ExtraTrees;
- binary SOC queue ExtraTrees with balanced/lower-threat/strong-benign weights;
- calibrated strong-benign ExtraTrees;
- calibrated Logistic Regression;
- three-class SOC queue ExtraTrees;
- hierarchical two-stage ExtraTrees; and
- hybrid rule/anomaly/supervised decision support.

Strict gates require FPR `<=0.10`, threat-positive F1 `>=0.85`, suspicious recall `>=0.80`, malicious recall `>=0.80`, ECE `<=0.10`, and maximum confidence/accuracy gap `<=0.15` on every required split.

## Results

The post-evaluation diagnostic ranking selected `hybrid_rule_anomaly_supervised_decision_support`, but it is not eligible for activation.

### Baseline Versus Final Diagnostic Comparison

All ranges below come from the same locked five-view evaluator, so they are reproducible and comparable. "Final diagnostic" means the highest-ranked v4.9 analysis candidate, not an activated model or a strategy that improved every split.

| Strategy | Role | Threat F1 range | Benign-like FPR range | Suspicious recall range | Malicious recall range | Calibration gates passed |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Deterministic rules | Explainable baseline | 0.6703-0.9191 | 0.0217-0.9241 | 0.5641-0.9412 | 0.8226-0.9848 | 0 / 5 |
| IsolationForest | Unsupervised baseline | 0.4033-0.7830 | 0.1964-0.4227 | 0.5290-1.0000 | 0.4571-0.8605 | 0 / 5 |
| Flat five-class ExtraTrees | Supervised baseline | 0.2260-0.8475 | 0.0372-0.6063 | 0.0294-0.7094 | 0.6000-0.9271 | 0 / 5 |
| Hybrid rule/anomaly/supervised | Final diagnostic candidate | 0.7310-0.8165 | 0.0169-0.7232 | 0.4701-0.8235 | 0.5286-0.9726 | 0 / 5 |

The hybrid narrowed some random-split variation and produced the lowest temporal FPR, but the zone-proxy FPR, recall floors, and calibration remain unacceptable. It therefore passes zero of five strict split gates and cannot replace the current governed runtime behavior.

| View | Threat F1 | Benign-like FPR | Suspicious recall | Malicious recall | ECE | Max gap |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Temporal | 0.7310 | 0.0169 | 0.8235 | 0.5286 | 0.2579 | 0.3747 |
| Zone proxy | 0.7513 | 0.7232 | 0.6323 | 0.9726 | 0.1589 | 0.3127 |
| Random 7 | 0.8165 | 0.0811 | 0.6667 | 0.8527 | 0.1336 | 0.4073 |
| Random 17 | 0.7648 | 0.0608 | 0.4701 | 0.8450 | 0.1289 | 0.3836 |
| Random 42 | 0.8063 | 0.1318 | 0.7440 | 0.8306 | 0.1311 | 0.4095 |

The predeclared calibrated strong-benign ExtraTrees candidate also failed all-split reliability:

- threat F1 range `0.2363-0.8415`;
- FPR range `0.0709-0.2198`;
- suspicious recall range `0.1176-0.7200`;
- malicious recall range `0.2857-0.9147`; and
- calibration passed 0 of 5 splits.

The controlled deterministic rules were strong on the temporal view but reached FPR `0.9241` on the zone proxy, demonstrating environment dependence. The hybrid reduced some random-split noise but did not repair calibration or cross-zone generalization.

The locked v4.0 CSE-CIC-IDS2018 evidence remains unchanged and was not used for fitting, calibration, thresholds, or tuning. Its FPR is `1.0000`, threat F1 ranges `0.4363-0.5243`, and its strict external gate fails.

## Error Diagnosis

- **False positives:** zone/environment shift, low-specificity deny/app-risk/unknown-app evidence, repeated allowed services, and schema-dependent behavior features.
- **False negatives:** suspicious rows at the benign/unusual boundary, late temporal-window malicious behavior, and evidence whose source diversity or correlation context does not transfer across partitions.
- **Calibration:** confidence does not reliably represent observed queue risk across splits; no strategy passes both ECE and maximum-gap gates everywhere.
- **Schema transfer:** provider-flow rows lack Palo Alto action, app, zone, source identity, and behavior-window fields; missing fields are reported rather than fabricated.

## Readiness Lock

Readiness: `candidate_only` with 3 of 5 governance checks passed.

Passed:

- all required internal splits evaluated;
- all leakage audits passed; and
- final labels excluded from fit/calibration/threshold selection.

Blocked:

- predeclared candidate passes every strict split gate; and
- locked external benchmark passes strict gates.

The active legacy artifact is unchanged and has unknown registration metadata. It must not be described as the v4.9 candidate or as production-promoted.

## Generated Evidence

The following are intentionally ignored and must not be committed:

- `ml_baseline_reviews/v4_9_detection_ml_reliability_<timestamp>.md`
- `ml_baseline_reviews/v4_9_split_stability_<timestamp>.md`
- `ml_baseline_reviews/v4_9_model_comparison_latest.json`

## Requirement Closure Matrix

| Original task | Status | Authoritative evidence |
| --- | --- | --- |
| 1. Audit parser, schema, rules, ML, registry, gates, tests, and UI | Complete | Unified evaluator and generated baseline evidence; `atdr/app/detection/v49_detection_ml_reliability.py`; this report. |
| 2. Versioned taxonomy and unsupported claims | Complete | `docs/detection/ATDR_DETECTION_TAXONOMY.md`; `atdr/app/detection/attack_mapping.py`. |
| 3. Sigma-inspired versioned rule contract | Complete | `atdr/app/detection/rule_catalog.py`; `docs/detection/ATDR_RULE_PACK_CONTRACT.md`; contract validator/tests. |
| 4. Rule false-positive/negative and evidence audit | Complete | `atdr/app/detection/rules.py`; catalog claim boundaries; rule and v4.9 tests. |
| 5. Controlled positive, negative, boundary, malformed, duplicate, and isolation corpus | Complete | `data/samples/scenarios/`; `docs/detection/ATDR_SCENARIO_CORPUS_CONTRACT.md`; 24/24 disposable scenario result. |
| 6. External benchmark adapter and safe provenance | Complete | `data/samples/benchmarks/cse_cic_ids2018_v49_manifest.json`; locked evaluator adapter; external files/reports remain outside Git. |
| 7. Inference-safe temporal/diversity/missingness features | Complete | `atdr/app/ml/features.py`; causal scalar/bulk equivalence and future/source-isolation tests. |
| 8. Required rule, anomaly, supervised, hierarchical, and hybrid comparisons | Complete | `strategy_comparison` in the generated v4.9 JSON and the baseline/final table above. |
| 9. Temporal, grouped proxy, repeated-random, scenario, and external validation | Complete | Five internal views, 24/24 scenario matrix, locked external result; thresholds selected outside final-test labels. |
| 10. Metrics, calibration, queue, source/attack, and error analysis | Complete | Generated comparison/stability reports and this report's results/error sections. |
| 11. Conservative reliability targets | Complete | Strict gates encoded in the evaluator; zero candidates pass all five; readiness remains `candidate_only`. |
| 12. Layered alert explanation provenance | Complete | `atdr/app/detection/explanations.py`; `atdr/app/services/alert_service.py`; explanation regression tests. |
| 13. Model-registry clarity | Complete | `frontend/src/pages/MLGovernance.tsx`; registry API behavior and frontend/backend regression tests. |
| 14. Comprehensive safety and reliability tests | Complete | v4.9/parser/rule/supervised/API tests plus full backend, Playwright, scenario, assistant, performance, and release gates. |
| 15. Named docs and governance updates | Complete | v4.9 report/change/allowlist, labeling/rule standards, PRD, traceability, compliance, AI status/index, and task board. |

## Next Evidence Required

1. Collect independently reviewed evidence from more than one physical firewall/source and time period.
2. Define a separate development corpus for calibration and schema-shift repair.
3. Reserve a new untouched compatible benchmark for final validation.
4. Register full model, feature, data, threshold, calibration, and artifact metadata before any activation discussion.
5. Keep response automation and real firewall blocking disabled under a separate safety gate.

### External Input Boundaries

| Input owner | Required next evidence | Why Codex/local automation cannot close it alone |
| --- | --- | --- |
| Human analysts | Independently review new multi-source/time labels and resolve ambiguous benign/suspicious boundaries. | AI-assisted suggestions cannot be converted into human-reviewed ground truth. |
| Advisor/governance owner | Approve evaluation scope, acceptable error tradeoffs, data handling, and any future activation protocol. | Numeric gates do not replace institutional risk acceptance. |
| Firewall/router hardware owner | Provide controlled device-disjoint Palo Alto/syslog evidence from at least two physical sources and different time periods. | The current label evidence represents one physical firewall; a zone proxy is not a device holdout. |
| Dataset/provider owner | Supply or approve a new untouched schema-compatible benchmark and its permitted-use terms. | The locked CICFlowMeter evidence has a material schema mismatch and now belongs only to final historical evidence. |

MFU identity-provider and Gemini acceptance are separate product gates; neither is required to reproduce this read-only v4.9 detector evaluation, and neither authorizes model promotion or response automation.

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v49_detection_ml_reliability --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.validate_rule_pack_contract --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_validation_suite --all --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release --pretty --timeout 1200
```

Run time on the current large local SQLite database was about 42 seconds, including roughly 9 seconds for causal feature generation. The command is read-only with respect to operational data and the active artifact.

## Verification Closure

- Ruff, compileall, and Alembic drift checks passed.
- Full backend suite: `623 passed, 1 skipped`.
- React lint and production build passed.
- Playwright: `25 passed, 1 skipped`.
- Controlled scenario matrix: `24/24` passed, 15 expected/actual alerts, and zero response actions.
- Assistant safety regression: `20/20` questions passed with zero response, detection, label, model, alert, or log side effects.
- Replay dry-run parsed the two-line safe sample and wrote zero rows.
- Read-only performance smoke had no warnings: Overview `0.1693s`, cached Overview `0.0113s`, ML Governance `1.2144s`, alerts `0.0332s`, cases `0.0714s`, and 20-row feature generation `0.0070s`.
- Release gate returned `ok: true` with no failed required checks.

The performance smoke now exercises the production batch feature API. Persisted batches of two or more rows use the leakage-safe bulk path; single-log inference behavior is unchanged.

### Recovery Revalidation

The recovered v4.9 goal was revalidated against the current worktree on 2026-07-22, including the later read-only v5.0 shadow-audit refinements. The evaluator reproduced the same split metrics and `candidate_only` decision in `34.547s`; database counts and the active artifact remained unchanged. The controlled corpus passed `24/24`, assistant QA passed `20/20`, the full backend passed `632 passed, 1 skipped`, and Playwright passed `25 passed, 1 skipped`.

The recovery run also found stale API assertions that still referenced the pre-sanitization parser fixture. They were aligned to the reserved documentation-address fixture, and remaining MFU-specific identifiers were removed from the tracked two-line demo/syslog samples. Replay dry-run parsed both sanitized rows and wrote zero records. Read-only performance remained warning-free: Overview `0.1658s`, cached Overview `0.0109s`, ML Governance `1.1861s`, alerts `0.0432s`, cases `0.0707s`, and 20-row feature generation `0.0068s`. The release gate completed with `ok: true` and no failed required checks.
