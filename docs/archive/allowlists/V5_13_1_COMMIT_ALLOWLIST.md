# v5.13.1 Exact Cumulative Commit Allowlist

Date: 2026-07-28

## Purpose

This is the exact review boundary for the cumulative uncommitted v4.9-v5.13
Detection/ML, parser, runtime source-quality, API/UI, test, migration, and
governance program plus the v5.13.1 closure records.

It does not authorize staging, committing, pushing, deleting files, migrating
the configured database, or changing runtime/model/response state. Separate
explicit owner approval is required for any Git operation.

## Exact Paths By Subsystem

### Alembic migrations (3)

```text
migrations/versions/c5d6e7f8a9b0_add_ml_shadow_observations.py
migrations/versions/d6e7f8a9b0c1_add_ml_profile_covering_index.py
migrations/versions/e7f8a9b0c1d2_add_source_parser_quality_aggregate.py
```

### Backend configuration, data model, API, and schemas (6)

```text
atdr/app/core/config.py
atdr/app/db/models.py
atdr/app/routers/ml.py
atdr/app/routers/sources.py
atdr/app/schemas/logs.py
atdr/app/schemas/sources.py
```

### Backend runtime services (20)

```text
atdr/app/services/alert_service.py
atdr/app/services/assistant_service.py
atdr/app/services/detection_service.py
atdr/app/services/job_dispatcher.py
atdr/app/services/job_service.py
atdr/app/services/log_service.py
atdr/app/services/ml_service.py
atdr/app/services/operation_worker.py
atdr/app/services/private_log_preflight_service.py
atdr/app/services/resumable_ingestion_service.py
atdr/app/services/runtime_parser_quality_service.py
atdr/app/services/source_service.py
atdr/app/services/suppression_service.py
atdr/app/services/syslog_service.py
atdr/app/services/v50_shadow_validation_service.py
atdr/app/services/v510_detection_operations_service.py
atdr/app/services/v511_shadow_monitoring_service.py
atdr/app/services/v512_parser_baseline_service.py
atdr/app/services/v58_shadow_scoring_service.py
atdr/app/services/v59_shadow_observation_service.py
```

### Backend tests (31)

```text
atdr/tests/test_api.py
atdr/tests/test_detection_grouping.py
atdr/tests/test_detection_validation_suite.py
atdr/tests/test_layered_detection_validation.py
atdr/tests/test_ml_baseline_review.py
atdr/tests/test_parser.py
atdr/tests/test_release_gate.py
atdr/tests/test_replay_and_dedup.py
atdr/tests/test_rule_pack_contract.py
atdr/tests/test_rules.py
atdr/tests/test_source_scenarios.py
atdr/tests/test_supervised_ml.py
atdr/tests/test_syslog_lab_ingestion.py
atdr/tests/test_syslog_sender.py
atdr/tests/test_v393_resumable_ingestion.py
atdr/tests/test_v46_mfu_shell_distribution.py
atdr/tests/test_v49_detection_ml_reliability.py
atdr/tests/test_v50_real_paloalto_shadow_validation.py
atdr/tests/test_v51_supervised_lifecycle.py
atdr/tests/test_v510_detection_operations.py
atdr/tests/test_v511_shadow_monitoring.py
atdr/tests/test_v512_parser_profile_baseline_repair.py
atdr/tests/test_v513_runtime_parser_contract.py
atdr/tests/test_v52_shadow_reliability.py
atdr/tests/test_v53_temporal_generalization.py
atdr/tests/test_v54_temporal_evidence.py
atdr/tests/test_v55_development_model_repair.py
atdr/tests/test_v56_private_panos_model_repair.py
atdr/tests/test_v57_independent_shadow_revalidation.py
atdr/tests/test_v58_governed_shadow_runtime.py
atdr/tests/test_v59_longitudinal_shadow_observation.py
```

### CLI, validation, and release tooling (23)

```text
atdr/scripts/generate_detection_variants.py
atdr/scripts/manage_supervised_lifecycle.py
atdr/scripts/performance_smoke.py
atdr/scripts/profile_ml_governance.py
atdr/scripts/replay_logs.py
atdr/scripts/run_layered_detection_validation.py
atdr/scripts/run_v49_detection_ml_reliability.py
atdr/scripts/run_v50_real_paloalto_shadow_validation.py
atdr/scripts/run_v51_supervised_shadow_activation.py
atdr/scripts/run_v510_detection_operations_acceptance.py
atdr/scripts/run_v511_shadow_monitoring.py
atdr/scripts/run_v512_parser_profile_baseline_repair.py
atdr/scripts/run_v52_shadow_reliability.py
atdr/scripts/run_v53_temporal_generalization.py
atdr/scripts/run_v54_temporal_evidence_preparation.py
atdr/scripts/run_v55_development_model_repair.py
atdr/scripts/run_v56_private_panos_model_repair.py
atdr/scripts/run_v57_independent_shadow_revalidation.py
atdr/scripts/run_v58_governed_shadow_runtime.py
atdr/scripts/run_v59_longitudinal_shadow_observation.py
atdr/scripts/send_sample_syslog.py
atdr/scripts/validate_rule_pack_contract.py
atdr/scripts/verify_release.py
```

### Detection and supervised ML (16)

```text
atdr/app/detection/attack_mapping.py
atdr/app/detection/explanations.py
atdr/app/detection/rule_catalog.py
atdr/app/detection/rules.py
atdr/app/detection/supervised_detector.py
atdr/app/detection/supervised_workflow.py
atdr/app/detection/v331_noise_reduction.py
atdr/app/detection/v398_independent_holdout_validation.py
atdr/app/detection/v49_detection_ml_reliability.py
atdr/app/detection/v51_supervised_lifecycle.py
atdr/app/detection/v52_shadow_reliability.py
atdr/app/detection/v53_temporal_generalization.py
atdr/app/detection/v54_temporal_evidence.py
atdr/app/detection/v55_development_model_repair.py
atdr/app/detection/v56_private_panos_model_repair.py
atdr/app/detection/v57_independent_shadow_revalidation.py
```

### Governance, status, security, and product documentation (44)

```text
docs/AI_TRAINING_RUNBOOK.md
docs/AI-DOCS-INDEX.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/detection/ATDR_DETECTION_TAXONOMY.md
docs/detection/ATDR_RULE_PACK_CONTRACT.md
docs/detection/ATDR_SCENARIO_CORPUS_CONTRACT.md
docs/detection/V5_7_INDEPENDENT_EVIDENCE_ACQUISITION.md
docs/detection/V5_9_INDEPENDENT_EVIDENCE_ACQUISITION.md
docs/prd/PRD-ATDR.md
docs/security/ATDR_DETECTION_LABELING_POLICY.md
docs/security/ATDR_DETECTION_RULE_STANDARD.md
docs/V4_9_COMMIT_ALLOWLIST.md
docs/V4_9_DETECTION_ML_RELIABILITY_LOCK.md
docs/V5_1_COMMIT_ALLOWLIST.md
docs/V5_1_SUPERVISED_SHADOW_ACTIVATION.md
docs/V5_10_COMMIT_ALLOWLIST.md
docs/V5_10_DETECTION_OPERATIONS_AND_SHADOW_ACCEPTANCE.md
docs/V5_11_COMMIT_ALLOWLIST.md
docs/V5_11_OPERATIONAL_DRIFT_AND_SHADOW_MONITORING.md
docs/V5_12_COMMIT_ALLOWLIST.md
docs/V5_12_PARSER_PROFILE_BASELINE_REPAIR.md
docs/V5_13_1_COMMIT_ALLOWLIST.md
docs/V5_13_1_DETECTION_PARSER_PROGRAM_CONSOLIDATION.md
docs/V5_13_COMMIT_ALLOWLIST.md
docs/V5_13_RUNTIME_PARSER_CONTRACT_AND_SOURCE_QUALITY.md
docs/V5_2_COMMIT_ALLOWLIST.md
docs/V5_2_SHADOW_RELIABILITY_AND_LAYERED_REPAIR.md
docs/V5_3_COMMIT_ALLOWLIST.md
docs/V5_3_TEMPORAL_GENERALIZATION_AND_OOD.md
docs/V5_4_COMMIT_ALLOWLIST.md
docs/V5_4_TEMPORAL_EVIDENCE_AND_SHADOW_DRIFT.md
docs/V5_5_COMMIT_ALLOWLIST.md
docs/V5_5_DEVELOPMENT_MODEL_REPAIR_AND_ANOMALY_AUDIT.md
docs/V5_6_COMMIT_ALLOWLIST.md
docs/V5_6_PRIVATE_PANOS_EVIDENCE_AND_ASSISTED_MODEL_REPAIR.md
docs/V5_7_COMMIT_ALLOWLIST.md
docs/V5_7_INDEPENDENT_EVIDENCE_READINESS_AND_BLIND_REVALIDATION.md
docs/V5_8_COMMIT_ALLOWLIST.md
docs/V5_8_GOVERNED_SHADOW_SCORING_RUNTIME.md
docs/V5_9_COMMIT_ALLOWLIST.md
docs/V5_9_LONGITUDINAL_SHADOW_OBSERVATION.md
```

### ML feature pipeline (1)

```text
atdr/app/ml/features.py
```

### Parser contracts and implementation (2)

```text
atdr/app/parsers/paloalto_contract.py
atdr/app/parsers/paloalto_parser.py
```

### Playwright tests (1)

```text
frontend/tests/smoke.spec.ts
```

### React contracts and UI (7)

```text
frontend/src/components/Badge.tsx
frontend/src/hooks/useApiQueries.ts
frontend/src/lib/api.ts
frontend/src/pages/AlertsTriage.tsx
frontend/src/pages/ExecutiveOverview.tsx
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
```

### Root configuration and documentation (3)

```text
.env.example
.env.lab.example
README.md
```

### Synthetic samples and non-secret lock manifests (6)

```text
data/samples/benchmarks/cse_cic_ids2018_v49_manifest.json
data/samples/benchmarks/v511_operational_diagnostics_lock.json
data/samples/benchmarks/v53_temporal_evidence_lock.json
data/samples/benchmarks/v57_independent_evidence_manifest.template.json
data/samples/paloalto-demo.txt
data/samples/scenarios/scenario_expectations.json
```

### T1-T20 change records (15)

```text
docs/changes/T1_T20_V4_9_DETECTION_ML_RELIABILITY_LOCK.md
docs/changes/T1_T20_V5_1_SUPERVISED_SHADOW_ACTIVATION.md
docs/changes/T1_T20_V5_10_DETECTION_OPERATIONS_AND_SHADOW_ACCEPTANCE.md
docs/changes/T1_T20_V5_11_OPERATIONAL_DRIFT_AND_SHADOW_MONITORING.md
docs/changes/T1_T20_V5_12_PARSER_PROFILE_BASELINE_REPAIR.md
docs/changes/T1_T20_V5_13_1_DETECTION_PARSER_PROGRAM_CONSOLIDATION.md
docs/changes/T1_T20_V5_13_RUNTIME_PARSER_CONTRACT_AND_SOURCE_QUALITY.md
docs/changes/T1_T20_V5_2_SHADOW_RELIABILITY_AND_LAYERED_REPAIR.md
docs/changes/T1_T20_V5_3_TEMPORAL_GENERALIZATION_AND_OOD.md
docs/changes/T1_T20_V5_4_TEMPORAL_EVIDENCE_AND_SHADOW_DRIFT.md
docs/changes/T1_T20_V5_5_DEVELOPMENT_MODEL_REPAIR_AND_ANOMALY_AUDIT.md
docs/changes/T1_T20_V5_6_PRIVATE_PANOS_EVIDENCE_AND_ASSISTED_MODEL_REPAIR.md
docs/changes/T1_T20_V5_7_INDEPENDENT_EVIDENCE_READINESS_AND_BLIND_REVALIDATION.md
docs/changes/T1_T20_V5_8_GOVERNED_SHADOW_SCORING_RUNTIME.md
docs/changes/T1_T20_V5_9_LONGITUDINAL_SHADOW_OBSERVATION.md
```

### Taskboard records (2)

```text
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

### Team startup tooling (1)

```text
scripts/start_system.ps1
```

Path count: **181**

## Reconciliation

- 174 paths come from the unique union of the v4.9-v5.13 phase allowlists.
- `atdr/app/services/private_log_preflight_service.py`,
  `atdr/app/services/suppression_service.py`, and `scripts/start_system.ps1`
  are source-evidenced omissions resolved by v5.13.1.
- Four paths are v5.13.1 closure records or the newly refreshed state lock.
- Every path exists, appears once in this document, and is changed relative to
  the published baseline.

## Explicit Exclusions

- `.env` and every private environment profile or secret;
- databases, journals, backups, and configured local data;
- real/private logs and raw evidence;
- model binaries and active/candidate artifacts;
- `ml_baseline_reviews/`, `demo_exports/`, and processed evidence;
- generated CSV/JSON/HTML/PDF reports outside intentionally tracked docs;
- frontend build/test output, dependencies, caches, and temporary files; and
- every changed path not listed above.

## Safety State

- Staging, commit, and push are not authorized.
- Configured data and historical evidence remain unchanged.
- Deterministic rules remain alert-authoritative.
- Supervised lifecycle remains `shadow_observation`.
- Model activation/promotion, automatic response, and real blocking remain
  disabled.
