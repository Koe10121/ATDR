# v5.24 Exact Cumulative Commit Allowlist

Date: 2026-08-02

## Purpose

This file defines the exact tracked review boundary for the uncommitted v5.19
through v5.24 detection-evidence, supervised-rebuild, live-source, and bounded
investigation/Gemini quality work. It does not authorize a commit or push.

## Exact Paths

```text
atdr/app/detection/explanations.py
atdr/app/detection/supervised_detector.py
atdr/app/detection/v51_supervised_lifecycle.py
atdr/app/detection/v519_independent_labeled_validation.py
atdr/app/detection/v520_schema_aware_abstention.py
atdr/app/detection/v520_schema_aware_abstention_validation.py
atdr/app/detection/v521_native_panos_evidence.py
atdr/app/detection/v522_supervised_model_rebuild.py
atdr/app/services/assistant_llm.py
atdr/app/services/assistant_service.py
atdr/app/services/ml_evidence_snapshot_service.py
atdr/app/services/syslog_service.py
atdr/app/services/v523_live_source_acceptance_service.py
atdr/app/services/v524_investigation_gemini_quality_service.py
atdr/app/services/v58_shadow_scoring_service.py
atdr/scripts/run_v519_independent_labeled_validation.py
atdr/scripts/run_v520_schema_aware_abstention.py
atdr/scripts/run_v521_native_panos_evidence.py
atdr/scripts/run_v522_supervised_model_rebuild.py
atdr/scripts/run_v523_live_source_acceptance.py
atdr/scripts/run_v524_investigation_gemini_quality_lock.py
atdr/tests/test_iam_rbac.py
atdr/tests/test_syslog_lab_ingestion.py
atdr/tests/test_v519_independent_labeled_validation.py
atdr/tests/test_v520_schema_aware_abstention.py
atdr/tests/test_v521_native_panos_evidence.py
atdr/tests/test_v522_supervised_model_rebuild.py
atdr/tests/test_v523_live_source_acceptance.py
atdr/tests/test_v524_investigation_gemini_quality.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/LAB_RUNBOOK.md
docs/V5_19_COMMIT_ALLOWLIST.md
docs/V5_19_INDEPENDENT_LABELED_BLIND_VALIDATION.md
docs/V5_20_COMMIT_ALLOWLIST.md
docs/V5_20_SCHEMA_AWARE_ABSTENTION.md
docs/V5_21_COMMIT_ALLOWLIST.md
docs/V5_21_NATIVE_PANOS_EVIDENCE_PROGRAM.md
docs/V5_22_COMMIT_ALLOWLIST.md
docs/V5_22_SUPERVISED_MODEL_REBUILD.md
docs/V5_23_COMMIT_ALLOWLIST.md
docs/V5_23_LIVE_SOURCE_ACCEPTANCE.md
docs/V5_24_COMMIT_ALLOWLIST.md
docs/V5_24_INVESTIGATION_AND_GEMINI_QUALITY_LOCK.md
docs/changes/T1_T20_V5_19_INDEPENDENT_LABELED_BLIND_VALIDATION.md
docs/changes/T1_T20_V5_20_SCHEMA_AWARE_ABSTENTION.md
docs/changes/T1_T20_V5_21_NATIVE_PANOS_EVIDENCE_PROGRAM.md
docs/changes/T1_T20_V5_22_SUPERVISED_MODEL_REBUILD.md
docs/changes/T1_T20_V5_23_LIVE_SOURCE_ACCEPTANCE.md
docs/changes/T1_T20_V5_24_INVESTIGATION_AND_GEMINI_QUALITY_LOCK.md
docs/detection/V5_21_PANOS_FIELD_CONTRACT.md
docs/detection/V5_22_FROZEN_SHADOW_CANDIDATE_CONTRACT.md
docs/detection/V5_23_LIVE_SOURCE_ACCEPTANCE_CONTRACT.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/components/AppShell.tsx
frontend/src/components/AssistantAnswerContent.tsx
frontend/src/components/MLEvidenceSnapshotPanel.tsx
frontend/src/pages/AlertsTriage.tsx
frontend/src/pages/DemoControls.tsx
frontend/src/pages/LogExplorer.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

Exact path count: `68`.

## Explicit Exclusions

Do not stage:

- private PAN-OS evidence, paths, raw rows, addresses, or fingerprints;
- manifests, assisted/blind packs, predictions, or generated reports under
  `ml_baseline_reviews/`;
- `.env`, credentials, provider keys, tokens, or secrets;
- databases, backups, journals, temporary PostgreSQL files, or model artifacts;
- `demo_exports/`, processed evidence, build output, test output, or unrelated
  local work; or
- deferred-gate evidence that has not actually been observed.

## Boundary Checks

Before any separately approved Git operation:

1. compare the changed-path set exactly with these 68 paths;
2. run `git diff --check`;
3. verify generated/private evidence remains ignored and untracked;
4. scan all allowlisted paths for private paths, raw evidence, IP addresses,
   fingerprints, database URLs, credentials, and secrets;
5. confirm the staging area is empty until separate exact-path approval; and
6. preserve v5.23 as deferred/open rather than passed.

No commit or push is authorized by this document.
