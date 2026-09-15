# v5.21 Exact Cumulative Commit Allowlist

Date: 2026-08-01

## Purpose

This file defines the exact tracked review boundary for the uncommitted v5.19
Independent Labeled Blind Validation, v5.20 Schema-Aware Abstention, and v5.21
Native PAN-OS Evidence Program. It does not authorize a commit or push.

## Exact Paths

```text
atdr/app/detection/explanations.py
atdr/app/detection/supervised_detector.py
atdr/app/detection/v51_supervised_lifecycle.py
atdr/app/detection/v519_independent_labeled_validation.py
atdr/app/detection/v520_schema_aware_abstention.py
atdr/app/detection/v520_schema_aware_abstention_validation.py
atdr/app/detection/v521_native_panos_evidence.py
atdr/app/services/ml_evidence_snapshot_service.py
atdr/app/services/v58_shadow_scoring_service.py
atdr/scripts/run_v519_independent_labeled_validation.py
atdr/scripts/run_v520_schema_aware_abstention.py
atdr/scripts/run_v521_native_panos_evidence.py
atdr/tests/test_v519_independent_labeled_validation.py
atdr/tests/test_v520_schema_aware_abstention.py
atdr/tests/test_v521_native_panos_evidence.py
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
docs/changes/T1_T20_V5_19_INDEPENDENT_LABELED_BLIND_VALIDATION.md
docs/changes/T1_T20_V5_20_SCHEMA_AWARE_ABSTENTION.md
docs/changes/T1_T20_V5_21_NATIVE_PANOS_EVIDENCE_PROGRAM.md
docs/detection/V5_21_PANOS_FIELD_CONTRACT.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/components/MLEvidenceSnapshotPanel.tsx
frontend/src/pages/AlertsTriage.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

Exact path count: `39`.

## Explicit Exclusions

Do not stage:

- the private PAN-OS source file, its local path, raw rows, addresses, or
  fingerprints;
- v5.21 manifests, development/blind CSV packs, or generated reports under
  `ml_baseline_reviews/`;
- external CTU-13 data, manifests, frozen predictions, labels, checksums, or
  reports;
- `.env` files, credentials, tokens, API keys, or secrets;
- databases, backups, journals, or temporary PostgreSQL files;
- active or candidate model artifacts;
- `demo_exports/`, processed evidence, `.tmp/`, or unrelated local work.

## Boundary Checks

Before any separately approved Git operation:

1. compare the changed-path set exactly with these 39 paths;
2. run `git diff --check`;
3. verify ignored/private evidence remains untracked;
4. scan every allowlisted file for private paths, raw evidence, IP addresses,
   fingerprints, database URLs, credentials, and secrets;
5. confirm the staging area is empty until the owner gives separate exact-path
   approval; and
6. confirm no blind decision or private pack is included.

No commit or push is authorized by this document.
