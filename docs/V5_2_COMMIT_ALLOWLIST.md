# v5.2 Commit Allowlist

Date: 2026-07-22

## Purpose

This is the exact path-level review boundary for v5.2. It does not authorize
staging, committing, or pushing. Several shared files also contain earlier
uncommitted v4.9-v5.1 work, so their complete diffs must be reviewed before any
future approval.

## Exact Paths (35)

```text
atdr/app/detection/attack_mapping.py
atdr/app/detection/explanations.py
atdr/app/detection/v331_noise_reduction.py
atdr/app/detection/v49_detection_ml_reliability.py
atdr/app/detection/v51_supervised_lifecycle.py
atdr/app/detection/v52_shadow_reliability.py
atdr/app/routers/ml.py
atdr/app/services/detection_service.py
atdr/scripts/generate_detection_variants.py
atdr/scripts/manage_supervised_lifecycle.py
atdr/scripts/run_layered_detection_validation.py
atdr/scripts/run_v52_shadow_reliability.py
atdr/tests/test_detection_grouping.py
atdr/tests/test_detection_validation_suite.py
atdr/tests/test_layered_detection_validation.py
atdr/tests/test_rules.py
atdr/tests/test_supervised_ml.py
atdr/tests/test_v49_detection_ml_reliability.py
atdr/tests/test_v51_supervised_lifecycle.py
atdr/tests/test_v52_shadow_reliability.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/V5_2_COMMIT_ALLOWLIST.md
docs/V5_2_SHADOW_RELIABILITY_AND_LAYERED_REPAIR.md
docs/changes/T1_T20_V5_2_SHADOW_RELIABILITY_AND_LAYERED_REPAIR.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/pages/AlertsTriage.tsx
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

## Explicit Exclusions

- No `.env`, credential, database, private/real log, raw evidence, processed
  data, label/review file, model binary, benchmark snapshot, generated report,
  `ml_baseline_reviews/`, or `demo_exports/` output.
- No path outside the list above.
- No commit or push without separate exact-scope owner approval.
