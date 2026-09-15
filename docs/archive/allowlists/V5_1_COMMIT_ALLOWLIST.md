# v5.1 Commit Allowlist

Date: 2026-07-22

## Purpose

This is the exact path-level review boundary for the v5.1 governed supervised
shadow-activation work. It does not authorize staging, committing, or pushing.
Those operations require separate explicit owner approval.

Several shared files below also contain uncommitted v4.9/v5.0 work. A future
approval must account for their complete current diffs; a v5.1-only approval
must not silently publish earlier work.

## Exact Paths (28)

```text
README.md
atdr/app/detection/explanations.py
atdr/app/detection/supervised_detector.py
atdr/app/detection/supervised_workflow.py
atdr/app/detection/v51_supervised_lifecycle.py
atdr/app/routers/ml.py
atdr/app/services/assistant_service.py
atdr/app/services/v50_shadow_validation_service.py
atdr/scripts/manage_supervised_lifecycle.py
atdr/scripts/run_v50_real_paloalto_shadow_validation.py
atdr/scripts/run_v51_supervised_shadow_activation.py
atdr/tests/test_api.py
atdr/tests/test_supervised_ml.py
atdr/tests/test_v51_supervised_lifecycle.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/V5_1_COMMIT_ALLOWLIST.md
docs/V5_1_SUPERVISED_SHADOW_ACTIVATION.md
docs/changes/T1_T20_V5_1_SUPERVISED_SHADOW_ACTIVATION.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

## Explicit Exclusions

- No `.env` or credential file.
- No database, private/real log, raw evidence, processed data, label/review file,
  benchmark snapshot, model binary, generated report, `ml_baseline_reviews/`,
  or `demo_exports/` output.
- No ignored pytest, shadow-validation, or frontend build artifact.
- No path outside the list above.
- No commit or push without a separate exact-scope approval.
