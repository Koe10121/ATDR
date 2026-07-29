# v5.8 Exact Commit Allowlist

No commit or push is authorized by this file. If separate explicit approval
is provided later, only the following v5.8 paths may be staged:

```text
.env.example
.env.lab.example
atdr/app/core/config.py
atdr/app/detection/v51_supervised_lifecycle.py
atdr/app/routers/ml.py
atdr/app/services/v58_shadow_scoring_service.py
atdr/scripts/run_v58_governed_shadow_runtime.py
atdr/tests/test_api.py
atdr/tests/test_v58_governed_shadow_runtime.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/V5_8_COMMIT_ALLOWLIST.md
docs/V5_8_GOVERNED_SHADOW_SCORING_RUNTIME.md
docs/changes/T1_T20_V5_8_GOVERNED_SHADOW_SCORING_RUNTIME.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/components/Badge.tsx
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

Generated shadow output, model artifacts, private evidence, `.env`, database
files, `ml_baseline_reviews/`, `demo_exports/`, processed evidence, and test
artifacts are excluded.
