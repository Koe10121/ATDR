# v5.9 Exact Commit Allowlist

No commit or push is authorized by this file. If separate explicit approval
is provided later, only the following v5.9 paths may be staged:

```text
.env.example
.env.lab.example
atdr/app/core/config.py
atdr/app/db/models.py
atdr/app/routers/ml.py
atdr/app/services/job_dispatcher.py
atdr/app/services/job_service.py
atdr/app/services/operation_worker.py
atdr/app/services/v59_shadow_observation_service.py
atdr/scripts/run_v59_longitudinal_shadow_observation.py
atdr/tests/test_api.py
atdr/tests/test_v59_longitudinal_shadow_observation.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/V5_9_COMMIT_ALLOWLIST.md
docs/V5_9_LONGITUDINAL_SHADOW_OBSERVATION.md
docs/changes/T1_T20_V5_9_LONGITUDINAL_SHADOW_OBSERVATION.md
docs/detection/V5_9_INDEPENDENT_EVIDENCE_ACQUISITION.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/hooks/useApiQueries.ts
frontend/src/lib/api.ts
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
migrations/versions/c5d6e7f8a9b0_add_ml_shadow_observations.py
```

Generated observations/reports, model artifacts, private evidence, `.env`,
database files, `ml_baseline_reviews/`, `demo_exports/`, processed evidence,
test output, and private manifests are excluded.
