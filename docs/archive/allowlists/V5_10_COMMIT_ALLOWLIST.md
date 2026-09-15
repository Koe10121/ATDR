# v5.10 Exact Commit Allowlist

No commit or push is authorized by this file. This v5.10 changeset assumes
the approved v4.9-v5.9 changes are published first or staged in their
documented sequence. If separate explicit approval is provided later, only
the following v5.10 paths may be staged:

```text
atdr/app/db/models.py
atdr/app/routers/ml.py
atdr/app/services/ml_service.py
atdr/app/services/v510_detection_operations_service.py
atdr/app/services/v59_shadow_observation_service.py
atdr/scripts/performance_smoke.py
atdr/scripts/profile_ml_governance.py
atdr/scripts/run_v510_detection_operations_acceptance.py
atdr/tests/test_api.py
atdr/tests/test_replay_and_dedup.py
atdr/tests/test_v510_detection_operations.py
atdr/tests/test_v59_longitudinal_shadow_observation.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/V5_10_COMMIT_ALLOWLIST.md
docs/V5_10_DETECTION_OPERATIONS_AND_SHADOW_ACCEPTANCE.md
docs/changes/T1_T20_V5_10_DETECTION_OPERATIONS_AND_SHADOW_ACCEPTANCE.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/hooks/useApiQueries.ts
frontend/src/lib/api.ts
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
migrations/versions/d6e7f8a9b0c1_add_ml_profile_covering_index.py
```

Generated observations/reports, model artifacts, private evidence, `.env`,
database files, `ml_baseline_reviews/`, `demo_exports/`, processed evidence,
test output, and private manifests are excluded.
