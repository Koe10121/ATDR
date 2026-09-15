# v5.5 Exact Commit Allowlist

Date: 2026-07-26

This document defines the exact source-controlled boundary for v5.5. It does
not authorize staging, committing, or pushing.

1. `atdr/app/detection/v55_development_model_repair.py`
2. `atdr/scripts/run_v55_development_model_repair.py`
3. `atdr/tests/test_v55_development_model_repair.py`
4. `atdr/app/detection/v51_supervised_lifecycle.py`
5. `frontend/src/pages/MLGovernance.tsx`
6. `frontend/src/types/api.ts`
7. `docs/V5_5_DEVELOPMENT_MODEL_REPAIR_AND_ANOMALY_AUDIT.md`
8. `docs/changes/T1_T20_V5_5_DEVELOPMENT_MODEL_REPAIR_AND_ANOMALY_AUDIT.md`
9. `docs/V5_5_COMMIT_ALLOWLIST.md`
10. `docs/prd/PRD-ATDR.md`
11. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
12. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
13. `docs/AI_TRAINING_RUNBOOK.md`
14. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
15. `docs/AI-DOCS-INDEX.md`
16. `docs/tasks/tasklist-progress.md`
17. `docs/tasks/tasklist-progress.html`

Excluded:

- `.env` and secrets;
- databases and backups;
- real/private logs and processed evidence;
- model artifacts;
- `ml_baseline_reviews/`;
- `demo_exports/`;
- generated reports outside the governed taskboard HTML; and
- every path not listed above.

Before any later approved commit, compare the staged path set exactly against
these 17 paths, rerun repository hygiene checks, and require separate explicit
owner approval.
