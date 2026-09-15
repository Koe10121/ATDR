# v5.6 Exact Commit Allowlist

Date: 2026-07-26

This document defines the exact source-controlled boundary for v5.6. It does
not authorize staging, committing, or pushing.

1. `atdr/app/detection/v56_private_panos_model_repair.py`
2. `atdr/scripts/run_v56_private_panos_model_repair.py`
3. `atdr/tests/test_v56_private_panos_model_repair.py`
4. `atdr/app/detection/v49_detection_ml_reliability.py`
5. `atdr/tests/test_v49_detection_ml_reliability.py`
6. `atdr/app/detection/v51_supervised_lifecycle.py`
7. `frontend/src/pages/MLGovernance.tsx`
8. `frontend/src/types/api.ts`
9. `frontend/tests/smoke.spec.ts`
10. `docs/V5_6_PRIVATE_PANOS_EVIDENCE_AND_ASSISTED_MODEL_REPAIR.md`
11. `docs/changes/T1_T20_V5_6_PRIVATE_PANOS_EVIDENCE_AND_ASSISTED_MODEL_REPAIR.md`
12. `docs/V5_6_COMMIT_ALLOWLIST.md`
13. `docs/prd/PRD-ATDR.md`
14. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
15. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
16. `docs/AI_TRAINING_RUNBOOK.md`
17. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
18. `docs/AI-DOCS-INDEX.md`
19. `docs/tasks/tasklist-progress.md`
20. `docs/tasks/tasklist-progress.html`

Excluded:

- `.env` and secrets;
- databases and backups;
- real/private logs and processed evidence;
- active or diagnostic model artifacts;
- `ml_baseline_reviews/`;
- `demo_exports/`;
- generated reports outside the governed taskboard HTML; and
- every path not listed above.

Before any later approved commit, compare the staged path set exactly against
these 20 paths, rerun repository hygiene checks, and require separate explicit
owner approval.
