# v5.3 Exact Commit Allowlist

This file defines only the v5.3 Temporal Generalization and OOD phase. It does
not authorize staging, committing, or pushing. The worktree also contains
earlier cumulative v4.9-v5.2 changes that require their own explicit scopes.

## Exact v5.3 Paths

1. `atdr/app/detection/v53_temporal_generalization.py`
2. `atdr/scripts/run_v53_temporal_generalization.py`
3. `atdr/tests/test_v53_temporal_generalization.py`
4. `atdr/app/detection/v51_supervised_lifecycle.py`
5. `frontend/src/types/api.ts`
6. `frontend/src/pages/MLGovernance.tsx`
7. `frontend/tests/smoke.spec.ts`
8. `docs/V5_3_TEMPORAL_GENERALIZATION_AND_OOD.md`
9. `docs/changes/T1_T20_V5_3_TEMPORAL_GENERALIZATION_AND_OOD.md`
10. `docs/V5_3_COMMIT_ALLOWLIST.md`
11. `docs/prd/PRD-ATDR.md`
12. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
13. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
14. `docs/AI_TRAINING_RUNBOOK.md`
15. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
16. `docs/AI-DOCS-INDEX.md`
17. `docs/tasks/tasklist-progress.md`
18. `docs/tasks/tasklist-progress.html`

## Explicitly Excluded

- `.env*` private configuration and secrets;
- databases, logs, processed evidence, and private PAN-OS files;
- `ml_baseline_reviews/` generated reports or review material;
- `demo_exports/` and generated JSON/CSV/HTML/PDF evidence;
- model binaries and active/candidate artifact directories; and
- any earlier cumulative path not listed above.

Before any future approved commit, compare the staged path set exactly with
this list, run `git diff --check`, and repeat tracked-secret/protected-artifact
hygiene checks. Never force-push.
