# v5.51 Exact Commit Allowlist

No commit or push is authorized by this document. A separate explicit user
approval is required.

Because v5.50 remains local and unpublished, the exact cumulative v5.50-v5.51
tracked path set is 30 paths:

1. `README.md`
2. `atdr/app/routers/evidence_review.py`
3. `atdr/app/schemas/evidence_review.py`
4. `atdr/app/services/v551_field_qualification_service.py`
5. `atdr/scripts/run_v551_detection_field_qualification.py`
6. `atdr/tests/test_v537_evidence_review_workspace.py`
7. `atdr/tests/test_v551_field_qualification.py`
8. `docs/AI-DOCS-INDEX.md`
9. `docs/AI_TRAINING_RUNBOOK.md`
10. `docs/ATDR_PRODUCT_FINISH_LINE.md`
11. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
12. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
13. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
14. `docs/CURRENT_SYSTEM_STATE_LOCK.md`
15. `docs/V5_50_COMMIT_ALLOWLIST.md`
16. `docs/V5_50_CURRENT_STATE_TRUTH_LOCK.md`
17. `docs/V5_51_COMMIT_ALLOWLIST.md`
18. `docs/V5_51_DETECTION_PIPELINE_FIELD_QUALIFICATION.md`
19. `docs/changes/T1_T20_V5_50_CURRENT_STATE_TRUTH_LOCK.md`
20. `docs/changes/T1_T20_V5_51_DETECTION_PIPELINE_FIELD_QUALIFICATION.md`
21. `docs/detection/V5_51_FIELD_QUALIFICATION_CONTRACT.md`
22. `docs/detection/V5_51_FRESH_EVIDENCE_PROTOCOL.md`
23. `docs/prd/PRD-ATDR.md`
24. `docs/tasks/tasklist-progress.html`
25. `docs/tasks/tasklist-progress.md`
26. `frontend/src/hooks/useApiQueries.ts`
27. `frontend/src/lib/api.ts`
28. `frontend/src/pages/MLGovernance.tsx`
29. `frontend/src/types/api.ts`
30. `frontend/tests/smoke.spec.ts`

Explicitly excluded are `.env` files, credentials, databases, private logs,
raw evidence, labels/reviews, protected workspaces, protocols, claims/results,
predictions, fingerprints, reviewer or source identities, model artifacts,
generated reports, provider payloads, `ml_baseline_reviews/`, `demo_exports/`,
processed evidence, temporary test storage, IP addresses, and secrets.

This allowlist does not authorize staging, commit, push, model evaluation,
training, artifact write, activation, promotion, alert-authority change,
automatic response, or real firewall action.
