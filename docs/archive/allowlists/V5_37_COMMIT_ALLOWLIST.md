# v5.37 Exact Commit Allowlist

This file does not authorize a commit or push. A repository owner must provide
separate explicit approval before staging these exact 22 paths:

1. `atdr/app/main.py`
2. `atdr/app/routers/evidence_review.py`
3. `atdr/app/schemas/evidence_review.py`
4. `atdr/app/services/evidence_review_service.py`
5. `atdr/tests/test_v537_evidence_review_workspace.py`
6. `frontend/src/App.tsx`
7. `frontend/src/components/AppShell.tsx`
8. `frontend/src/hooks/useApiQueries.ts`
9. `frontend/src/lib/api.ts`
10. `frontend/src/pages/EvidenceReviewPage.tsx`
11. `frontend/src/types/api.ts`
12. `frontend/tests/smoke.spec.ts`
13. `docs/V5_37_BLIND_EVIDENCE_REVIEW_WORKSPACE.md`
14. `docs/changes/T1_T20_V5_37_BLIND_EVIDENCE_REVIEW_WORKSPACE.md`
15. `docs/V5_37_COMMIT_ALLOWLIST.md`
16. `docs/AI_TRAINING_RUNBOOK.md`
17. `docs/LAB_RUNBOOK.md`
18. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
19. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
20. `docs/prd/PRD-ATDR.md`
21. `docs/tasks/tasklist-progress.md`
22. `docs/tasks/tasklist-progress.html`

Explicitly excluded: `.env` files, databases, private logs, raw evidence,
human review worksheets, labels, model artifacts, `ml_baseline_reviews/`,
`demo_exports/`, processed evidence, generated reports, provider payloads, API
keys, and every path not listed above.
