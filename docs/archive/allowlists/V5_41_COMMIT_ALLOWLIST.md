# v5.41 Exact Commit Allowlist

No commit or push is authorized by this document. A separate explicit user
approval is required.

The exact tracked v5.41 path set is:

1. `atdr/app/detection/v541_governed_blind_evidence.py`
2. `atdr/scripts/run_v541_blind_evidence_acquisition.py`
3. `atdr/app/routers/evidence_review.py`
4. `atdr/app/schemas/evidence_review.py`
5. `atdr/tests/test_v541_governed_blind_evidence.py`
6. `atdr/tests/test_v537_evidence_review_workspace.py`
7. `frontend/src/types/api.ts`
8. `frontend/src/lib/api.ts`
9. `frontend/src/hooks/useApiQueries.ts`
10. `frontend/src/pages/MLGovernance.tsx`
11. `frontend/tests/smoke.spec.ts`
12. `docs/V5_41_GOVERNED_BLIND_EVIDENCE_ACQUISITION.md`
13. `docs/changes/T1_T20_V5_41_BLIND_EVIDENCE_ACQUISITION.md`
14. `docs/V5_41_COMMIT_ALLOWLIST.md`
15. `docs/AI_TRAINING_RUNBOOK.md`
16. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
17. `docs/prd/PRD-ATDR.md`
18. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
19. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
20. `docs/tasks/tasklist-progress.md`
21. `docs/tasks/tasklist-progress.html`

Explicitly excluded:

- `.env` and all secrets
- configured or temporary databases
- the private PAN-OS file and all other private logs
- `ml_baseline_reviews/`, including v5.41 custody state, candidates,
  predictions, review packs, and reports
- `demo_exports/` and processed evidence
- model artifacts
- human review decisions and reviewer identities
- raw logs, IP addresses, private paths, fingerprints, source identities, and
  generated reports
