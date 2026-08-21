# v5.42 Exact Cumulative Commit Allowlist

No commit or push is authorized by this document. A separate explicit user
approval is required.

Because v5.41 remains uncommitted, this is the exact cumulative v5.41-v5.42
tracked path set:

1. `atdr/app/detection/v541_governed_blind_evidence.py`
2. `atdr/app/detection/v542_development_candidate_freeze.py`
3. `atdr/app/routers/evidence_review.py`
4. `atdr/app/schemas/evidence_review.py`
5. `atdr/scripts/run_v541_blind_evidence_acquisition.py`
6. `atdr/scripts/run_v542_candidate_freeze_readiness.py`
7. `atdr/tests/test_v537_evidence_review_workspace.py`
8. `atdr/tests/test_v541_governed_blind_evidence.py`
9. `atdr/tests/test_v542_development_candidate_freeze.py`
10. `docs/AI_TRAINING_RUNBOOK.md`
11. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
12. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
13. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
14. `docs/V5_41_COMMIT_ALLOWLIST.md`
15. `docs/V5_41_GOVERNED_BLIND_EVIDENCE_ACQUISITION.md`
16. `docs/V5_42_COMMIT_ALLOWLIST.md`
17. `docs/V5_42_DEVELOPMENT_CANDIDATE_FREEZE_READINESS.md`
18. `docs/changes/T1_T20_V5_41_BLIND_EVIDENCE_ACQUISITION.md`
19. `docs/changes/T1_T20_V5_42_DEVELOPMENT_CANDIDATE_FREEZE_READINESS.md`
20. `docs/prd/PRD-ATDR.md`
21. `docs/tasks/tasklist-progress.html`
22. `docs/tasks/tasklist-progress.md`
23. `frontend/src/hooks/useApiQueries.ts`
24. `frontend/src/lib/api.ts`
25. `frontend/src/pages/MLGovernance.tsx`
26. `frontend/src/types/api.ts`
27. `frontend/tests/smoke.spec.ts`

Explicitly excluded:

- `.env` files, API keys, credentials, and all secrets
- configured or temporary databases
- private PAN-OS data and all other private logs
- `ml_baseline_reviews/`, including custody state, candidate seals, model
  artifacts, predictions, review packs, and generated reports
- `demo_exports/`, processed evidence, temporary test output, and caches
- human review decisions and reviewer identities
- raw logs, IP addresses, private paths, evidence fingerprints, and source
  identities

The allowlist does not authorize a commit, push, model freeze, model
activation, promotion, response automation, or real firewall action.
