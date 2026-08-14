# v5.39 Exact Commit Allowlist

This file records the exact tracked review boundary for v5.39. It does not
authorize staging, committing, or pushing. Separate explicit owner approval is
required.

Exact path count: **23**.

1. `atdr/app/routers/evidence_review.py`
2. `atdr/app/schemas/evidence_review.py`
3. `atdr/app/services/evidence_review_service.py`
4. `atdr/app/services/v539_independent_evidence_decision_service.py`
5. `atdr/scripts/run_v536_independent_evidence_activation_decision.py`
6. `atdr/scripts/run_v539_independent_evidence_decision.py`
7. `atdr/tests/test_v537_evidence_review_workspace.py`
8. `atdr/tests/test_v539_independent_evidence_decision.py`
9. `docs/AI_TRAINING_RUNBOOK.md`
10. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
11. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
12. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
13. `docs/LAB_RUNBOOK.md`
14. `docs/V5_39_COMMIT_ALLOWLIST.md`
15. `docs/V5_39_INDEPENDENT_EVIDENCE_AND_ACTIVATION_DECISION.md`
16. `docs/changes/T1_T20_V5_39_INDEPENDENT_EVIDENCE_DECISION.md`
17. `docs/tasks/tasklist-progress.html`
18. `docs/tasks/tasklist-progress.md`
19. `frontend/src/hooks/useApiQueries.ts`
20. `frontend/src/lib/api.ts`
21. `frontend/src/pages/EvidenceReviewPage.tsx`
22. `frontend/src/types/api.ts`
23. `frontend/tests/smoke.spec.ts`

Explicitly excluded:

- `.env` files and credentials;
- databases, private logs, IP addresses, raw evidence, and provider payloads;
- reviewer decisions, private packs, review tokens, fingerprints, and digests;
- model artifacts and generated reports;
- `ml_baseline_reviews/`, `demo_exports/`, processed evidence, `.tmp/`, and
  test artifacts; and
- any path not listed above.

The allowlist preserves `shadow_observation`, deterministic-rule authority,
read-only Assistant behavior, response simulation, and disabled real firewall
blocking.
