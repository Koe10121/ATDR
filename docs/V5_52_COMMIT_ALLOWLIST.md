# v5.52 Exact Commit Allowlist

No commit or push is authorized by this document. A separate explicit user
approval is required.

Because v5.50 and v5.51 remain local and unpublished, the exact cumulative
v5.50-v5.52 tracked path set is 42 paths:

1. `README.md`
2. `atdr/app/routers/evidence_review.py`
3. `atdr/app/schemas/assistant.py`
4. `atdr/app/schemas/evidence_review.py`
5. `atdr/app/services/assistant_llm.py`
6. `atdr/app/services/assistant_response_contracts.py`
7. `atdr/app/services/assistant_service.py`
8. `atdr/app/services/v551_field_qualification_service.py`
9. `atdr/scripts/run_v551_detection_field_qualification.py`
10. `atdr/tests/test_assistant.py`
11. `atdr/tests/test_v534_assistant_concision_reliability.py`
12. `atdr/tests/test_v537_evidence_review_workspace.py`
13. `atdr/tests/test_v551_field_qualification.py`
14. `docs/AI-DOCS-INDEX.md`
15. `docs/AI_TRAINING_RUNBOOK.md`
16. `docs/ATDR_PRODUCT_FINISH_LINE.md`
17. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
18. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
19. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
20. `docs/CURRENT_SYSTEM_STATE_LOCK.md`
21. `docs/V5_50_COMMIT_ALLOWLIST.md`
22. `docs/V5_50_CURRENT_STATE_TRUTH_LOCK.md`
23. `docs/V5_51_COMMIT_ALLOWLIST.md`
24. `docs/V5_51_DETECTION_PIPELINE_FIELD_QUALIFICATION.md`
25. `docs/V5_52_ANALYST_EXPERIENCE_AND_SOC_ASSISTANT_CLOSURE.md`
26. `docs/V5_52_COMMIT_ALLOWLIST.md`
27. `docs/changes/T1_T20_V5_50_CURRENT_STATE_TRUTH_LOCK.md`
28. `docs/changes/T1_T20_V5_51_DETECTION_PIPELINE_FIELD_QUALIFICATION.md`
29. `docs/changes/T1_T20_V5_52_ANALYST_EXPERIENCE_AND_SOC_ASSISTANT_CLOSURE.md`
30. `docs/detection/V5_51_FIELD_QUALIFICATION_CONTRACT.md`
31. `docs/detection/V5_51_FRESH_EVIDENCE_PROTOCOL.md`
32. `docs/prd/PRD-ATDR.md`
33. `docs/tasks/tasklist-progress.html`
34. `docs/tasks/tasklist-progress.md`
35. `frontend/src/components/AssistantAnswerContent.tsx`
36. `frontend/src/hooks/useApiQueries.ts`
37. `frontend/src/lib/api.ts`
38. `frontend/src/lib/assistantSession.ts`
39. `frontend/src/pages/AssistantPage.tsx`
40. `frontend/src/pages/MLGovernance.tsx`
41. `frontend/src/types/api.ts`
42. `frontend/tests/smoke.spec.ts`

Explicitly excluded are `.env` files, credentials, databases, private logs,
raw evidence, labels/reviews, protected workspaces, protocols, claims/results,
predictions, fingerprints, reviewer or source identities, model artifacts,
generated reports, provider payloads, `ml_baseline_reviews/`, `demo_exports/`,
processed evidence, temporary test storage, IP addresses, and secrets.

This allowlist does not authorize staging, commit, push, model evaluation,
training, artifact write, activation, promotion, alert-authority change,
automatic response, or real firewall action.
