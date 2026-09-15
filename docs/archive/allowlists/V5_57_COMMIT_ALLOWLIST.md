# v5.57 Commit Allowlist

Date: 2026-09-04

This is the exact cumulative tracked-path review boundary for v5.56 SOC
Assistant Operational Reliability and v5.57 End-to-End Analyst Workflow,
Accessibility, And Startup Reliability Lock. It authorizes no staging,
commit, push, merge, deployment, provider approval, model activation, or
external acceptance. Separate explicit user approval is required for any Git
publication.

## Exact Paths

1. `.env.example`
2. `.env.lab.example`
3. `.env.shell.example`
4. `atdr/app/core/config.py`
5. `atdr/app/schemas/assistant.py`
6. `atdr/app/services/assistant_llm.py`
7. `atdr/app/services/assistant_response_contracts.py`
8. `atdr/app/services/assistant_service.py`
9. `atdr/app/services/v538_product_reliability_service.py`
10. `atdr/scripts/evaluate_assistant_qa.py`
11. `atdr/scripts/run_e2e_workflow_validation.py`
12. `atdr/scripts/run_v557_analyst_workflow_acceptance.py`
13. `atdr/tests/test_assistant.py`
14. `atdr/tests/test_e2e_workflow_validation.py`
15. `atdr/tests/test_v43_portable_shell_runtime.py`
16. `atdr/tests/test_v556_assistant_operational_quality.py`
17. `atdr/tests/test_v557_analyst_workflow_acceptance.py`
18. `data/samples/assistant/v556_quality_corpus.json`
19. `docs/AI-DOCS-INDEX.md`
20. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
21. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
22. `docs/changes/T1_T20_V5_56_SOC_ASSISTANT_OPERATIONAL_RELIABILITY.md`
23. `docs/changes/T1_T20_V5_57_END_TO_END_ANALYST_WORKFLOW_ACCESSIBILITY_STARTUP.md`
24. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
25. `docs/CURRENT_SYSTEM_STATE_LOCK.md`
26. `docs/LAB_RUNBOOK.md`
27. `docs/prd/PRD-ATDR.md`
28. `docs/QUICKSTART_FOR_TEAM.md`
29. `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md`
30. `docs/tasks/tasklist-progress.html`
31. `docs/tasks/tasklist-progress.md`
32. `docs/V5_56_COMMIT_ALLOWLIST.md`
33. `docs/V5_56_SOC_ASSISTANT_OPERATIONAL_RELIABILITY.md`
34. `docs/V5_57_COMMIT_ALLOWLIST.md`
35. `docs/V5_57_END_TO_END_ANALYST_WORKFLOW_ACCESSIBILITY_STARTUP.md`
36. `frontend/package.json`
37. `frontend/package-lock.json`
38. `frontend/README.md`
39. `frontend/src/components/AppShell.tsx`
40. `frontend/src/components/DetailDrawer.tsx`
41. `frontend/src/components/LoadingPanel.tsx`
42. `frontend/src/components/SafeSelect.tsx`
43. `frontend/src/components/TableToolbar.tsx`
44. `frontend/src/pages/AlertsTriage.tsx`
45. `frontend/src/pages/AssistantPage.tsx`
46. `frontend/src/pages/AuditLogPage.tsx`
47. `frontend/src/pages/EvidenceReviewPage.tsx`
48. `frontend/src/pages/ExecutiveOverview.tsx`
49. `frontend/src/pages/LogExplorer.tsx`
50. `frontend/src/pages/LoginPage.tsx`
51. `frontend/src/pages/ResponseCenter.tsx`
52. `frontend/src/styles.css`
53. `frontend/src/types/api.ts`
54. `frontend/tailwind.config.ts`
55. `frontend/tests/smoke.spec.ts`
56. `README.md`
57. `scripts/check_system.ps1`
58. `scripts/setup_team.ps1`
59. `scripts/start_system.ps1`
60. `scripts/stop_system.ps1`
61. `scripts/system_common.ps1`

## Mandatory Exclusions

Do not stage private `.env` files, databases, raw or private logs, labels,
protected reviews, model artifacts, provider prompts or responses, provider
payloads, generated reports, SBOM output, `ml_baseline_reviews/`,
`demo_exports/`, processed evidence, temporary databases, acceptance
manifests, tokens, credentials, keys, or secrets.

## Pre-Commit Reconciliation

- Changed-path set must equal these 61 paths exactly.
- Staging must remain empty until separate explicit approval.
- `git diff --check` must pass.
- Repository security scan and dependency audits must pass.
- Private and generated evidence must remain ignored and untracked.
- Consumed v5.49b evidence must remain unopened and unmodified.
- No commit or push is authorized by this file.
