# v5.56 Commit Allowlist

Date: 2026-09-04

This is the exact cumulative tracked-path review boundary for v5.56 SOC
Assistant Operational Reliability And Analyst Quality Lock. It includes the
two preserved pre-v5.56 documentation corrections in `docs/LAB_RUNBOOK.md`
and `frontend/README.md`. It authorizes no staging, commit, push, merge,
deployment, provider approval, model activation, or external acceptance.
Separate explicit user approval is required for any Git publication.

## Exact Paths

1. `.env.example`
2. `.env.lab.example`
3. `.env.shell.example`
4. `atdr/app/core/config.py`
5. `atdr/app/schemas/assistant.py`
6. `atdr/app/services/assistant_llm.py`
7. `atdr/app/services/assistant_response_contracts.py`
8. `atdr/app/services/assistant_service.py`
9. `atdr/scripts/evaluate_assistant_qa.py`
10. `atdr/tests/test_assistant.py`
11. `atdr/tests/test_v556_assistant_operational_quality.py`
12. `data/samples/assistant/v556_quality_corpus.json`
13. `docs/AI-DOCS-INDEX.md`
14. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
15. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
16. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
17. `docs/LAB_RUNBOOK.md`
18. `docs/V5_56_COMMIT_ALLOWLIST.md`
19. `docs/V5_56_SOC_ASSISTANT_OPERATIONAL_RELIABILITY.md`
20. `docs/changes/T1_T20_V5_56_SOC_ASSISTANT_OPERATIONAL_RELIABILITY.md`
21. `docs/prd/PRD-ATDR.md`
22. `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md`
23. `docs/tasks/tasklist-progress.html`
24. `docs/tasks/tasklist-progress.md`
25. `frontend/README.md`
26. `frontend/src/pages/AssistantPage.tsx`
27. `frontend/src/types/api.ts`
28. `frontend/tests/smoke.spec.ts`

## Mandatory Exclusions

Do not stage private `.env` files, databases, raw/private logs, labels,
protected reviews, model artifacts, provider prompts or responses, provider
payloads, generated reports, SBOM output, `ml_baseline_reviews/`,
`demo_exports/`, processed evidence, temporary databases, acceptance
manifests, tokens, credentials, keys, or secrets.

## Pre-Commit Reconciliation

- Changed-path set must equal these 28 paths exactly.
- Staging must remain empty until separate explicit approval.
- `git diff --check` must pass.
- Repository security scan and dependency audits must pass.
- Private and generated evidence must remain ignored and untracked.
- Consumed v5.49b evidence must remain unopened and unmodified.
- No commit or push is authorized by this file.
