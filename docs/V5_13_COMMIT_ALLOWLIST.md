# v5.13 Exact Commit Allowlist

Date: 2026-07-28

## Purpose

This is the exact source-controlled path set for v5.13 Runtime Parser
Contract Adoption and Source Quality Operations.

It is a scope record only. It does not authorize staging, committing, or
pushing. Separate explicit approval is required before any Git operation.

## Exact Paths

```text
atdr/app/db/models.py
atdr/app/routers/sources.py
atdr/app/schemas/logs.py
atdr/app/schemas/sources.py
atdr/app/services/job_service.py
atdr/app/services/log_service.py
atdr/app/services/resumable_ingestion_service.py
atdr/app/services/runtime_parser_quality_service.py
atdr/app/services/source_service.py
atdr/app/services/syslog_service.py
atdr/scripts/replay_logs.py
atdr/scripts/verify_release.py
atdr/tests/test_api.py
atdr/tests/test_parser.py
atdr/tests/test_replay_and_dedup.py
atdr/tests/test_release_gate.py
atdr/tests/test_source_scenarios.py
atdr/tests/test_syslog_lab_ingestion.py
atdr/tests/test_v393_resumable_ingestion.py
atdr/tests/test_v50_real_paloalto_shadow_validation.py
atdr/tests/test_v513_runtime_parser_contract.py
migrations/versions/e7f8a9b0c1d2_add_source_parser_quality_aggregate.py
frontend/src/lib/api.ts
frontend/src/pages/ExecutiveOverview.tsx
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/V5_13_COMMIT_ALLOWLIST.md
docs/V5_13_RUNTIME_PARSER_CONTRACT_AND_SOURCE_QUALITY.md
docs/changes/T1_T20_V5_13_RUNTIME_PARSER_CONTRACT_AND_SOURCE_QUALITY.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

Path count: **38**

## Explicit Exclusions

- `.env` and any private environment profile;
- databases and database journals;
- private or real log files and raw evidence;
- model artifacts and active/candidate model binaries;
- `ml_baseline_reviews/`;
- `demo_exports/`;
- processed evidence and generated reports;
- private provider/IAM configuration; and
- every changed path not listed above.

## Safety State

- No historical reparse or data reset is authorized.
- No label, model activation/promotion, automatic response, or real blocking
  is authorized.
- Deterministic rules remain alert-authoritative.
- Supervised ML remains in `shadow_observation`.
