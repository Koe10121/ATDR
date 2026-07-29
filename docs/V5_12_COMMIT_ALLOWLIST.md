# v5.12 Exact Commit Allowlist

Date: 2026-07-28

This file records the exact v5.12 source-controlled path set. It does not
authorize staging, committing, or pushing. Separate explicit owner approval
is required.

Exact allowlist, 27 paths:

```text
atdr/app/parsers/paloalto_contract.py
atdr/app/parsers/paloalto_parser.py
atdr/app/routers/ml.py
atdr/app/services/v512_parser_baseline_service.py
atdr/app/services/v58_shadow_scoring_service.py
atdr/app/services/v59_shadow_observation_service.py
atdr/scripts/run_v512_parser_profile_baseline_repair.py
atdr/tests/test_api.py
atdr/tests/test_parser.py
atdr/tests/test_v512_parser_profile_baseline_repair.py
data/samples/benchmarks/v511_operational_diagnostics_lock.json
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/V5_12_COMMIT_ALLOWLIST.md
docs/V5_12_PARSER_PROFILE_BASELINE_REPAIR.md
docs/changes/T1_T20_V5_12_PARSER_PROFILE_BASELINE_REPAIR.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/hooks/useApiQueries.ts
frontend/src/lib/api.ts
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

Do not stage:

- `.env` or any private environment profile;
- databases or backups;
- raw/private logs, source paths, IP addresses, or processed evidence;
- model artifacts;
- `ml_baseline_reviews/`;
- `demo_exports/`;
- generated diagnostic reports outside the tracked documentation paths;
- local test output, build output, caches, or runtime logs; or
- any cumulative v4.9-v5.11 path not independently approved.

Before any future approved commit:

```powershell
git status --short --untracked-files=all
git diff --check
git diff --cached --name-only
```

The staged path set must exactly match this allowlist. No commit, push, or
force-push is authorized by v5.12 implementation work.
