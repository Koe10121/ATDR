# v5.15 Exact Commit Allowlist

Date: 2026-07-29

## Purpose

This is the exact 14-path review boundary for v5.15 Long-Duration Runtime
Soak And Recovery Acceptance.

It does not authorize staging, committing, pushing, deleting data, migrating
the configured database, activating a model, or changing response authority.
Any Git publication requires separate explicit owner approval.

## Exact Paths

### Backend runtime and tests (4)

```text
atdr/app/services/v514_large_file_runtime_service.py
atdr/app/services/v515_runtime_soak_service.py
atdr/scripts/run_v515_runtime_soak_acceptance.py
atdr/tests/test_v515_runtime_soak_acceptance.py
```

### Governance and operating documentation (10)

```text
README.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/LAB_RUNBOOK.md
docs/V5_15_COMMIT_ALLOWLIST.md
docs/V5_15_LONG_DURATION_RUNTIME_SOAK.md
docs/changes/T1_T20_V5_15_LONG_DURATION_RUNTIME_SOAK.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

## Explicit Exclusions

The boundary excludes:

- private or real log files and their paths;
- `.env` files, credentials, tokens, and secrets;
- SQLite/PostgreSQL databases, backups, and journal files;
- `ml_baseline_reviews/` and reviewed-label exports;
- `demo_exports/` and generated JSON/CSV/HTML/PDF reports;
- processed evidence and temporary/staged inputs;
- model artifacts and benchmark snapshots; and
- any unrelated local work.

## Boundary Checks

Before any separately approved Git operation:

1. compare the changed-path set exactly with the 14 paths above;
2. confirm `git diff --check` passes;
3. confirm protected/private files remain ignored and untracked;
4. confirm no private path, raw row, IP address, fingerprint, or secret is
   present in tracked v5.15 content; and
5. stage only these exact paths after separate explicit approval.
