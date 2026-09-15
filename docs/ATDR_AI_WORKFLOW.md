# ATDR Engineering And AI Governance Workflow

This is the active workflow for non-trivial ATDR changes. Historical workflow
material is retained under `docs/archive/`; it is evidence, not current
instruction.

## Source Truth

Use this order when claims conflict:

1. Runtime source, migrations, tests, and mounted routes.
2. Current state locks and operator runbooks.
3. PRD, traceability, compliance, and security contracts.
4. Archived phase records and university reference material.

Primary runtime evidence is `atdr/app/main.py`, `atdr/app/routers/`,
`atdr/app/db/models.py`, `atdr/app/detection/`, `atdr/app/services/`,
`frontend/src/App.tsx`, `frontend/src/lib/api.ts`, `atdr/tests/`, and
`frontend/tests/`.

## Required Change Flow

1. Inspect source, tests, current Git state, and relevant contracts.
2. State the intended behavior, safety boundary, and acceptance evidence.
3. Implement the smallest coherent change that completes the requirement.
4. Add tests proportional to the behavior and blast radius.
5. Update the PRD or traceability only when product behavior changes.
6. Update `docs/tasks/tasklist-progress.md` and regenerate its HTML view.
7. Add a T1-T20 record for non-trivial work.
8. Run focused checks, then the complete release matrix.
9. Inspect repository hygiene and prepare an exact commit allowlist.
10. Commit or push only after separate explicit approval.

## Safety Invariants

- Deterministic rules are alert-authoritative.
- IsolationForest, supervised ML, and hybrid scores are advisory.
- Supervised runtime is `unqualified` until a future governed protocol passes
  every fixed gate and receives separate activation approval.
- The SOC Assistant is read-only and cannot run detection, alter labels,
  activate models, modify users, delete data, or create response actions.
- External Assistant context excludes raw logs by default and redacts IPs.
- Response is `simulation_only`; automatic response and real blocking remain
  disabled.
- Consumed evaluation evidence is immutable and must never be rerun or tuned.
- AI-assisted labels are never represented as human-reviewed labels.

## Documentation Rules

- Current instructions live only in the canonical documents listed in
  `docs/AI-DOCS-INDEX.md`.
- Historical phase, allowlist, and T1-T20 files live under `docs/archive/`.
- Archived records are not edited to match newer behavior.
- University template material under `docs/reference/` is reference-only.
- Configuration does not prove external IAM, provider, hardware, or deployment
  acceptance.

## Repository Hygiene

Never commit private `.env` files, credentials, databases, raw/private logs,
review decisions, labels, model artifacts, provider payloads, generated
reports, `ml_baseline_reviews/`, `demo_exports/`, or processed evidence.

Use `python -m atdr.scripts.audit_repository_surface --pretty` to check active
Markdown links, documented commands, Python syntax, imports, compatibility
CLIs, wrappers, migrations, routers, tests, and CI references.

Preview disposable caches with
`python -m atdr.scripts.cleanup_repository_caches --pretty`. Deletion requires
an explicit confirmation and is limited to allowlisted cache/build directories;
it can never target databases, logs, evidence, models, `.env`, runtime storage,
or paths outside the repository.

## Done Criteria

Work is complete only when behavior and documentation agree, required tests
pass, migrations are consistent, safety states are unchanged or explicitly
approved, private data remains excluded, the taskboard is current, and the
exact changed-path boundary is known.

The preserved pre-v5.59 workflow is in
`docs/archive/governance/ATDR_AI_WORKFLOW_THROUGH_V5_58.md`.
