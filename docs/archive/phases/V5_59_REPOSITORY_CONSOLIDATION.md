# v5.59 Repository Consolidation And Final Documentation Lock

Date: 2026-09-14

## Decision

v5.59 reduces ATDR's active documentation surface without changing product
runtime behavior. Historical records remain tracked and byte-identical in
`docs/archive/`; current instructions now live in a concise canonical set.

No database, label, protected review, evidence lock, consumed evaluation,
detection rule, threshold, model, IAM flow, Assistant behavior, API, schema, or
startup command was changed. No model was activated or promoted. Rules remain
alert-authoritative, supervised runtime remains `unqualified`, and response
remains `simulation_only`.

## Baseline

- Published v5.58 commit:
  `e1dd0de18ed47c287c738a47b7cc2f78478945e5`.
- Branch was clean, on `main`, synchronized with `origin/main`, and `0/0`
  ahead/behind before v5.59 edits.
- v5.58 GitHub Actions and CodeQL were green.

## Consolidation Result

| Classification | Decision |
| --- | --- |
| Keep active | Current product, operator, security, IAM, deployment, detection, taskboard, templates, and source documentation |
| Merge | Duplicate startup, runbook, governance, status, taskboard, and presentation guidance merged into canonical files |
| Archive | 497 historical files moved intact into category directories |
| Remove | No tracked source or historical record removed; generated taskboard HTML replaced from its canonical Markdown source |

All 497 moved files match their v5.58 Git blob exactly. The archive contains
70 allowlists, 207 phase records, 163 T1-T20 records, 29 presentation files, 18
legacy guides, four governance snapshots, three runbook snapshots, one index
snapshot, and two taskboard snapshots.

## Canonical Documentation

- `README.md`
- `docs/QUICKSTART_FOR_TEAM.md`
- `docs/CURRENT_SYSTEM_STATE_LOCK.md`
- `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
- `docs/OPERATIONS_RUNBOOK.md`
- `docs/LAB_RUNBOOK.md`
- `docs/AI_TRAINING_RUNBOOK.md`
- `docs/DETECTION_RULE_CATALOG.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/ATDR_AI_WORKFLOW.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/RELEASE_CHECKLIST.md`
- `docs/EXTERNAL_ACCEPTANCE.md`
- `docs/PRESENTATION_BRIEF.md`
- active references under `docs/security/`, `docs/detection/`, and
  `docs/DEPLOYMENT_GUIDE.md`

## Repository Audit

`atdr.scripts.audit_repository_surface` builds tracked/intended Markdown and
Python AST/import/entry-point graphs. Machine-readable mode classifies active,
archived, reference, and generated documentation and inventories runbooks,
allowlists, change records, versioned scripts, wrappers, migrations, routers,
job handlers, tests, and CI workflows.

Initial analysis found all 253 baseline script modules justified by package,
documented/static/dynamic reference, or executable compatibility role. No
Python script was deleted. After adding the audit CLI, all script modules remain
classified for retention.

Current graph acceptance requires:

- zero broken Markdown targets or anchors;
- zero nonportable local links;
- zero Python parse errors;
- zero missing documented commands; and
- no filesystem write, private-evidence access, or runtime change by the audit.

## Disposable Cache Safety

`atdr.scripts.cleanup_repository_caches` is dry-run by default. It can discover
only root pytest/Ruff caches, Python `__pycache__` directories under `atdr/` and
`migrations/`, and exact frontend build/test output directories. Apply mode
requires `DELETE_DISPOSABLE_CACHES` and revalidates every target inside the
repository. It excludes databases, logs, evidence, reviews, models, `.env`,
runtime storage, toolchains, dependencies, and paths outside the repository.

No apply-mode cleanup was run against the working repository.

## Verification

| Gate | Result |
| --- | --- |
| Repository surface | Pass: zero broken Markdown targets, nonportable links, Python parse errors, missing commands, or missing runtime documentation references |
| Archive integrity | Pass: all 497 destination blobs equal their v5.58 source blobs |
| Backend | Pass: Ruff, compileall, 1,084 tests passed, one skipped, and Alembic reported no new operations |
| Frontend | Pass: lint, production build, and Playwright with 42 passed and one intentionally skipped live scenario |
| Detection | Pass: disposable source scenario and all 288 layered controlled runs; zero controlled FP/FN |
| Assistant | Pass: 30 grounded cases, 100% required citations, all word budgets, follow-up continuity, and zero authoritative side effects |
| Security | Pass: zero tracked-secret findings; dependency, SBOM, and CodeQL controls remain configured |
| Performance | Pass: no budget warnings on 145,232 configured SQLite rows; 0.8467-second cold and 0.0102-second cached Overview |
| Release gate | Pass: config, compileall, full backend suite, Alembic, and deployment-operation checks |
| Hygiene | Pass: no staged paths, no tracked private/generated evidence, and no diff-check errors |

The test runner reports known dependency/deprecation warnings and a local
`.pytest_cache` Windows ACL warning; neither changed test outcomes. The cleanup
utility detected 21 disposable cache directories in dry-run mode and removed
nothing.

No tracked source or historical record was removed. Four small root-level
compatibility pointers preserve existing Assistant citation contracts while
directing readers to active or archived truth.

v5.59 is complete locally. No commit or push is authorized by this status
record; publication still requires separate explicit approval.

## Remaining Product Boundary

The consolidated repository remains a controlled local release candidate.
External MFU lifecycle acceptance, institutional Gemini governance, an
approved shared host, physical teammate validation, and independent
multi-device/future detection evidence remain pending and test-ready through
their preserved preflights.

There are no further substantial implementation phases required for the
controlled local release candidate. Five owner-backed acceptance tracks remain:
physical detection evidence, MFU IAM lifecycle, institutional Gemini governance,
shared-host qualification, and teammate usability/accessibility acceptance.
