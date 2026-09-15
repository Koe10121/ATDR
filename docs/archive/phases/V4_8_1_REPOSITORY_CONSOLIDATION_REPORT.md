# v4.8.1 Repository Consolidation Report

Date: 2026-07-18

## Decision

The tracked in-repository `NewSystem/` Node/Vue/Mongo runtime copy was not used
by ATDR runtime, tests, launchers, or CI. Selected university workflow, IAM,
security, and manifest evidence is preserved under
`docs/reference/NewSystem/`; the remaining tracked runtime copy is removed from
the proposed cleanup changeset. The separately distributed MFU companion shell
and its checksum contract are unchanged.

These changes are intentionally uncommitted and unpushed pending a separate,
explicit approval of `docs/V4_8_1_COMMIT_ALLOWLIST.md`.

## Audit Classification

| Classification | Areas | Decision |
| --- | --- | --- |
| Active runtime | `atdr/`, `frontend/`, `migrations/`, `scripts/`, `config/`, `deploy/`, `.github/workflows/` | Preserve |
| Active documentation | ATDR PRD, workflow, traceability, compliance, task board, runbooks, security docs, current v4 evidence | Preserve/update |
| Required historical evidence | ATDR T1-T20 records and versioned validation/status docs | Preserve |
| Reference material | Selected NewSystem workflow/IAM/security/manifests | Move to `docs/reference/NewSystem/` |
| Generated/reproducible | caches, builds, reports, review outputs, local package/runtime output | Keep ignored; do not commit |
| Safe cleanup candidate | unused tracked NewSystem Node/Vue/Mongo runtime and assets | Remove from tracked tree |
| Protected/private | `.env*`, DBs/backups, real logs, labels/reviews, model artifacts, exports, processed evidence | Leave untouched and untracked |

## Measured Scope

- Original tracked `NewSystem/` inventory: 526 files.
- Preserved directly from that copy: 9 non-secret reference files.
- Removed from the tracked runtime copy: 517 files.
- Existing NewSystem-specific workflow/history files moved from active doc
  locations into the reference archive: 15 files.
- Preserved or relocated reference files: 24.
- New archive-boundary document: 1 (`REFERENCE_SCOPE.md`).
- Total files now in `docs/reference/NewSystem/`: 25.
- Active runtime/test/script/CI references to `NewSystem/`: 0 before removal.
- Tracked files remaining under `NewSystem/`: 0 after removal.

Two private environment files remain under the local old directory. They were
not read, moved, deleted, staged, or included in the allowlist. The root ignore
policy now covers private `.env.*` files while retaining `*.example` templates,
so those local files no longer appear as untracked staging candidates.

## Preserved Reference Set

- `docs/reference/NewSystem/README.md`
- `docs/reference/NewSystem/TEMPLATE.md`
- `docs/reference/NewSystem/ENVIRONMENTS.md`
- `docs/reference/NewSystem/.iam-template.json`
- `docs/reference/NewSystem/template.manifest.json`
- `docs/reference/NewSystem/backend-node/docs/IAM_PRD.md`
- `docs/reference/NewSystem/backend-node/docs/IAM_RECOMMENDATIONS.md`
- `docs/reference/NewSystem/backend-node/docs/IAM_SYSTEM_OVERVIEW.md`
- `docs/reference/NewSystem/backend-node/docs/OWASP_TOP10_REPORT.md`
- `docs/reference/NewSystem/workflow/` original workflow/PRD/T1-T20/agent examples
- `docs/reference/NewSystem/REFERENCE_SCOPE.md`

The archived IAM recommendation and OWASP prose contained two legacy
high-entropy identifiers; those identifiers were replaced with
`<redacted-from-reference>`. A follow-up archive scan found no long hexadecimal
token, Google API-key pattern, OAuth client-ID pattern, or private-key header.

## Dependency Proof

`git grep` across `atdr`, `frontend`, `scripts`, `migrations`, `deploy`,
`config`, and `.github` returned no dependency on the tracked `NewSystem/`
path. ATDR remains FastAPI + React + SQLAlchemy/Alembic. The normal MFU shell
entry uses the separately distributed versioned companion package, not this
removed template runtime.

## Safety And Rollback

- No database, backup, log, label, review output, model, export, environment
  file, migration, test, or current ATDR T1-T20 record was deleted.
- Detection, ML, assistant, IAM, response, schema, API, and startup behavior are
  unchanged.
- Response automation and real firewall blocking remain disabled.
- Rollback before commit is a Git restore of this exact allowlist. After a
  future approved commit, rollback is a normal revert; no data rollback exists.

## Verification

- Published baseline: commit `15e43c8`; GitHub Actions run `29640334774` passed
  backend release, PostgreSQL persistence, and frontend dashboard jobs.
- Backend: Ruff and compileall passed; full tests passed `612 passed, 1 skipped`;
  release gate independently repeated `612 passed, 1 skipped` and returned
  `ok: true`.
- Schema: Alembic reported no new upgrade operations at head.
- Frontend: lint and production build passed; Playwright passed `25 passed, 1
  skipped`.
- Read-only operations: replay dry-run parsed two bundled rows and wrote zero;
  performance smoke returned no warnings (Overview `0.1600s`, warm cached
  `0.0091s`, ML Governance `1.0452s`, alerts `0.0295s`, cases `0.0613s`).
- Assistant: deterministic QA passed `20/20`; the bounded Gemini probe used no
  raw-log context, retained IP redaction, and exposed no secret.
- Repository: active dependency search, archive secret-pattern scan, changed-doc
  link check, tracked hygiene, `git diff --check`, and exact allowlist comparison
  passed. Private `.env.*` files are ignored and safe `*.example` templates
  remain eligible for version control.

An initial direct pytest run placed its temporary root in an unapproved
repository directory, so six backup tests correctly rejected that verifier path.
Those six tests and the complete suite passed under the approved ignored `.tmp/`
root. The application safeguard was not changed.

## Remaining External Gates

- Approved MFU/Google provider configuration and account/group lifecycle
  acceptance.
- Approved-host PostgreSQL, HTTPS, monitoring, secrets, backup/recovery, and
  capacity evidence.
- Independently collected real firewall/syslog evidence and stable supervised
  model validation.
- Gemini organizational privacy, quota/cost, key-rotation, and real-traffic
  answer-quality acceptance.
- Any future real response connector requires a separately approved safety
  architecture.
