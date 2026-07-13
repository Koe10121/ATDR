# v3.88 Product Baseline Consolidation And Release Checkpoint

Date: 2026-07-12

## Purpose

v3.88 consolidates the implemented v3.78-v3.87 supervisor-template handoff and real-LLM assistant work into one source-backed release baseline before PostgreSQL, durable workers, observability, or further model productization.

This checkpoint does not add a large feature and does not claim production readiness.

## Consolidated Runtime Baseline

### ATDR Runtime

- FastAPI remains the backend.
- React remains the primary SOC dashboard.
- SQLAlchemy/Alembic remain the persistence contract.
- SQLite remains the normal local database.
- Existing startup commands are unchanged.

### Supervisor-Template Login Shell

- The advisor-provided template remains outside the ATDR runtime and acts as an optional MFU login/account shell.
- The template launcher opens ATDR through a short-lived session handoff value.
- ATDR clears token-like URL values, validates the session through the protected template profile endpoint, checks configured school-email domains, and maps the identity to a local ATDR user.
- New approved identities default to analyst; admin requires an explicit allowlist.
- Local ATDR login remains available when handoff is disabled or fails.
- Current local database evidence contains one `mfu_iam_login_success` audit and one external-auth user.

This proves the local integration path, not preprod/production IAM readiness. HTTPS routing, group-role synchronization, provider-managed 2FA evidence, account recovery, deprovisioning, and formal operating approval remain open.

### Real LLM SOC Assistant

- Gemini is available only through private configuration and remains disabled in committed examples and CI.
- Deterministic fallback remains first-class.
- Server-owned actor-scoped context preserves alert/log/source/case follow-ups.
- Explicit IDs override prior context; global/latest prompts and Reset context clear stale context.
- Provider output is schema-validated, cited, bounded, redacted, rate-limited, and audited with safe metadata.
- Raw log bodies are excluded by default.
- Prompt-injection/action/secret requests are handled as untrusted input.
- The assistant cannot execute response, detection, label, model, user, source, email, firewall, or deletion operations.

## Repository Audit Result

The exact commit allowlist contains 73 visible paths. Historical IAM examples and tests use the synthetic `student.test@lamduan.mfu.ac.th` fixture; the real student test address is not present in trackable source.

The visible modified/untracked files are attributable to v3.78-v3.88 implementation, tests, examples, and documentation. No unrelated tracked source change was identified. `docs/tasks/tasklist-progress.html` is generated but intentionally tracked as the supervisor-style progress-board artifact.

Ignored/private state remains outside the commit set:

- `.env` and frontend private environment files
- `atdr.db` and SQLite files
- real/private logs and processed runtime logs
- model artifacts
- `ml_baseline_reviews/`
- `demo_exports/`
- build outputs, dependencies, caches, and temporary test directories
- in-repo/external template private environment files

The detailed file classification and exact staging commands are in `docs/V3_88_CHANGESET_MANIFEST.md`.

## CI And Clean-Environment Position

GitHub CI uses Python 3.11, Node.js 20.19.0, a disposable SQLite database, disabled external LLM/raw-log context, repository-local pytest temp/cache paths, backend tests, Alembic upgrade/drift checks, Ruff, tasklist standard validation, frontend dependency audit, React lint/build, and Playwright.

CI intentionally runs the release gate's backend constituent checks directly instead of invoking `verify_release` and duplicating the full backend suite. The local v3.88 checkpoint still runs `verify_release` as an independent final gate.

No CI job requires the private `.env`, a real Gemini call, MFU IAM availability, PostgreSQL, Docker, or the user's current database.

The clean-install audit also found and fixed five frontend dependency advisories through non-breaking lockfile updates. `npm audit --package-lock-only` now reports zero vulnerabilities. The frontend declares Node `>=20.19.0`; CI's Node 20 channel resolves a supported current release, while this workstation's older Node 20.11 can still build but emits an engine warning and should be upgraded.

The no-`.env` backend defaults now use the committed safe sample and include React dev origins, matching the documented local workflow instead of the old root-level private-log name and Streamlit-only CORS default.

## Safety Invariants

- No database reset or deletion.
- No raw evidence deletion.
- No automatic response.
- No real firewall blocking.
- No model activation or promotion.
- No raw-log sharing with an external provider by default.
- No secret or token in API status, provider probes, audit metadata, docs, or Git.
- No production-readiness claim.

## Remaining Product Risks

1. SQLite is not the target for shared multi-user scale.
2. Import, detection, and ML operations are tracked but still run in the API process rather than a durable worker queue.
3. Real router/firewall forwarding remains unvalidated without hardware.
4. Preprod/production IAM lifecycle and group mapping remain incomplete.
5. Gemini availability, cost/quota, key custody, privacy approval, and real-traffic answer quality remain operational risks.
6. Supervised ML remains decision support with conservative, candidate-only governance.
7. Metrics, correlation IDs, distributed tracing, audit integrity/retention enforcement, and operational alerting remain incomplete.
8. The external supervisor-template folder is not version controlled; its launcher must be backed up or recoverable from a clean advisor archive before future edits.

## Recommended Next Phase

After this checkpoint is committed and CI passes, the highest-value next phase is **PostgreSQL/shared-lab persistence and backup/restore validation**.

Why:

- it addresses the largest multi-user operational limitation;
- portability, migration, and backup drill groundwork already exists;
- it can preserve SQLite for local use;
- it creates the foundation needed before a durable background-job worker.

The phase after that should implement a durable worker architecture with idempotency, retries, cancellation, progress, and failure recovery.

## Verification Evidence

- Tasklist render and standard check: passed.
- Ruff and compileall: passed.
- Full backend tests: `473 passed, 1 skipped`.
- Alembic drift check: no new upgrade operations.
- Clean-config copy: private `.env` absent, current DB absent, external providers disabled, targeted backend tests `89 passed`, fresh frontend install/build passed.
- Frontend clean install: `npm ci` passed; npm audit reports zero vulnerabilities.
- React lint/build: passed with Vite `6.4.3`.
- Playwright: `19 passed, 1 skipped`.
- Template bridge/static readiness: passed with no secrets exposed.
- Provider status probes: configured Gemini reported safely; no provider call executed; raw-log context false; secrets exposed false.
- Replay dry-run: passed and wrote no rows.
- Performance smoke repeat: no warnings; Overview `0.3794s`, cached `0.0057s`, alert list `0.0309s`, case summary `0.0362s`, ML Governance `1.1196s`.
- Release gate: `ok: true`; all required checks passed.

One performance run immediately after the heavy test/install workload showed a transient `9.3692s` cold Overview call. The immediate controlled repeat returned to budget with no warnings. This remains a large-SQLite cold-I/O monitoring risk rather than a repeatable regression.

The optional live template-runtime probe was not required for this source checkpoint and found the services stopped. Static contract/config checks passed, and prior local audit evidence remains. Start all four services before the next manual handoff check.

## Checkpoint Decision

The source is ready for exact-path staging. It is not yet committed or pushed. CI is expected to pass after the allowlisted commit because the clean-config simulation and all CI-equivalent local checks passed.
