# ATDR Current System State Lock

Date: 2026-07-28

Purpose: this document is the current-state memory anchor before larger ATDR productization work. It captures what exists now, what must stay safe, and what must not be deleted or committed while ATDR moves from controlled academic/lab prototype toward a more serious SOC/SaaS-style product.

Checkpoint: the published baseline is commit `04c14c5` on `origin/main`; its
GitHub Actions run passed. It includes the consolidated v4.9-v5.13.1
detection, ML, parser, source-quality, and repository-closure program. v5.14
large-file runtime acceptance is implemented and locally verified but remains
uncommitted pending exact-path review and separate owner approval. Existing
ATDR data, MFU companion-shell distribution, model lifecycle, and response
safety remain unchanged. This is a source-backed state lock, not a
production-readiness claim.

## Source Evidence

| Area | Current source evidence |
| --- | --- |
| Product scope and startup commands | `README.md` |
| Backend app and mounted API routers | `atdr/app/main.py`, `atdr/app/routers/*.py` |
| Runtime configuration and safety validation | `atdr/app/core/config.py`, `.env.example`, `.env.lab.example` |
| Database model truth | `atdr/app/db/models.py`, `migrations/versions/*.py` |
| Parser and normalization | `atdr/app/parsers/paloalto_parser.py`, `atdr/app/services/log_service.py` |
| Detection and explanations | `atdr/app/detection/*`, `atdr/app/services/detection_service.py`, `atdr/app/detection/explanations.py` |
| ML / AI governance | `atdr/app/routers/ml.py`, `atdr/app/services/ml_service.py`, `atdr/app/detection/supervised_*`, `atdr/app/ml/features.py` |
| Current AI/ML product truth | `docs/CURRENT_AI_ML_PRODUCT_STATUS.md` |
| SOC Assistant | `atdr/app/routers/assistant.py`, `atdr/app/services/assistant_service.py`, `atdr/app/services/assistant_llm.py`, `frontend/src/pages/AssistantPage.tsx` |
| Durable operation reliability | `atdr/app/services/job_service.py`, `atdr/app/services/job_dispatcher.py`, `atdr/app/services/operation_worker.py`, `atdr/app/routers/jobs.py`, `atdr/scripts/run_operation_worker.py` |
| IAM / school-email groundwork | `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py`, `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md` |
| Response safety | `atdr/app/routers/response.py`, `atdr/app/services/response_service.py`, `atdr/tests/test_response_safety.py` |
| Detection/ML productization evidence | `atdr/app/detection/v372_unified_detection_ml_evaluation.py`, `atdr/scripts/evaluate_detection_ml_productization.py`, `frontend/src/pages/MLGovernance.tsx` |
| Current detection/parser program closure | `docs/V4_9_DETECTION_ML_RELIABILITY_LOCK.md`, `docs/V5_1_SUPERVISED_SHADOW_ACTIVATION.md` through `docs/V5_13_RUNTIME_PARSER_CONTRACT_AND_SOURCE_QUALITY.md`, and `docs/V5_13_1_DETECTION_PARSER_PROGRAM_CONSOLIDATION.md` |
| Runtime parser-quality contract | `atdr/app/parsers/paloalto_contract.py`, `atdr/app/services/runtime_parser_quality_service.py`, `atdr/app/services/source_service.py`, `atdr/tests/test_v513_runtime_parser_contract.py` |
| Large-file private runtime acceptance | `atdr/app/services/v514_large_file_runtime_service.py`, `atdr/scripts/run_v514_large_file_runtime_acceptance.py`, `atdr/tests/test_v514_large_file_runtime_acceptance.py`, `docs/V5_14_LARGE_FILE_RUNTIME_ACCEPTANCE.md` |
| Governed shadow operations | `atdr/app/services/v58_shadow_scoring_service.py`, `atdr/app/services/v59_shadow_observation_service.py`, `atdr/app/services/v510_detection_operations_service.py`, `atdr/app/services/v511_shadow_monitoring_service.py` |
| Independent holdout evidence | `atdr/app/detection/v398_independent_holdout_validation.py`, `atdr/scripts/run_v398_independent_holdout_validation.py`, `atdr/tests/test_v398_independent_holdout_validation.py`, `docs/V3_98_INDEPENDENT_DETECTION_ML_HOLDOUT_VALIDATION.md` |
| Synthetic multi-source frozen revalidation | `atdr/app/detection/v399_multisource_frozen_revalidation.py`, `atdr/scripts/run_v399_multisource_frozen_revalidation.py`, `atdr/tests/test_v399_multisource_frozen_revalidation.py`, `docs/V3_99_INDEPENDENT_MULTI_SOURCE_EVIDENCE_AND_FROZEN_REVALIDATION.md` |
| Frontend route truth | `frontend/src/App.tsx`, `frontend/src/pages/*`, `frontend/src/lib/api.ts` |
| Tests and release gate | `atdr/tests/*`, `frontend/tests/*`, `atdr/scripts/verify_release.py`, `.github/workflows/ci.yml` |
| Supervisor shell contract | Separately supplied `<MFU_SHELL_ROOT>` plus `docs/V4_3_PORTABLE_MFU_SHELL_RUNTIME.md` and `scripts/*system*` |

## Current Architecture

ATDR currently uses:

- Backend: FastAPI with Python 3.11, SQLAlchemy, Alembic, Pydantic settings, JWT authentication, request/security middleware, and structured logging.
- Frontend: React 18, Vite, TypeScript, React Router, TanStack Query/Table, Recharts, Playwright.
- Database: SQLite for normal local workflow, with optional PostgreSQL/shared-lab validation paths. The current local workflow does not require Docker or PostgreSQL.
- ML stack: Python feature generation, rule detection, IsolationForest anomaly support, supervised classifier experiments, model registry, and conservative governance gates.
- Normal team runtime: `.\scripts\start_system.cmd`, which starts the MFU shell backend/frontend and the existing ATDR FastAPI/React components, then opens the shell sign-in page.
- Existing direct component commands remain available for diagnostics/development. Direct ATDR authentication requires explicit `ATDR_AUTH_MODE=local_recovery`.

## Backend API Status

Mounted FastAPI routers currently include:

- `/api/auth`
- `/api/users`
- `/api/logs`
- `/api/sources`
- `/api/ingestion`
- `/api/jobs`
- `/api/detection`
- `/api/alerts`
- `/api/ml`
- `/api/assistant`
- `/api/response`
- `/api/audit`
- `/api/dashboard`
- `/api/demo`
- `/api/suppressions`
- `/api/watchlists`

The backend also exposes `/health` and clean database-unavailable handling. Runtime config validation keeps unsafe settings from silently starting, including response automation and raw-log assistant context constraints.

The dashboard router includes a read-only detection/ML productization status endpoint at `/api/dashboard/detection-ml-productization`. It is intended for governance visibility only and must not write labels, activate models, create response actions, or expose raw logs.

## Frontend Status

The React dashboard is the main UI. Current protected pages include:

- Overview
- Alerts
- Investigation / Log Explorer
- SOC Assistant
- AI Governance
- Response & Audit
- Threat Controls
- Detection Tuning
- User Admin
- Demo Controls

Admin-only routing is implemented for user administration and demo controls. The legacy Streamlit dashboard remains continuity material only, not the primary product direction.

## Database And Model Status

Main SQLAlchemy entities include:

- `LogSource`
- `RawLog`
- `NormalizedLog`
- `Alert`
- `AlertEvidence`
- `AlertNote`
- `ResponseAction`
- `BlockedIP`
- `AuditLog`
- `User`
- `AccountEmailVerificationToken`
- `EmailNotificationEvent`
- `AssistantFeedback`
- `SuppressionRule`
- `WatchlistItem`
- `MLModelRun`
- `MLShadowObservation`
- `IngestionRun`
- `DetectionRun`
- `OperationJob`
- `OperationWorkerHeartbeat`
- `MLLabel`

Alembic migrations exist under `migrations/versions/`. Any schema change must use Alembic and must not reset or delete the user's current database.

### v3.89 Persistence Status

- SQLite remains the default local workflow.
- PostgreSQL uses optional dialect-aware pool, connection, pre-ping, and statement-timeout settings.
- `backup_database`, `restore_database`, and `validate_persistence_profile` provide dry-run-first backup/restore validation with checksum manifests and active-target refusal.
- Local v3.89 validation passed using fresh temporary synthetic SQLite databases. It confirmed checksum, integrity, matching table counts/Alembic revision, zero response/model side effects, and an unchanged configured current-database fingerprint.
- PostgreSQL runtime validation is pending the isolated GitHub Actions job or an approved host because this workstation has no PostgreSQL/Docker tools installed.

### v3.90 Durable Operation Status

- Selected long operations can be explicitly queued with private staged input, idempotency, lease/heartbeat tracking, ownership-scoped APIs, audit lifecycle events, and a separately launched worker.
- The normal FastAPI command does not start a worker. `OPERATION_WORKER_ENABLED` defaults to `false`; a manual `--once` cycle is safe for controlled use.
- Running jobs are never force-cancelled. Evidence-mutating lease expiry fails closed; only report exports can automatically retry.
- Worker dispatch excludes response actions, firewall changes, model activation/promotion, label changes, user changes, external IAM/LLM calls, and deletion.
- SQLite is validated with one worker. Managed-worker supervision, PostgreSQL/multi-worker behavior, resumable large imports, and automatic retention remain future work.

### v3.97 Large-File Ingestion Status

- The queued import path uses bounded indexed raw-content fingerprint lookups and chunk-level ORM flushing while preserving exact raw evidence and storing duplicate events.
- Cumulative raw/parsed/failed/duplicate counters are visible in Operations Health and low-cardinality metrics.
- The isolated 100,000-row synthetic validator passed at 724.45 rows/second with 8.71 MiB peak traced memory, one forced resume, zero resume duplicates, changed-input rejection, cooperative cancellation, and zero response/detection/label/model side effects.
- Migration `b4c5d6e7f8a9` was validated on a disposable copy of the current SQLite database. Every one of its 145,232 raw rows received a 64-character fingerprint.
- A timestamped ignored backup exists. The configured database is still at revision `a3b4c5d6e7f8`; do not apply v3.97 to it without explicit user approval.

## Log Ingestion Status

ATDR can currently:

- Import log files through backend/API/script workflows.
- Replay safe samples or selected external files.
- Simulate live ingestion through replay and syslog lab tooling.
- Track ingestion runs and operation jobs.
- Attach logs to optional log sources.
- Preserve raw evidence independently from parsed/normalized fields.

Known limitation: very large/shared-lab usage should move toward PostgreSQL or another production-grade database plan. SQLite remains appropriate for local development and controlled lab workflow.

### v5.14 Runtime Acceptance Status

- The complete private PAN-OS file was inspected as aggregate-only evidence:
  773,551 nonblank rows, 771,932 TRAFFIC, 1,619 THREAT, zero parser errors,
  zero structural warnings, and zero exact duplicate rows.
- A disposable 100,000-row run used the real staging, job, worker,
  transactional import, source-quality, detection, alert, case, and dashboard
  services. It created exactly 100,000 raw and normalized rows with zero parse
  failures.
- A forced 1,000-row handoff resumed from the committed checkpoint with zero
  extra rows. Cancellation, idempotent enqueue, staging cleanup, and a
  temporary SQLite lock-wait probe passed.
- One observed device stream was divided into two explicitly simulated
  50,000-row logical windows. No second physical device is claimed.
- Source-scoped rules evaluated 100,000 rows and every created alert retained
  log/source traceability. These are detector outputs, not labeled accuracy.
- The configured database marker remained unchanged. Temporary database and
  raw/staged evidence were removed, and no path, raw row, IP, fingerprint, or
  secret was returned.
- Labels, model runs, activation, promotion, and response actions remained
  zero. Rules remain authoritative and supervised lifecycle remains
  `shadow_observation`.

## Parser And Normalization Status

Current parser behavior supports:

- Palo Alto CSV/syslog-style traffic parsing.
- Generic syslog profile.
- Raw fallback for malformed or unsupported lines.
- Blank/malformed/missing-field robustness.
- Parser failure accounting and safe examples.
- Raw evidence preservation even when parsing fails.

Parser expansion remains future work for additional vendors and real-world format drift.

## Detection And Rule Status

Current detection combines:

- Explainable rule-based detection.
- Alert deduplication with occurrence counts and related log counts.
- Lightweight case grouping.
- ATT&CK-style mapping and "Why flagged?" explanations.
- Source-scoped detection.
- Scenario validation against safe synthetic corpora.

Current detection quality work has improved controlled validation, but real-source validation and continued false-positive/false-negative hardening remain important productization work.

### v3.98 Holdout Status

- v3.98 evaluates deterministic rules, fresh in-memory IsolationForest, the repaired binary SOC review queue, hybrid decision support, Logistic Regression, and a majority baseline without activation or artifact writes.
- Reviewed latest labels are grouped by exact raw fingerprint, near behavior, used-feature equality, and normalized-log identity before splitting.
- Fit, sigmoid calibration, threshold selection, and final test are isolated; final-test labels are never reused for tuning.
- Three fingerprint-grouped random diagnostics evaluated. Primary queue F1 ranged from 0.9713 to 0.9804, but benign-like FPR ranged from 0.0303 to 0.3939 and sparse confidence buckets failed the conservative calibration gate.
- Temporal holdout failed closed because its final window had no `non_threat` support. Source holdout is unavailable because all 2,235 reviewed rows belong to `local_import`.
- Readiness remains `candidate_only`. Current evidence is internal unseen holdout evidence, not an external independent benchmark or production accuracy.

### v3.99 Synthetic Multi-Source Revalidation Status

- v3.99 generated 720 deterministic synthetic rows across `v399-campus-router-normal`, `v399-edge-firewall-probing`, and `v399-mixed-workstation`, with four seven-day-separated collection windows.
- The evidence manifest records source type, parser profile, category/scenario distribution, expectation provenance, evidence kind, and duplicate/overlap state. Every row is `human_reviewed=false` and `import_ready=false`.
- All 720 rows passed exact raw, normalized near-pattern, and used-feature overlap checks against reviewed evidence; no row required quarantine.
- Existing reviewed evidence alone supplied 1,006 fit, 335 calibration, and 335 threshold rows. A separate 559-row internal holdout remained reserved. No v3.99 row or label entered fitting, calibration, or threshold selection.
- The primary queue produced F1 `0.9524-0.9551`, synthetic FPR `0.0`, and suspicious/malicious recall `1.0` across source, latest-window temporal, and three grouped random final views.
- Calibration remained weak on every split: ECE approximately `0.1097-0.1115` and maximum bucket gap `0.5128-0.5227`.
- False negatives were allowed `needs_context` unknown TCP/UDP services; no synthetic suspicious/malicious control was missed.
- Readiness remains `candidate_only`. Results are reproducible regression evidence, not provider-blinded, real-device, externally reviewed, or production accuracy.

## Supervised ML Status

ATDR currently has:

- Human/assisted label workflow.
- Supervised model training and diagnostic evaluation scripts.
- Model registry and governance UI.
- Candidate-only, diagnostic profiles.
- Conservative readiness gates.
- Explicit `production_promoted=false` / model activation safety discipline.
- Unified detection/ML productization evaluator that checks rule contracts, scenario status, training-data readiness, output policy, and response-safety invariants.

Important current limitation: supervised outputs remain decision support. Recent work found that flat multi-class labels and exact severity/benign boundaries are still weaker than binary SOC queue / evidence-first triage framing. No ML output may trigger automatic response.

## Assistant / Chatbot Status

Current SOC Assistant support includes:

- Authenticated read-only assistant API.
- Deterministic fallback answers.
- External LLM adapter for configured providers, including Gemini, OpenAI-compatible APIs, Claude/Anthropic, and mock test provider.
- Validated structured-answer contract, bounded actor-scoped conversation context, citation filtering, retry/timeout handling, rate limiting, prompt-injection refusal, and deterministic fallback.
- Safe provider and full-service probes: `atdr/scripts/test_assistant_llm_provider.py` and `atdr/scripts/test_assistant_chat_provider.py`.
- Raw log context disabled by default.
- IP redaction enabled by default.
- Audit logging for assistant questions.
- Feedback and answer-quality review workflow.
- Dashboard page with safety badges and citations.

The assistant must never execute response actions, run detection, change labels, activate/promote models, mutate users, delete data, or enable automation.

Known limitation: external-provider availability, cost/quota, key custody, organizational privacy approval, and real-traffic answer evaluation remain operational work. The assistant is not autonomous and cannot execute ATDR actions.

## IAM / School Email Status

Current IAM support includes:

- Local JWT username/password login.
- Optional local email login.
- Admin/analyst RBAC.
- School-email metadata on local accounts.
- Disabled-by-default email verification/dev-outbox foundation.
- Disabled-by-default generic OIDC groundwork.
- Optional v3.91 supervisor-template opaque-code handoff configured only through private `.env`; browser token-login is retired.
- Verified school-email mapping into local ATDR users with analyst default and explicit IAM-group-based admin mapping.
- Source-level handoff/contract validation, frontend form-post coverage, and safe audit/diagnostic behavior are verified locally; provider-backed login evidence is still pending.
- Config aliases for supervisor template `IAM_SDK_*`, `IAM_ADMIN_*`, and `PROJECT_PERMISSION_*` variable names.
- Supervisor template wrapper env names and backend env names have been inspected by key name only. The backend template contains `IAM_SDK_*`, `IAM_ADMIN_*`, `PROJECT_PERMISSION_*`, `PROJECT_IAM_*`, `PROJECT_INIT_ADMIN_EMAILS`, `PROJECT_AUTH_REQUIRE_2FA`, and `GOOGLE_CLIENT_ID`. Values are secrets/private deployment settings and must not be printed or committed.

Current gaps:

- No direct ATDR-owned Google/MFU OAuth browser callback flow; the supervisor template remains the intended outer login shell.
- No provider-backed preproduction validation of external IAM group-to-role mapping.
- No independently verified preprod/production template callback, provider-managed 2FA, recovery, or deprovisioning policy.
- No real SMTP delivery by default.
- No viewer/read-only role.
- No formal production IAM hardening.

## Response Safety Status

Current response behavior:

- Simulated response only.
- Analyst/admin approval required.
- Justification required.
- Protected IP safeguards.
- Denied and accepted actions audited.
- No real firewall connector enabled.
- No automatic response.
- ML and assistant outputs cannot trigger containment.

Real firewall blocking must remain disabled unless explicitly approved later with a formal safety design, allowlist, rollback plan, and audit policy.

## Current Known Limitations

- ATDR is not production-certified software.
- SQLite is local-development friendly but not the target for multi-user SaaS scale.
- Real firewall/router syslog forwarding still needs controlled hardware validation.
- The local template-shell handoff is implemented and exercised, but preprod/production URLs, IAM group-role mapping, provider-managed 2FA evidence, recovery, deprovisioning, and deployment approval remain incomplete.
- Real SMTP/OTP requires provider approval and security policy.
- Supervised ML still needs better stability, calibration, and real-source validation before stronger claims.
- Case grouping is lightweight, not a full incident/ticketing platform.
- Observability is still mostly app logs, health checks, scripts, and performance smoke; production metrics/alerting is future work.
- The published v5.13.1 baseline is clean and CI-green at `04c14c5`. The
  v5.14 worktree remains local and must not be staged or pushed outside its
  exact allowlist or without explicit owner approval.

## Current Verification Commands

Use these before claiming a stable checkpoint:

```powershell
node scripts/render-tasklist-progress-html.js .
node scripts/check-tasklist-progress-standard.js .
ruff check .
.\.venv\Scripts\python.exe -m compileall -q atdr migrations
.\.venv\Scripts\python.exe -m pytest atdr/tests -q
.\.venv\Scripts\alembic.exe check
cd frontend
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
cd ..
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

If an external LLM key is configured privately, only run the execute probe when intentionally testing provider calls:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --execute --pretty
```

## Important Files And Folders

Keep:

- `atdr/app/`
- `atdr/scripts/`
- `atdr/tests/`
- `frontend/src/`
- `frontend/tests/`
- `migrations/`
- `data/samples/`
- `docs/`
- `.github/workflows/`
- `.env.example`
- `.env.lab.example`
- `.env.production.example`
- `.gitignore`

Reference only:

- `docs/reference/NewSystem/` contains selected archived university-template
  workflow/IAM/security/manifests only; it is not runtime authority.
- The separately supplied `<MFU_SHELL_ROOT>` is the approved supervisor shell source. Its location is private runtime configuration, not a repository constant.

## Ignored Or Sensitive Folders

Must not be committed:

- `.env`
- frontend `.env`
- API keys and client secrets
- DB files such as `atdr.db`, `*.sqlite`, `*.sqlite3`
- real/private firewall logs
- `ml_baseline_reviews/`
- `demo_exports/`
- `atdr/data/processed/` outputs except `.gitkeep`
- model artifacts under `atdr/models/`
- generated CSV/JSON/HTML/PDF reports unless explicitly intended documentation artifacts
- `node_modules/`
- `.venv/`

## What Must Not Be Deleted Without Explicit Backup/Approval

- The user's current database and labels.
- Private `.env` files.
- Private real logs outside Git.
- `ml_baseline_reviews/` review work.
- `demo_exports/` evidence/report work.
- Model artifacts used for local experiments.
- Alembic migrations.
- Safe sample scenarios.
- Current ATDR docs and test evidence.

## Productization Principle

Future work can make larger architectural, backend, and UI changes, but every major change must preserve:

- raw evidence preservation
- explainable detection
- assistant and ML read-only decision-support safety
- analyst-approved response only
- school-email IAM direction without hard-coded single-user access
- repo hygiene
- verifiable tests and release gates

## Historical v3.99 Checkpoint

The cumulative v3.97-v3.99 worktree was verified on 2026-07-14:

- Ruff and compileall: passed.
- Backend tests: `549 passed, 1 skipped`.
- Configured database: unchanged at `a3b4c5d6e7f8`; disposable copy: `b4c5d6e7f8a9 (head)` with no Alembic drift.
- v3.97 100,000-row closure rerun: passed in 146.1105 seconds at 684.41 rows/second with 8.70 MiB peak traced memory and zero unsafe side effects.
- v3.98 internal holdout: completed on 2,235 reviewed latest labels; three random splits evaluated, strict temporal/source splits failed closed, readiness `candidate_only`, database/artifact/session unchanged.
- v3.99 frozen multi-source evaluation: 720/720 accepted synthetic rows across three sources/four windows; zero exact/near/feature overlap; primary F1 `0.9524-0.9551`, FPR `0.0`, suspicious/malicious recall `1.0`; calibration passed `0/5`; readiness `candidate_only`; database/artifact/session unchanged.
- React lint/build: passed.
- Playwright: `21 passed, 1 skipped`.
- Replay dry-run: parsed two safe rows and wrote zero.
- Performance smoke: no warnings with Overview `0.4315s`, cached Overview `0.0062s`, alert list `0.0334s`, case summary `0.0666s`, ML Governance `1.1671s`, and feature sample `0.2731s`.
- Release gate: `ok: true`; config, compile, repeated tests, Alembic, and deployment-operations checks passed. Optional running-stack smoke was skipped.

This evidence proves the current controlled repository/local checkpoint. It does not establish production readiness, provider-blinded or real-source Detection/ML independence, approved-host deployment acceptance, or permission to activate a model or response action.

## v4.0 External Evidence Update

ATDR has now executed one provider-blinded public benchmark under frozen prediction-before-label ordering. Two official CSE-CIC-IDS2018 days supplied 4,000 deterministic feature-only samples; seven duplicate exact flows were quarantined and 3,993 were scored. Accepted exact, near-pattern, and used-feature overlap with 2,235 reviewed internal rows and 720 v3.99 rows was zero.

The protocol succeeded but the model gate failed. The frozen supervised queue produced precision `0.3171`, recall `1.0000`, F1 `0.4815`, benign FPR `1.0000`, Brier `0.6538`, and ECE `0.6614`. The provider schema lacks IP/action/app/zone/source-port/app-risk and source-window context, causing nearly all flows to receive high review probability. The benchmark is locked final evidence and cannot be used for tuning.

Configured database and active artifact state remained unchanged. No labels, models, detection runs, response actions, automation, or firewall behavior changed. Current readiness remains `candidate_only`.

Final v4.0 closure verification passed: task-board render/check, Ruff, compileall, backend `556 passed, 1 skipped`, disposable Alembic no-drift check, React lint/build, Playwright `21 passed, 1 skipped`, replay dry-run, warning-free performance smoke, and release gate `ok: true`. The configured database was not migrated or written during these checks.

## v4.1 Schema-Aware Development Update

v4.1 keeps the v4.0 provider-blinded benchmark immutable by checking all seven locked files and hashes before and after each run. It uses three separate checksum-verified CSE-CIC-IDS2018 development files only for diagnostic design work and reserves UNSW-NB15 as a future untouched benchmark. Provider data remains non-human and non-importable.

The evaluator defines distinct Palo Alto, generic syslog, provider-flow, and raw-fallback contracts. It records missingness and schema availability rather than inventing absent IP, action, application, zone, or source-window fields. A complete 16,817-flow development run produced strong pooled random-split signals, but calibration was weak for every strategy and provider source/time plus schema-held-out transfer remained unstable. The candidate gate therefore failed honestly: readiness is `candidate_only`, no active model/artifact changed, and no labels, detection runs, response actions, automation, or firewall behavior changed.

Focused v4.1 tests passed (`12 passed`). Final closure verification also passed: task-board render/check, Ruff, compileall, full backend `568 passed, 1 skipped`, disposable Alembic no-drift check, React lint/build, Playwright `21 passed, 1 skipped`, replay dry-run, warning-free performance smoke, and release gate `ok: true`. The configured database was not migrated or written during these checks. The next detection/ML gate is a separately governed untouched benchmark and independently collected multi-source real firewall/syslog evidence, not further tuning against v4.0.

## v4.2 Assistant And UI Update

v4.2 does not alter the v4.1 model evidence, configured database, active artifact, detection rules, response policy, or startup commands. It adds citation-derived grounding metadata, a concise external-provider contract, and a sanitized session-scoped React snapshot so assistant context survives route navigation without replaying a provider request.

The private Gemini readiness check and one synthetic probe passed on 2026-07-14 without printing a key: provider/model/key configured, structured output valid, IP redaction enabled, raw-log context excluded, and `secrets_exposed=false`. The dashboard calls an answer **Gemini Assisted** only when that answer actually reports successful provider use; otherwise it shows the local evidence or fallback mode.

MFU burgundy/gold visual tokens are adapted from the official external supervisor shell. ATDR remains FastAPI + React + SQLAlchemy/Alembic; no Node/Vue/MongoDB runtime migration occurred. The assistant remains read-only and cannot trigger response, detection, label, model, account, deletion, or firewall actions.

## v4.5 Reproducible Product Baseline Update

v4.5 supersedes the earlier local migration warning: the configured SQLite database is now at Alembic head `b4c5d6e7f8a9`, with no reset or deletion. A disposable path-with-spaces copy with no existing venv, JavaScript dependencies, database, private environment, private logs, models, review reports, or exports completed setup from scratch using Python 3.11 and Node `20.19.0`.

Installation readiness and identity-provider readiness are now separate. The current approved shell copy has its private MFU IAM proxy field contract populated, but both Google OAuth client fields are absent. Provider readiness is therefore false and normal startup intentionally fails closed. Real MFU account acceptance remains an external university/provider action.

AI Governance now reads one canonical evidence snapshot and returns unavailable when that ignored evidence is absent; it no longer substitutes historical metrics. IsolationForest, active supervised artifact metadata, and diagnostic candidate state are displayed independently. The assistant visible contract is bounded to two summary points, three evidence points, and three next steps. Rendered Overview, Alerts, Investigation, Assistant, and AI Governance pages are checked at projector, laptop, and mobile viewports.

The separately supplied shell still lacks a published companion repository/archive version and checksum. `config/mfu-shell-contract.json` provides structure and non-secret fingerprinting, but approved shell distribution remains a release blocker. See `docs/V4_5_REPRODUCIBLE_PRODUCT_BASELINE.md` and `docs/V4_5_CURRENT_STATE_MANIFEST.md`.

The earlier v4.5 clean-room verification passed its documented backend,
frontend, replay, assistant, performance, and release gates. Its historical
migration warning is superseded: the configured SQLite database is now at
Alembic head `b4c5d6e7f8a9`.

## v4.7 Performance Update

v4.7 replaced the dominant wide Overview quality scan with index-servable
counts, removed recent-alert evidence N+1 reads, and consolidated freshness
checks. The read-only five-run profile passed local budgets without increasing
cache TTL, prewarming, adding a migration, or mutating the configured database.
The latest 2026-07-18 smoke rerun measured Overview uncached `0.1729s`, first
cached `0.1437s`, warm `0.0120s`, ML Governance `1.3065s`, alert list `0.0396s`,
case summary `0.0747s`, and feature sample `0.4803s`, with no warnings.

## v4.8 Product Acceptance Update

v4.8 passed a fail-closed 50,000-log acceptance run on a unique disposable
SQLite database. It applied existing migrations and exercised source creation,
durable queue/worker import, resumability and cancellation, parser accounting,
source-scoped detection, alert deduplication, case/explanation traceability,
assistant citations/redaction/provider-failure fallback, metrics, and isolated
backup/restore. It created no users, labels, model runs, or response actions and
left the configured database unchanged. Commit `15e43c8` was pushed without
force; GitHub Actions run `29640334774` passed backend, PostgreSQL persistence,
and frontend jobs.

## v4.8.1 Consolidation Update

The published cleanup proves that ATDR runtime, tests, scripts, launchers, and
CI have no dependency on the former tracked `NewSystem/` runtime. Selected
workflow/IAM/security references remain under `docs/reference/NewSystem/`;
unrelated Node/Vue/Mongo runtime files were removed. Private environment files,
databases, logs, labels, models, reviews, exports, migrations, tests, and
current ATDR change records remained protected. Commit `e05032a` and GitHub
Actions run `29646770282` completed successfully.

## v4.9-v5.13 Detection And Parser Program Update

The cumulative local program now provides:

- versioned detection taxonomy, rule, scenario, and labeling contracts;
- controlled rule/anomaly/supervised/hybrid validation with 24/24 scenarios
  and 288/288 layered runs;
- a reproducible supervised SOC queue artifact restricted to
  `shadow_observation`;
- immutable development/final/external evidence roles and leakage controls;
- read-only governed shadow scoring, longitudinal aggregate observations,
  operational acceptance, and drift diagnostics;
- versioned PAN-OS parser contracts and parser-profile-aware quality baselines;
  and
- shared runtime parser-quality accounting for future file, replay, UDP,
  durable, and scenario ingestion plus privacy-safe source operations.

The strong controlled checks do not satisfy the independent evidence gates.
Temporal/source/external model results remain insufficient, only one real
device is available, and the private source lacks independent human ground
truth. Supervised lifecycle therefore remains `shadow_observation`; no model
may create/suppress alerts, change severity, or trigger response. Rules remain
alert-authoritative.

The v5.13 closure verification recorded full backend `741 passed, 1 skipped`,
Playwright `26 passed, 1 skipped`, controlled `24/24`, layered `288/288`,
assistant QA `20/20`, a warning-free performance smoke, and a passing release
gate. The v5.13.1 consolidation reruns the full matrix and records its exact
approval-gated path set in `docs/V5_13_1_COMMIT_ALLOWLIST.md`.
