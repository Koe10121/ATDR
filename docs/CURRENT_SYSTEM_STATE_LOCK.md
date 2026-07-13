# ATDR Current System State Lock

Date: 2026-07-13

Purpose: this document is the current-state memory anchor before larger ATDR productization work. It captures what exists now, what must stay safe, and what must not be deleted or committed while ATDR moves from controlled academic/lab prototype toward a more serious SOC/SaaS-style product.

Checkpoint: v3.90 adds an opt-in durable operation queue/worker to the v3.88-v3.89 local product baseline. This document remains a source-backed state lock, not a production-readiness claim.

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
| SOC Assistant | `atdr/app/routers/assistant.py`, `atdr/app/services/assistant_service.py`, `atdr/app/services/assistant_llm.py`, `frontend/src/pages/AssistantPage.tsx` |
| Durable operation reliability | `atdr/app/services/job_service.py`, `atdr/app/services/job_dispatcher.py`, `atdr/app/services/operation_worker.py`, `atdr/app/routers/jobs.py`, `atdr/scripts/run_operation_worker.py` |
| IAM / school-email groundwork | `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py`, `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md` |
| Response safety | `atdr/app/routers/response.py`, `atdr/app/services/response_service.py`, `atdr/tests/test_response_safety.py` |
| Detection/ML productization evidence | `atdr/app/detection/v372_unified_detection_ml_evaluation.py`, `atdr/scripts/evaluate_detection_ml_productization.py`, `frontend/src/pages/MLGovernance.tsx` |
| Frontend route truth | `frontend/src/App.tsx`, `frontend/src/pages/*`, `frontend/src/lib/api.ts` |
| Tests and release gate | `atdr/tests/*`, `frontend/tests/*`, `atdr/scripts/verify_release.py`, `.github/workflows/ci.yml` |
| Supervisor template reference | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response` |

## Current Architecture

ATDR currently uses:

- Backend: FastAPI with Python 3.11, SQLAlchemy, Alembic, Pydantic settings, JWT authentication, request/security middleware, and structured logging.
- Frontend: React 18, Vite, TypeScript, React Router, TanStack Query/Table, Recharts, Playwright.
- Database: SQLite for normal local workflow, with optional PostgreSQL/shared-lab validation paths. The current local workflow does not require Docker or PostgreSQL.
- ML stack: Python feature generation, rule detection, IsolationForest anomaly support, supervised classifier experiments, model registry, and conservative governance gates.
- Runtime command shape:
  - Backend: `.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload`
  - Frontend: `cd frontend` then `npm.cmd run dev`

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
- `IngestionRun`
- `DetectionRun`
- `OperationJob`
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

## Log Ingestion Status

ATDR can currently:

- Import log files through backend/API/script workflows.
- Replay safe samples or selected external files.
- Simulate live ingestion through replay and syslog lab tooling.
- Track ingestion runs and operation jobs.
- Attach logs to optional log sources.
- Preserve raw evidence independently from parsed/normalized fields.

Known limitation: very large/shared-lab usage should move toward PostgreSQL or another production-grade database plan. SQLite remains appropriate for local development and controlled lab workflow.

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
- The worktree currently contains many uncommitted productization changes and docs. Treat Git status as a source of truth before any push/cleanup.

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

- `NewSystem/` inside this repo until a separate cleanup phase proves it can be moved or removed safely.
- `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response` is the official supervisor template source and should be inspected before major template/IAM/process work.

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

## Latest Verified Checkpoint

The latest v3.87 verification evidence in this workspace showed:

- Ruff: passed.
- Compileall: passed.
- Backend tests: `471 passed, 1 skipped`.
- Alembic check: no drift.
- React lint/build: passed.
- Playwright: `19 passed, 1 skipped`.
- Real Gemini provider and full assistant probes: structured output valid, raw logs excluded, secrets hidden, assistant audit created, and response/detection/label/model side effects all zero.
- Replay dry-run: passed against the safe two-line sample.
- Performance smoke: no warnings; Overview `0.4715s`, cached Overview `0.0073s`, alert list `0.0504s`, case summary `0.0394s`, and ML Governance `1.314s`.
- Release gate: passed.

This evidence proves the current controlled productization checkpoint, not production readiness.
