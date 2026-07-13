# ATDR Productization Roadmap

Date: 2026-06-27

Purpose: define the target SaaS-like SOC product direction for ATDR after the Phase 0 current-state lock and Phase 1 supervisor-template gap analysis. This is a planning document. It does not claim production readiness, does not enable real firewall blocking, does not enable automatic response, and does not change runtime behavior by itself.

Checkpoint: updated after the v3.73 detection/ML governance dashboard integration. The roadmap treats the official supervisor template as IAM/process evidence and keeps ATDR on FastAPI + React + SQLAlchemy/Alembic.

## Source Evidence

| Area | Source evidence |
| --- | --- |
| Current state anchor | `docs/CURRENT_SYSTEM_STATE_LOCK.md` |
| Supervisor template comparison | `docs/PRODUCTIZATION_TEMPLATE_GAP_ANALYSIS.md` |
| Active PRD | `docs/prd/PRD-ATDR.md` |
| Requirement traceability | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| Backend routes | `atdr/app/main.py`, `atdr/app/routers/*.py` |
| Database models | `atdr/app/db/models.py`, `migrations/versions/*.py` |
| Frontend routes/pages | `frontend/src/App.tsx`, `frontend/src/pages/*`, `frontend/src/lib/api.ts` |
| Verification and CI | `atdr/scripts/verify_release.py`, `.github/workflows/ci.yml`, `frontend/tests/*`, `atdr/tests/*` |
| Official supervisor template | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response` |
| Supervisor IAM evidence | `backend-node/docs/IAM_PRD.md`, `backend-node/docs/IAM_SYSTEM_OVERVIEW.md`, `backend-node/docs/IAM_RECOMMENDATIONS.md`, `backend-node/server/integrations/iam/*`, `frontend-vue/src/projects/components/dialog/SignIn.vue`, `frontend-vue/src/projects/components/dialog/TwoFA.vue` |

## Product Direction

ATDR should become a serious SOC-style product for controlled school/lab and future shared deployment use. The core product promise is:

- ingest firewall, syslog, and log-file data;
- preserve raw evidence;
- parse and normalize logs safely;
- detect suspicious or malicious activity with rules plus ML-assisted decision support;
- explain why an alert was raised;
- help analysts investigate with a read-only SOC assistant;
- support school-email IAM and role-based access;
- keep response actions simulated, audited, and analyst-approved until a separate real-response safety design is approved.

ATDR should keep its current FastAPI + React + SQLAlchemy/Alembic direction unless a later architecture decision record proves a stronger alternative. The supervisor template should be treated as a source of IAM, process, permission, and deployment patterns, not as a command to migrate to Node, Vue, or MongoDB.

## Architecture Principles

1. Source evidence first: code, routes, migrations, tests, runbooks, and the official supervisor template must be checked before major work.
2. Safety first: ML and assistant outputs are decision support only; they cannot trigger containment.
3. Raw evidence stays intact: parsing, normalization, deduplication, and case grouping must not delete raw logs.
4. Local workflow remains simple: SQLite and the existing backend/frontend commands should keep working.
5. Shared-lab workflow becomes stronger: PostgreSQL, backups, service health, and real syslog should be validated as optional shared-lab or deployment steps.
6. Secrets stay outside Git: `.env`, API keys, IAM client secrets, DB files, real logs, model artifacts, review batches, and generated reports must remain ignored.
7. External services are opt-in: MFU IAM, Google/MFU Mail login, SMTP, and external LLM providers must be disabled unless configured through private environment variables.

## Phase 2 Architecture Decision

The productization target is a modular FastAPI + React SOC product, not a stack migration.

- Keep FastAPI as the backend application layer because ATDR already has domain-specific routers, services, tests, release gates, and Python ML integration.
- Keep React as the dashboard because the current app already has protected routes for Overview, Alerts, Investigation, Assistant, AI Governance, Response/Audit, Tuning, and Admin.
- Keep SQLAlchemy/Alembic as the operational data model because ATDR's workflow data is relational: users, roles, logs, normalized records, alerts, evidence, labels, sources, runs, jobs, audit events, assistant feedback, suppressions, and watchlists.
- Use the supervisor template to guide IAM, permission matrix, 2FA/OTP, audit, account lifecycle, and deployment discipline.
- Do not copy Node/Vue/MongoDB runtime code into ATDR unless a later architecture decision proves a narrow adapter is better than a native Python/React implementation.
- Treat every external provider as optional and disabled-by-default until private configuration and tests prove it works safely.

## Target Backend Modules

| Module | Current status | Productization direction |
| --- | --- | --- |
| Auth and IAM | Local JWT login, admin/analyst roles, disabled MFU/OIDC placeholders, token-login harness | Add real MFU IAM or Google/MFU Mail login after provider details are confirmed. Keep local fallback. Add viewer role and stronger permission matrix. |
| Users and account lifecycle | User admin, email field, disabled-by-default verification/dev outbox | Add invite, disable/reactivate, verified school email status, last login, and audited account lifecycle. Real SMTP stays disabled until approved. |
| Ingestion | File import, replay, syslog/testing support, ingestion runs | Add more robust resumable imports, large-file progress, backpressure, and source-specific ingestion diagnostics. |
| Sources and health | Source management, health, parser profile, data quality | Add source onboarding workflow, expected parser profile checks, drift warnings, and hardware/syslog validation evidence. |
| Parser and normalization | Palo Alto, generic syslog, raw fallback, parse-failure handling | Add parser profile registry, vendor-specific test corpora, malformed-field telemetry, and safer format evolution. |
| Detection rules | Rule-based detections, explanations, deduplication, case grouping | Add rule catalog lifecycle, owner review, suppression policy, false-positive tracking, and versioned rule tests. |
| ML and AI governance | IsolationForest, supervised diagnostic workflows, model registry, readiness gates | Redesign supervised output around SOC queue decision support, independent validation, calibration, and explicit candidate/active separation. No auto-promotion. |
| SOC Assistant | Read-only deterministic fallback, external LLM adapter, citations, feedback | Improve follow-up context, real-provider resilience, answer evaluation, citations, and privacy controls. No actions. |
| Response safety | Simulated response, justification, protected IPs, audit | Keep simulated until a dedicated real-response design is approved. Add stronger preflight checks and rollback plans before any real connector. |
| Audit and compliance | Audit logs and verification docs | Add audit retention, tamper-evidence plan, search/export controls, and compliance reporting. |
| Jobs and operations | Operation jobs, run history, performance smoke, opt-in durable queue/worker, lease/heartbeat, safe retry/cancel controls, v3.92 worker supervision and operational warnings | Validate PostgreSQL multi-worker runtime behavior, add resumable large imports/backpressure, service-manager deployment, and approved archive policy. |
| Admin/config | Settings/status panels | Add configuration doctor UI, IAM readiness status, assistant provider status, source onboarding, and safe maintenance workflows. |

## Backend Module Boundaries

Future large backend changes should keep domain boundaries clear:

- `core/`: runtime config, security, middleware, logging, request IDs, provider-safe settings validation.
- `db/`: SQLAlchemy models, sessions, migrations, retention/index decisions.
- `parsers/`: parser profiles, raw fallback behavior, vendor-specific parsing contracts.
- `services/`: ingestion, normalization, source health, detection, assistant, IAM, response, audit, email, jobs.
- `detection/`: rules, feature extraction support, explanations, scenario contracts, ML evaluation utilities.
- `routers/`: API contracts only; keep heavy logic in services/evaluators.
- `scripts/`: safe operational CLI tools for replay, scenarios, verification, config doctor, provider probes.
- `tests/`: regression proof for every safety boundary and product workflow.

This split should guide refactors before adding major new behavior.

## Target Frontend Modules

| Area | Product direction |
| --- | --- |
| App shell and navigation | Keep React as the main dashboard. Use professional SOC/SaaS navigation with role-aware visibility. |
| Overview | Show operational summary, source health, alert posture, run status, and safety badges without clutter. |
| Alerts | Focus on triage queue, severity, source context, why flagged, dedup counts, analyst next checks, and suppression visibility. |
| Investigation | Provide search-first log explorer, source/case filters, normalized fields, raw evidence access controls, and labeling support. |
| SOC Assistant | Provide read-only assistant with context handoff, follow-up continuity, citations, safety badges, and provider status. |
| AI Governance | Separate model registry, diagnostic reports, readiness gates, data quality, and calibration status. Avoid presenting weak metrics as active model quality. |
| Response and Audit | Keep simulated response status prominent. Show approvals, denials, protected IP safeguards, and audit history. |
| Sources and Operations | Add source detail, parser profile, source health, data quality, recent runs, failed jobs, and troubleshooting hints. |
| Admin and IAM | Add local users, school-email status, IAM readiness, permission matrix, verification state, and external provider configuration status without secrets. |
| Reports and exports | Keep exports safe, explicit, and ignored by Git. Add evidence bundle workflow only after access control is clear. |

## Database Direction

ATDR should keep SQLAlchemy and Alembic as the database source of truth.

Local development:

- SQLite remains the default because it is simple for teammates and demos.
- Existing startup commands should keep working.
- Local `.env` should default to `sqlite:///./atdr.db` unless the user intentionally switches.

Shared lab and SaaS direction:

- PostgreSQL should become the validated shared-lab database path.
- Add migration checks, backup/restore drills, connection-health diagnostics, and indexes for source, time, alert, run, user, and audit queries.
- Add retention policies for logs, audit records, operations jobs, assistant feedback, and generated artifacts.
- Consider object storage or external archive for very large raw-log evidence later, while keeping database references and hashes.
- Do not replace the relational workflow with MongoDB. MongoDB could only be reconsidered later as an external raw-log lake, not the core operational database.

Future SaaS design needs:

- organization or tenant model;
- tenant-scoped users, sources, alerts, labels, and audit records;
- permission scopes by role, path, action, and data boundary;
- migrations that never reset user data.

## Authentication And IAM Direction

Current state:

- Local username/password JWT login works.
- Local email login and school-email metadata exist.
- Admin and analyst roles exist.
- Generic OIDC remains disabled-by-default groundwork.
- The optional supervisor-template session handoff is implemented behind private configuration, including protected-profile validation, allowed-domain checks, local user mapping, analyst default, explicit admin allowlist, URL cleanup, and local-login fallback.
- Local runtime validation and one external-user login audit exist; preprod/production identity lifecycle validation does not.

Target direction:

1. Keep local login as a fallback for development and recovery.
2. Implement real MFU IAM or Google/MFU Mail login only after live provider details are confirmed.
3. Accept `@lamduan.mfu.ac.th` and other approved domains through configuration, not hard-coded single-user logic.
4. Map external users to ATDR local users.
5. Default unknown approved school-email users to `analyst`.
6. Grant `admin` only through explicit configured mapping or IAM group/permission mapping.
7. Add a future `viewer` role for read-only users.
8. Add path/action permission checks aligned with the supervisor template permission matrix.
9. Audit login success, login failure, token validation, role assignment, and permission denials.
10. Never expose IAM secrets, access tokens, refresh tokens, or client secrets in API responses, logs, docs, or Git.

Recommended next IAM implementation slice:

1. Preserve the supervisor template as the login/account shell and ATDR as the SOC application.
2. Validate the same handoff contract in an approved preprod environment using HTTPS and provider-approved session/callback settings.
3. Define authoritative IAM group-to-role mapping, deprovisioning, recovery, 2FA evidence, and audit-retention policy.
4. Add a direct ATDR-owned OAuth/OIDC callback only if the supervisor template can no longer own the outer login flow.

Provider input required:

- approved MFU IAM base URL and environment;
- client ID and client secret in private `.env` or a secret manager;
- audience, scopes, token path, introspection path, and profile path;
- callback/redirect URLs if browser OAuth is used;
- group-to-role mapping;
- 2FA/OTP policy;
- account recovery and deprovisioning policy.

## SOC Assistant And LLM Direction

Current state:

- Read-only SOC Assistant exists.
- Deterministic fallback works.
- Optional Gemini, OpenAI-compatible, and Claude adapters exist and are disabled unless configured privately.
- The Gemini path has been validated through provider and full-service probes with structured output and zero mutation side effects.
- Server-owned actor-scoped context preserves alert/log/source/case follow-ups and clears stale context for global prompts.
- Raw log context is disabled by default.
- IP redaction is enabled by default.
- Assistant questions are audited.
- Feedback and quality review exist.

Target direction:

1. Make follow-up questions reliably preserve alert, log, source, case, and prior question context.
2. Use external LLM only when configured through private `.env`.
3. Prefer Gemini if MFU/Google access is available and approved; otherwise use an OpenAI-compatible provider or Claude depending on policy and key availability.
4. Keep deterministic fallback available if the provider fails, times out, or is disabled.
5. Keep context bounded, cited, and redacted.
6. Do not send raw logs by default.
7. Do not expose API keys or provider secrets.
8. Never allow the assistant to execute response actions, run detection, change labels, activate models, mutate users, delete data, or enable automation.
9. Add answer-quality evaluation and prompt-injection/privacy tests.
10. Show clear dashboard status: read-only, decision support, raw logs disabled, external provider enabled/disabled.

Recommended next assistant implementation slice:

1. Keep deterministic fallback, structured validation, context isolation, privacy filtering, and no-action checks as release invariants.
2. Add provider cost/quota dashboards and operational alerting only after shared deployment requirements are known.
3. Expand controlled answer-quality evaluation with real-source-safe summaries without enabling raw-log sharing.
4. Keep assistant work secondary to persistence, background processing, and operational hardening unless a real quality defect appears.

## Detection And ML Pipeline Direction

Current state:

- Parser and normalization are robust for current sample/lab data.
- Rules and explanations are the main reliable detection layer.
- Alert deduplication and case grouping exist.
- ML workflows are diagnostic and decision support only.
- Supervised model registry exists, but active/candidate metadata needs clearer product semantics.

Target direction:

1. Keep rules as the explainable foundation.
2. Maintain parser-driven features for app, action, src/dst, ports, direction, source behavior, and rule evidence.
3. Treat anomaly and supervised ML outputs as assistive signals, not final truth.
4. Redesign supervised outputs toward SOC queue decisions instead of overclaiming exact class/severity prediction.
5. Add independent validation across time split, random split, and source-aware split.
6. Track false positives, false negatives, suppression effects, and calibration.
7. Keep candidate-only model runs separate from active artifacts.
8. Do not activate or promote models automatically.
9. Do not allow ML outputs to trigger response.
10. Continue using controlled corpora and, later, real-source validation.

Recommended next detection/ML implementation slice:

1. Separate active artifact metadata from candidate diagnostic runs in the registry and dashboard.
2. Build a diagnostic SOC queue model comparison that evaluates binary threat-positive, three-class triage, hierarchical, calibrated tree, and calibrated linear strategies.
3. Keep all outputs diagnostic until split stability, calibration, false-positive rate, suspicious recall, and malicious recall meet conservative gates.
4. Make alert explanations rule/evidence-first; ML should add confidence/risk context, not replace evidence.

## Logging, Audit, And Observability

Target product work:

- structured logs with request IDs and operation IDs;
- health endpoints that distinguish API, database, cache, IAM, LLM, and background-job status;
- no secrets in logs;
- audit records for auth, IAM, user changes, assistant questions, response attempts, label changes, model actions, imports, detection runs, and exports;
- audit retention and export policy;
- performance smoke and dashboard profiling in CI or release gates;
- future metrics dashboard for ingestion rate, parser failures, alert rate, job failures, LLM failures, and IAM failures.

## Deployment Direction

Local:

- Keep current commands:
  - `.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload`
  - `cd frontend`
  - `npm.cmd run dev`

Shared lab:

- Validate PostgreSQL with Alembic, backup/restore, performance smoke, and source-pilot checks.
- Add environment-specific `.env.example` guidance without committing real `.env`.
- Add service-health docs and config-doctor checks.

Future SaaS:

- containerized deployment;
- reverse proxy and TLS;
- secret manager;
- managed PostgreSQL;
- queue worker service;
- object storage or evidence archive;
- monitoring/alerting;
- backup, restore, rollback, and disaster-recovery runbooks.

## Testing Strategy

Required gates should stay or become stronger:

- `ruff check .`
- `python -m compileall -q atdr migrations`
- `python -m pytest atdr/tests -q`
- `alembic check`
- `cd frontend && npm.cmd run lint && npm.cmd run build && npm.cmd run test:e2e`
- `python -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty`
- `python -m atdr.scripts.performance_smoke --pretty`
- `python -m atdr.scripts.test_assistant_llm_provider --pretty`
- `python -m atdr.scripts.verify_release`

Future specialized gates:

- MFU IAM mock tests and, when approved, preprod live tests;
- real LLM provider probe with no raw logs and secret-safe output;
- parser corpus validation;
- detection false-positive/false-negative regression suite;
- source pilot validation;
- backup/restore drill;
- permission matrix tests;
- prompt-injection and assistant no-side-effect tests.

## Security Boundaries

Non-negotiable current boundaries:

- no automatic response;
- no real firewall blocking;
- no response action without authorization and justification;
- no ML model activation/promotion without explicit reviewed workflow;
- no assistant action execution;
- no raw-log external LLM context by default;
- no secrets in docs, logs, API responses, or Git;
- no single hard-coded school-email user gate;
- no database reset/delete during normal development.

Future hardening:

- rate limiting;
- stricter CORS/security headers;
- CSRF policy for browser flows;
- path/action permission matrix;
- session lifecycle and refresh-token policy;
- IAM token verification and expiry handling;
- audit integrity controls;
- data retention and deletion policy;
- tenant data isolation if SaaS multi-tenancy is added.

## Data Privacy Boundaries

Protected local/generated data:

- `.env` files;
- API keys and client secrets;
- real/private log files;
- SQLite/PostgreSQL DB files;
- model artifacts;
- `ml_baseline_reviews/`;
- `demo_exports/`;
- processed/generated reports;
- benchmark snapshots.

External LLM privacy:

- summarize context before sending;
- redact IPs when configured;
- do not include raw log lines unless a future privacy review explicitly enables it;
- keep provider status visible without exposing keys;
- audit whether external provider was used and whether raw context was included.

## What Requires User Or Provider Input

| Need | Why it is required |
| --- | --- |
| MFU IAM client secret and approved client ID | Real MFU token introspection or OAuth cannot be live-completed without approved credentials. |
| MFU/Google callback URLs | Browser login requires registered redirect URLs. |
| Allowed school-email domains | Prevents hard-coded single-user logic and supports team access. |
| IAM group-to-role mapping | Needed to assign admin/analyst/viewer safely. |
| SMTP or email service approval | Needed for real verification, invites, and notifications. |
| LLM provider key and policy | Needed for external assistant mode and privacy review. |
| Real firewall/router/syslog device | Needed for live-source validation beyond replay/no-hardware tests. |
| Shared hosting/database target | Needed for PostgreSQL, deployment, backup, and monitoring decisions. |
| Real response connector approval | Needed before any real firewall blocking design can be built. |

## Productization Phases

### Phase A: Repository Cleanup And Reference Archiving

- Decide whether in-repo `NewSystem/` is kept, moved to `docs/reference/`, or deleted.
- Preserve useful supervisor-template evidence.
- Remove ignored local artifacts only with explicit approval.
- Update docs so the official external template path remains the canonical reference.

### Phase B: SOC Assistant Follow-Up And Real Provider QA

- Completed locally through v3.87: actor-scoped follow-up context, explicit context reset, structured Gemini output, citations, provider telemetry, retries, privacy controls, prompt-injection resistance, deterministic fallback, and zero action side effects.
- Deployment approval, quota/cost monitoring, and real-traffic answer evaluation remain operational follow-up work.

### Phase C: Real School-Email IAM Path

- Local supervisor-template session handoff is implemented and exercised.
- School-email users map to local ATDR users; analyst is the default and admin requires explicit mapping.
- Local login fallback remains available.
- Preprod/production HTTPS routing, IAM group synchronization, provider-managed 2FA evidence, recovery, and deprovisioning remain incomplete.

Implementation order note: Phase B is complete for the local checkpoint. Continue Phase C only in an approved preprod/production identity environment; do not replace the working local fallback or duplicate the supervisor template's login UI inside ATDR.

### Phase D: Detection And ML Product Hardening

- Clarify model registry active vs candidate status.
- Continue SOC queue model design instead of overclaiming exact severity.
- Add split-stability and calibration gates.
- Improve false-positive and false-negative review flow.
- Keep model activation manual and conservative.

### Phase E: Shared-Lab Persistence And Operations

- Validate PostgreSQL in a shared-lab environment.
- Add backup/restore and migration drills.
- v3.90 adds an opt-in durable queue and separately launched single-worker flow; validate managed-worker supervision and PostgreSQL/multi-worker behavior next.
- v3.92 adds bounded request correlation, explicit liveness/readiness, dependency-free low-cardinality metrics, warning visibility, SQLite single-worker enforcement, graceful worker shutdown, and dry-run-first audit retention. PostgreSQL multi-worker runtime validation remains open.
- Harden performance and retention for large datasets.

### Phase F: Professional Product Dashboard

- Refine role-aware navigation.
- Build cleaner Admin/IAM/settings screens.
- Improve source onboarding, alert triage, assistant, and AI Governance UX.
- Remove outdated class/demo wording from dashboard surfaces.

### Phase G: Observability, Audit, And Security Hardening

- Add metrics, request IDs, security headers, rate limits, audit retention, and health breakdowns.
- Improve config doctor and deployment checks.
- Add prompt-injection and external-provider privacy tests.

### Phase H: Productization Release Candidate

- Run full verification.
- Complete docs, runbooks, rollback plan, and acceptance checklist.
- Clearly state what is production-ready, what is lab-ready, and what remains disabled.

## Non-Goals For This Track

- Do not migrate ATDR to Node, Vue, or MongoDB just because the supervisor template uses them.
- Do not delete `NewSystem/` without a dedicated cleanup decision.
- Do not commit secrets or generated/private data.
- Do not enable real firewall blocking.
- Do not enable automatic response.
- Do not claim production readiness before deployment, IAM, security, data-retention, observability, and response-safety gates pass.

## Acceptance Criteria For The Productization Track

ATDR can be treated as a serious productization candidate when:

- local and shared-lab setup are documented and repeatable;
- IAM has a real approved school-email path or a documented provider blocker;
- SOC Assistant works with deterministic fallback and optional real provider without unsafe side effects;
- parser and detection validation cover controlled and real-source cases;
- ML governance clearly separates diagnostic candidates from active decision-support artifacts;
- response remains safe, audited, and analyst-approved;
- GitHub CI and local release gates pass;
- secrets and private/generated data remain out of Git;
- dashboard workflows are professional and role-aware;
- operations, audit, backup, restore, and performance checks are documented and tested.

## Immediate Next Implementation Candidates

Choose one of these as the next code phase:

| Candidate | Why now | Main risk | Definition of done |
| --- | --- | --- | --- |
| PostgreSQL/shared-lab persistence and backup/restore | SQLite is the largest remaining multi-user operational constraint, while portability and drill scripts already exist. | Environment availability and migration/backup correctness. | PostgreSQL validation passes on an approved host; migrations, backup, restore, and rollback are documented and tested without changing normal SQLite startup. |
| PostgreSQL multi-worker and managed worker validation | Durable queue, local supervision, and resumable imports are implemented; the largest remaining operations gap is shared-lab concurrency and process management. | Environment availability, shared staging semantics, and concurrent lease behavior. | Approved PostgreSQL host validates multiple workers, managed restart behavior, backup/restore during controlled activity, and rollback without changing the SQLite local workflow. |
| Detection/ML independent quality validation | Detection quality is central and real-source evidence remains limited. | More synthetic tuning can overfit without new independent data. | Frozen candidate evaluated on independent/source-aware data; no activation; evidence-first explanations and conservative gates remain. |
| Observability/security/audit hardening | Shared operation needs metrics, correlation IDs, health breakdowns, and retention/integrity controls. | Telemetry can leak sensitive evidence if designed poorly. | Secret-safe metrics and request/operation IDs cover ingestion, jobs, IAM, assistant, detection, and failures; audit retention/integrity is tested. |

Recommended next code phase after the v3.88 checkpoint: **PostgreSQL/shared-lab persistence and backup/restore validation**, followed by a durable background-job architecture. The assistant and local template-shell handoff have reached stable local checkpoints; persistence and operation isolation now have the largest product-level risk reduction.

### v3.89 Checkpoint Update

The shared-lab persistence foundation is now implemented. SQLite stays the local default, while the optional PostgreSQL path has dialect-aware pooling, isolated backup/restore validation, a PostgreSQL-safe boolean migration default, and an ephemeral CI validation job. The remaining evidence gap is the remote CI result or an approved PostgreSQL lab host; do not claim PostgreSQL shared-lab runtime validation until one passes.

The recommended v3.90 phase remains durable background-job architecture with idempotency, retries, cancellation, progress, failure recovery, and SQLite-local compatibility.

### v3.90 Checkpoint Update

The durable background-job foundation is now implemented as an opt-in database-backed queue with private staging, idempotency, lease/heartbeat recovery, scoped RBAC, safe retry/cancel behavior, worker audit events, and compact Operations Health visibility. The API does not spawn a worker automatically, and SQLite remains a one-worker local profile. The next operations phase should validate a managed worker and PostgreSQL concurrency on an approved shared-lab host rather than layering more background behavior onto SQLite.

### v3.92 Checkpoint Update

Operational observability and local worker supervision are now implemented without an external monitoring dependency. Readiness fails closed for database, migration, or configuration problems; metrics are low-cardinality and evidence-safe; SQLite rejects a second fresh worker; and audit retention remains explicit, bounded, and raw-evidence preserving. The recommended next phase is resumable large-file ingestion and backpressure, followed by approved PostgreSQL multi-worker runtime validation.

### v3.93 Checkpoint Update

Queued file imports now stream through transactional chunks that atomically advance raw/normalized evidence, source and ingestion-run counters, job progress/checkpoints, lease renewal, and worker heartbeat. Running imports can be cancelled cooperatively at chunk boundaries and resumed only when the local staged input still matches its size and SHA-256 fingerprint. Queue and storage backpressure fail clearly, completed jobs remove staged input, failed/cancelled jobs retain it only through a bounded resume window, and cleanup remains dry-run by default.

This closes the local resumable-ingestion gap but does not establish global exactly-once semantics or distributed processing. Recommended v3.94: PostgreSQL multi-worker runtime validation, managed worker deployment, shared staging design, and backup/restore concurrency drills on an approved host.

### v3.94 Checkpoint Update

The queue now has PostgreSQL skip-locked claim and recovery statements, lease-token fencing, storage-aware file claims, source-row concurrency protection, graceful resumable-import handoff, worker/backup advisory coordination, and unprivileged systemd examples. Disposable PostgreSQL validators and an ephemeral CI job cover concurrent claims, lease recovery, source creation, same-source imports, backup drain refusal, and isolated restore without changing SQLite startup or safety behavior.

Local evidence is limited to SQL compilation, unit tests, migration checks, deployment validation, and dry-run harnesses because this workstation has no PostgreSQL/Docker/client runtime. A successful remote CI or approved-host execution is still required before calling the shared PostgreSQL runtime validated. Global exactly-once, multi-host mount behavior, API-wide maintenance quiescing, external monitoring, TLS, managed secrets, and disaster recovery remain open.

Recommended next phase after remote v3.94 evidence: deployment observability and security hardening, including persistent metrics/alerts, audit-integrity/retention scheduling, reverse-proxy TLS, managed secrets, load testing, and a documented recovery exercise. Independent detection/ML validation remains a parallel evidence track and must not activate a model automatically.

### v3.95 Checkpoint Update

Repository-side deployment security and recovery controls are now implemented. ATDR has an optional HTTPS Nginx reference, explicit trusted-proxy handling, Prometheus scrape/alert references, report-only systemd maintenance timers, managed-secret operations guidance, a bounded GET-only load harness, backup artifact verification, and an isolated separate-target recovery drill. Local validation passed without changing the configured database or normal startup workflow.

This closes the repository-design gap, not the environment evidence gap. Real certificates/DNS, Linux service installation, Prometheus persistence and alert routing, managed-secret integration, measured PostgreSQL RPO/RTO, multi-host shared storage, and remote PostgreSQL CI remain pending. The recommended v3.96 phase is an approved-host deployment rehearsal and evidence closure. If no approved environment is available, prioritize independent detection/ML validation rather than adding more deployment abstractions.

## Phase 2 Completion Evidence

This roadmap now reflects:

- current backend router and settings evidence from `atdr/app/main.py` and `atdr/app/core/config.py`;
- current relational model evidence from `atdr/app/db/models.py`;
- current React route evidence from `frontend/src/App.tsx`;
- Phase 0 and Phase 1 productization docs;
- supervisor IAM/process evidence from the official template path;
- the v3.73 detection/ML governance checkpoint.

No runtime behavior, database schema, IAM behavior, LLM behavior, model state, or response behavior was changed by this document.
