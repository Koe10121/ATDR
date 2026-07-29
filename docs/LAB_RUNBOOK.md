# ATDR Lab Runbook

This runbook covers the portable MFU-shell team profile and deeper lab checks. SQLite remains the normal ATDR database. Docker and PostgreSQL are optional ATDR deployment targets; MongoDB is required locally only because the approved MFU shell owns authentication and account lifecycle.

## Normal Team Workflow

Run setup once with the separately approved shell path:

```powershell
.\scripts\setup_team.cmd -TemplateRoot "<MFU_SHELL_ROOT>"
```

Start all components:

```powershell
.\scripts\start_system.cmd
```

Open:

```text
http://localhost:8080/#/pages/login
```

Sign in through the shell, then open ATDR through its registry/dashboard action. The one-time handoff creates an HttpOnly ATDR session. Direct local credentials are available only in explicit `local_recovery` mode.

Check or stop the system:

```powershell
.\scripts\check_system.cmd
.\scripts\stop_system.cmd
```

The lifecycle retains the existing component commands internally and must continue to support log import, detection, alert triage, AI Governance, reviewed CSV import, diagnostic model training, simulated response actions, and audit review.

## Health Check

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected result: status `ok`, database `ok`, and response mode `simulation`.

## MFU Supervisor-Template Login Shell

ATDR runs behind the advisor-provided MFU template as the normal school-email identity shell. This does not replace FastAPI/React; it composes the separate Node/Vue/Mongo shell with the ATDR services.

Safe readiness checks:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.template_auth_doctor --template-root "<MFU_SHELL_ROOT>" --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_bridge_contract --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.validate_template_shell_runtime --check-runtime --pretty
```

The authentication doctor must report matching configured frontend/backend Google clients, no legacy fallback, and `secrets_exposed: false`. Real account acceptance still requires an approved OAuth client and a successful MFU sign-in.

The v3.91 flow is deliberately server-mediated: the template verifies its own school session, creates a short-lived single-use code, and submits it to ATDR by form POST. ATDR exchanges that code with the template backend, maps a minimal identity to a local user, defaults new external users to analyst, and grants admin only through approved IAM groups. No school token, OTP, or bridge secret may be placed in a URL, browser storage, or Git.

Use `docs/TEAM_ONE_COMMAND_START.md` for local startup, `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md` for the security contract, and `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md` for provider-backed validation. Local username/password is an explicit recovery profile, not an automatic fallback. Source-level implementation does not prove preproduction routing, IAM group values, provider-managed 2FA, recovery, or deprovisioning.

The template launcher source lives outside this repository at:

```text
<MFU_SHELL_ROOT>\frontend-vue\src\views\Dashboard.vue
```

Do not copy template `.env` files or credentials into ATDR or Git.

## SOC Assistant

v3.87 keeps the assistant read-only and adds validated external-provider answers, bounded server-owned follow-up context, structured citations, retries, rate limiting, and deterministic fallback.

Open the React dashboard and use:

```text
SOC Assistant
```

Safe example questions:

- What is the latest critical alert?
- Why was alert 1 flagged?
- Show latest critical alerts.
- Which sources have warnings?
- What changed recently?
- Summarize failed jobs.
- Why is the model not production promoted?
- How do I import reviewed labels?
- How do I run a safe scenario?
- Summarize source health.
- Summarize recent operation jobs.
- Explain current ML model status.
- How do I run replay or detection?

Assistant safety defaults:

- External LLM provider is disabled by default and enabled only through private `.env` configuration.
- Raw log context is disabled by default.
- IP redaction is enabled by default.
- Questions are audited.
- Recent assistant questions are shown from safe audit summaries.
- The assistant cannot run response actions, detection, model activation, label changes, or data deletion.

Assistant configuration placeholders are in `.env.example` and `.env.lab.example`:

```text
ASSISTANT_ENABLED=false
ASSISTANT_PROVIDER=disabled
ASSISTANT_MODEL=
ASSISTANT_API_KEY=
ASSISTANT_MAX_CONTEXT_ROWS=20
ASSISTANT_REDACT_IPS=true
ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false
```

Do not commit `.env` files or API keys. External-provider deployment still requires privacy, quota, key-custody, and organizational review.

### Real Provider Safety Checks

These commands never print the configured API key:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --execute --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_chat_provider --execute --pretty
```

The last command uses synthetic data in a temporary database. Confirm `structured_output_valid=true`, `raw_log_context_included=false`, `secrets_exposed=false`, and zero response, detection, label, and model side effects.

For a dashboard check, ask about a valid alert, ask a follow-up such as `What logs are related?`, verify the active alert context and citations remain correct, then use **Clear context** before asking a global question such as `Explain the latest critical alert.`

## v3.4 Shared-Lab Readiness Checks

These checks prepare ATDR for shared-lab validation without changing the normal local workflow or claiming production readiness.

Run the combined v3.4 readiness report:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v34_shared_lab_readiness --pretty
```

The report combines config and secret safety checks, PostgreSQL configured/not-configured status, backup/restore readiness, dashboard summary performance profiling, real-source pilot status, source health, ingestion/detection run health, response safety, and audit counts.

Run the safe backup/restore drill:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_backup_restore_drill --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_backup_restore_drill --pretty
```

For SQLite, the non-dry-run command creates an ignored backup copy under `.tmp/atdr-backups` and verifies that row counts can be read from the copy. It never restores over or overwrites the live database.

Profile cold Overview/ingestion performance:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.profile_dashboard_summary --runs 5 --pretty
```

The v4.7 profiler is read-only. It reports independent application-cache misses and warm hits, min/median/p95/max, query counts, stable payload fingerprints, SQLAlchemy database time, and safe SQLite query-plan details. It does not flush operating-system page caches, so retain separately observed true cold-disk evidence. If the cold Overview summary is slow but cached hits are fast, treat it as a large-SQLite/shared-lab performance item. Do not reset or delete data to hide performance warnings. See `docs/V4_7_LARGE_SQLITE_PERFORMANCE_STABILIZATION.md`.

For PostgreSQL shared-lab validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty
```

If the current `DATABASE_URL` is SQLite, the expected status is `postgres_lab_validation_blocked_by_environment`. That is non-destructive and confirms the normal local workflow remains unchanged.

## v3.89 Persistence And Restore Drill

Run an isolated local persistence validation without touching the configured database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_persistence_profile --pretty
```

Use the new explicit backup command for an operator backup. It is dry-run unless `--execute` is present:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir C:\ATDR-backups --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir C:\ATDR-backups --execute --pretty
```

The command writes a checksum manifest next to the backup. Restore validation requires a new empty target and refuses the active configured database. See `docs/V3_89_SHARED_LAB_PERSISTENCE_AND_BACKUP_RESTORE.md` for the confirmation command and optional isolated PostgreSQL procedure.

## v3.90 Durable Operation Worker

ATDR now supports an opt-in database-backed worker for selected long-running imports, detection runs, ML scoring/training, and report exports. The FastAPI API process does **not** start a worker automatically, so the normal local workflow is unchanged.

Run one deliberate worker cycle after a queued operation is submitted:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --once --pretty
```

For a shared-lab watcher, set `OPERATION_WORKER_ENABLED=true` only in the private `.env`, then run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --watch --pretty
```

Use one worker with SQLite. Operations Health shows queue state and the latest worker heartbeat. Queue payloads and staged upload paths are not exposed through the UI or API. Imports stage files under ignored `.atdr_runtime/` storage. Completed jobs remove the staged copy; failed or cooperatively cancelled imports retain it only while the bounded resume window remains open.

Safety rules:

- Queued or retry-waiting jobs cancel immediately. Running resumable imports accept a cancellation request and stop only after the current chunk commits or rolls back safely.
- Evidence-mutating jobs fail closed after a worker lease expires; only report exports can auto-retry.
- The worker cannot execute response actions, firewall changes, model activation/promotion, label changes, user changes, external IAM/LLM calls, or data deletion.
- Existing direct import/detection/ML endpoints remain synchronous unless explicitly queued.

See `docs/V3_90_DURABLE_BACKGROUND_JOBS.md` for API details and retry policy.

## v3.93 Resumable Large-File Imports

Queue an admin file import from **Admin > Demo Controls > Durable file import**. This keeps the existing synchronous sample import unchanged. Start exactly one SQLite worker separately:

```powershell
$env:OPERATION_WORKER_ENABLED="true"
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --watch --pretty
```

Operations Health reports committed records, percentage, chunk count, heartbeat, cancellation state, and resume eligibility. It deliberately does not show a guessed ETA, private path, or checksum.

Default local controls are documented in `.env.example`:

```text
INGESTION_CHUNK_SIZE=500
INGESTION_PROGRESS_UPDATE_INTERVAL=500
OPERATION_MAX_QUEUED_IMPORTS=10
OPERATION_MAX_QUEUED_JOBS_PER_ACTOR=5
OPERATION_STAGING_MAX_TOTAL_BYTES=1073741824
OPERATION_STAGING_MIN_FREE_BYTES=268435456
OPERATION_STAGING_RETENTION_HOURS=24
```

Cancellation is cooperative. Request it from Operations Health and wait for the worker to acknowledge it at the next transaction boundary. Already committed raw and normalized evidence remains in the database.

Resume is admin-only and available only for eligible failed or cancelled file jobs. ATDR verifies the staged input's size and SHA-256 fingerprint, continues the same ingestion run after the last committed byte/line checkpoint, and refuses missing, changed, expired, or concurrently resumed input. This is a transactional chunk guarantee for one verified staged file, not global exactly-once ingestion across separate jobs.

Preview staged-input retention cleanup:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.cleanup_staged_inputs --pretty
```

Applying cleanup requires `--apply --confirm APPLY-STAGED-CLEANUP`. Review the preview first. Cleanup protects active and still-resumable inputs and never deletes raw or normalized log evidence.

Failure recovery:

1. Stop or replace the failed worker.
2. Wait for lease recovery or confirm the job is `failed` or `cancelled`.
3. Check committed progress and resume eligibility in Operations Health.
4. Resume as an admin only if the staged input is still valid.
5. Restart exactly one SQLite worker and confirm the child job completes.

If resume is ineligible, upload the file as a new job. Do not copy an unverified file over the staged input and do not delete raw evidence to restart.

## v3.97 Large-File Reliability Validation

Apply the additive raw-log fingerprint migration before using the optimized worker:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
```

Operations Health now shows cumulative raw imported, parsed, failed, and duplicate counts while a chunked import runs. Duplicate counts report previously seen content; they do not delete or suppress raw evidence.

Run the 100,000-line acceptance check only with its required disposable-database flag:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_large_ingestion --use-temp-db --lines 100000 --pretty
```

The validator creates synthetic generic syslog under ignored `.tmp` storage, forces a checkpoint handoff, validates resume/cancellation/file-change safety, verifies zero unsafe side effects, and cleans up. Without `--use-temp-db` it refuses to run. It never imports a private file and never targets the configured database.

Expected v3.97 reference result: 100,000 raw and normalized rows, 0 parse failures, 200 chunk commits, 0 duplicate rows after resume, changed input rejected, cooperative cancellation passed, and no detection/model/label/response actions. Local runtime was about 138 seconds with an 8.71 MiB traced Python-memory peak; this is local synthetic evidence, not a capacity SLA.

## v5.14 Private PAN-OS Large-File Runtime Acceptance

Keep the private PAN-OS file outside Git. Run the complete aggregate preflight
without creating database rows:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v514_large_file_runtime_acceptance `
  --sample-path "<PRIVATE_PANOS_LOG>" `
  --preflight-only `
  --pretty
```

Run the bounded end-to-end acceptance only against disposable storage:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v514_large_file_runtime_acceptance `
  --sample-path "<PRIVATE_PANOS_LOG>" `
  --limit 100000 `
  --chunk-size 1000 `
  --use-temp-db `
  --simulate-interruption `
  --resume `
  --run-detection `
  --pretty
```

The command refuses runtime processing without `--use-temp-db`. It creates
two simulated logical chronological windows from one observed physical-device
stream; it does not claim two firewalls. Temporary raw rows, staging files,
and the SQLite database are removed after the run. Output excludes the input
path, raw rows, IPs, fingerprints, database location, and secrets.

Current local reference result: full aggregate scan `773,551/773,551` with
zero parser errors/structural warnings/exact duplicates; disposable processing
`100,000/100,000` raw and normalized with zero parse failures; forced
1,000-row checkpoint handoff/resume with zero extra rows; cooperative
cancellation and SQLite lock-wait probes passed; rule detection evaluated
100,000 rows and preserved alert/log/source traceability; response actions,
labels, and model runs remained zero. See
`docs/V5_14_LARGE_FILE_RUNTIME_ACCEPTANCE.md` for measured timings and
limitations.

Detection totals are operational outputs, not human-labeled accuracy. Rules
remain alert-authoritative, supervised ML remains `shadow_observation`, and
automatic response/real firewall blocking remain disabled.

## v3.99 Frozen Multi-Source Revalidation

v3.99 must use a migrated disposable validation database, not the configured database. Set `DATABASE_URL` only in the current PowerShell process:

```powershell
$env:DATABASE_URL='sqlite:///C:/path/to/disposable-validation.sqlite3'
.\.venv\Scripts\python.exe -m atdr.scripts.run_v399_multisource_frozen_revalidation --rows-per-source 240 --seed 399 --summary-only --pretty
```

The command generates three ignored source CSVs and a manifest under `ml_baseline_reviews/v3_99_evidence/`. They contain safe deterministic synthetic evidence and scenario expectations only. They are not human-reviewed, import-ready, real-device, or production evidence.

Expected current reference result:

- 720 attempted and accepted rows;
- three source identities and four time windows;
- zero exact, near-pattern, or used-feature overlap with reviewed evidence;
- external rows used for fit/calibration/threshold selection: zero;
- primary queue F1 approximately `0.9524-0.9551` and synthetic FPR `0.0`;
- calibration remains weak;
- readiness remains `candidate_only`;
- database counts and active artifact metadata remain unchanged;
- model activation and response automation remain disabled.

Do not tune using these final results. See `docs/V3_99_INDEPENDENT_MULTI_SOURCE_EVIDENCE_AND_FROZEN_REVALIDATION.md` for protocol and limitations.

## v3.94 PostgreSQL Multi-Worker And Managed Deployment

The local SQLite workflow remains one worker. Do not set `OPERATION_WORKER_CONCURRENCY` above `1` for SQLite.

On an approved PostgreSQL host, copy the relevant values from `.env.lab.example` into a private environment file. All worker hosts must mount the same absolute staging root and use the same storage ID. Validate configuration before starting services:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_worker_deployment --require-shared --pretty
```

Reference Linux service units and installation guidance are under `deploy/systemd/`. The API and workers are separate processes; the API never starts a worker. A managed `SIGTERM` lets a resumable import commit its current chunk, release its fenced lease, and return to the queue for a replacement worker.

Use the PostgreSQL validators only with disposable databases whose names contain `v394`, `test`, or `ci`. Execute mode requires the exact confirmation phrases:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_postgres_multiworker --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.validate_postgres_multiworker --execute --confirm ISOLATED_V394_POSTGRES --pretty

.\.venv\Scripts\python.exe -m atdr.scripts.validate_backup_worker_concurrency --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.validate_backup_worker_concurrency --execute --confirm ISOLATED_V394_BACKUP_DATABASES --pretty
```

The execute commands read isolated database URLs from `ATDR_V394_POSTGRES_DATABASE_URL`, `ATDR_V394_BACKUP_SOURCE_DATABASE_URL`, and `ATDR_V394_BACKUP_RESTORE_DATABASE_URL`. Do not post these values or commit them.

PostgreSQL backup pauses cooperative worker cycles with an advisory lock and refuses to run while a mutating operation is active. A full deployment backup also requires an approved API maintenance/read-only window because unrelated API clients are outside the worker lock.

Troubleshooting:

- `staging storage mismatch`: confirm every worker has the same shared mount and `OPERATION_STAGING_STORAGE_ID`.
- `legacy local staged input`: finish it with the originating local profile or submit it again through shared staging; do not copy an unverified file into place.
- `lease ownership lost`: another worker recovered the expired lease; the stale worker must stop writing.
- `operation_workers_active` or `active_mutating_jobs`: drain workers/jobs before backup; never delete evidence to force the backup.
- graceful stop exceeds the service timeout: inspect the current chunk size and database health before increasing the timeout.

See `docs/V3_94_POSTGRESQL_MULTIWORKER_AND_MANAGED_DEPLOYMENT.md` for guarantees, limitations, rollback, and CI status.

## Operation Job Maintenance

ATDR records synchronous operation jobs for imports, replay, detection, ML actions, and exports. v3.7 adds safe maintenance tooling for stale jobs and old terminal job history. This does not delete raw logs, normalized logs, alerts, labels, audit records, response actions, ingestion runs, or detection runs.

Preview current job health and maintenance candidates:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.maintenance_jobs --dry-run --pretty
```

Preview stale jobs using a custom threshold:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.maintenance_jobs --dry-run --mark-stale-jobs --stale-after-minutes 60 --pretty
```

Explicitly mark stale active jobs as failed:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.maintenance_jobs --execute --mark-stale-jobs --stale-after-minutes 60 --pretty
```

Preview old terminal operation-job cleanup:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.maintenance_jobs --dry-run --cleanup-completed-jobs --older-than-days 30 --limit 100 --pretty
```

Explicitly delete old terminal operation-job rows only:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.maintenance_jobs --execute --cleanup-completed-jobs --older-than-days 30 --limit 100 --pretty
```

Retention-related settings in `.env.example` and `.env.lab.example`:

```text
JOB_STALE_AFTER_MINUTES=60
JOB_RETENTION_DAYS=30
RUN_HISTORY_RETENTION_DAYS=90
```

These settings are advisory by default. Normal backend startup does not perform cleanup.

## Safe Lab Scenario Runner

Dry run first:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --dry-run --use-sample-data --pretty
```

Run against the safe sample file without resetting current data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --use-sample-data --no-ml --pretty
```

Run against an explicit private log path only when intended:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --sample-path "$HOME\Downloads\paloalto-firewall.log" --limit 5000 --pretty
```

Optional destructive demo reset is explicit:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --reset-demo --use-sample-data --pretty
```

The runner never resets data unless `--reset-demo` is passed. It never imports private logs unless `--sample-path` is passed. Simulated response is skipped unless `--simulate-response` is passed.

The output includes import timing, detection timing, ML scoring timing when enabled, feature-generation timing, dashboard summary timing, top attack types, top source IPs, and audit presence.

## Import Logs Manually

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_logs "$HOME\Downloads\paloalto-firewall.log" --limit 5000
```

Real or large logs should stay outside Git. Do not place private logs in the repository root.

## Run Detection

Through API after login, or from the dashboard Demo Controls. For CLI-style local validation, use the optional lab scenario runner. Detection remains rule-first, and ML remains assistive.

## Live Syslog Local Test

Terminal 1:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

Terminal 2:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
```

Verify:

- Raw logs increased.
- Normalized logs increased.
- AI Governance Data Quality shows latest ingestion time.
- Investigation page can find the new rows.
- Detection can be run after ingestion.
- Overview > Log Sources shows a `syslog_udp:<sender-ip>` source with recent activity.

The UDP receiver is local/lab only. Do not bind it to `0.0.0.0` unless host firewall rules and network scope are approved.

## Log Source Management

ATDR v0.3 tracks optional log sources/sensors so a lab operator can tell whether a file import, replay source, or syslog sender is healthy. Normal file import still works without choosing a source. If no source is provided, ATDR uses the safe default source `local_import`.

Source records include:

- name and source type
- host and port when available
- enabled or disabled state
- last seen and last log received time
- logs received, parse success count, and parse failure count
- latest parser/source error
- health status: `healthy`, `idle`, `warning`, `error`, or `disabled`
- parser profile: `palo_alto`, `generic_syslog`, or `raw_fallback`

Register or update a lab source:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.register_log_source --name lab-firewall-1 --source-type firewall --parser-profile palo_alto --host 192.0.2.10 --port 514 --pretty
```

Register a UDP syslog source before local validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.register_log_source --name syslog-localhost --source-type syslog_udp --parser-profile palo_alto --host 127.0.0.1 --port 5514 --pretty
```

List sources through the API:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/sources -Headers @{ Authorization = "Bearer <token>" }
```

Source health logic:

- `healthy`: recent logs were received and parse failures are low.
- `idle`: no logs have arrived recently.
- `warning`: parse failures, latest parser error, or format mismatch need review.
- `error`: repeated parser failures indicate the sender/parser profile should be checked.
- `disabled`: an administrator disabled the source; historical data remains intact.

Disabling a source never deletes raw logs, normalized logs, alerts, labels, or audit records.

Filter logs by source:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/logs?source_name=lab-firewall-1" -Headers @{ Authorization = "Bearer <token>" }
```

Filter alerts or cases by source:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/alerts?source_name=lab-firewall-1" -Headers @{ Authorization = "Bearer <token>" }
Invoke-RestMethod "http://127.0.0.1:8000/api/alerts/cases?source_name=lab-firewall-1" -Headers @{ Authorization = "Bearer <token>" }
```

In React, use source filters in **Investigation / Log Explorer** and **Alert Workbench**. Click a source card in Overview to inspect source health, quality warnings, recent source-linked runs, and parser examples.

Run detection for one source only when validating source-specific replay:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/detection/run?limit=1000&use_ml=true&source_id=<source_id>" -Method Post -Headers @{ Authorization = "Bearer <token>" }
```

The unfiltered detection command remains unchanged. Source-scoped detection is optional and useful for confirming that recent replay or syslog activity from one lab source can be traced into source-linked detection run history.

## v3.0 Production-Readiness Track

v3.0 is the next hardening track after the final controlled academic prototype. It does not claim production readiness.

Run the stricter readiness doctor:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.production_readiness_doctor --pretty
```

Validate a real/lab source after logs have arrived:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v30_real_source_pilot_validation --source-name lab-firewall-real-1 --expected-min-logs 100 --window-minutes 60 --pretty
```

Run the stricter v3.5 read-only source/syslog pilot check:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v35_real_source_pilot_check --source-name lab-firewall-real-1 --expected-min-logs 100 --window-minutes 60 --pretty
```

Export safe pilot evidence as JSON. By default this prints to the terminal and does not write a file:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.export_real_source_pilot_evidence --source-name lab-firewall-real-1 --expected-min-logs 100 --pretty
```

Only when you intentionally need an ignored evidence artifact, add `--write`; output goes under ignored `demo_exports/real_source_pilot/` and includes IDs/counts rather than full private raw log contents:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.export_real_source_pilot_evidence --source-name lab-firewall-real-1 --expected-min-logs 100 --write --pretty
```

The v3.5 report distinguishes `source_pipeline_validated` from `real_device_forwarding_validated`. Replay, sample, scenario, demo, or test sources can validate the ATDR source pipeline but must not be presented as real hardware forwarding validation.

Validate optional PostgreSQL lab deployment on a PostgreSQL/Docker-capable host:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty
```

Audit database portability from any host:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.database_portability_audit --pretty
```

On a configured PostgreSQL host, include optional safe sample and smoke validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --include-smoke --include-sample-ingest --pretty
```

Run read-only real-source ML monitoring:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_real_source_ml_monitoring --pretty
```

Run the no-hardware source pilot when a real firewall/router is not available:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v32_no_hardware_source_pilot --pretty
```

Use these docs:

- `docs/V3_0_PRODUCTION_READINESS_TRACK.md`
- `docs/V3_0_REAL_DEVICE_SYSLOG_PILOT_PLAN.md`
- `docs/V3_5_REAL_SOURCE_SYSLOG_PILOT.md`
- `docs/V3_0_POSTGRESQL_LAB_DEPLOYMENT_VALIDATION.md`
- `docs/V3_0_OBSERVABILITY_AND_OPERATIONS_PLAN.md`
- `docs/V3_0_REAL_SOURCE_ML_MONITORING_PLAN.md`
- `docs/V3_1_PERFORMANCE_STABILIZATION_PLAN.md`
- `docs/V3_1_POSTGRESQL_PERFORMANCE_VALIDATION_PLAN.md`
- `docs/V3_2_NO_HARDWARE_SOURCE_PILOT.md`
- `docs/V3_3_POSTGRESQL_SHARED_LAB_READINESS.md`
- `docs/V3_3_BACKUP_RESTORE_AND_RETENTION_PLAN.md`
- `docs/V3_3_DOCKER_POSTGRES_LAB_RUNBOOK.md`

Response automation, real firewall blocking, production promotion, and model activation remain disabled.

## v0.7 Controlled Detection Quality Validation

ATDR v0.7 validates defensive detection quality with safe synthetic/replayed logs. This is controlled small-subnet/lab-scale validation, not production certification and not an offensive test.

Run the expectation-based suite against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_validation_suite --all --pretty
```

The suite reads `data/samples/scenarios/scenario_expectations.json`, imports each scenario, runs detection, compares actual results to expected outcomes, checks raw evidence preservation, checks evidence quality, verifies no response actions were created, and writes JSON/Markdown reports plus a risk-calibration report to ignored `demo_exports/detection_validation/`.

Current v0.7 scenarios:

- `normal_allowed_traffic`: clean allowed traffic, no high/critical alert.
- `normal_web_dns_quic_traffic`: routine web, DNS, and QUIC traffic, no noisy alert creation.
- `normal_high_volume_but_allowed_traffic`: approved moderate-volume business traffic below exfiltration threshold.
- `normal_repeated_same_service_traffic`: repeated allowed common-service access, no scan/beacon alert.
- `mixed_small_subnet_validation`: benign plus scan-like, brute-force-like, beacon-like, and odd rows in one source.
- `port_scan_like_traffic`: port-scan-style evidence from repeated ports.
- `brute_force_like_traffic`: repeated denied attempts against a service/authentication port.
- `malware_c2_like_beaconing`: repeated outbound destination behavior with risky/uncommon app context.
- `data_exfiltration_suspicion`: high outbound byte-volume pattern.
- `policy_violation_suspicious_app`: high-risk app and suspicious app characteristics.
- `ddos_or_connection_flood_like`: repeated connection flood-like behavior.
- `repeated_dedup_traffic`: repeated alert evidence updates occurrence count instead of creating endless duplicate alerts.
- `generic_syslog_mixed`: raw evidence preserved with limited generic parser fields.
- `malformed_raw_fallback`: raw evidence preserved and parser failures counted without crashing.

The Overview page reads the latest generated validation report through `/api/dashboard/validation-summary` and shows only safe metadata such as pass count and report filenames.

Only write validation rows to the current dashboard database when you intentionally want to inspect them in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_validation_suite --scenario port_scan_like_traffic --write-to-current-db --pretty
```

See `docs/V0_7_DETECTION_QUALITY_HARDENING.md` for the v0.7 scenario catalog, risk calibration behavior, and dashboard summary details.

## v0.8 Detection Generalization Validation

ATDR v0.8 checks whether detection behavior still holds when the safe scenario samples are varied. The suite generates synthetic defensive variants with shifted timestamps, safe IP changes, safe port changes, byte/session variation, and benign noise. It does not create offensive payloads, does not execute attacks, and does not create response actions.

Generate variants without importing them into the current dashboard database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.generate_detection_variants --scenario port_scan_like_traffic --variants 3 --pretty
```

Run the full generalization suite against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_generalization_suite --all --variants 5 --pretty
```

Reports are written to ignored `demo_exports/detection_generalization/`; generated variant files are written to ignored `demo_exports/detection_variants/`. The Overview page shows a compact latest generalization status with pass count and false-positive/false-negative counts.

Use current-database mode only when you intentionally want to inspect generated variants in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_generalization_suite --scenario port_scan_like_traffic --variants 2 --write-to-current-db --pretty
```

See `docs/V0_8_DETECTION_GENERALIZATION.md` for report interpretation, safety boundaries, and known limits.

## v0.9 Layered Detection Validation

ATDR v0.9 compares detection layers across controlled scenarios:

- `rules_only`
- `anomaly_only`
- `supervised_only`
- `hybrid`

Run the full layered validation suite against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_layered_detection_validation --all --variants 3 --pretty
```

The report explains what rules caught, where anomaly scoring contributed, where supervised SOC triage produced advisory signals, and how hybrid scoring combines the evidence. Reports are written to ignored `demo_exports/layered_detection/`. The Overview page shows a compact latest layered validation status.

Use current-database mode only when you intentionally want to inspect generated layered validation rows in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_layered_detection_validation --scenario port_scan_like_traffic --variants 1 --write-to-current-db --pretty
```

See `docs/V0_9_LAYERED_DETECTION_VALIDATION.md` for layer definitions, current results, and limitations.

## v1.0 End-to-End Workflow Validation

ATDR v1.0 validates the complete controlled SOC workflow: safe log ingestion, raw evidence preservation, parsing, source health, source-scoped detection, alert creation, **Why flagged?** explanation, investigation evidence links, case grouping, optional simulated response approval/denial, audit trail, and report generation.

Run the default end-to-end validation against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_e2e_workflow_validation --pretty
```

Exercise simulated response safety as part of the workflow:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_e2e_workflow_validation --scenario port_scan_like_traffic --simulate-response --pretty
```

Reports are written to ignored `demo_exports/e2e_validation/`. The default temporary database mode does not modify your current dashboard data. Only use current-database mode when you intentionally want the validation source, logs, alerts, and audit rows visible in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_e2e_workflow_validation --scenario port_scan_like_traffic --source-name e2e-dashboard-check --write-to-current-db --simulate-response --pretty
```

Dashboard verification:

1. Open Overview and confirm the **E2E Workflow** validation card is visible.
2. Check Log Sources for the validation source when current-database mode is used.
3. Open Alerts and confirm **Why flagged?**, evidence count, attack type, and source context are visible.
4. Open Investigation and filter by the validation source to inspect normalized rows and raw evidence.
5. Open Response & Audit and confirm simulated response attempts are audited when `--simulate-response` was used.
6. Confirm no automatic response or real firewall blocking occurred.

See `docs/V1_0_E2E_WORKFLOW_VALIDATION.md` for report fields, safety defaults, and limitations.

## v1.1 Detection Reliability And Benchmarking

ATDR v1.1 adds reliability and benchmarking reports around the existing controlled validation suites. Reports are written to ignored `demo_exports/detection_reliability/`.

Run the full v1.1 reliability baseline against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_reliability_baseline --pretty
```

Run a mapped CSV benchmark without committing the dataset:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_benchmark --csv-path C:\path\to\benchmark.csv --limit 1000 --pretty
```

Analyze controlled false positives/false negatives and risk calibration:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.analyze_detection_errors --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.calibrate_detection_risk --pretty
```

Generate ML/SOC triage reliability, drift, and stress reports:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_ml_reliability_report --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.monitor_detection_drift --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_stress_test --iterations 10 --pretty
```

The internal controlled benchmark manifest is:

```text
data/samples/benchmarks/internal_controlled_benchmark.json
```

The dashboard Overview page shows only compact reliability, benchmark, and drift indicators. Detailed evidence remains in reports. These reports do not execute real attacks, do not use offensive tooling, do not enable automatic response, do not perform real firewall blocking, and do not claim production readiness.

See `docs/V1_1_DETECTION_RELIABILITY_AND_BENCHMARKING.md`.

## v1.2 Realistic Benchmark And ML Strengthening

ATDR v1.2 separates larger benchmark-style data from the main local firewall-log database. Use it for public-style, synthetic, or approved benchmark CSVs. Do not commit benchmark CSVs, prepared snapshots, or generated reports.

Prepare a sanitized benchmark snapshot:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.prepare_benchmark_dataset `
  --input-csv "C:\path\to\benchmark.csv" `
  --mapping-config data\samples\benchmarks\example_firewall_mapping.json `
  --label-config data\samples\benchmarks\example_label_mapping.json `
  --limit 5000 `
  --sample-strategy balanced `
  --pretty
```

Run detection benchmark evaluation against the prepared snapshot:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_benchmark `
  --prepared-snapshot "demo_exports\benchmarks\benchmark_snapshot_<id>.json" `
  --detection-mode hybrid `
  --pretty
```

Run safe benchmark ML experiments without activating a model:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_benchmark_ml_experiment `
  --prepared-snapshot "demo_exports\benchmarks\benchmark_snapshot_<id>.json" `
  --split time `
  --test-size 0.3 `
  --pretty
```

Compare rule-only, anomaly-only, supervised-only, and hybrid behavior:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.compare_layered_benchmark_reliability `
  --prepared-snapshot "demo_exports\benchmarks\benchmark_snapshot_<id>.json" `
  --pretty
```

Outputs are ignored under `demo_exports/benchmarks/` and `ml_baseline_reviews/benchmark_ml_experiments/`. The dashboard shows only compact benchmark/readiness status. Benchmark metrics must not be described as production accuracy or mixed with local firewall-log metrics by default.

See `docs/V1_2_REALISTIC_BENCHMARK_AND_ML_STRENGTHENING.md`.

## v0.5 Controlled Replay Validation Archive

ATDR v0.5 uses controlled simulation and replay as the current validation path because real firewall/router hardware is not available yet. This validates source health, parser behavior, source-scoped detection, alert evidence, deduplication, case grouping, simulated response safety, and dashboard investigation flow. It does not validate real device forwarding or real firewall enforcement.

See `docs/V0_5_SIMULATION_DEMO_PLAN.md` for the advisor/demo script and scenario catalog. `docs/V0_5_REAL_SOURCE_VALIDATION_PLAN.md` is kept for future hardware validation.

Use this flow when proving ATDR can receive and investigate traffic from a controlled simulated lab source. It does not reset the database and it does not enable automatic response.

Validate a named source after replay/syslog activity:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_live_source --source-name lab-firewall-1 --source-type firewall --parser-profile palo_alto --duration 60 --run-detection --pretty
```

Useful flags:

- `--duration 0`: check current source state without waiting.
- `--require-activity`: fail validation if no new raw logs arrive during the validation window.
- `--run-detection`: run source-scoped detection and record alert/dedup counts.
- `--no-report`: skip writing the validation report.
- `--report-dir <path>`: write the report somewhere other than the default ignored report folder.

Export a source validation report without running detection:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.export_lab_validation_report --source-name lab-firewall-1 --pretty
```

Reports are written to:

```text
demo_exports/lab_validation_reports/
```

This folder is ignored by Git. A validation report includes source details, parser quality, ingestion and detection run summaries, alert and case summaries, response/audit summary, performance timings, and safety limitations. It explicitly states that response is simulated and ML is decision support only.

Recommended v0.5 dashboard verification:

1. Open Overview and confirm source health, latest ingestion run, latest detection run, and alert count are understandable.
2. Open the source detail drawer and inspect parser profile, quality warnings, parser errors, and recent runs.
3. Open Investigation, filter by source, and confirm raw/normalized evidence is visible.
4. Open Alerts, filter by source, and confirm evidence count, occurrence count, and **Why flagged?** are clear.
5. For repeated replay, confirm raw logs remain available while alerts deduplicate.
6. In Response & Audit, confirm response remains simulated, requires justification, and protected IP attempts are denied/audited.
7. In Admin / Settings, confirm External IAM remains not configured unless explicitly enabled later.

## Source Scenario Validation

ATDR includes small synthetic scenario files in `data/samples/scenarios/` for controlled source-aware validation. These files are safe examples, not private firewall logs.

Run every scenario against a temporary database when you want proof without touching current local data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario normal_allowed_traffic --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario repeated_dedup_traffic --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario brute_force_like_traffic --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario malware_c2_like_beaconing --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario data_exfiltration_suspicion --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario ddos_or_connection_flood_like --use-temp-db --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario generic_syslog_mixed --use-temp-db --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario malformed_raw_fallback --use-temp-db --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario policy_violation_suspicious_app --use-temp-db --run-detection --pretty
```

Expected outcomes:

- `normal_allowed_traffic`: imports and parses clean allowed traffic; no high or critical alerts should be created.
- `port_scan_like_traffic`: creates at least one suspicious/port-scan-style alert when detection runs.
- `repeated_dedup_traffic`: imports and detects the same pattern twice; raw evidence is preserved, while matching active alerts should update `occurrence_count` instead of flooding the queue.
- `brute_force_like_traffic`: creates a brute-force-like service-attempt alert from repeated denied service traffic.
- `malware_c2_like_beaconing`: creates a C2/beaconing-style alert from repeated outbound uncommon/risky app behavior.
- `data_exfiltration_suspicion`: creates a high outbound data-transfer alert.
- `ddos_or_connection_flood_like`: creates a connection flood-style alert from repeated same-target connections.
- `generic_syslog_mixed`: preserves raw evidence and minimal syslog wrapper fields; source health may show warning because firewall-specific fields are limited.
- `malformed_raw_fallback`: preserves raw evidence, counts parser failures, and does not crash.
- `policy_violation_suspicious_app`: creates at least one suspicious/policy-style alert from high app risk and suspicious app characteristics.

Dry-run a scenario without writing rows:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario malformed_raw_fallback --dry-run --pretty
```

Run a scenario against the current local database only when you intentionally want it visible in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name scenario-lab-firewall-1 --source-type firewall --parser-profile palo_alto --run-detection --pretty
```

Dashboard validation:

1. Open Overview and confirm the source appears in **Log Sources**.
2. Open the source detail drawer and check health, parser profile behavior, quality warnings, recent ingestion runs, and recent detection runs.
3. Filter **Investigation** by source and confirm raw evidence can be inspected.
4. Filter **Alerts** by source and open the alert evidence panel.
5. For repeated traffic, confirm `occurrence_count`, `related_log_count`, and dedup counts increase while raw logs remain available.
6. For generic/raw fallback traffic, treat warnings as parser-profile signals, not data loss.

If a scenario fails, check the runner's `expected_outcome.checks` output first. Then inspect source health, parser error examples, and whether detection was run with `--run-detection` for alert-producing scenarios.

## Controlled Real Syslog Lab Flow

For a real firewall/router lab test, keep the receiver bound to localhost until the host firewall and network scope are approved. For a device on the same lab network, configure the device to forward syslog to the ATDR host IP and approved UDP/TCP port. Vendor-specific forwarding screens differ, so treat the following as generic guidance:

1. Start the backend normally.
2. Start the UDP receiver:

   ```powershell
   .\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
   ```

3. Validate the path locally before using a device:

   ```powershell
   .\.venv\Scripts\python.exe -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
   ```

4. Open React at `http://127.0.0.1:5173`.
5. Check Overview > Log Sources for a healthy or recently active source.
6. Check Investigation for the received raw and normalized log rows.
7. Run detection and verify alerts/cases update.
8. If the source is idle, confirm sender IP, receiver bind address, port, host firewall rules, and whether the device is sending UDP or TCP.
9. If the source is warning/error, inspect parse failure examples and confirm the parser profile matches the sender format.

TCP syslog and vendor-specific forwarding validation are future lab work unless explicitly configured and approved.

## Parser Profile Readiness

ATDR currently supports these parser-profile behaviors:

- Palo Alto syslog CSV: splits syslog timestamp and hostname first, then parses the Palo Alto CSV payload with `csv.reader`.
- Generic syslog: preserves the original raw line and minimal syslog wrapper/message metadata with a warning that normalized firewall fields are limited.
- Raw fallback: preserves the original raw line, marks a parser error, and keeps the row available for evidence review when the format is unknown.
- Unknown or incomplete Palo Alto fields: stores known normalized fields, stores the full parsed payload in `parsed_json`, and records missing-field warnings.

Parser failures are operational signals, not data loss. Raw evidence is always preserved.

## Safe Log Replay Mode

Replay mode simulates near-real-time ingestion from a sample log file. It never resets the database. Dry-run mode parses only and does not send syslog packets or write database rows.

Dry-run against the safe demo sample:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
```

Replay the safe sample to the local UDP syslog receiver:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to syslog --host 127.0.0.1 --port 5514 --limit 20 --rate 2 --pretty
```

Replay directly through the local import service when you do not want to run the UDP receiver:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to direct --limit 20 --rate 0 --pretty
```

Replay directly as a specific lab firewall source:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to direct --source-name lab-firewall-1 --source-type firewall --source-host 192.0.2.10 --source-port 514 --parser-profile palo_alto --limit 100 --rate 1 --pretty
```

Replay directly and run detection afterward:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to direct --limit 20 --rate 0 --run-detection --pretty
```

Replay directly as a named source and run source-linked detection afterward:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to direct --source-name lab-firewall-1 --source-type firewall --parser-profile palo_alto --limit 100 --rate 0 --run-detection --pretty
```

Replay a real/private log only when you explicitly provide the path:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --sample-path "$HOME\Downloads\paloalto-firewall.log" --send-to syslog --limit 100 --rate 1 --pretty
```

Keep real and large logs outside Git.

## Near-Real-Time Ingestion Validation Flow

1. Start the backend normally.
2. If testing UDP, start the receiver:

   ```powershell
   .\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
   ```

3. Replay safe logs using `replay_logs`.
4. Open React at `http://127.0.0.1:5173`.
5. Verify Overview > System Health and Ingestion Quality Snapshot:
   - latest raw log time changed
   - latest normalized log time changed
   - parse success count increased
   - parse failure count remains explainable
   - source health changed from idle to healthy or warning
6. Open Investigation and search for the replayed source IP or destination port.
7. Filter Investigation by the source name or source status.
8. Run detection from Demo Controls or API.
9. Verify Alerts show related evidence and can be filtered by source.
10. Verify Active Case Grouping shows related alert/log counts, top destination ports, top actions, and recommended analyst focus.
11. Verify Audit Log contains import/syslog/detection activity.

Repeated replay is expected to preserve every raw log as evidence while deduplicating matching active alerts into occurrence counts instead of flooding the queue.

## Run History Checks

ATDR records lightweight run history for ingestion/import/replay/syslog work and detection work.

List latest ingestion runs:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/ingestion/runs -Headers @{ Authorization = "Bearer <token>" }
```

List latest detection runs:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/detection/runs -Headers @{ Authorization = "Bearer <token>" }
```

List latest long-running operation jobs:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/jobs -Headers @{ Authorization = "Bearer <token>" }
```

List the compact job health summary:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/jobs/summary -Headers @{ Authorization = "Bearer <token>" }
```

The React Overview page shows a compact **Operations Health** panel with:

- latest ingestion run status
- latest detection run status
- latest operation job status
- active and stale job counts
- parser failures
- deduplicated alert count
- alert creation count
- runtime duration

ATDR v3.6 tracks long-running dashboard and CLI operations in `operation_jobs`. v3.7 adds explicit stale-job and old terminal job maintenance. This is a synchronous lab-safe status trail, not a Celery/Redis worker queue. Direct replay writes a job record when it imports logs; replay dry-run remains read-only and does not write job history.

Run history source names use safe labels such as filenames or `udp:host:port`; private full paths are not exposed in API output.

## Alert Deduplication Behavior

ATDR v0.2 deduplicates live/replayed alert noise by updating an active matching alert when these fields line up inside a short window:

- alert type/rule
- source pattern
- destination pattern
- destination port/service pattern
- event-time window

Deduplication updates the existing alert metadata:

- `occurrence_count`
- `related_log_count`
- first seen / last seen
- sample sources and destinations
- destination ports
- actions and protocols

Raw logs are never deleted. New evidence log IDs are linked to the existing alert, and an `alert_deduplicated` audit event is recorded.

Interpretation:

- `alerts_created`: new SOC alert groups created during the run.
- `alerts_deduplicated`: active alert groups updated instead of creating duplicates.
- `alerts_suppressed`: low-volume or explicitly suppressed groups.
- `occurrence_count`: repeated matching activity represented in one alert.
- `related_log_count`: distinct evidence logs linked to the alert.

## Performance Smoke

Run the read-only performance smoke report:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --feature-limit 20 --pretty
```

This does not import logs, reset data, run detection, score ML, or perform response actions. It times Overview summary, Operations Health run-history queries, alert list, case grouping, ML Governance lightweight summary, supervised report loading, and feature-generation reads.

Local lab budgets:

- Overview application-cache miss: median at most `2s` and p95 at most `3s` on the current large local SQLite profile.
- Overview warm cache hit: at most `0.05s`.
- ML Governance lightweight summary: ideally under `2s`.
- Heavy supervised report/export: acceptable up to a few seconds because it is an explicit governance/reporting action.

If a timing warning appears, run the five-pass v4.7 profiler and review its query plans before changing cache TTL or adding indexes. Do not prewarm or lengthen TTL to hide an uncached regression. For larger/shared datasets, prefer PostgreSQL lab mode and keep ML Governance on the default cached view; use **Refresh ML Summary** after training, scoring, or label import.

Parser-error example extraction is intentionally lightweight for large local datasets. Full raw evidence is still retained and can be inspected through Log Explorer or specific alert/log details.

## Parser Failure Troubleshooting

Parser failures are preserved as raw evidence and visible in Overview/AI Governance data-quality panels.

Common causes:

- blank lines
- missing syslog timestamp / hostname / payload wrapper
- malformed CSV payload
- incomplete Palo Alto payload
- missing source IP, destination IP, action, or timestamp
- unknown or incomplete application values

For a bad row, inspect the parser error example, then compare it with the expected syslog wrapper:

```text
<syslog_timestamp> <hostname> <Palo Alto CSV payload>
```

## Triage And Simulated Response

1. Open Alerts.
2. Select an alert.
3. Review why flagged, evidence logs, ATT&CK-style mapping, and behavior-window evidence.
4. Assign to yourself or mark `Investigating`.
5. Add an analyst note.
6. Use simulated block only when evidence exists and the target is not protected internal infrastructure.
7. Confirm the action.
8. Open Response & Audit or Audit Trail and verify actor, action, target, and reason.

Response actions remain simulated. ATDR records denied response attempts too.

## Optional PostgreSQL/Docker Lab Workflow

Use this only on a Docker-capable host:

```powershell
Copy-Item .env.lab.example .env
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
docker compose --profile postgres up -d postgres
docker compose --profile postgres run --rm migrate
docker compose --profile postgres up --build api dashboard
.\.venv\Scripts\python.exe -m atdr.scripts.lab_smoke_check
```

Docker/PostgreSQL is not required for normal local testing.

If the backend starts but login fails with `Database unavailable` or the log says `could not translate host name "postgres"`, `.env` is probably using the optional PostgreSQL lab profile outside Docker. For the normal local workflow, switch back to SQLite:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.use_local_sqlite_config --dry-run --pretty
```

If the dry-run output looks correct, write the local profile:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.use_local_sqlite_config --write --pretty
```

The helper preserves a backup under ignored `.tmp/env-backups/` and does not reset or delete the database.

## Optional Reset And Seed

Do not reset the current local database unless you intend to clear demo data.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.reset_demo --yes --path data/samples/paloalto-demo.txt --limit 5000
```

Use `--yes` only when you understand it clears local demo data.

## Troubleshooting

- API health check failed: confirm uvicorn is running on port `8000`.
- React shows failed fetch: confirm `VITE_API_BASE_URL` points to `http://127.0.0.1:8000`.
- Login fails: run `python -m atdr.scripts.seed_users`. If the error is `Database unavailable`, check `DATABASE_URL` with `python -m atdr.scripts.config_doctor --pretty`.
- Config Doctor warns about demo JWT secret: expected in local demo, unsafe for lab/prod.
- Config Doctor warns about missing sample path: set `DEMO_SAMPLE_LOG_PATH` in private `.env` or use `data/samples/paloalto-demo.txt`.
- Syslog test receives nothing: confirm receiver is running before sender and that both use the same host/port.

## Safety Rules

- Do not enable automatic response.
- Do not claim certified production readiness.
- Do not commit real logs, DB files, model artifacts, generated CSV/reports, `.env`, `ml_baseline_reviews/`, or `demo_exports/`.

## v1.3 Reviewed-Label Validation

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.audit_training_data_quality --split time --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.generate_v13_label_target_plan --split time --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.export_v13_ai_training_review_sample --limit 500 --focus balanced --pretty
```

Review and import the CSV through React AI Governance. Then run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.train_v13_supervised_candidates --split time --test-size 0.3 --min-samples 6 --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.analyze_v13_ml_errors --split time --test-size 0.3 --min-samples 6 --pretty
```

All outputs stay under ignored `ml_baseline_reviews/`. No candidate is activated and response automation remains disabled.

## v1.4 Low-Noise SOC Queue Validation

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v14_false_positive_reduction --split time --test-size 0.3 --min-samples 6 --review-limit 200 --pretty
```

Review the generated comparison and calibration reports under ignored `ml_baseline_reviews/`. The command does not activate a model. AI Governance reads only the latest lightweight report summary and continues to show decision-support and automation-disabled status.

## v1.4b Actionable QUIC Review

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v14b_false_positive_mitigation --split time --test-size 0.3 --min-samples 6 --review-limit 200 --pretty
```

Review `ml_baseline_reviews/v1_4b_actionable_false_positive_review_sample.csv`, fill the human-review columns, and import it through React AI Governance. The default file excludes protected manual labels. No candidate is activated by the command or by CSV import.

## v1.4c Malicious Recall And Calibration Validation

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v14c_malicious_recovery --split time --test-size 0.3 --min-samples 6 --review-limit 150 --pretty
```

Use this after v1.4b review import. It checks whether malicious recall can recover while keeping benign-like false positives at or below `0.15`, verifies that QUIC mitigation does not suppress strong threat evidence, compares confidence calibration methods, and optionally exports `ml_baseline_reviews/v1_4c_malicious_recall_review_sample.csv`.

All v1.4c outputs are ignored. The runner does not write or activate a model artifact and cannot enable response automation.

## v1.5 Internal AI Readiness Benchmark

The v1.5 manifest builds a safe 240-row benchmark with normal, near-boundary, suspicious, malicious, and limited-context traffic. It uses synthetic reserved addresses and never executes attacks.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.build_internal_ai_readiness_benchmark --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v15_ai_readiness_validation --pretty
```

Verify the concise result in React AI Governance. Detailed generated evidence remains under ignored `demo_exports/benchmarks/` and `ml_baseline_reviews/`.

Interpret `benchmark_validated_candidate` as internal benchmark evidence for analyst review only. Production promotion, model activation, automatic response, and real firewall blocking remain disabled.

## v1.6 Unseen Holdout Validation

Run the fixed safe holdout from the repository root:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.build_fixed_unseen_holdout --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_external_benchmark_validation --holdout-from-current-data --pretty
```

The holdout contains 320 synthetic labeled rows across five source names and 14 scenarios. Despite the historical switch name, no private current-database rows are copied.

Verify the concise status in Overview and AI Governance. Detailed transfer, calibration, per-attack, false-positive, false-negative, and overfitting evidence remains under ignored `demo_exports/benchmarks/`.

The current holdout exposes a significant generalization gap, so the correct interpretation is `internal_benchmark_validated_candidate`. Do not activate the candidate or describe internal benchmark metrics as deployment accuracy.

## v1.7 External Generalization Improvement

Run the external profile comparison and boundary review export:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v17_external_generalization --review-limit 300 --pretty
```

The v1.7 pass compares lower-noise, suspicious-recall, calibrated, hybrid, three-class, and hierarchical external profiles. It writes an external error-analysis report and exports `ml_baseline_reviews/v1_7_external_boundary_review_sample.csv` for analyst review.

Current v1.7 evidence lowers benign false positives and improves suspicious recall on the unseen holdout, but calibration and external-readiness checks remain conservative. Production promotion, model activation, automatic response, and real firewall blocking remain disabled.

### Importing Reviewed v1.7 Benchmark Rows

The v1.7 boundary file uses `benchmark_row_id`, so it must not be sent to the normal reviewed-label importer.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_benchmark_review_csv `
  --input-csv "C:\path\to\v1_7_external_boundary_review_sample_REVIEWED.csv" `
  --benchmark-kind external_holdout `
  --pretty
```

Apply those reviews during external validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_external_benchmark_validation `
  --holdout-from-current-data `
  --reviewed-benchmark-csv "C:\path\to\v1_7_external_boundary_review_sample_REVIEWED.csv" `
  --pretty
```

The React AI Governance page exposes a separate **Import Benchmark Review CSV** action. Benchmark artifacts remain ignored and separate from `ml_labels`.

## v1.8 External Benchmark Finalization

After reviewed v1.7 benchmark labels have been applied, run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v18_external_benchmark_finalization --pretty
```

Verify in React AI Governance:

1. External profile is `external_recall_plus`.
2. Threat F1, threat recall, suspicious recall, malicious recall, and benign FPR
   are visible.
3. Calibration shows the selected method and status.
4. Readiness says `external_benchmark_validated_candidate`.
5. Decision Support Only and Response Automation Disabled remain visible.

Detailed reports remain under ignored `demo_exports/benchmarks/`. The external
holdout is reviewed and separate from local firewall labels, but it is still a
synthetic benchmark. Run a new independent holdout and controlled real-source
validation before making deployment claims.

## v1.9 Independent And Controlled Source Validation

Generate the separate v1.9 holdout:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.build_independent_holdout --pretty
```

Exercise Palo Alto-style replay, generic syslog, raw fallback, deduplication,
source health, alert evidence, cases, protected-IP denial, and audit behavior in
temporary SQLite databases:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_controlled_real_source_validation --pretty
```

Then run independent profile revalidation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v19_independent_revalidation --pretty
```

The controlled source command does not write to the current local database. Its
explicit response check remains simulated and analyst-approved. It is not a
real router/firewall forwarding certification.

Review the compact v1.8 external, v1.9 independent, controlled-source, readiness,
calibration, and blocker indicators in Overview and AI Governance. Detailed
reports remain under ignored `demo_exports/benchmarks/`.

## v1.9b FPR Stabilization Check

After v1.9 independent and controlled-source validation, run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v19b_independent_fpr_stabilization --pretty
```

Verify in Overview and AI Governance:

1. profile is `independent_fpr_stabilized`;
2. benign-like FPR is at or below `0.15`;
3. suspicious and malicious recall remain above their safety thresholds;
4. ambiguous boundary rows are shown as analyst-review work;
5. controlled-source validation remains passed;
6. Decision Support Only, Response Automation Disabled, and Not Production
   Promoted remain visible.

The stabilization rule does not use source/scenario names and does not suppress
behavior-window evidence. A fresh future holdout and real hardware forwarding
test remain recommended.

## v2.0 Final Controlled Validation

Run the frozen-candidate sequence from the repository root:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.lock_v20_candidate --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.build_fresh_blind_holdout --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v20_fresh_blind_revalidation --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_final_controlled_source_acceptance --pretty
```

Expected current status:

- fresh blind holdout: passed without tuning;
- final controlled source acceptance: passed;
- readiness v8: `final_controlled_validation_candidate`;
- response mode: simulated and analyst-approved;
- production promotion/model activation/real blocking: disabled.

The controlled source workflow uses temporary databases and does not change the
current dashboard database. Real router/firewall forwarding remains future
hardware validation.

See `docs/FINAL_ENGINEERING_VALIDATION_SUMMARY.md`.

## v3.92 Operations Observability

### Health checks

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health/live
Invoke-RestMethod http://127.0.0.1:8000/health/ready
```

`/health/live` proves only that the API process responds. `/health/ready` also checks the database, Alembic revision, and runtime safety configuration; it returns `503` when any required dependency is not ready. It never returns credentials or connection strings.

To inspect low-cardinality local metrics:

```powershell
Invoke-WebRequest http://127.0.0.1:8000/metrics | Select-Object -ExpandProperty Content
```

Metrics intentionally omit request IDs, paths, users, email addresses, IP addresses, file names, raw logs, and secrets. Admin users can inspect the safe detailed status at `GET /api/operations/health`.

### Operation worker

The API does not start a worker. Process at most one queued job:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --once --pretty
```

Persistent watch mode must be explicitly enabled in the private environment:

```powershell
$env:OPERATION_WORKER_ENABLED="true"
.\.venv\Scripts\python.exe -m atdr.scripts.run_operation_worker --watch --pretty
```

Use only one worker with SQLite. A second fresh worker is rejected. v3.94 adds the PostgreSQL concurrency contract and isolated CI drills; environment-backed validation still requires a successful remote CI or approved-host run.

### Audit retention report

Review only; this is the normal command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.audit_retention --pretty
```

Do not apply retention casually. Applying one bounded batch requires `--apply --confirm APPLY-AUDIT-RETENTION`. IAM, authentication, account, verification, denied, response, and block/unblock events are protected, and raw log evidence is never considered by this tool.

### Troubleshooting readiness

- `database status=error`: inspect `DATABASE_URL` without posting its value and make sure the configured service is running.
- `migration status=not_at_head` or `unversioned`: run `.\.venv\Scripts\alembic.exe upgrade head`, then retry readiness.
- `configuration issue_count > 0`: run `.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty`. An enabled but incomplete MFU IAM profile intentionally keeps readiness false.
- `worker_unavailable`: start the explicit worker only if queued background work is intended.
- `queue_backlog`: inspect the Operations Health job list before starting or restarting a worker; do not delete evidence to clear a queue.
- `repeated_job_failures`: inspect the latest failed job summary and logs using its request/job correlation, then correct the input/configuration cause.

## v3.95 Deployment Operations Validation

These commands are optional deployment checks. They do not change the normal local backend/frontend commands.

Validate committed deployment references and safety policy:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_deployment_operations --pretty
```

Preview the read-only load plan:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.load_test_readonly --pretty
```

Execution uses GET only. Provide a short-lived bearer token in `ATDR_LOAD_TEST_BEARER_TOKEN`, use `--execute`, and remove the variable afterward. Remote targets also require `--allow-remote --confirm READ_ONLY_REMOTE_LOAD_TEST`. Never put a token on the command line or in Git.

Verify the newest configured backup without restoring:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.verify_latest_backup --pretty
```

Run the isolated recovery exercise:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_disaster_recovery_drill --execute --confirm ISOLATED_V395_DRILL --pretty
```

The exercise creates and restores only disposable databases under ignored `.tmp` storage. It validates checksum, integrity, table counts, and Alembic revision and refuses active-database overwrite.

Deployment references:

- Nginx/HTTPS: `deploy/nginx/README.md`
- Prometheus/alerts: `deploy/monitoring/README.md`
- API/worker/timers: `deploy/systemd/README.md`
- managed secrets: `deploy/secrets/README.md`
- complete recovery and drain procedure: `docs/V3_95_DEPLOYMENT_SECURITY_MONITORING_AND_RECOVERY.md`

RPO 24 hours and RTO 4 hours are planning assumptions only. Do not present them as measured guarantees until an approved PostgreSQL deployment drill records timing evidence.

## v3.96 Preproduction Acceptance Preflight

The v3.96 preflight is safe to run locally and makes no database connection by default:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v396_preproduction_preflight --pretty
```

Missing Linux, PostgreSQL, DNS, TLS, staging, Prometheus, managed-secret, or MFU handoff checks mean the environment is incomplete; they do not mean the local SQLite application failed.

On an approved host only, add the exact read-only probe confirmation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v396_preproduction_preflight --probe-database --confirm READ_ONLY_V396_PREPRODUCTION_PREFLIGHT --require-accepted --pretty
```

For a local GET-only load sample, keep the short-lived token in `ATDR_LOAD_TEST_BEARER_TOKEN` and optionally observe internal metrics with `--metrics-url http://127.0.0.1:8000/metrics`. Remove the token immediately afterward. Remote load also requires `--allow-remote --confirm READ_ONLY_REMOTE_LOAD_TEST` and prior target approval.

The current private configuration enables MFU IAM without completing B2B or secure-handoff requirements. For normal local SQLite use, temporarily set `MFU_IAM_ENABLED=false`; otherwise complete the private v3.91 handoff fields. Never post their values. See `docs/V3_96_PREPRODUCTION_DEPLOYMENT_REHEARSAL.md` and `docs/V3_96_OPERATIONAL_ACCEPTANCE_CHECKLIST.md`.

## v4.0 Provider-Blinded External Validation

The v4.0 evaluator is a diagnostic research command, not a normal startup step. It requires the two verified official CSE-CIC-IDS2018 files documented in `docs/V4_0_PROVIDER_BLINDED_EXTERNAL_EVIDENCE_AND_FROZEN_VALIDATION.md` beneath ignored `.tmp/external_evidence/cse_cic_ids2018/`.

Run it only against a migrated disposable database:

```powershell
$env:DATABASE_URL='sqlite:///C:/path/to/disposable-validation.sqlite3'
.\.venv\Scripts\python.exe -m atdr.scripts.run_v400_provider_blinded_external_validation --rows-per-file 2000 --seed 400 --summary-only --pretty
```

Expected protocol evidence:

- provider sizes and SHA-256 values verified;
- feature sample excludes `Label`;
- prediction artifact is written and hashed before labels are reopened;
- external fit/calibration/threshold rows are `0/0/0`;
- provider labels remain non-human and non-importable;
- no database/model/response side effect occurs;
- readiness remains `candidate_only`.

The current frozen candidate fails the external benign-FPR gate. Do not tune against the v4.0 labels and do not present the result as production accuracy.

## v4.1 Schema-Aware SOC Queue Development Validation

v4.1 is a diagnostic research command, not a normal dashboard workflow. It uses a separate verified CSE-CIC-IDS2018 development corpus, locks the v4.0 final benchmark by name and SHA-256, and must run only against a migrated disposable database. It does not write labels, active model artifacts, detection runs, response actions, or raw operational evidence.

```powershell
$env:DATABASE_URL='sqlite:///C:/path/to/disposable-validation.sqlite3'
$env:MFU_IAM_ENABLED='false'
$env:ASSISTANT_LLM_ENABLED='false'
.\.venv\Scripts\python.exe -m atdr.scripts.run_v401_schema_aware_soc_queue --rows-per-provider-label 3000 --seed 401 --summary-only --pretty
```

Required ignored development files belong under `.tmp/development_corpus/cse_cic_ids2018_v41/`. The command fails closed if checksums differ, a v4.0 locked artifact is supplied for development, or the reserved future benchmark is used. Treat its results as candidate-only: v4.1 random-split metrics are not a production claim because calibration and time/source/schema-held-out stability remain weak.

## v4.2 SOC Assistant Presentation Check

The SOC Assistant retrieves bounded structured context from ATDR services and displays the returned records/documentation under **Grounded In**. Gemini is an optional wording and summarization layer; it is not the detector or database source.

Safe provider checks do not print the key:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --execute --pretty
```

Use `--execute` only when the private `.env` intentionally enables a supported provider. Expected safety fields are `raw_log_context_allowed=false`, `raw_log_context_included=false`, `redaction_enabled=true`, and `secrets_exposed=false`. Provider failure must leave the Local Evidence Assistant available.

Manual workflow:

1. Open **SOC Assistant** and ask about an existing alert ID.
2. Confirm concise Summary, Why flagged / evidence, Analyst next steps, Safety, and Grounded In sections.
3. Click a follow-up and verify the same alert remains active.
4. Navigate to another page and return; the question and answer should remain without another provider request.
5. Use **Clear context** before starting a different investigation.
6. Confirm no response-action, detection, label, model, account, deletion, or firewall control is present.

The browser snapshot is tab/session scoped and stores only whitelisted rendered fields. It excludes raw-log context, secrets, tokens, and arbitrary technical payloads. Logout and session expiry clear it. See `docs/V4_2_PRESENTATION_READY_SOC_ASSISTANT.md`.

## v4.8 End-to-End Product Acceptance

Use this command to validate the integrated product workflow without touching the configured database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v48_product_acceptance `
  --use-temp-db `
  --log-count 50000 `
  --simulate-interruption `
  --run-detection `
  --test-assistant `
  --test-backup-restore `
  --pretty
```

Expected high-level result:

- `ok=true` and no failed checks;
- exact raw/normalized counts equal to `--log-count`;
- three intentional raw-fallback parser failures with raw evidence preserved;
- interruption and cancellation resume checks pass;
- one source-scoped `possible_port_scan` alert is deduplicated to 20 occurrences and 20 related logs;
- a source-traceable case and `Why flagged?` explanation are available;
- assistant follow-up context, citations, IP redaction, and deterministic provider-failure fallback pass;
- response actions, labels, model runs, and users remain zero;
- backup checksum/count/revision restore checks pass against a separate disposable target;
- `current_database_unchanged=true` and `temp_artifacts_removed=true`.

The command refuses to run without `--use-temp-db`. It disables external IAM, SMTP, and LLM calls inside the acceptance runtime and does not change normal startup commands. The generic-router warning and raw-fallback error are expected data-quality evidence, not infrastructure failures. See `docs/V4_8_END_TO_END_PRODUCT_ACCEPTANCE.md`.
