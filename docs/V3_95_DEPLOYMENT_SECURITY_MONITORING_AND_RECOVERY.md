# v3.95 Deployment Security, Monitoring, And Recovery Operations

## Status

v3.95 adds controlled shared-deployment references and validators around the existing ATDR runtime. It does not make PostgreSQL, Docker, Nginx, Prometheus, or systemd mandatory for normal local use, and it does not claim production readiness.

The normal local commands remain unchanged:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm.cmd run dev
```

Response remains simulated and analyst-approved. The SOC Assistant remains read-only. Real firewall blocking, automatic response, and ML model activation remain disabled.

## Implemented Controls

### Deployment Edge

- `deploy/nginx/atdr.conf.example` terminates HTTPS, redirects HTTP, applies secure headers, limits request size, uses bounded proxy timeouts, supports protocol upgrades, and restricts `/metrics` to the local host.
- The managed API example binds Uvicorn to loopback and uses `--no-proxy-headers`.
- ATDR honors `X-Forwarded-For` and `X-Forwarded-Proto` only when `TRUST_PROXY_HEADERS=true` and the direct peer belongs to `TRUSTED_PROXY_CIDRS`.
- The Nginx reference overwrites the forwarded client chain with its direct client address. It does not append an untrusted inbound chain.
- Trusted proxy handling is disabled by default, preserving localhost development behavior.

Reference deployment values belong in a private host environment:

```text
TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
RESPONSE_SIMULATION=true
ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false
```

Do not enable proxy trust for a broad network. If Nginx runs on another host, approve only that proxy's exact address or narrow network.

### Monitoring And Alerts

`deploy/monitoring/prometheus.yml.example` and `deploy/monitoring/atdr-alerts.yml` provide optional external collection and rules for:

- target and API readiness;
- database availability;
- unsafe runtime configuration;
- unexpected response-simulation disablement;
- durable queue backlog;
- stale operation workers;
- repeated job failures;
- recent ingestion/parser failures;
- recent detection failures;
- staged-input capacity pressure.

Metrics contain bounded method/status, job type/state, and outcome dimensions. They intentionally exclude users, email addresses, IP addresses, request IDs, paths, file names, raw logs, tokens, and secrets. Prometheus persistence, Alertmanager routing, and paging ownership still require an approved deployment environment.

### Scheduled Safe Maintenance

Example systemd timers under `deploy/systemd/` schedule only non-destructive reporting:

- runtime readiness check;
- audit-retention dry run;
- staged-input cleanup dry run;
- latest-backup verification.

No scheduled unit contains `--apply`, `--execute`, or a destructive confirmation phrase. Applying retention or cleanup remains an explicit operator action after reviewing the report. Raw log evidence is never a cleanup target.

### Managed Secrets

`deploy/secrets/README.md` defines secret classes, owners, rotation triggers, startup behavior, and failure expectations for JWT signing, database credentials, MFU handoff, external LLM, SMTP, and TLS material. Values are never placed in committed examples or status responses.

Private deployment secrets must come from a restricted environment file or managed secret service. Rotation must use an overlap or maintenance procedure appropriate to the secret. A missing required secret must fail closed instead of silently enabling an unsafe fallback.

## Read-Only Load Test

Preview the bounded GET-only plan:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.load_test_readonly --pretty
```

To execute against a running local API, place a short-lived analyst/admin token only in the current process environment:

```powershell
$env:ATDR_LOAD_TEST_BEARER_TOKEN="<short-lived-token>"
.\.venv\Scripts\python.exe -m atdr.scripts.load_test_readonly --execute --base-url http://127.0.0.1:8000 --requests-per-endpoint 5 --concurrency 4 --pretty
Remove-Item Env:\ATDR_LOAD_TEST_BEARER_TOKEN
```

The harness sends only GET requests to liveness, readiness, Overview, alerts, cases, sources, operations, and assistant status. It does not report response bodies or the token. Remote targets require both `--allow-remote` and the exact confirmation phrase `READ_ONLY_REMOTE_LOAD_TEST`.

### Local Evidence

On 2026-07-13, a controlled run against the current large SQLite database completed 24 authenticated/public GET requests with:

- successes: 24;
- error rate: 0;
- throughput: 14.973 requests/second;
- performance warnings: none;
- Overview p95: 1.2355 seconds;
- alerts p95: 0.2391 seconds;
- cases p95: 0.4005 seconds;
- operations p95: 0.2322 seconds;
- readiness p95: 0.1735 seconds.

This is a small local smoke workload, not a capacity limit, SLA, or production certification. Write-load tests are not supported by this command. Any future write test must use an explicitly isolated disposable database and a separate approved design.

## Backup Verification And Recovery Drill

Verify only the latest configured backup and manifest:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.verify_latest_backup --pretty
```

The verifier checks manifest shape, artifact name, existence, size, SHA-256, timestamp/freshness, Alembic revision, and recorded table-count coverage. It does not restore or mutate a database.

Preview the disaster-recovery drill:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_disaster_recovery_drill --pretty
```

Execute only the built-in isolated SQLite drill:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_disaster_recovery_drill --execute --confirm ISOLATED_V395_DRILL --pretty
```

The drill migrates a synthetic source database, creates a backup and manifest, validates its checksum, restores to a separate empty target, and compares integrity, table counts, and Alembic revision. It refuses to restore over the configured database.

Local isolated evidence passed with migration, backup, checksum, restore integrity, row-count match, and revision match all true. The configured database fingerprint remained unchanged.

The final read-only performance smoke also passed with no warnings: Overview `0.4319s`, cached Overview `0.0061s`, ML Governance `1.1984s`, alerts `0.0318s`, cases `0.0361s`, and operation-job summary `0.0062s`.

## Recovery Objectives

Current planning assumptions are:

- RPO: 24 hours, based on an intended daily verified backup schedule;
- RTO: 4 hours, allowing diagnosis, environment provisioning, isolated restore validation, service deployment, and controlled reopening.

These are design assumptions, not measured or contractually certified objectives. A shared deployment must run timed drills with its actual PostgreSQL volume, backup storage, secret service, and responsible operators before adopting them.

## API And Worker Drain Procedure

1. Announce a controlled maintenance window and stop accepting new mutating work at the deployment edge.
2. Inspect Operations Health and wait for running resumable imports to reach a committed checkpoint.
3. Stop workers gracefully and confirm no mutating operation remains `running`.
4. Keep the API read-only or stopped while taking the coordinated backup.
5. Verify the backup manifest and checksum before any upgrade or rollback.
6. Restore only to a separate target and compare revision and row counts.
7. Start the API first, verify liveness/readiness, then start the approved worker count.
8. Reopen mutating traffic only after queue, database, staging, and response-simulation checks pass.

## Rollback Procedure

1. Drain API mutations and operation workers as above.
2. Preserve the failed deployment logs and request IDs without copying secrets or raw evidence into Git.
3. Roll back the application and reverse-proxy configuration to the last approved revision.
4. Prefer a forward-compatible application rollback. Downgrade Alembic only after reviewing migration reversibility and job dependencies.
5. If data restore is required, restore a verified backup to a separate database first; never overwrite the active database during diagnosis or a drill.
6. Point the controlled deployment at the validated target, run migrations/readiness, then reopen services in order.
7. Never delete raw logs, labels, alerts, or audit evidence as rollback cleanup.

## Validation Commands

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_deployment_operations --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.load_test_readonly --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_disaster_recovery_drill --execute --confirm ISOLATED_V395_DRILL --pretty
```

The deployment validator checks proxy controls, alert coverage, dry-run-only scheduled units, Uvicorn proxy-header policy, runtime safety, response simulation, and raw-log assistant policy. It reports no secret values.

## PostgreSQL CI Status

The `postgres-persistence` GitHub Actions job is configured to use disposable PostgreSQL 16 databases and exercise migrations, persistence restore, concurrent workers, shared staging, lease recovery, and backup coordination. This workstation cannot provide remote GitHub Actions evidence. A deliberate reviewed commit and push is still required before that job can run; no push was performed in v3.95 without user approval.

The latest public remote run is CI #44 for older commit `9d8580b`, and it failed before this cumulative work was pushed. Local `main` is one commit ahead of `origin/main`, while v3.89-v3.95 remain uncommitted. Therefore the remote result is not evidence for or against the current v3.95 implementation.

## Final Local Verification

On 2026-07-13:

- task-board render/check passed;
- Ruff and compileall passed;
- backend tests passed: `523 passed, 1 skipped`;
- Alembic reported no drift at `a3b4c5d6e7f8`;
- React lint/build passed;
- Playwright passed: `21 passed, 1 skipped` (hardware-dependent live-source scenario);
- replay dry-run parsed two safe rows and wrote none;
- deployment validator and isolated recovery drill passed;
- performance smoke passed with no warnings;
- release gate returned `ok: true`, including the deployment-operations validator;
- secret-pattern and protected-artifact hygiene checks passed.

## Remaining Environment Gaps

- successful remote PostgreSQL CI evidence;
- installation and validation on an approved Linux host;
- real TLS certificates and DNS;
- persistent Prometheus storage and approved alert routing;
- managed secret-provider integration and rotation exercises;
- measured RPO/RTO using deployment-sized PostgreSQL data;
- multi-host shared-storage permission and failure testing;
- sustained real-device syslog validation;
- cold large-SQLite Overview and ML Governance performance investigation.

ATDR remains a controlled lab/shared-deployment candidate, not certified production software.
