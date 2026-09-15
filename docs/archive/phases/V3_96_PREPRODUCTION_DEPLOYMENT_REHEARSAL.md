# v3.96 Controlled Preproduction Deployment Rehearsal

## Decision

ATDR has a repository-validated and locally rehearsed shared-deployment profile, but it has **not** passed operational acceptance on an approved preproduction host. No approved Linux host, deployment PostgreSQL instance, DNS record, TLS material, persistent Prometheus service, managed-secret provider, or provider-backed MFU handoff was available on 2026-07-13.

This phase therefore records three evidence classes:

- **Repository validated:** source, configuration examples, proxy/monitoring rules, tests, and CI controls pass.
- **Isolated local measured:** GET-only load and separate-target SQLite recovery were executed against disposable copies.
- **Environment blocked:** Linux, real TLS/DNS, persistent monitoring, managed secrets, multi-host storage, deployment PostgreSQL, and MFU preproduction handoff remain unverified.

ATDR remains a controlled shared-deployment candidate. It is not production-certified. Response is simulated, the SOC Assistant is read-only, raw-log LLM context is disabled, and no model or firewall connector was activated.

## Environment Availability

| Requirement | 2026-07-13 Result | Evidence / Next Input |
| --- | --- | --- |
| Approved Linux host | unavailable | Current host is Windows. Obtain the hostname, OS/version, owner, access method, and written rehearsal approval. |
| PostgreSQL deployment instance | unavailable locally | Disposable PostgreSQL 16 migration, concurrency, lease-recovery, and backup coordination passed in GitHub Actions #50. An approved private `DATABASE_URL` and host tools are still required. |
| DNS name | candidate unprovisioned | The supervisor package names `preprod-mfu-ai-driven-log-based-threat-detection-and-response.mfu.ac.th`, but a credential-free read-only check on 2026-07-13 found no DNS A record and no HTTPS endpoint. Confirm ownership and provision the approved record before rehearsal. |
| TLS certificate and key | unavailable | Install approved material outside Git and restrict the key to its service owner. |
| Shared staging mount | unavailable | Provide an absolute shared path, storage identity, service owner/group, capacity, and mount behavior on every worker host. |
| Prometheus / alert destination | unavailable | Provide an internal Prometheus URL, retention policy, Alertmanager destination, and alert owner. |
| Managed-secret provider | unavailable | Select Vault, a cloud secret manager, Kubernetes Secret, or systemd credentials and define rotation ownership. |
| MFU outer-shell handoff | incomplete in private profile | The current private profile enables MFU IAM but does not complete either B2B credentials or secure handoff. Disable it for local use or privately configure the v3.91 handoff contract. |

No remote deployment, DNS change, certificate installation, secret rotation, MFU call, or non-read-only remote load was performed.

The same discovery pass found no configured GitHub Environment and no usable ATDR host/PostgreSQL/TLS/Prometheus/shared-storage coordinates in the supervisor package. Its MFU IAM variables and generic Node/Vue/Mongo deployment files do not constitute an ATDR preproduction runtime. No IAM endpoint was contacted and no secret value was read into the report.

## Acceptance Preflight

`atdr.scripts.run_v396_preproduction_preflight` reports only booleans, bounded status values, missing requirement IDs, and one secret-safe operator action for every missing requirement. Failed check wording is explicitly framed as a requirement to verify. It validates:

Start from `.env.preproduction.example`, but copy real values only into an approved private environment/secret provider. The committed example deliberately cannot pass acceptance unchanged.

- explicit rehearsal approval and a shared-lab/preproduction environment, never a production profile;
- Linux and required Nginx/systemd/PostgreSQL tools;
- PostgreSQL with an explicitly confirmed read-only migration probe;
- Alembic-only schema management and a non-placeholder JWT secret;
- HTTPS URL/DNS agreement, absolute certificate/key paths, and owner-only key permissions;
- explicit HTTPS CORS origins and scoped private/loopback trusted proxies;
- absolute shared staging, non-local storage identity, access, ownership, and non-world-write permissions;
- protected backup storage plus a fresh manifest/checksum-verified backup;
- Prometheus configuration and an approved managed-secret provider;
- separately managed multi-worker settings and MFU one-time-code handoff readiness;
- secure handoff cookies, response simulation, and assistant raw-log/provider safety.

Dry-run inspection makes no database connection:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v396_preproduction_preflight --pretty
```

An approved operator may add the bounded read-only database probe only after reviewing the private target:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v396_preproduction_preflight --probe-database --confirm READ_ONLY_V396_PREPRODUCTION_PREFLIGHT --require-accepted --pretty
```

The second command may connect to the configured database, but it performs no schema or data writes. Do not run it against an unapproved remote target.

## Deployment Topology

The intended topology remains:

```text
MFU outer shell
  -> one-time opaque code form POST
  -> Nginx HTTPS edge / React static assets
  -> loopback FastAPI API
  -> PostgreSQL
  -> separately supervised operation workers
  -> shared private staging
  -> private Prometheus scrape and alert routing
```

Repository checks confirm HTTP-to-HTTPS redirect, TLS protocol policy, security headers, request-size and timeout limits, SPA fallback, protocol-upgrade compatibility, loopback-only metrics access, and replacement of untrusted forwarded-client chains. Runtime installation and certificate behavior remain environment blocked.

## Monitoring And Alerting

Low-cardinality metrics now include bounded PostgreSQL pool state and backup freshness:

- `atdr_database_pool_observable`
- `atdr_database_pool_connections{state=checked_in|checked_out|overflow}`
- `atdr_database_pool_configured_size`
- `atdr_database_pool_max_overflow`
- `atdr_database_pool_utilization_ratio`
- `atdr_backup_configured`
- `atdr_backup_fresh`
- `atdr_backup_age_seconds`

The alert reference now includes database pool saturation and stale/unavailable backup alerts in addition to service/database readiness, unsafe configuration, response-simulation changes, queue backlog, stale workers, repeated failures, ingestion/detection failures, and staging pressure. Metrics contain no users, emails, IPs, paths, tokens, raw logs, or request/job identifiers.

Persistent scrape history, alert delivery, paging ownership, and alert-noise tuning still require the approved environment.

## Read-Only Load Evidence

The v3.96 runs used ignored SQLite snapshots and temporary APIs on loopback. Tokens existed only in process memory or ignored `.tmp` storage and were removed after each run. All measured requests were GET requests; no response bodies or secrets were reported.

The initial run exposed an N+1 query in computed case summaries: one 20-case service call issued 398 SQL statements. `list_alert_cases` now select-in eager-loads alert evidence and normalized logs without changing grouping or response fields. The same isolated service path now issues 2 statements, and its best three-run time improved from `0.1100s` to `0.0261s`.

| Measurement | Result |
| --- | ---: |
| Requests / successes | 160 / 160 |
| Error rate | 0.0% |
| Throughput | 31.686 requests/second |
| Runtime | 5.0495 seconds |
| Liveness p95 | 0.0226 seconds |
| Readiness p95 | 0.2808 seconds |
| Overview p95 | 1.3146 seconds |
| Alerts p95 | 0.5966 seconds |
| Cases p95 | 0.5764 seconds |
| Sources p95 | 0.0522 seconds |
| Operations p95 | 0.3479 seconds |
| Assistant status p95 | 0.0357 seconds |
| Queue depth observed | 3 |

The follow-up run had no performance-budget warnings. Before the N+1 repair, alerts p95 was `1.2887s` and cases p95 was `2.3139s`; both are retained as root-cause evidence. PostgreSQL pool observability was correctly false because these runs used SQLite. The improved results are still a bounded local stability sample, not an SLA, capacity claim, or deployment PostgreSQL result.

## Backup And Recovery Evidence

The isolated recovery drill passed:

- synthetic migration applied;
- backup and checksum manifest created;
- restore used a separate empty target;
- integrity, row counts, and Alembic revision matched;
- current configured database remained unchanged;
- latest measured isolated rehearsal RTO: **2.3882 seconds** (an earlier repeat measured `2.5215s`).

That measurement covers only the built-in synthetic SQLite drill. `approved_host_measurement=false`. RPO was not measured because no approved deployment backup history or failure point existed. The 24-hour RPO and 4-hour RTO remain planning assumptions, not guarantees.

## Safety Invariants

- `RESPONSE_SIMULATION=true` and provider `simulation` are required by acceptance.
- Automatic response and real firewall blocking remain unavailable.
- The SOC Assistant cannot execute actions and raw-log external context remains disabled.
- No model was activated or promoted.
- No current database, evidence, labels, alerts, or audit records were changed or deleted.
- Scheduled maintenance examples remain report-only.
- Backup restore targets must remain separate from the configured database.

## Private Configuration Required

An approved operator must privately provide:

1. Linux host identity, owner, access route, and written authorization.
2. Preproduction FQDN, DNS owner, HTTPS base URL, certificate/key paths, and renewal owner.
3. PostgreSQL URL, database owner, version, maintenance window, and separate restore target.
4. Shared staging path, storage ID, owner/group, capacity, and all-worker mount evidence.
5. Prometheus URL, retention, alert destination, and on-call owner.
6. Managed-secret provider and rotation process for JWT, database, MFU handoff, assistant provider, SMTP, and TLS secrets.
7. MFU shell origin, ATDR origin, dedicated handoff secret custody, approved domains, group-role mapping, 2FA/session policy, and deprovisioning owner.

Do not send any value through chat, screenshots, Git, command arguments, or public logs.

## Acceptance Outcome

**Operational acceptance: blocked by environment availability.** Repository and isolated-local validation passed, but the approved-host evidence gate is intentionally not satisfied.

Final repository/local verification passed on 2026-07-13: Ruff, compileall, backend `532 passed, 1 skipped`, Alembic no drift, React lint/build, Playwright `21 passed, 1 skipped`, replay dry-run, deployment validators, performance smoke, isolated recovery, and the release gate. GitHub Actions run #50 independently passed backend, frontend, and disposable PostgreSQL persistence jobs at baseline commit `c05e3e0`. The hardware-dependent Playwright scenario remained the only intentional skip.

Recommended v3.97: provision the approved preproduction host and execute this checklist, then address measured PostgreSQL load/recovery findings. If the host remains unavailable, profile the alert/case cold-query path and preserve this acceptance gate unchanged.
