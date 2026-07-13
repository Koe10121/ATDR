# v3.96 Operational Acceptance Checklist

Use this checklist only on an approved shared-lab or preproduction environment. A repository pass is not a production-readiness claim.

## Gate Status

| Area | Status | Acceptance Evidence |
| --- | --- | --- |
| Written host/rehearsal approval | blocked | No approved Linux host was supplied. |
| Secret-safe preflight implementation | pass | `run_v396_preproduction_preflight` and v3.96 tests; every failed requirement has a one-to-one remediation action. |
| Linux service runtime | blocked | Nginx/systemd unavailable on current Windows host. |
| PostgreSQL migrations | pass in disposable CI; host blocked | GitHub Actions #50 passed PostgreSQL 16 validation; approved deployment instance unavailable. |
| Concurrent workers / lease recovery | pass in disposable CI; host blocked | v3.94 CI validators passed; multi-host service behavior remains unmeasured. |
| Shared staging permissions | blocked | No shared mount was supplied. |
| DNS and TLS | blocked | No FQDN or certificate material was supplied. |
| Reverse-proxy source controls | pass | Redirect, headers, limits, timeouts, metrics restriction, forwarded-chain overwrite, and SPA fallback validated. |
| Persistent monitoring / alert delivery | blocked | Metrics/rules pass source validation; no Prometheus/Alertmanager runtime supplied. |
| Backup freshness metric/rule | pass in source | Read-only verifier, metrics, and stale-backup alert implemented. |
| Isolated backup/restore | pass | Separate-target synthetic SQLite drill passed; current DB unchanged. |
| Deployment RPO/RTO | blocked | Latest synthetic RTO 2.3882s only; deployment RPO unmeasured and RTO uncertified. |
| Bounded read-only load | pass locally | Follow-up 160/160 GET run had no warnings after case-summary queries fell from 398 to 2; approved-host load remains pending. |
| MFU outer-shell handoff | blocked | Source contract exists; private profile is incomplete and no provider-backed preproduction evidence exists. |
| Response/assistant/model safety | pass | Simulation only, assistant read-only/raw logs disabled, no model activation or firewall call. |
| Operational acceptance | **blocked** | Environment-backed required gates remain open. |

## Before Connecting

- [ ] Written approval identifies the host, environment, owner, and test window.
- [ ] Private configuration is loaded from an approved secret provider, not Git.
- [ ] `ENVIRONMENT` is `shared_lab` or `preproduction`, never `production` for this rehearsal.
- [ ] `DEPLOYMENT_REHEARSAL_APPROVED=true` is set only for the approved window.
- [ ] PostgreSQL source and separate restore databases are identified.
- [ ] DNS, HTTPS URL, certificate, private key, and renewal owner are identified.
- [ ] Shared staging and backup paths are absolute, mounted, owned correctly, and not world-writable.
- [ ] Prometheus and alert destination owners are present.
- [ ] MFU handoff origin/domain/group/session details are approved.
- [ ] Response simulation and assistant raw-log restrictions are confirmed.

## Preflight And Deployment

- [ ] Run the dry preflight and review every missing requirement ID.
- [ ] Run the confirmed read-only DB probe only against the approved PostgreSQL target.
- [ ] Run Alembic upgrade once through the deployment owner and confirm `at_head`.
- [ ] Install Nginx and service units under unprivileged accounts.
- [ ] Confirm the API binds to loopback with generic proxy headers disabled.
- [ ] Confirm workers are separate services and use the same staging identity.
- [ ] Confirm HTTPS redirect, React deep-link fallback, API routing, upload limits, timeouts, and protocol upgrades.
- [ ] Confirm forwarded headers are ignored from untrusted peers.
- [ ] Confirm `/metrics` is unreachable from unapproved clients.

## Identity And Access

- [ ] MFU shell signs in an approved school account with the provider's required 2FA.
- [ ] One-time handoff code is form-posted and accepted only once.
- [ ] No credential, token, or handoff secret appears in a URL, log, metric, or screenshot.
- [ ] Default school user maps to analyst.
- [ ] Admin maps only through an approved group policy.
- [ ] Logout, expiration, replay rejection, recovery login, and deprovisioning are tested.
- [ ] Denied and successful handoffs are audited without secrets.

## Monitoring And Load

- [ ] Prometheus scrapes API readiness, queue/worker, ingestion/detection, staging, pool, and backup metrics.
- [ ] Alert rules pass `promtool check rules`.
- [ ] Alertmanager sends a controlled test alert to the approved destination.
- [ ] No metric contains actor, email, IP, path, token, raw log, request ID, run ID, or job ID.
- [ ] GET-only load runs with a short-lived environment token and explicit remote confirmation.
- [ ] Record throughput, error rate, p50/p95/p99, pool utilization, queue depth, and dashboard latency.
- [ ] Investigate any budget warning before acceptance.
- [ ] Do not run write load without a separate disposable environment and approval.

## Backup And Recovery

- [ ] Enter the approved API maintenance/read-only window.
- [ ] Drain workers at committed boundaries and confirm no mutating jobs are running.
- [ ] Create a backup and manifest through the approved operator process.
- [ ] Verify age, size, checksum, revision, and count coverage.
- [ ] Restore only to a separate empty database.
- [ ] Run Alembic and compare integrity, revision, and row counts.
- [ ] Measure failure point, last verified backup point, RPO, and full service RTO.
- [ ] Keep the active database untouched throughout the drill.

## Safety And Closure

- [ ] Response actions remain simulated and analyst-approved.
- [ ] SOC Assistant cannot execute actions or send raw logs externally.
- [ ] No model is activated or promoted.
- [ ] No firewall operation occurs.
- [ ] No evidence or current database is deleted/reset.
- [ ] Remove the temporary load token and temporary rehearsal approval.
- [ ] Preserve only redacted acceptance evidence outside Git.
- [ ] Record unresolved findings, owner, deadline, rollback, and final accept/reject decision.

## Stop Conditions

Stop immediately if a secret is exposed, an active target is selected for restore, forwarded headers are trusted broadly, HTTPS/session protection is absent, response simulation changes, raw logs reach an external provider, a model is activated, a firewall connector runs, or any required environment owner is unavailable.
