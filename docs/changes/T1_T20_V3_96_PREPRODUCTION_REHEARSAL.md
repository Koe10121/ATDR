# T1-T20: v3.96 Controlled Preproduction Rehearsal

## T1 Change Title

- Title: v3.96 Controlled Preproduction Deployment Rehearsal and Operational Acceptance
- Date: 2026-07-13
- Owner / acting agent: Codex with operator approval gates
- Related version: v3.96

## T2 Requirement

- Convert v3.95 deployment references into secret-safe, measurable acceptance evidence.
- Preserve SQLite/local startup, current data, simulated response, read-only assistant, and candidate-only ML.
- Stop before remote deployment, DNS/TLS changes, secret rotation, MFU contact, non-read-only load, commit, or push.

## T3 Source Evidence

| Source | Evidence |
| --- | --- |
| Runtime/config | `atdr/app/main.py`, `atdr/app/core/config.py`, `atdr/app/db/engine.py` |
| Deployment | `deploy/nginx/*`, `deploy/monitoring/*`, `deploy/secrets/*`, `deploy/systemd/*` |
| Persistence/workers | `atdr/app/services/persistence_service.py`, `atdr/scripts/validate_postgres_multiworker.py`, `atdr/scripts/validate_backup_worker_concurrency.py` |
| MFU handoff | `atdr/app/services/mfu_iam_service.py`, `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md` |
| Existing tests/CI | `atdr/tests/test_v394_postgres_multiworker.py`, `atdr/tests/test_v395_deployment_operations.py`, `.github/workflows/ci.yml` |

## T4 Current Behavior

- v3.95 had secure deployment examples, bounded metrics, GET-only load, backup verification, and isolated recovery.
- It lacked a unified environment acceptance report, pool/backup monitoring, and explicit synthetic-versus-approved-host RPO/RTO fields.
- Approved Linux, DNS/TLS, persistent monitoring, managed secrets, shared mounts, deployment PostgreSQL, and MFU provider validation were unavailable.

## T5 Impacted Areas / Agents

| Area / Agent | Impacted | Reason |
| --- | --- | --- |
| Orchestrator / Product | yes | Defines accept/reject boundary and evidence classes. |
| Database / Backend | yes | Adds read-only preflight, pool metrics, and backup freshness. |
| Frontend | no | No React behavior changed. |
| AI/ML | safety review only | No training, activation, or promotion. |
| Security / IAM | yes | Validates proxy, secrets, MFU handoff, response, and LLM boundaries. |
| QA / Release-Ops | yes | Adds checks, rehearsal measurements, docs, and CI dry preflight. |

## T6 Scope

### In Scope

- Secret-safe readiness report, configuration examples, metrics/alerts, bounded load observations, isolated recovery evidence, tests, docs, and task board.

### Out Of Scope

- Remote deployment, real DNS/TLS installation, secret rotation, live MFU calls, write-load tests, current DB mutation, automatic response, firewall operation, and model activation.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-V396-001 | Fail acceptance unless all approved-host requirements are evidenced. | Must |
| FR-V396-002 | Never expose connection URLs, secrets, private paths, raw logs, or tokens. | Must |
| FR-V396-003 | Report PostgreSQL pool, queue, and backup freshness using bounded metrics. | Must |
| FR-V396-004 | Keep load GET-only and remote-confirmed; report percentiles and telemetry. | Must |
| FR-V396-005 | Distinguish synthetic rehearsal RTO from deployment RPO/RTO evidence. | Must |
| FR-V396-006 | Preserve all SOC response, assistant, ML, and evidence safety controls. | Must |

## T8 Acceptance Criteria

| ID | Criterion | Verification |
| --- | --- | --- |
| AC-001 | Local/default preflight is safe and incomplete. | v3.96 tests and CLI dry run. |
| AC-002 | A fully supplied synthetic Linux profile can pass the logic gate. | Mocked source test only. |
| AC-003 | Production profile, broad proxy, unsafe response, or raw LLM context fails. | v3.96 tests. |
| AC-004 | Load reports p50/p95/p99, pool/queue data, and no token/body. | v3.95/v3.96 focused tests and isolated run. |
| AC-005 | Recovery uses a separate target and reports only measured synthetic RTO. | isolated drill and test. |
| AC-006 | Operational acceptance remains blocked without real environment evidence. | checklist/decision. |

## T9 API Contract

- No API route changed.
- `/metrics` gains bounded pool and backup gauges.
- Existing auth/RBAC behavior is unchanged.
- The preflight is an operator CLI, not a public endpoint.

## T10 Data Model / Migration

- No schema, migration, index, or existing-data change.
- Rollback removes the new services/script/metrics/rules/docs and config placeholders.

## T11 Backend Plan / Changes

- Add preproduction acceptance service and confirmed read-only preflight CLI.
- Extract backup freshness verification into a reusable read-only service.
- Add pool/backup metrics and bounded load telemetry parsing.
- Make recovery measurement scope explicit.
- Strengthen deployment validator coverage and CI dry preflight.

## T12 Frontend Plan / Changes

- No frontend change. Existing dashboard and startup commands remain unchanged.

## T13 Security / Response / AI Safety

- Response simulation required: yes.
- Automatic response: disabled.
- Real firewall enforcement: absent.
- Assistant raw-log context: disabled.
- Model activation/promotion: not performed.
- Secret values and private paths: excluded from output.
- Security decision: pass for repository controls; block operational acceptance pending environment evidence.

## T14 Test Plan

- Task-board render/check, Ruff, compileall, full backend tests, Alembic check.
- React lint/build/Playwright regression.
- Replay dry-run and performance smoke.
- Deployment validator, preflight, isolated load, isolated recovery, release gate, and hygiene scan.
- Disposable PostgreSQL CI evidence; no unapproved remote execution.

## T15 Implementation Summary

| Area | Summary |
| --- | --- |
| Config/preflight | Added disabled deployment fields and strict secret-safe acceptance checks. |
| Monitoring | Added pool and backup freshness metrics and alerts. |
| Load | Added optional bounded pool/queue observations. |
| Case-query stability | Removed a computed-case N+1 through select-in evidence loading; API contract and grouping are unchanged. |
| Recovery | Added measurement scope, synthetic RTO, and explicit unmeasured RPO. |
| Verification/docs | Added tests, CI dry preflight, runbook, checklist, and governance updates. |

## T16 Tests Run / Evidence

- Focused v3.95/v3.96 tests: 17 passed, including bounded case-summary query count.
- Default preflight returns one secret-safe operator action for every failed requirement, with no database probe, write, network call, or secret output.
- Initial isolated load: 160/160 successful, 0% errors, 15.556 requests/second; alerts p95 `1.2887s` and cases p95 `2.3139s` exposed the case-query N+1.
- Follow-up isolated load: 160/160 successful, 0% errors, 31.686 requests/second, no warnings; alerts p95 `0.5966s`, cases p95 `0.5764s`.
- Isolated case service: 398 SQL statements before, 2 after; best measured call `0.1100s` before and `0.0261s` after.
- Isolated recovery: passed; latest synthetic RTO 2.3882s (prior repeat 2.5215s); RPO unmeasured; configured DB unchanged.
- Deployment source validator: passed under a safe local override.
- Full backend: `532 passed, 1 skipped`; Alembic reported no drift.
- React lint/build passed; Playwright `21 passed, 1 skipped` with only the hardware-dependent live scenario skipped.
- Performance smoke passed without warnings: Overview `0.4473s`, cached Overview `0.0062s`, alerts `0.0350s`, cases `0.0743s`, and ML Governance `1.1685s`.
- Release gate returned `ok: true` with no failed required checks.
- GitHub Actions #50 independently remained successful for backend, frontend, and disposable PostgreSQL persistence at baseline commit `c05e3e0`.
- GitHub Actions run `29258487703` passed backend, frontend, and disposable PostgreSQL persistence for committed v3.96 SHA `f49a50a`.
- Credential-free environment discovery found the supervisor-named preproduction FQDN unresolved, HTTPS unavailable, no configured GitHub Environment, and no ATDR deployment-host coordinates; no IAM call or remote state change occurred.

Skipped environment checks:

- Approved Linux/Nginx/systemd, real TLS/DNS, persistent Prometheus/alert delivery, managed secrets, multi-host staging, deployment PostgreSQL, and provider-backed MFU handoff.
- Reason: required approved resources were not available.
- Risk: operational acceptance remains blocked.

## T17 PRD / Docs Updated

- Updated PRD, traceability, compliance checklist, lab/deployment/security runbooks, docs index, and task board.
- Created the v3.96 rehearsal guide, operational checklist, and this change record.

## T18 Risks / Blockers / Assumptions / Decisions

- Current private MFU profile is enabled but incomplete; use an explicit local override or complete the private handoff/B2B configuration.
- Local SQLite alert/case p95 warnings are not PostgreSQL capacity evidence.
- Synthetic recovery timing is not an SLA.
- Environment-backed checks are blockers, not test failures.
- The supervisor-named preproduction URL is a configuration intention, not evidence of a provisioned host; DNS and HTTPS were unavailable during the read-only check.

## T19 Release / Rollback

- Release impact: additive operator tooling, metrics, alerts, tests, docs, and disabled placeholders.
- Local startup/data behavior: unchanged.
- Rollback: revert the allowlisted files; no data rollback is needed.
- Deployment: prohibited until separate explicit approval and checklist completion.

## T20 Final Handoff

- Status: repository implementation complete; operational acceptance blocked.
- Behavior changed: deployment diagnostics and monitoring only.
- Safety: preserved; no actions, model activation, firewall call, or data mutation.
- Next action: obtain the seven private environment inputs listed in `docs/V3_96_PREPRODUCTION_DEPLOYMENT_REHEARSAL.md`, then run the confirmed preflight on the approved host.
