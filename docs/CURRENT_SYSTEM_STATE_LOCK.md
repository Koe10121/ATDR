# ATDR Current System State Lock

Date: 2026-09-03

## Release Baseline

The published source baseline is:

- v5.54 release-candidate commit:
  `1b45ce03755cd8afa9a9803706c1c60ff454544e`
- GitHub Actions run `33585630166`: passed
- CodeQL run `33585630219`: passed

v5.56 and v5.57 are uncommitted local reliability changes. They strengthen
Assistant output/provider operations, the integrated analyst workflow,
accessibility, responsive behavior, and startup/recovery. They do not certify
production use or close an external owner gate.

## Product Decision

Current decision: **`local_release_candidate_ready`**.

ATDR is a locally verified release candidate for a controlled SOC lab. It is
not production ready. Local software controls are verified; university,
provider, physical-machine, field-evidence, and approved-host acceptance remain
external and pending.

The supported workflow is:

1. collect logs by file/API, durable import job, replay, or UDP syslog;
2. preserve raw evidence and parse/normalize supported PAN-OS or generic
   syslog records;
3. apply source-scoped deterministic detection rules and advisory anomaly/ML
   signals;
4. create deduplicated alerts and cases with evidence, explanations, and
   analyst recommendations;
5. support investigation through the React dashboard and read-only SOC
   Assistant; and
6. record analyst-approved simulated response decisions and audit events.

## Current Architecture

| Layer | Current implementation |
| --- | --- |
| Normal identity entry | Approved MFU Node/Vue/Mongo companion shell, then a short-lived one-time handoff to ATDR |
| Backend | FastAPI, Python 3.11, SQLAlchemy, Alembic, JWT/session security, structured logging |
| Frontend | React 18, TypeScript, Vite, React Router, TanStack Query/Table, Recharts |
| Local persistence | SQLite; no Docker or PostgreSQL required for the local profile |
| Shared persistence | PostgreSQL-compatible worker, migration, scale, backup, and recovery paths; approved-host acceptance pending |
| Detection | Nineteen versioned deterministic rules are alert-authoritative; IsolationForest and supervised output are advisory |
| Assistant | Deterministic database-backed context with optional bounded Gemini synthesis and deterministic fallback |
| Response | Analyst-approved simulation only; automatic response and real firewall blocking are disabled |

## Supported Profiles

### MFU Shell-First Local SQLite

Normal users start the complete system with:

```powershell
.\scripts\start_system.cmd
```

The entry point is `http://localhost:8080/#/pages/login`. MongoDB is required
by the MFU shell. Redis is optional for local use because the shell falls back
to a process-local rate-limit store. ATDR itself uses SQLite in this profile.

### Explicit Local Recovery

Local username/password access is available only when the operator explicitly
selects `ATDR_AUTH_MODE=local_recovery`. It is a recovery/development path, not
the normal identity flow. Disposable v5.54 acceptance verifies that a seeded
recovery administrator can authenticate without changing the configured
database.

### Teammate Shell Distribution

`setup_team.cmd` installs a versioned, integrity-checked shell package under
ignored runtime storage and preserves private configuration outside Git.
Physical clean-machine acceptance is still required from a teammate.

### Shared PostgreSQL Deployment

ATDR includes PostgreSQL migrations, durable workers, multi-worker locking,
100k/250k qualification paths, Nginx, systemd, Prometheus rules, managed-secret
examples, and backup/recovery tooling. These are implementation assets, not
evidence that an approved shared environment exists.

## Locally Verified Evidence

- Disposable team lifecycle: `11/11` stages passed, covering archive, setup,
  start, health, login handoff, stop, restart, repeated health/handoff/stop,
  and explicit local recovery.
- Controlled source validation: `4/4` scenarios and `10/10` checks passed.
- Deterministic detection: `24/24` scenarios passed.
- Layered detection: `288/288` governed checks passed.
- SOC Assistant: v5.56 passes `30/30` deterministic questions plus a passing
  contextual sequence with citation rate `1.0` and average/max response length
  `56.0/110` words.
- Integrated analyst workflow: v5.57 passes `24/24` disposable checks from
  ingestion through audit, including three contextual Assistant turns, case
  handoff, simulated-response guards, and zero authoritative Assistant writes.
- Accessibility: automated WCAG A/AA rules pass on login and eight primary
  analyst routes; keyboard and five-viewport regressions pass.
- Gemini: private minimal and full synthetic probes passed with redaction,
  raw-log exclusion, structured output, and zero authoritative mutations.
- Large SQLite: `145,232` normalized logs and `3,231` alerts; the read-only
  smoke passes with a `0.0163s` cached Overview path and one soft cold-Overview
  warning (`1.0875s` against the `1.0s` local target).
- Repository security: zero findings across `1,376` tracked or intended text
  paths; Python and npm dependency audits found zero known vulnerabilities.
- Deployment source validation passed while preserving
  `production_ready=false`.

Full backend passes `1067/1`; Playwright passes `42/1`; taskboard checks pass;
and the independent release gate passes with `ok=true` and no failed required
checks.

## Product Status By Area

| Area | Current status | Remaining evidence |
| --- | --- | --- |
| Ingestion and jobs | Locally verified | Real non-loopback forwarding and long-running field operation |
| Parsing/normalization | Locally verified for supported contracts | More PAN-OS versions, second source, and device-backed field accuracy |
| Deterministic detection | Locally verified in controlled regression | Independent real-traffic FP/FN evidence and environment baselines |
| Supervised ML | No candidate; `shadow_observation` | Fresh development evidence, second source, untouched future evaluation, stable gates, approval |
| IsolationForest | Advisory only | Evidence does not support detector authority |
| Alert explanations | Locally verified | Asset/business context and external incident-management integration |
| SOC Assistant | Locally verified and read-only | Institutional Gemini governance and representative field evaluation |
| Dashboard | Locally verified by automated browser, axe, keyboard, and five-viewport coverage | Independent analyst and assistive-technology acceptance |
| MFU IAM | Local integration controls verified | University lifecycle, admin group, 2FA, recovery, and deprovisioning acceptance |
| Shared deployment | Source and disposable controls verified | Approved host, TLS/DNS, managed secrets, monitoring, RPO/RTO, DR, and load evidence |
| Security and recovery | Local scans/audits/tooling verified | Environment DAST/penetration testing and scheduled owner drills |

## AI, ML, And Alert Authority

The immutable v5.49b evaluation bound 180 genuine protected decisions, ran
eight fixed strategies exactly once, and selected no candidate. Protected
rows, identities, fingerprints, labels, predictions, and claims remain private.
No active supervised artifact was written.

Deterministic rules remain the only alert-authoritative detector. The legacy
artifact with incomplete metadata is not a selected candidate. The dashboard
must say that active metadata is unknown rather than presenting `unknown` as a
model family.

Gemini may rephrase a bounded deterministic answer only when private settings
enable it. Raw log lines are excluded, IP redaction remains enabled, citations
are allowlisted, provider failure falls back safely, and the Assistant has no
write path for detection, labels, models, users, response, or deletion.

## External Acceptance Tracks

1. **MFU IAM owner:** approve callbacks/origins, map a real admin group, and
   test login, issuer/audience, 2FA, expiry, logout, recovery, and
   deprovisioning.
2. **Shared-host owner:** provide Linux/PostgreSQL, DNS/TLS, managed secrets,
   shared storage, monitoring, backup/restore, load, rollback, and measured
   RPO/RTO/DR evidence.
3. **Gemini/provider owner:** approve privacy/retention, billing/quota, key
   custody/rotation, monitoring, and representative evaluation.
4. **Teammate:** perform the shell-first clean-clone lifecycle and login handoff
   on a separate physical machine.
5. **Detection field owners:** provide a second physical source, real
   non-loopback forwarding, independent labels, and an untouched future window.

Exact checklists are in `docs/V5_54_EXTERNAL_OWNER_ACCEPTANCE.md`.

## Safety And Privacy Invariants

- Do not reset the configured database or alter protected evidence.
- Do not rerun the consumed v5.49b evaluation.
- Do not call assisted labels human-reviewed.
- Do not activate or promote a model without a separate governed decision.
- Keep deterministic rules alert-authoritative.
- Keep the Assistant read-only and external raw-log context disabled.
- Keep automatic response and real firewall blocking disabled.
- Never commit `.env` files, databases, private logs, reviews, model artifacts,
  provider payloads, generated reports, SBOMs, or processed evidence.
- Configuration never counts as owner acceptance.

## Active References

- `README.md`
- `docs/V5_57_END_TO_END_ANALYST_WORKFLOW_ACCESSIBILITY_STARTUP.md`
- `docs/V5_54_RELEASE_CANDIDATE_TRUTH_LOCK.md`
- `docs/V5_54_OPERATOR_HANDOFF.md`
- `docs/V5_54_EXTERNAL_OWNER_ACCEPTANCE.md`
- `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
- `docs/prd/PRD-ATDR.md`
- `docs/OPERATIONS_RUNBOOK.md`
- `docs/DEPLOYMENT_GUIDE.md`
- `docs/QUICKSTART_FOR_TEAM.md`
- `docs/tasks/tasklist-progress.md`

Historical version documents remain immutable implementation evidence. They do
not override this current-state lock when old readiness or model wording
differs.
