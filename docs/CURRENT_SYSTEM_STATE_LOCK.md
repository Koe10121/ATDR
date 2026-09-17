# ATDR Current System State Lock

Date: 2026-09-17

## Release Baseline

The published source baseline is v5.61 commit `df8f3b8`, which adds the
explicit governed advisory IsolationForest bootstrap. The current uncommitted
v5.62-v5.63 work adds a fresh supervised qualification campaign, expands its
selected capacity to 1,000 rows, and provides protected batched review.
Publication remains separately approval-gated.

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
3. apply source-scoped deterministic detection rules, bounded advisory
   IsolationForest scoring, and a fail-closed supervised eligibility check;
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
| Detection | Nineteen versioned rules are `active_authoritative`; IsolationForest is explicitly bootstrapped and `active_advisory` when available; supervised runtime is `unqualified`; hybrid triage is advisory |
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
Automated clean-machine acceptance now proves the published remote clone,
versioned package, setup, lifecycle, recovery, and controlled analyst workflow.
A real physical teammate and approved MFU-account sign-in remain external.

### Shared PostgreSQL Deployment

ATDR includes PostgreSQL migrations, durable workers, multi-worker locking,
100k/250k qualification paths, Nginx, systemd, Prometheus rules, managed-secret
examples, and backup/recovery tooling. These are implementation assets, not
evidence that an approved shared environment exists.

## Locally Verified Evidence

- Disposable team lifecycle: `11/11` stages passed, covering archive, setup,
  start, health, login handoff, stop, restart, repeated health/handoff/stop,
  and explicit local recovery.
- Genuine v5.60 clean-machine acceptance: `27/27` stages passed from a new
  `origin/main` clone with isolated dependencies and SQLite, provider-missing
  fail-closed behavior, setup/start/stop/restart idempotence, stale-process and
  occupied-port diagnostics, shell handoff contracts, recovery login, safe
  workflow execution, and complete temporary cleanup.
- v5.61 anomaly bootstrap preflight accepts 41 of 45 committed synthetic rows,
  excludes four unresolved-application rows, writes nothing by default, and
  requires exact confirmation before disposable training. Acceptance proves
  zero model-driven alerts, suppressions, labels, model runs, detection runs,
  or response actions.
- v5.62 private disposable preparation parses 773,551 records with zero parser
  failures, retains 298,963 fresh eligible rows, rejects 228 consumed-overlap
  rows, contains 52,881 near duplicates, and locks 300 prediction-blind review
  rows across four chronological roles. Review remains `0/300`; one physical
  source is present, so supervised runtime remains unqualified.
- v5.63 revalidates that boundary, preserves all 300 rows, and selects 700
  additional unique development-safe rows with zero original overlap and zero
  added future-evaluation rows. Seven protected 100-row batches are ready;
  combined review remains `0/1,000`, 19 windows and one source are present,
  and no model operation is allowed.
- v5.60 controlled clean-clone workflow: 10 records preserved and normalized,
  one expected rule alert, three contextual deterministic Assistant turns with
  citation counts `10/10/3`, zero response actions, and no model activation.
- Controlled source validation: `4/4` scenarios and `10/10` checks passed.
- Deterministic detection: `24/24` scenarios passed.
- Layered detection: `288/288` governed checks passed.
- SOC Assistant: v5.56 passes `30/30` deterministic questions plus a passing
  contextual sequence with citation rate `1.0` and average/max response length
  `56.0/110` words.
- Integrated analyst workflow: v5.57 passes `24/24` disposable checks from
  ingestion through audit, including three contextual Assistant turns, case
  handoff, simulated-response guards, and zero authoritative Assistant writes.
- Detection runtime: the v5.58 read-only status check reports rules
  `active_authoritative`, IsolationForest `active_advisory`, supervised
  `unqualified`, hybrid `active_advisory`, response `simulation_only`, and zero
  writes or authority changes.
- Accessibility: automated WCAG A/AA rules pass on login and eight primary
  analyst routes; keyboard and five-viewport regressions pass.
- Gemini: private minimal and full synthetic probes passed with redaction,
  raw-log exclusion, structured output, and zero authoritative mutations.
- Large SQLite: `145,232` normalized logs and `3,231` alerts; the read-only
  smoke passes overall with a `0.0150s` cached Overview path. The current
  `1.1947s` cold Overview measurement carries a non-failing warning against
  the aggressive `1.0s` local target.
- Repository security: zero findings across `1,433` tracked or intended text
  paths; Python and npm dependency audits found zero known vulnerabilities.
- Deployment source validation passed while preserving
  `production_ready=false`.

Full backend passes `1108 passed, 1 skipped`; Playwright passes `44 passed, 1
skipped`; taskboard checks pass; and the independent release gate passes with
`ok=true` and no failed required checks.

## Product Status By Area

| Area | Current status | Remaining evidence |
| --- | --- | --- |
| Ingestion and jobs | Locally and clean-clone verified | Real non-loopback forwarding and long-running field operation |
| Parsing/normalization | Locally verified for supported contracts | More PAN-OS versions, second source, and device-backed field accuracy |
| Deterministic detection | Locally verified in controlled regression | Independent real-traffic FP/FN evidence and environment baselines |
| Supervised ML | v5.62-v5.63 fresh campaign prepared with 1,000 selected rows; effective runtime `unqualified`; no candidate | Complete 300 original and 700 supplemental reviews, obtain second source, preserve untouched evaluation, pass fixed gates, freeze, and separately approve |
| IsolationForest | Reproducible through explicit governed bootstrap; advisory only | Evidence does not support threat-accuracy or detector-authority claims |
| Alert explanations | Locally verified | Asset/business context and external incident-management integration |
| SOC Assistant | Locally verified and read-only | Institutional Gemini governance and representative field evaluation |
| Dashboard | Locally verified by automated browser, axe, keyboard, and five-viewport coverage | Independent analyst and assistive-technology acceptance |
| MFU IAM | Local and packaged handoff controls verified | University lifecycle, real account, admin group, 2FA, recovery, and deprovisioning acceptance |
| Shared deployment | Source and disposable controls verified | Approved host, TLS/DNS, managed secrets, monitoring, RPO/RTO, DR, and load evidence |
| Security and recovery | Local scans/audits/tooling verified | Environment DAST/penetration testing and scheduled owner drills |

## AI, ML, And Alert Authority

The immutable v5.49b evaluation bound 180 genuine protected decisions, ran
eight fixed strategies exactly once, and selected no candidate. Protected
rows, identities, fingerprints, labels, predictions, and claims remain private.
No active supervised artifact was written.

v5.58 makes that negative decision enforceable at runtime. A historical
lifecycle row or artifact cannot authorize scoring. Normal detection checks
eligibility and refuses supervised inference unless a later decision qualifies
and freezes exactly one matching, fully validated candidate. The current
development repair passed `0/3` strict views, so active shadow scoring remains
off.

Deterministic rules remain the only alert-authoritative detector. The legacy
artifact with incomplete metadata is not a selected candidate. The dashboard
must say that active metadata is unknown rather than presenting `unknown` as a
model family.

v5.61 also separates anomaly capability from anomaly accuracy. Clean clones
remain operational without an artifact and show `Advisory anomaly model
unavailable` plus a write-free preflight command. Explicit bootstrap trains in
disposable SQLite, installs only ignored outputs, and records a sanitized
manifest. `Advisory anomaly model available` never means threat accuracy has
been validated.

v5.62 prepares a new supervised path without weakening that boundary. All
v5.49b evidence is excluded, roles are assigned chronologically, duplicate
families are isolated, future-evaluation labels are sealed, and development
loading fails closed until genuine review closure. Only the time-window gate
currently passes; source, label-support, comparable-row, and model-quality
gates remain failed or blocked.

v5.63 reaches the fixed selected capacity with 700 append-only supplemental
rows, but it does not convert selection into human-reviewed evidence. The
combined review remains `0/1,000`. The time-window gate passes at 19/2; the
physical-source gate remains 1/2; class-support and quality gates remain failed
or blocked. Untouched evaluation labels are still inaccessible.

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
4. **Teammate:** repeat the now-automated shell-first clean-clone lifecycle on a
   separate physical machine and retain usability evidence; use a real MFU
   account only with the approved private provider profile.
5. **Detection field owners:** provide a second physical source, real
   non-loopback forwarding, independent labels, and an untouched future window.

Exact checklists are in `docs/EXTERNAL_ACCEPTANCE.md`.

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
- `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
- `docs/prd/PRD-ATDR.md`
- `docs/OPERATIONS_RUNBOOK.md`
- `docs/LAB_RUNBOOK.md`
- `docs/AI_TRAINING_RUNBOOK.md`
- `docs/DEPLOYMENT_GUIDE.md`
- `docs/QUICKSTART_FOR_TEAM.md`
- `docs/EXTERNAL_ACCEPTANCE.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/tasks/tasklist-progress.md`

Historical version documents under `docs/archive/` remain immutable
implementation evidence. They do not override this current-state lock when old
readiness or model wording differs.
