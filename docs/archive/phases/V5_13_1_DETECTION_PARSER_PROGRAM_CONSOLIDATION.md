# v5.13.1 Detection/Parser Program Consolidation And Repository Closure

Date: 2026-07-28

## Purpose

This closure reconciles the cumulative uncommitted v4.9-v5.13 Detection/ML,
parser, source-quality, API, React, test, migration, and governance work into
one reviewable repository boundary. It changes no detector authority, model
lifecycle, response policy, startup command, or stored evidence.

This record does not authorize staging, committing, pushing, deleting files,
reparsing history, migrating the configured database, or activating a model.

## Published Baseline

- Branch: `main`
- Published commit: `e05032acb758ae91aaf60a2880513ef34f6f53a7`
- Remote comparison: local `HEAD` equals `origin/main`
- Published GitHub Actions run:
  `https://github.com/Koe10121/ATDR/actions/runs/29646770282`
- Published CI conclusion: success
- Staged paths at audit start: 0

The published commit is the v4.8.1 repository-consolidation baseline. The
v4.9-v5.13 program exists only in the local working tree until the owner gives
separate explicit approval for the exact v5.13.1 allowlist.

## Phase Reconciliation

| Phase | Implemented result | Conservative decision |
| --- | --- | --- |
| v4.9 | Versioned detection taxonomy/rule contracts, causal features, strict five-view reliability evaluation, and truthful registry reporting. Controlled scenarios passed 24/24. | No supervised candidate passed every required split; external evidence remained failed. |
| v5.1 | Reproducible calibrated SOC queue artifact and governed lifecycle controls. | Artifact is usable only in `shadow_observation`; decision-support influence remains blocked. |
| v5.2 | Layered rule/anomaly/supervised/hybrid repair reached 288/288 controlled runs. | Controlled success did not override failed temporal/source/external gates. |
| v5.3 | Locked temporal, rolling, OOD, and source-aware diagnostics. | Temporal FPR remained near 1.0 and source holdout failed closed. |
| v5.4 | Immutable evidence roles, development-only manifest, private aggregate inspection, and drift state. | One-device and independent-label gaps remained. |
| v5.5 | Development-only supervised strategy comparison and IsolationForest reliability audit. | No candidate passed all chronological development gates. |
| v5.6 | Bounded processing of 773,551 private PAN-OS rows and assisted diagnostic repair. | Evidence was one-device and lacked independent human ground truth. |
| v5.7 | Frozen-candidate and independent-evidence qualification protocol. | Blind revalidation correctly remained pending without qualifying evidence. |
| v5.8 | Disabled-by-default governed shadow scoring with aggregate-only telemetry. | Rules remained alert-authoritative; scoring could not mutate alerts or responses. |
| v5.9 | Longitudinal aggregate shadow observations, retention controls, and acquisition protocol. | Collection stayed disabled by default and lifecycle stayed `shadow_observation`. |
| v5.10 | Bounded operational scope planner and eight acceptance observations. | Eight operational gates passed; quality warnings remained visible. |
| v5.11 | Root-cause drift diagnostics, hysteresis, privacy repair, and disabled cadence. | No always-on scheduler or automatic lifecycle advancement was introduced. |
| v5.12 | Versioned PAN-OS parser contracts and parser-profile-aware quality baselines. | Real SYSTEM evidence and generic/raw governed baselines remained unavailable. |
| v5.13 | Shared runtime parser-quality accounting for file, replay, UDP, durable, and scenario ingestion plus source operations and read-only historical impact preview. | History remained unchanged; supervised lifecycle remained `shadow_observation`. |

All 14 phase status documents, 14 T1-T20 records, and 14 commit allowlists
exist. Every T1-T20 record contains T1 through T20. Every phase allowlist path
exists, and their unique union covers 174 of the 177 paths changed at the start
of this closure.

## Changed-Path Classification

The final v5.13.1 review boundary contains 181 paths. The four-path increase
from the starting 177 consists only of this status record, its T1-T20 record,
the exact master allowlist, and the refreshed current-system state lock.

| Subsystem | Paths |
| --- | ---: |
| Alembic migrations | 3 |
| Backend configuration, data model, API, and schemas | 6 |
| Backend runtime services | 20 |
| Backend tests | 31 |
| CLI, validation, and release tooling | 23 |
| Detection and supervised ML | 16 |
| Governance, status, security, and product documentation | 44 |
| ML feature pipeline | 1 |
| Parser contracts and implementation | 2 |
| Playwright tests | 1 |
| React contracts and UI | 7 |
| Root configuration and documentation | 3 |
| Synthetic samples and non-secret lock manifests | 6 |
| T1-T20 change records | 15 |
| Taskboard records | 2 |
| Team startup tooling | 1 |
| **Total** | **181** |

Every path is listed exactly once and grouped by subsystem in
`docs/V5_13_1_COMMIT_ALLOWLIST.md`.

## Previously Uncovered Paths

| Path | Decision | Source evidence |
| --- | --- | --- |
| `atdr/app/services/private_log_preflight_service.py` | Include. It was omitted from earlier phase allowlists by documentation error. | Imported by v5.0/v5.4/v5.6 private-evidence services and CLI paths; directly tested by `atdr/tests/test_v50_real_paloalto_shadow_validation.py`; returns aggregate/redacted evidence only. |
| `atdr/app/services/suppression_service.py` | Include. It is a runtime optimization supporting cumulative detection work. | `detection_service.py` preloads active rules once and passes them to `matching_suppression`; existing API/RBAC/detection suites cover suppression behavior. |
| `scripts/start_system.ps1` | Include. It is a truthful startup usability repair. | Adds only wait/first-compile guidance before launching the existing four-component runtime; it changes no command, process, auth, or safety behavior. |

## Orphan, Duplicate, And Generated-File Audit

- Exact duplicate changed files: 0
- Changed files larger than 1 MiB: 0
- Total changed-file size at the starting audit: approximately 4.43 MiB
- Stale paths in the 14 phase allowlists: 0
- Missing paths in the 14 phase allowlists: 0
- Source modules without runtime, test, CLI, or governance references: 0 found
- Deletion candidates authorized by this closure: 0

The large `docs/tasks/tasklist-progress.html` file is generated but
intentionally tracked as the required supervisor-style taskboard view. The
versioned v4.9-v5.13 status/evaluator files are historical governance and
reproducibility records, not redundant runtime copies.

## Migration And Contract Audit

The cumulative additive migration chain is linear:

```text
b4c5d6e7f8a9
  -> c5d6e7f8a9b0  ML shadow observations
  -> d6e7f8a9b0c1  ML profile covering index
  -> e7f8a9b0c1d2  source parser-quality aggregate
```

Alembic reports one head: `e7f8a9b0c1d2`. The migrations add aggregate
observation storage, an index, and nullable/default-empty parser-quality
metadata. They do not reset or delete the configured database.

The changed React API calls match mounted FastAPI routes for source details,
historical reparse preview, shadow observation summary, operational acceptance,
monitoring diagnostics, and parser-quality diagnostics. TypeScript field names
match the corresponding Pydantic/service payloads. Final build, API, and
Playwright evidence is recorded below.

## Verification

The complete closure matrix passed on 2026-07-28:

- taskboard render and standards check: passed
- Ruff: passed with no findings
- compileall: passed for `atdr` and `migrations`
- full backend tests: `741 passed, 1 skipped`
- Alembic: one head/current revision `e7f8a9b0c1d2`; no drift
- React lint and production build: passed
- Playwright: `26 passed, 1 skipped`; the skip requires live hardware
- controlled scenarios: `24/24`, 15 expected alerts, zero unexpected-alert
  scenarios, zero missed-alert scenarios, and zero response actions
- layered validation: `288/288`, zero false positives, zero false negatives,
  and automation disabled
- deterministic assistant QA: `20/20`, citation pass rate `1.0`, unsafe
  refusal passed, and zero authoritative side effects
- replay dry-run: two safe sample rows parsed, zero sent/imported/written
- performance smoke on 145,232 rows: Overview `0.8749s`, cached Overview
  `0.0144s`, AI Governance `1.5028s`, alert list `0.0877s`, no warnings
- official release gate: `ok: true`, zero failed required checks, backend
  `741 passed, 1 skipped`
- diff, exact 181-path allowlist, privacy, ignored-file, staging, and tracked
  hygiene checks: passed

An initial full-test invocation used an unnecessarily long Windows temporary
path and produced four fixture path-length failures. The same tests passed
under a short external temporary root, and the official release gate also
passed the complete suite. This was an execution-environment path issue, not
an ATDR behavior failure.

## Safety State

- Deterministic rules remain alert-authoritative.
- IsolationForest and supervised output remain advisory.
- Supervised lifecycle remains `shadow_observation`.
- No label is created, overwritten, or represented as human-reviewed.
- No model is activated or promoted.
- No automatic response or real firewall blocking is enabled.
- No historical evidence is reparsed, reset, or deleted.
- No private path, raw evidence, IP address, credential, or secret is added to
  the tracked review boundary.

## Remaining Product Gaps

1. Independent, legitimately reviewed, multi-device and multi-period native
   PAN-OS evidence is required before supervised lifecycle advancement.
2. Real SYSTEM logs and long-duration real-device syslog forwarding remain
   unvalidated.
3. Generic syslog and raw fallback still need governed comparable baselines.
4. MFU IAM preproduction account/group, 2FA, recovery, and deprovisioning
   acceptance depend on the university provider.
5. Approved-host PostgreSQL, multi-worker, backup/restore, TLS, managed-secret,
   monitoring, load, and disaster-recovery validation remain external work.
6. Gemini privacy approval, key custody, quota/cost monitoring, and real SOC
   answer evaluation remain operational gates.
7. Real response integration requires a separately approved safety design.

## Completion Estimate

These are engineering estimates, not accuracy metrics:

- controlled academic/lab product: 90-95%;
- clean teammate/advisor release: 75-80% until this worktree is explicitly
  approved, published, CI-verified, and tested from a clean clone; and
- production-grade multi-user product: 55-65% because external evidence,
  provider, infrastructure, and operational-security gates remain.

The taskboard percentage is a workflow score and must not be presented as model
accuracy or production readiness.

## Recommended Next Phase

After explicit publication and clean-clone verification, proceed to **v5.14
Large-File Multi-Source Runtime Acceptance**. Exercise the v5.13 parser contract
through durable import, replay, and bounded UDP source flows on disposable
storage at realistic volume; measure progress, resumability, source quality,
deduplication, alert/case traceability, queue latency, and zero response
side-effects. Keep supervised ML in shadow observation unless independent
evidence gates pass.
