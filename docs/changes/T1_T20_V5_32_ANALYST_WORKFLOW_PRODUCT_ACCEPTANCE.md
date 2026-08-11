# T1-T20: v5.32 Analyst Workflow Product Acceptance

## T1 Change Title

v5.32 Analyst Workflow, Dashboard, and Assistant Product Acceptance Lock.

## T2 Requirement

Demonstrate a reliable, concise analyst workflow from supported startup and
source visibility through alert/log/case investigation, evidence-grounded
Assistant guidance, and audited simulated response. Add an honest operational
detection view without presenting workload as accuracy.

## T3 Source Evidence

Runtime truth is the lifecycle scripts, FastAPI routers/services/models, React
routes/pages/API types, backend tests, Playwright suites, release gate, current
AI/ML status, and lab runbook. Existing configured-database measurements are
aggregate and read-only; no private evidence is copied into tracked files.

## T4 Current Behavior

Startup, investigation links, Assistant context replacement/persistence,
Gemini/fallback truthfulness, response safety, and responsive UI already had
strong automated coverage. Overview exposed alert and ingestion totals but did
not combine rule volume, distinct source-linked alerts, dispositions,
occurrences, dedup updates, parser context, and run trends into one clearly
non-accuracy operational surface. One dashboard document still described the
retired Streamlit-first path.

## T5 Impacted Areas / Agents

Dashboard backend, React Overview, TypeScript contracts, frontend/backend QA,
performance, AI/response safety, runbook, traceability, and governance records.
Detection rules, model training, IAM provider behavior, response authority,
schema, and startup commands are not changed.

## T6 Scope

In scope: source audit, runtime acceptance, cached aggregate projection,
compact Overview UI, Assistant/context regression, multi-viewport regression,
performance ceiling, documentation, and exact review boundary.

Out of scope: database reset, model retraining/activation/promotion, new labels,
external provider enrollment, automatic response, real blocking, fake data,
and production claims.

## T7 Functional Requirements

- Preserve supported outer-shell startup and health diagnostics.
- Keep alert/log/source/case deep links entity-correct.
- Preserve Assistant entity context across navigation and replace/reset it for
  explicit or broad requests.
- Keep Assistant answers concise, cited, provider-truthful, redacted, and
  mutation-free.
- Show rule/source/disposition/dedup/parser/run operational evidence.
- Count each source-linked alert distinctly despite repeated evidence rows.
- Mark unavailable accuracy as insufficient evidence.
- Preserve dashboard cache/query ceilings and responsive/keyboard behavior.

## T8 Acceptance Criteria

Focused backend and browser tests pass; complete Playwright workflow passes;
source volume is distinct by alert; workload is not labeled accuracy; Assistant
context, citations, concision, provider state, and zero mutations remain
locked; response automation remains disabled; the full repository matrix and
hygiene checks pass.

## T9 API Contract

`GET /api/dashboard/summary` gains the additive optional
`detection_operations` object. Existing keys and routes remain unchanged. The
new object contains aggregate counts and status text only; it contains no raw
logs, IPs, credentials, secrets, or model-accuracy claim.

## T10 Data Model / Migration

No model, schema, index, or migration change. Existing records are read through
portable SQLAlchemy statements. The configured database is neither reset nor
mutated.

## T11 Backend Plan / Changes

Consolidate existing alert severity/status/type/occurrence accounting into one
scan, add a distinct source-alert aggregate, project explicit parser and
accuracy-evidence states, and keep the existing application cache and query
signature behavior.

## T12 Frontend Plan / Changes

Add a compact Overview Detection Operations section with four workload metrics,
primary rule/source/disposition lists, parser context, an explicit insufficient-
evidence accuracy note, and a collapsed recent-run table. Preserve the current
MFU-compatible visual system, responsive constraints, deep links, and technical
detail hierarchy.

## T13 Security / Response / AI Safety

Rules remain alert-authoritative. IsolationForest and supervised ML remain
advisory; lifecycle remains `shadow_observation`. Gemini and deterministic
Assistant modes remain read-only. No label/model/user/detection/response write
is introduced. Automatic response and real firewall blocking remain disabled.

## T14 Test Plan

Run targeted dashboard/Assistant/explainability tests, PostgreSQL statement
compilation, cache query-count and response-equality tests, React lint/build,
smoke and integrated Playwright, complete backend tests, Alembic, controlled
and layered detection, Assistant QA, replay dry-run, performance smoke, release
gate, taskboard checks, npm audit, and repository hygiene.

## T15 Implementation Summary

Added the cached `detection_operations` projection, distinct source alert
volume, consolidated alert accounting, compact Overview surface, backend
semantic/mutation regression, browser assertions, corrected React-first
dashboard documentation, and v5.32 governance records.

## T16 Tests Run / Evidence

Assistant/explanation/workflow backend `58 passed`; v5.32/dashboard
performance `8 passed`; full backend `873 passed, 1 skipped`; Alembic no drift;
React lint/build passed; npm audit `0`; Playwright `31 passed, 1 skipped`;
controlled detection `24/24`; layered detection `288/288`; Assistant QA
`20/20`; replay dry-run passed; and performance smoke passed without warnings.
The official release gate returned `ok: true` with no failed required checks.
The 145,232-row profile stayed at 33 cold/1 warm queries; current smoke timings
are Overview `0.3602s`, cached `0.0131s`, ML Governance `0.2944s`, alert list
`0.0391s`, and case summary `0.0632s`. A too-long Windows pytest temp path
caused one backup-copy failure; the test and full suite pass under short
`C:\t` roots.

## T17 PRD / Docs Updated

Updated the ATDR PRD, traceability matrix, lab runbook, current AI/ML status,
dashboard product path, taskboard, and rendered taskboard. Added the v5.32
status, this T1-T20 record, and exact commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Operational volume cannot establish accuracy. A large-SQLite first cold-disk
summary remains slower than the cached path. Independent native labels,
another real source, human Assistant review, MFU/provider acceptance, and
managed-host operations remain external blockers. These do not justify fake
metrics, weaker gates, or unsafe response authority.

## T19 Release / Rollback

No staging, commit, or push is authorized by this change. Rollback is source-
only across the exact allowlist; no migration downgrade or data rollback is
required.

## T20 Final Handoff

Use the supported shell launcher, inspect Detection Operations, trace one
source/alert/log/case, exercise contextual Assistant follow-ups, and verify an
analyst-approved simulated response/audit. Describe the result as controlled
lab product acceptance, not production readiness or measured field accuracy.
