# T1-T20: v5.64 Window-Aware Advisory Anomaly Redesign

## T1 Change Title

- Title: Window-Aware Advisory Anomaly Redesign
- Date: 2026-09-18
- Owner / acting agent: Codex under project-owner direction
- Related phase: v5.64

## T2 Requirement

Evaluate whether chronology, behavior context, cohort calibration, and OOD
abstention can improve advisory anomaly utility without weakening fixed gates
or changing runtime authority.

## T3 Source Evidence

Published v5.63.1 baseline `fea2857`, private CLI-only PAN-OS evidence,
committed controlled scenarios, current ignored artifact, rule engine, and
v5.61/v5.63.1 governance contracts.

## T4 Current Behavior

Rules are alert-authoritative. IsolationForest and hybrid output are advisory.
Supervised ML is unqualified and response is simulation-only.

## T5 Impacted Areas / Agents

Anomaly evaluation source, diagnostic CLI, focused backend tests, active AI/ML
status, runbook, PRD, traceability, compliance, taskboard, and documentation
index.

## T6 Scope

In scope: development-only anomaly comparison, drift, OOD, rule-overlap,
privacy, reproducibility, tests, and governance. Out of scope: model install,
supervised evidence access, database writes, alert changes, IAM, and response.

## T7 Functional Requirements

- Lock chronological fit/calibration/validation/untouched roles.
- Isolate duplicate families across roles.
- Compare all eight declared designs at four fixed queue targets (seven
  proved methodologically distinct; a dispatch defect that made the eighth,
  empirical percentile calibration, duplicate strategy 2 was found and fixed
  during code review and did not affect any gate, ranking, or decision).
- Measure application, action, direction, schema, time, behavior, OOD, drift,
  score buckets, rule overlap, and novel contribution.
- Never expose or write private evidence.
- Select at most one diagnostic candidate and install none.

## T8 Acceptance Criteria

Evidence preflight and privacy gates pass; fixed gates remain unchanged;
untouched holdout is excluded from selection; an unqualified result fails
closed; no artifact or authoritative state changes.

## T9 API Contract

No API change. The new interface is the read-only
`run_v564_window_aware_anomaly_redesign` CLI.

## T10 Data Model / Migration

No database model or migration change. Aggregate generated output is ignored.

## T11 Backend Plan / Changes

Add chronological context engineering, deterministic partitioning, boundary
quarantine, eight strategy adapters, empirical/cohort calibration, OOD
abstention, drift diagnostics, rule-overlap accounting, and no-install safety.

## T12 Frontend Plan / Changes

No frontend behavior change. Existing advisor wording remains accurate.

## T13 Security / Response / AI Safety

No path, raw line, address, identity, fingerprint, secret, or provider payload
is returned. No label/model/alert/response write path exists. Rules remain
authoritative and response remains simulation-only.

## T14 Test Plan

Test chronology, duplicate isolation, deterministic results, private-data
redaction, OOD abstention, fixed protocol, no installation, unchanged artifact,
and zero authoritative side effects, then run the complete project matrix.

## T15 Implementation Summary

Fifty thousand rows produced 49,883 trainable rows and four valid roles. The
best diagnostic reached 0% benign anomaly, 85.71% suspicious capture, 50%
malicious capture, and 2.75% validation queue rate. It failed the malicious
gate and was not frozen or installed.

## T16 Tests Run / Evidence

Focused v5.64 tests pass (8, after adding duplicate-disclosure coverage). Full
taskboard, backend (`1126 passed, 1 skipped`), migration, frontend
(lint/build/Playwright `45 passed, 1 skipped`), scenario, Assistant, replay,
performance, audit, security, and release checks (`verify_release` ok) all
ran on 2026-09-18 and passed.

A post-implementation code review found and fixed two correctness defects in
`v564_window_aware_anomaly.py`, verified before and after against the full
focused suite: (1) the `empirical_percentile_calibration` strategy's mode was
never matched by `_strategy_scores`' dispatch and silently computed the same
result as `robust_scaled_global_isolation_forest`; fixed with an explicit
branch, a `STRATEGY_KNOWN_DUPLICATES` disclosure, and a `duplicate_of_strategy`
field on every candidate report. (2) records built by this module use the key
`schema_profile`, but the legacy `evaluate_private_model` comparison path
(used only in the informational `current_artifact` diagnosis, not in
`_candidate_gates`) groups by `_schema`; the key was missing, so
`current_artifact.private_holdout.queue_by_schema` silently bucketed every
row as unknown. Fixed by setting both keys. Neither defect touched
`_candidate_gates`, `_rank`, or `_improves_current`, so the 0/32 no-candidate
decision and every reported controlled/private number are unaffected.

## T17 PRD / Docs Updated

v5.64 status, current state locks, AI runbook, PRD, traceability, compliance,
docs index, taskboard, HTML board, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

One unlabeled source cannot establish anomaly false-positive rate or concept
drift. C2-like cadence overlaps routine repeated traffic. Rule overlap is
99.01% for the best candidate, so blind threshold tuning is rejected.

## T19 Release / Rollback

The evaluator is additive and has no runtime integration. Removing its module,
CLI, test, and docs fully rolls it back. No commit or push is authorized here.

## T20 Final Handoff

Keep the current artifact advisory and unchanged. Do not tune against the
untouched role. Resume anomaly research only with new evidence or a declared
new representation; otherwise proceed to final detection truth/handoff.

