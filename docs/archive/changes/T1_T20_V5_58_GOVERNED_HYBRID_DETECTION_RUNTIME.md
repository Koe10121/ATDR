# T1-T20: v5.58 Governed Hybrid Detection Runtime Closure

## T1. Requirement

Close the local hybrid detection runtime with explicit authority, advisory,
abstention, and simulation states without activating an unqualified model.

## T2. Source Evidence

Primary source is `detection_service.py`, `rules.py`, `ml_detector.py`,
`supervised_detector.py`, `v51_supervised_lifecycle.py`, `explanations.py`, the
ML router, Assistant service, React AI Governance/Alerts pages, and v5.49b/v5.45
aggregate governance records.

## T3. Runtime Trace

Traced ingestion through parsing, normalization, advisory scoring,
rule-authoritative alerts, explanations, dashboard, Assistant, simulation, and
audit. Normal ML-enabled detection invokes rules and IsolationForest and checks
supervised eligibility.

## T4. Authority Contract

Rules are `active_authoritative`. Anomaly and hybrid are advisory. Supervised
may be `active_shadow` only after every gate passes. Response is
`simulation_only`.

## T5. Supervised Decision

v5.49b selected no candidate and is consumed. The effective runtime is
`unqualified`; historical `shadow_observation` metadata is not authorization.

## T6. Candidate Repair

The private-path v5.45 development repair ran in disposable mode. Its leader
passed `0/3` strict views, so no candidate was frozen, written, activated, or
promoted.

## T7. Artifact Safety

Runtime authorization validates registered version, target, feature schema,
calibration, threshold, provenance, strict gates, shadow safety, artifact
availability, and checksum. Missing evidence fails closed.

## T8. Legacy Safety

Normal predictions do not silently load the legacy artifact. Explicit legacy
diagnostics remain labeled and cannot affect alerts or response.

## T9. Status Safety

Lifecycle and registry status are read-only by default and do not execute the
historical shadow scorer.

## T10. Detection Job Output

Detection runs persist bounded layer state in run and audit details. Advisory
failure does not stop deterministic evaluation. The aggregate contract includes
bounded matched rule IDs, anomaly score/limitations, supervised confidence and
abstention state, hybrid analyst priority, evidence strength, missing context,
and up to three analyst checks.

## T11. Explanation

Alert explanations separate rule authority, anomaly evidence, supervised
runtime/abstention, hybrid interpretation, evidence strength, missing context,
and analyst checks.

## T12. Assistant

Deterministic and Gemini-assisted answers use the same bounded state and cannot
invent supervised availability or perform actions.

## T13. API

`GET /api/ml/runtime-status` is authenticated and exposes safe aggregate state
without paths, hashes, fingerprints, evidence, identities, or secrets.

## T14. Frontend

AI Governance displays the five runtime layers and effective registry state.
Alert triage presents a supervised signal rather than implying an active model.

## T15. Tests

Coverage includes negative-decision precedence, complete future gate checks,
metadata failure, explicit active/advisory/unavailable/abstained states,
read-only lifecycle status, legacy refusal, normal layer invocation, advisory
failure fallback, API auth/privacy, registry clarity, Assistant consistency,
responsive UI behavior, and accessible chart labels.

## T16. Data Integrity

No database reset, label write, protected review access, v5.49b rerun, active
artifact write, automatic response, or real blocking occurred.

## T17. Privacy

Private sample paths, rows, raw logs, IPs, identities, fingerprints, provider
payloads, and secrets are excluded from tracked output.

## T18. Verification

Complete verification passes: focused runtime `10/10`; backend and independent
release runs each `1077 passed, 1 skipped`; Playwright `42/1`; deterministic
`24/24`; layered `288/288` with FP/FN `0/0`; Assistant `30/30`; taskboard,
Ruff, compileall, Alembic, React lint/build, replay, performance, security,
runtime inspection, deployment operations, release, diff, and hygiene checks.
Live-source, MFU IAM, Gemini, PostgreSQL, and deployment preflights preserve
their external boundaries without leaking or writing private state. The exact
boundary is recorded in the v5.58 allowlist; staging remains empty.

## T19. Rollback

Revert the v5.58 source and documentation paths. No schema or data rollback is
required because the phase adds no migration and writes no governed state.

## T20. Handoff

Proceed to v5.59 repository consolidation. Keep external owner tracks pending
and do not activate supervised scoring until a new candidate passes every
predeclared gate and receives separate approval.
