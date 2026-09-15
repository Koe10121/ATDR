# T1-T20: v5.27 Blind Review And Gemini Real-Alert Quality

## T1 Change Title

v5.27 Independent Blind Review Intake and Gemini Real-Alert Quality Evaluation.

## T2 Requirement

Add a provenance-strict human-review intake and read-only evaluator for the
frozen v5.26 blind predictions, and evaluate the configured Gemini Assistant
against bounded existing dashboard evidence without authoritative mutation.

## T3 Source Evidence

Source truth is the v5.21 blind pack and manifest, v5.26 private prediction
lock and qualification record, Assistant service/LLM contracts, current
database models, v5.24 quality evaluator, tests, and release gates. Private
rows, tokens, fingerprints, paths, IPs, and secrets remain outside tracked
evidence.

## T4 Current Behavior

Before v5.27, v5.26 could freeze predictions and withhold metrics, but its
post-label checks did not fully reject assisted provenance, prediction
exposure, incomplete review metadata, duplicate tokens, or lock-identity
changes. Gemini had passed a controlled synthetic quality lock but lacked a
fresh bounded evaluation derived from current dashboard records.

## T5 Impacted Areas/Agents

Detection engineering, AI/ML governance, evidence custody, SOC Assistant,
privacy/security, QA/UAT, release operations, and documentation.

## T6 Scope

In scope: blind-review validation, private integrity seal, locked metric and
aggregate error evaluation, disposable real-record Assistant snapshots,
Gemini quality checks, fallback, tests, and governance.

Out of scope: creating human labels, rerunning v5.26 predictions, tuning on the
blind pack, model activation/promotion, raw-log provider context, response
execution, real blocking, or production claims.

## T7 Functional Requirements

- Reject incomplete, assisted, automated, weak, or prediction-exposed reviews.
- Match pack and prediction-lock identities privately without returning hashes.
- Calculate metrics only with legitimate support and both queue classes.
- Never rerun frozen predictions or write labels/model artifacts.
- Derive a bounded Assistant snapshot from existing records while replacing
  raw values, IPs, source names, and user fields.
- Verify citations, context, evidence, concision, unsupported IDs, fallback,
  privacy, latency/tokens, and zero authoritative mutation.

## T8 Acceptance Criteria

The unreviewed pack yields zero valid decisions and no metrics; valid synthetic
test reviews enable locked metrics; compromised reviews fail closed; Gemini
uses the configured provider for the bounded set; every fixed quality/safety
gate passes; configured database counters remain unchanged; no secret or
private evidence appears in output.

## T9 API Contract

No public API changed. Two safe CLIs were added:

```powershell
python -m atdr.scripts.run_v527_blind_review_evaluation --pretty
python -m atdr.scripts.run_v527_gemini_real_alert_quality --execute-provider --pretty
```

## T10 Data Model / Migration

No schema or migration changed. Review seals and evaluation reports remain in
ignored local evidence. Assistant evaluation uses disposable in-memory SQLite.

## T11 Backend Plan / Changes

Add a strict review validator and frozen-lock evaluator. Add a real-record
snapshot builder and Assistant evaluator that reuses existing deterministic
grounding, provider adapter, quality checks, and failure fallback.

## T12 Frontend Plan / Changes

No frontend behavior changed. Existing Assistant status, citations, context,
and safety badges remain the runtime interface.

## T13 Security / Response / AI Safety

No predictions are exposed to the reviewer. No AI output is treated as human
ground truth. Gemini receives no raw logs, IPs, source names, secrets, or
private paths. The Assistant stays read-only; rules stay alert-authoritative;
automatic response and real blocking stay disabled.

## T14 Test Plan

Test empty-review withholding, valid locked joins, no prediction rerun,
assisted/prediction-exposed rejection, duplicate/lock mismatch, bounded mock
provider quality, real-record privacy, citations, context, forced fallback,
zero mutations, and no-alert fail-closed behavior. Run the complete repository
matrix after documentation synchronization.

## T15 Implementation Summary

Implemented two independent v5.27 evaluators. Blind intake currently reports
0 valid and 40 unreviewed rows, so metrics remain unavailable. The bounded
Gemini run passed 12/12 checks across six calls over disposable snapshots of
current records.

## T16 Tests Run / Evidence

Focused v5.27 tests pass `8/8`. Blind preflight confirms every lock check and
withholds metrics. Live Gemini used six calls, passed all 12 checks, recorded
3,521.5 ms median and 3,878 ms P95 latency with 21,973 tokens, and produced zero
configured-database or authoritative disposable mutations. The complete
closure matrix passes: backend/release `840 passed, 1 skipped`, Alembic no
drift, React lint/build, Playwright `27 passed, 1 skipped`, controlled `24/24`,
layered `288/288`, Assistant `20/20`, replay dry-run, warning-free performance,
official release `ok: true`, and exact cumulative hygiene checks.

## T17 PRD / Docs Updated

v5.27 status, reviewer guide, this T1-T20 record, PRD, traceability,
compliance, runbooks, current AI/ML status, docs index, taskboard, and exact
commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

The pack has no genuine human decisions, so supervised quality remains
unknown. One source cannot prove source generalization. Gemini checks are
bounded automated contracts, not universal semantic proof. Human review,
second-source evidence, provider governance, and approved deployment remain
external.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes the v5.27 source/test/docs
files and v5.27 appendices. It requires no database migration or data rollback.
Ignored seals/reports remain under owner custody and must not be committed.

## T20 Final Handoff

Provide only the blind CSV and reviewer guide to a qualified independent human.
After review, run the locked evaluator once without rerunning predictions.
Do not tune on that pack. Keep the Assistant read-only and complete human
semantic/privacy plus provider-operations acceptance before deployment claims.
