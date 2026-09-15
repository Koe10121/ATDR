# T1-T20: v5.28 Review Readiness and Gemini Productization

## T1 Change Title

v5.28 Blind Review Readiness and Gemini Analyst-Quality Productization.

## T2 Requirement

Complete every locally controllable improvement for supervised-review
readiness and Gemini Assistant quality without opening or contaminating the
sealed blind evidence, changing detection authority, or creating human labels.

## T3 Source Evidence

Source truth is the v5.21 sealed evidence contract, v5.26 frozen prediction
lock, v5.27 provenance-strict evaluator and bounded real-record Gemini suite,
registered supervised artifact metadata, Assistant service/configuration,
tests, governance documents, and release gates. Private rows, tokens,
fingerprints, paths, IPs, prompts, answers, and secrets stay outside tracked
evidence.

## T4 Current Behavior

Before v5.28, review had to be performed directly in the sealed CSV, runtime
readiness lacked one consolidated read-only audit, and provider operations had
bounded timeout fallback but no configurable visible-output budget, circuit
breaker, or aggregate cost/failure telemetry.

## T5 Impacted Areas/Agents

AI/ML governance, evidence custody, SOC Assistant, frontend dashboard,
privacy/security, QA/UAT, release operations, and documentation.

## T6 Scope

In scope: an ignored human-only working-copy helper, progress validation,
separate-copy locked intake, label-independent shadow audit, Gemini budgets,
retry/error/circuit behavior, aggregate telemetry, concise UI status, tests,
and governance records.

Out of scope: performing human review, exposing predictions, calculating early
blind metrics, retraining/selecting/recalibrating/activating/promoting a model,
changing authoritative rules, external deployment approval, response
automation, or real blocking.

## T7 Functional Requirements

- Preserve the sealed pack and protected evidence exactly.
- Never expose detector or AI suggestions to the reviewer.
- Save and resume only valid human review fields in an ignored working copy.
- Keep the review file non-importable and never import automatically.
- Withhold metrics before the fixed support and class gate.
- Audit shadow artifact, schema, calibration, abstention, latency, drift, and
  registry state without scoring blind evidence or mutating state.
- Bound provider output, retry safely, open a circuit after repeated failure,
  fall back deterministically, and record content-free aggregate telemetry.
- Keep all Assistant operations read-only and privacy-safe.

## T8 Acceptance Criteria

Synthetic tests prove sealed evidence stays unchanged, save/resume preserves
tokens/evidence, assisted or modified reviews fail closed, and no early metric
is calculated. The readiness audit returns no paths/hashes/private identifiers
and creates no labels/models/responses. Gemini passes citation, context,
concision, privacy, retry, circuit, fallback, and zero-mutation gates. Full
repository verification and exact-path hygiene pass.

## T9 API Contract

No public route changed. Safe CLIs were added:

```powershell
python -m atdr.scripts.run_v528_blind_review_helper --prepare --pretty
python -m atdr.scripts.run_v528_blind_review_helper --status --pretty
python -m atdr.scripts.run_v528_blind_review_helper --interactive --reviewer "<institutional-id>" --pretty
python -m atdr.scripts.run_v528_supervised_readiness_audit --no-write --pretty
```

The v5.27 evaluator adds optional `--review-file` for a separately completed
working copy. Assistant status adds non-secret budget, circuit, and aggregate
operational fields; existing clients remain compatible.

## T10 Data Model / Migration

No schema or migration changed. Review copies and generated diagnostics remain
ignored local evidence. Operational provider telemetry is process-local and
aggregate only.

## T11 Backend Plan / Changes

Add blind helper/validator and read-only readiness modules with CLI wrappers;
keep the sealed evaluator authoritative. Extend the provider adapter with
budgets, typed failures, bounded retries, circuit breaker, deterministic
fallback, and content-free aggregate telemetry.

## T12 Frontend Plan / Changes

Refresh Assistant status after chat, persist only bounded aggregate per-answer
usage, display concise provider health and token/fallback information, and
preserve existing context and overflow protections.

## T13 Security / Response / AI Safety

No blind predictions or AI suggestions reach the reviewer. No AI output is
called human ground truth. Raw logs, IPs, private paths, prompts, answers, and
secrets are excluded from telemetry and provider context. Rules stay alert-
authoritative; Assistant/ML stay decision support only; automatic response and
real blocking remain disabled.

## T14 Test Plan

Test working-copy integrity, save/resume, assisted/modified review rejection,
separate label source, early metric withholding, readiness no-write behavior,
visible answer budgets, aggregate telemetry privacy, rate-limit retry, circuit
breaker/fallback, frontend status rendering, and existing full regressions.

## T15 Implementation Summary

Implemented the private review workflow and progress contract without opening
the actual pack, added the read-only supervised readiness audit, hardened the
Gemini adapter and status surface, and updated the Assistant UI and governance.
Human review remains deferred at 0/40.

## T16 Tests Run / Evidence

Focused backend coverage passes 58 tests. Full backend/release coverage passes
`848 passed, 1 skipped`; Alembic reports no drift; React lint/build pass;
Playwright passes `27` with one intentional external live-source skip;
controlled scenarios pass `24/24`; layered validation passes `288/288` with
zero controlled FP/FN; deterministic Assistant QA passes `20/20`; replay
dry-run writes zero rows; performance smoke has no warnings; and the official
release gate returns `ok: true`.

The read-only audit confirms a valid registered calibrated ExtraTrees artifact,
fail-closed schema abstention, 14.7438 ms registered p95 latency, zero state
mutations, and no blind-evidence access. The configured Gemini evaluation
passes 12/12 checks over six calls, uses 21,999 aggregate tokens at
3,494.5/3,795 ms median/p95 latency, returns no raw logs/IPs/secrets/private
paths, and creates zero authoritative mutations. Performance on 145,232 rows
is warning-free: Overview 0.555 s cold / 0.0089 s cached, alerts 0.0542 s,
cases 0.025 s, and ML Governance 1.2401 s.

The cumulative changed-path boundary matches the v5.28 allowlist exactly at
`44/44`; staging is empty; `git diff --check` has no whitespace errors; private
evidence/output/model locations remain ignored; no sensitive artifact type is
tracked; and the allowlisted files contain no user-private path, provider-key
prefix, private key block, or populated secret material.

## T17 PRD / Docs Updated

v5.28 status, this T1-T20 record, reviewer guide, PRD, AI runbook, current
AI/ML status, traceability, compliance, taskboard, docs index, and exact
commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Predictive quality remains unknown because no independent human review exists.
One native source cannot prove source generalization. Automated Gemini checks
do not prove universal semantic usefulness. External blockers are a qualified
reviewer, second source/device, university/provider approval, and approved
deployment host.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes v5.28 modules/tests/docs and
reverts the bounded Assistant configuration/status additions. No database
migration or data rollback is required. Ignored review/report files remain
under owner custody and must never be committed.

## T20 Final Handoff

Human review may begin later with the v5.28 helper. The custodian must preserve
the sealed pack, keep predictions separate, and run the locked evaluator only
after the fixed review gate. Until then, retain shadow lifecycle and rule
authority. Complete human Assistant evaluation and provider-host governance
before any deployment-quality claim.
