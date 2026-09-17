# T1-T20: v5.63.1 Advisor Demonstration Reliability Lock

## T1 Change Title

- Title: Controlled-Lab Detection and Advisor Demonstration Reliability Lock
- Date: 2026-09-17
- Owner / acting agent: Codex under project-owner direction
- Related version or sprint: v5.63.1

## T2 Requirement

Make the current ATDR workflow reliable, accurate in its claims, concise, and
demonstrable with available resources while deferring MFU provider acceptance,
second-device evidence, and physical-firewall validation.

## T3 Source Evidence

| Source | Evidence |
| --- | --- |
| Runtime | FastAPI services, React analyst routes, SQLAlchemy/Alembic, and normal MFU shell entry |
| Detection | 19-rule catalog, controlled source scenarios, layered 288-case suite |
| Anomaly | existing ignored IsolationForest artifact, v5.61 bootstrap contract, private CLI-only development source |
| Assistant | deterministic grounding, bounded history, response contracts, Gemini adapter, QA corpus |
| Safety | v5.58 rules-authoritative contract and response simulation policy |

## T4 Current Behavior

Rules create explainable alerts. IsolationForest and hybrid evidence remain
advisory. Supervised runtime is unqualified. The Assistant is read-only and
can use Gemini when privately configured. Response is simulated.

## T5 Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| ML telemetry | scored-row rate, scoring coverage, and stored-row prevalence separated |
| Anomaly evaluation | private-safe chronological diagnostics and fixed candidate gates |
| Acceptance | one disposable advisor workflow command |
| Frontend | explicit anomaly denominator and coverage wording |
| Tests | telemetry, privacy, manifest, candidate refusal, acceptance composition |
| Docs | status, runbook, PRD, traceability, taskboard, allowlist |

## T6 Scope

In scope: telemetry correctness, development-only anomaly comparison, safe
Gemini probe, Assistant QA, advisor acceptance, minimal UI wording, tests,
docs, and verification. Out of scope: supervised activation, external IAM
completion, real blocking, private evidence publication, and production claims.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-5631-01 | Distinguish anomaly rate, scoring coverage, and stored prevalence | Must |
| FR-5631-02 | Inspect private evidence without exposing source details | Must |
| FR-5631-03 | Compare fixed anomaly feature/threshold variants | Must |
| FR-5631-04 | Install no candidate unless every fixed gate passes | Must |
| FR-5631-05 | Validate concise grounded Assistant behavior and Gemini safety | Must |
| FR-5631-06 | Verify the complete advisor workflow in disposable storage | Must |
| FR-5631-07 | Preserve rule authority and simulated response | Must |

## T8 Acceptance Criteria

The dashboard must name the anomaly denominator; private output must contain
no path, raw record, address, identity, fingerprint, or secret; unqualified
candidates must not be installed; Gemini must exclude raw logs and secrets;
the disposable advisor workflow must pass; and authoritative database/model/
response state must remain unchanged.

## T9 API Contract

Existing ML status/profile/report responses add `scored_log_count`,
`anomaly_rate_basis`, `scoring_coverage_percent`, and
`stored_anomaly_prevalence_percent`. Existing fields remain available.

## T10 Data Model / Migration

No database schema or migration change. Candidate models and manifests remain
ignored local artifacts. Diagnostic output is stdout-only.

## T11 Backend Plan / Changes

Correct ML aggregate denominators; add v5.63.1 private-safe reliability
evaluation; support a stricter governed reliability manifest; retain atomic
rollback replacement; add the disposable advisor acceptance command.

## T12 Frontend Plan / Changes

Show scoring coverage on the AI Governance page and label anomaly rate as
"Among scored logs only." Use the same denominator wording in Detection
Tuning. No navigation or interaction redesign is required.

## T13 Security / Response / AI Safety

- Private paths enter only through CLI arguments.
- Public reports contain aggregate application/schema/window data only.
- No sealed supervised labels are accessed.
- Candidate installation fails closed.
- Gemini receives no raw logs and IP redaction remains enabled.
- Rules remain authoritative; response remains `simulation_only`.

## T14 Test Plan

Test scored-row denominator math, response-model compatibility, reliability
manifest gates, private-output redaction, unqualified install refusal, safe
error handling, disposable advisor acceptance, live-provider safety, and UI
denominator wording.

## T15 Implementation Summary

The former 0.98% value was stored-row prevalence at 41.47% score coverage. The
correct current scored-row anomaly rate is 2.36%. Eight private-development
variants were compared; none passed controlled suspicious/malicious capture
gates, so no candidate was selected or installed. The advisor acceptance
passes all ten stages, and the live Gemini probe returns safe structured output.

## T16 Tests Run / Evidence

Focused v5.61/v5.63.1 backend tests pass 14/14. The full backend suite passes
`1119 passed, 1 skipped`, including a second successful release-gate run.
Playwright passes `45 passed, 1 skipped`. The disposable advisor acceptance
passes 10/10 stages and 24/24 workflow checks. Layered detection passes
288/288 with zero controlled FP/FN. Assistant QA passes 30 cases and follow-up
continuity with 56.1 average words. Taskboard, Ruff, compileall, Alembic,
frontend lint/build, replay dry-run, performance, repository, security, and
release checks all pass.

## T17 PRD / Docs Updated

v5.63.1 status, advisor runbook, current state/AI status, training runbook,
presentation brief, PRD, traceability, compliance, docs index, taskboard,
HTML board, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

The legacy anomaly artifact is usable but has incomplete governed provenance
and weak controlled reliability. A quiet new model that misses threat
scenarios is worse, so replacement is refused. Supervised qualification still
requires genuine reviewed evidence. External IAM/device/deployment acceptance
is deferred by project-owner decision.

## T19 Release / Rollback

The runtime telemetry change is additive and reversible. No database
migration, active supervised artifact, or response policy changes. The
existing anomaly artifact remains untouched. No commit or push is authorized
by this record.

## T20 Final Handoff

Use `run_v5631_advisor_demo_acceptance --use-temp-db
--execute-provider-probe --pretty` before the presentation, then follow
`docs/ADVISOR_DEMO_RUNBOOK.md`. ATDR is advisor-demo ready. Two meaningful
internal detection phases remain:
window-aware anomaly redesign and governed supervised qualification after
genuine review.
