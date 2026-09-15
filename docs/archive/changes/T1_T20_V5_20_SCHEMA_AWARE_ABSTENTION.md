# T1-T20: v5.20 Schema-Aware Abstention

## T1 Change Title

v5.20 Schema-Aware Abstention.

## T2 Requirement

Prevent governed supervised ML from producing confident decisions for evidence
that does not satisfy the native PAN-OS feature contract, while preserving rule
authority and the immutable v5.19 result.

## T3 Source Evidence

- `atdr/app/detection/schema_contracts.py`;
- governed v5.1 scoring and v5.8 aggregate shadow runtime;
- v5.19 terminal protocol state and public aggregate result;
- alert explanation and ML evidence snapshot services;
- React Alerts and AI Governance surfaces; and
- existing lifecycle, shadow, explanation, and frontend tests.

## T4 Current Behavior

Before v5.20, missing feature values were measured after `predict_proba`. The
v5.19 flow-schema failure showed that imputation could still yield a confident
queue decision for incompatible evidence.

## T5 Impacted Areas/Agents

Detection, supervised ML governance, backend services, alert explanation,
frontend AI Governance/Alerts, QA, privacy, documentation, and orchestration.

## T6 Scope

Add a versioned pre-inference compatibility gate, explicit abstention contract,
aggregate telemetry, UI status, terminal v5.19 lock audit, tests, docs, and an
exact cumulative publication boundary. No detector thresholds, labels, model
artifacts, database schema, response authority, or startup command changes.

## T7 Functional Requirements

- Validate schema and required native fields before model inference.
- Never return a supervised probability for incompatible evidence.
- Preserve deterministic rule execution and alert authority.
- Return privacy-safe status, reason codes, and missing field names.
- Preserve legacy Palo Alto rows while still applying required-field checks.
- Lock v5.19 without reopening labels or frozen prediction rows.

## T8 Acceptance Criteria

Native complete PAN-OS rows score; generic, provider-flow, raw-fallback,
unknown, parser-failed, and incomplete rows abstain. Alert/UI output must not
represent abstention as a zero-score benign decision. Tests must prove zero
authoritative side effects and the full verification matrix must pass.

## T9 API Contract

Existing routes remain unchanged. Supervised prediction and alert-detection
summary payloads add `schema_compatibility`, `abstained`,
`abstention_reason_codes`, and `missing_required_features`. The ML evidence
snapshot advances to schema `1.1` and adds aggregate `schema_aware_abstention`.

## T10 Data Model / Migration

No database model or Alembic migration.

## T11 Backend Plan / Changes

- Add the v5.20 compatibility contract.
- Gate legacy and governed inference before `predict_proba`.
- Filter aggregate shadow inference to compatible rows.
- Add process telemetry for checks and abstentions.
- Project the result into alert explanations and ML evidence snapshots.
- Add a read-only terminal-lock validation CLI.

## T12 Frontend Plan / Changes

Show the fail-closed schema gate and aggregate counts in AI Governance. Show
**Abstained**, schema status, and missing field names in alert detail instead of
a false threat score. Preserve responsive layout and collapsible technical
policy details.

## T13 Security / Response / AI Safety

No raw logs, IPs, paths, fingerprints, labels, or secrets are returned by the
runtime/API contract. Private lock fingerprints remain ignored locally. Rules
remain authoritative; model activation/promotion, automatic response, and real
blocking remain disabled.

## T14 Test Plan

- Complete/legacy native PAN-OS compatibility.
- Generic/provider/raw/unknown/incomplete abstention.
- Mixed batch scores only compatible rows.
- No labels/model/detection/alert/response writes.
- Alert explanation and AI Governance visibility.
- Terminal v5.19 files remain byte-for-byte unchanged.
- Frontend lint/build and Playwright no-misleading-score checks.

## T15 Implementation Summary

v5.20 moves schema checking ahead of supervised inference. Runtime outputs now
distinguish model abstention from a prediction, aggregate shadow telemetry counts
only actually scored rows, alert explanations show the missing contract, and AI
Governance exposes the fail-closed policy.

## T16 Tests Run / Evidence

Focused backend `25 passed`, supervised regression `39 passed`, full backend
and release-gate backend `795 passed, 1 skipped` each, Alembic no-drift,
frontend lint/build, Playwright `27 passed, 1 skipped`, controlled detection
`24/24`, layered detection `288/288`, Assistant QA `20/20`, replay dry-run,
warning-free performance smoke, read-only v5.19 terminal lock, and release gate
`ok=true` all passed. Exact boundary, diff, privacy, ignored-evidence, staging,
and tracked-hygiene checks are recorded at closure.

## T17 PRD / Docs Updated

v5.20 status, this T1-T20 record, PRD, traceability, compliance, current state,
AI/ML status, training/lab runbooks, docs index, taskboard/rendered HTML, and
cumulative exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Compatibility does not improve model accuracy; it prevents unsupported claims.
Legacy rows infer the established Palo Alto default when parser metadata is
absent. Native independently labeled PAN-OS evidence, a second real device, and
provider/deployment approvals remain external.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes the v5.20 module/CLI/tests/UI
changes and documentation. No database rollback is required. Because v5.19 is
still uncommitted, publication requires the cumulative exact allowlist.

## T20 Final Handoff

Keep lifecycle `shadow_observation` and rules alert-authoritative. Proceed to
v5.21 native PAN-OS evidence preparation without using v5.19 final labels for
tuning and without representing assisted suggestions as human review.
