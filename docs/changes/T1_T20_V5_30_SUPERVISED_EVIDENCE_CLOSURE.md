# T1-T20: v5.30 Supervised ML Evidence Closure

## T1 Change Title

v5.30 Supervised ML Evidence Closure and Promotion-Readiness Decision.

## T2 Requirement

Reconcile configured labels, native PAN-OS roles, sealed blind evidence,
external transfer evidence, registered shadow state, and frozen diagnostic
candidate evidence into one conservative decision without training, label
writes, activation, promotion, or response authority.

## T3 Source Evidence

Source truth is the v5.19-v5.29 detection/evidence code and ignored locks,
`MLLabel`/`MLModelRun`, supervised lifecycle and readiness services, AI
Governance, tests, runbook, current AI/ML status, and the private PAN-OS file
supplied only as a CLI argument. No private path, row, IP, fingerprint, review,
artifact, database, or secret is tracked.

## T4 Current Behavior

Before v5.30, evidence truth was distributed across v5.19-v5.28 reports. The
registered v5.1 shadow artifact and the artifact-free v5.22 frozen diagnostic
candidate could be confused, and no single report declared which counts and
metrics were eligible for promotion claims.

## T5 Impacted Areas/Agents

AI/ML Governance, evidence custody, detection engineering, database audit,
security/privacy, QA/UAT, documentation, and release governance.

## T6 Scope

In scope: canonical provenance inventory, lock/leakage audit, read-only shadow
diagnostics, fixed gates, disposable private aggregate preflight, conservative
decision, CLI, tests, and governance records.

Out of scope: label creation/overwrite, model training/recalibration,
artifact writing, activation/promotion, alert authority changes, response
automation, real blocking, schema/API changes, and synthetic human review.

## T7 Functional Requirements

- Count one latest trainable label per log and separate human provenance from
  assisted/weak evidence even when `reviewed=true`.
- Reconcile development, calibration, threshold, locked future, external,
  synthetic, blind, and quarantine roles.
- Verify frozen-before-label, duplicate containment, future/blind exclusion,
  and no post-reveal tuning.
- Score only the registered shadow artifact read-only and label every result
  non-independent when overlap cannot be excluded.
- Withhold all promotion metrics until independent native support exists.
- Inspect private evidence only through CLI-supplied disposable storage.
- Return no private path, raw row, IP, fingerprint, reviewer identity, or
  secret.

## T8 Acceptance Criteria

Canonical counts reproduce current source truth; all custody checks pass;
assisted evidence is never counted as human; source/time limitations fail
closed; registered diagnostics include calibration, queue, class recall,
abstention, duplicate, and split results; private preflight is aggregate-only;
and database/model/response state is unchanged.

## T9 API Contract

No API route changes. The new interface is the local CLI
`python -m atdr.scripts.run_v530_supervised_evidence_closure`. It supports an
optional `--sample-path` plus mandatory `--use-temp-db`, report/output controls,
and an option to skip current-shadow diagnostics.

## T10 Data Model / Migration

No model or migration changes. The audit reads existing SQLAlchemy entities
and generated ignored evidence locks only.

## T11 Backend Plan / Changes

Add a v5.30 evidence-closure module that inventories labels, reads safe lock
summaries, audits provenance/leakage, scores the registered artifact without
training, computes non-promotion split/calibration diagnostics, invokes the
existing disposable PAN-OS preflight, applies fixed gates, and writes ignored
aggregate reports.

## T12 Frontend Plan / Changes

No frontend behavior change was required. AI Governance already exposes
lifecycle, artifact/calibration status, source-independence limitation,
evidence sufficiency, reliability blockers, rule authority, and disabled
automation without raw evidence.

## T13 Security / Response / AI Safety

No labels, models, alerts, detections, responses, or users are changed. The
private source path is accepted only at the CLI boundary and omitted from
output. Raw rows, IPs, identifiers, fingerprints, and secrets are excluded.
Rules remain authoritative; automatic response and real blocking remain
disabled.

## T14 Test Plan

Test human/assisted provenance separation, one-latest-label accounting,
source/time grouping, duplicate-safe diagnostics, fixed fail-closed gates,
private projection redaction, zero model/response writes, no review-pack
generation, and unchanged lifecycle authority.

## T15 Implementation Summary

Implemented the read-only v5.30 service and CLI, fixed promotion gates,
canonical evidence inventory, 15-check custody audit, registered shadow
diagnostics over current human-provenance rows, external/native candidate
separation, disposable private preflight projection, and conservative
promotion decision.

## T16 Tests Run / Evidence

Taskboard render/check, repository Ruff, compileall, Alembic no-drift, React
lint/build, zero-vulnerability npm audit, Playwright `31 passed, 1 skipped`,
controlled scenarios `24/24`, layered validation `288/288`, Assistant QA
`20/20`, rule/scenario contract, replay dry-run, warning-free performance, and
the official release gate all passed. Full backend tests passed `856 passed, 1
skipped` independently and again inside the release gate. Focused v5.30 tests
passed `4`, the registered-shadow diagnostic evaluated 1,672 rows read-only,
and the private disposable preflight parsed 773,551 rows with zero failures and
no configured-DB access/write. The one Playwright/backend skip is the existing
hardware-dependent live-source gate. The changed set matches the cumulative
20-path allowlist exactly, staging is empty, `git diff --check` passes, and no
forbidden private/generated artifact is tracked.

## T17 PRD / Docs Updated

v5.30 status, this T1-T20 record, current AI/ML status, AI training runbook,
requirement traceability, docs index, taskboard/rendered HTML, and exact commit
allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Configured labels represent one source and one calendar day; training overlap
cannot be excluded; the sealed native pack has zero human decisions; the
external transfer gate failed; and the v5.22 candidate has no artifact by
design. These are evidence blockers, not reasons to weaken gates. Lifecycle
therefore stays `shadow_observation`.

## T19 Release / Rollback

No staging, commit, or push is authorized. Rollback removes the v5.30
service/CLI/tests/docs and restores shared governance docs. No data, migration,
artifact, label, or runtime rollback is required.

## T20 Final Handoff

Use v5.30 as the canonical supervised evidence decision. Do not present current
DB or cross-schema diagnostics as blind accuracy. Complete qualified blind
review and acquire a second genuine source before model repair or lifecycle
reconsideration.
