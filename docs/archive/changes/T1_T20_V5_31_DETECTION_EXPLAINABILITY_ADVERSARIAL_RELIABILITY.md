# T1-T20: v5.31 Detection And Explainability Adversarial Reliability

## T1 Change Title

v5.31 Deterministic Detection and Explainability Adversarial Reliability Lock.

## T2 Requirement

Harden ATDR's alert-authoritative rules against obvious false positives,
missed correlation boundaries, cross-source merging, and unsupported threat
claims. Improve `Why flagged?`, traceability, analyst checks, and Assistant
follow-ups without changing ML lifecycle or response authority.

## T3 Source Evidence

Runtime source truth is `rules.py`, `detection_service.py`, `alert_service.py`,
`rule_catalog.py`, `attack_mapping.py`, `explanations.py`, `case_service.py`,
and `assistant_service.py`. Tests and synthetic scenarios provide executable
evidence. PAN-OS field documentation, MITRE ATT&CK, RFC 9000, and RFC 792 were
used for field semantics and conservative claim boundaries.

## T4 Current Behavior

Before v5.31, context-only scores could form singleton alerts, source identity
was not consistently carried through grouping/deduplication, brute-force
correlation was not target-specific, beacon and flood conditions were too
broad, horizontal probing had no dedicated rule, and explanations did not
consistently expose exact score components, limitations, false-positive
factors, or computed case trace. Completion auditing additionally proved that
timestamp-less rows could cross-correlate, independent behavior windows could
collapse into one alert, time-less findings could deduplicate indefinitely,
and incomplete explanation summaries could pass the old completeness check.

## T5 Impacted Areas / Agents

Detection engineering, source correlation, alert/case services,
explainability, SOC Assistant, AI governance, security/response safety, QA,
and documentation are impacted. Database schema, frontend routes, IAM, model
artifacts, and deployment are not impacted.

## T6 Scope

In scope: deterministic rule conditions, bounded correlation, source-aware
grouping/deduplication, explanation contracts, synthetic adversarial corpus,
safe CLI, tests, and governance records.

Out of scope: model training/selection/activation, human-label creation,
database migration/reset, automatic response, real blocking, production
claims, and tuning against private or locked evidence.

## T7 Functional Requirements

- Isolate behavior by registered source identity and bounded time window.
- Fail closed on cross-row correlation and deduplication when event-time
  evidence is unavailable, while keeping event-local evidence usable.
- Preserve separate behavior episodes as separate alert groups.
- Distinguish vertical scanning, horizontal scanning, and same-target auth
  failures using the appropriate diversity/target evidence.
- Require measured cadence for beaconing and corroborated/effective volume for
  flooding.
- Prevent context-only singleton alerts and direction-only flood claims.
- Preserve PAN-OS severity/name and `repeatcnt` semantics.
- Explain exact evidence, false positives, limits, prioritized checks, source,
  related logs, case trace, and supported mappings.
- Keep Assistant follow-ups bound to the selected alert when case evidence is
  merely a citation.

## T8 Acceptance Criteria

All 27 synthetic adversarial cases pass; expected-rule false-positive and
false-negative case counts are zero; distinct registered sources do not merge;
all 19 runtime rules match documented catalog contracts; explanation and
Assistant tests pass; no labels, model state, or responses are written; and
the complete repository verification matrix passes.

## T9 API Contract

No route or request-schema changes. Existing alert explanation responses gain
richer additive fields while preserving existing keys. The local CLI is:
`python -m atdr.scripts.run_v531_detection_explainability_adversarial_reliability`.

## T10 Data Model / Migration

No schema, model, index, or migration change. Existing data remains
compatible. Correlation reads bounded normalized evidence and registered
source identity already present in the schema.

## T11 Backend Plan / Changes

Refine deterministic counters and rule gates, add horizontal scanning, make
group/dedup keys source-aware, add case tracing and richer explanation fields,
consume those fields in the Assistant, and add a synthetic-only runner plus
regression tests.

## T12 Frontend Plan / Changes

No frontend source change is required. Existing Alerts, Investigation, and SOC
Assistant surfaces consume the additive explanation contract through current
APIs. Full frontend regression remains part of verification.

## T13 Security / Response / AI Safety

Rules remain alert-authoritative but have no response authority. IsolationForest
and supervised ML remain advisory. No model is trained, activated, or promoted.
No human label is created. Automatic response and real firewall blocking remain
disabled. The corpus is synthetic and contains no private evidence.

## T14 Test Plan

Run the v5.31 corpus, rule-contract validator, focused unit/integration tests,
all controlled scenarios and layered matrices, full backend tests, Alembic
check, frontend lint/build/Playwright, Assistant QA, replay dry-run,
performance smoke, release gate, and repository hygiene checks.

## T15 Implementation Summary

Implemented source-scoped correlation, target-aware auth detection, vertical
and horizontal scan diversity, cadence-aware beaconing, corroborated/effective
flood volume, vendor-severity-aware THREAT evidence, directional-byte handling,
context-only group suppression, source-aware grouping/deduplication, additive
explanations and traceability, Assistant context-routing repair, a 27-case
adversarial corpus, fail-closed missing-time handling, episode-specific alert
grouping, strict explanation completeness, CLI, and tests.

## T16 Tests Run / Evidence

The v5.31 runner passes `27/27` with zero expected-rule false-positive or
false-negative cases and zero label/model/response writes. The rule contract
passes with `19/19` implemented/documented/catalog rules and 24 documented
scenarios. The focused completion-audit regression set passes `38` tests. The complete
matrix passes: backend `872 passed, 1 skipped`; Alembic no drift; React
lint/build; npm audit zero; Playwright `31 passed, 1 skipped`; controlled
scenarios `24/24`; layered validation `288/288`; Assistant QA `20/20`; replay
dry-run; warning-free performance smoke; and official release `ok: true`.

## T17 PRD / Docs Updated

Updated the rule catalog, rule-pack contract, AI training runbook, current
AI/ML status, requirement traceability, taskboard, and rendered taskboard.
Added the v5.31 status, this change record, and exact commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Synthetic cases prove deterministic contracts, not field accuracy. Distributed
or slow behavior can fall outside bounded windows. Vendor/context signals do
not establish intent or compromise. Independent native evidence and source
diversity remain external blockers. These risks do not justify weakening the
current safety or supervised promotion gates.

## T19 Release / Rollback

No staging, commit, or push is authorized by this implementation. Rollback is
source-only: restore the listed detection/service/test/docs/sample paths. No
data rollback or migration downgrade is required.

## T20 Final Handoff

Use the v5.31 runner and rule-contract validator as the deterministic
adversarial lock. Do not describe synthetic pass rates as real-world accuracy.
Rules remain authoritative, ML remains in `shadow_observation`, and response
automation remains disabled. At least three externally owned evidence,
provider, and preproduction phases remain before a credible preproduction
candidate claim.
