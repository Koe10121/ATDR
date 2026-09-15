# T1-T20: v5.7 Independent Evidence Readiness And Blind Revalidation

## T1 Change Title

v5.7 Independent Evidence Readiness and Blind Shadow Revalidation.

## T2 Requirement

Freeze the v5.6 diagnostic candidate reproducibly, audit all v5.3-v5.6
evidence roles, qualify only genuinely independent PAN-OS-compatible evidence,
enforce predictions before labels, and perform a one-time blind evaluation
only when valid ground truth exists.

## T3 Source Evidence

- v5.3 evidence lock:
  `data/samples/benchmarks/v53_temporal_evidence_lock.json`.
- v5.4-v5.6 evaluators, ignored reports/manifests, and diagnostic candidate:
  `atdr/app/detection/v54_temporal_evidence.py`,
  `v55_development_model_repair.py`, and
  `v56_private_panos_model_repair.py`.
- Candidate/runtime contracts:
  `supervised_detector.py`, `v51_supervised_lifecycle.py`, and AI Governance.
- Official dataset sources and limitations are listed in
  `docs/detection/V5_7_INDEPENDENT_EVIDENCE_ACQUISITION.md`.
- Private evidence is supplied through a CLI argument and never named in
  tracked output.

## T4 Current Behavior

v5.6 froze a calibrated HistGradientBoosting diagnostic candidate after
development selection. Its single-device assisted future result was strong
but was not independent ground truth. Confidence gap, cross-device evidence,
and genuine human-label gates remained open.

## T5 Impacted Areas/Agents

Detection, supervised ML, IsolationForest governance, evidence acquisition,
backend CLI, AI Governance UI, security/privacy, QA, documentation, and
release governance.

## T6 Scope

In scope: evidence lock audit, immutable candidate identity, disposable
preflight, independent manifest qualification, official-source audit,
immutable prediction freeze, prediction-blind review pack, one-time label
reveal, fixed readiness gates, aggregate telemetry, tests, and documentation.

Out of scope: fabricated devices/ground truth, relabeling existing rows,
reusing opened evidence as fresh validation, configured-DB import, active
artifact replacement, model activation/promotion, alert-authority changes,
automatic response, real blocking, and production claims.

## T7 Functional Requirements

1. Fail closed if any v5.3-v5.6 evidence or candidate lock changes.
2. Record candidate feature, preprocessing, calibration, threshold, training,
   code, and artifact identities in ignored output.
3. Reject reused files/roles, configured-DB overlap, duplicate leakage,
   unsupported schemas, tiny/invalid chronology, or unverified source/time
   independence.
4. Require a documented prior-evidence overlap audit.
5. Freeze predictions before labels and prevent freeze replacement.
6. Hide predictions from the human review pack.
7. Accept only allowed human/provider ground-truth provenance.
8. Seal the first successful label reveal and reject later reveals.
9. Evaluate supervised and IsolationForest metrics only after a valid reveal.
10. Preserve configured DB, labels, artifacts, alert authority, and response
    state.

## T8 Acceptance Criteria

- All v5.3-v5.6 locks and the candidate artifact match.
- The private source is recognized as reused v5.6 evidence.
- No invalid corpus produces blind metrics.
- The candidate is threshold-only with no post-prediction suppression guard.
- A valid prediction freeze is immutable.
- Label reveal is contract-bound, provenance-checked, advisor-approved, and
  one-time.
- No private paths, raw rows, IPs, row values/fingerprints, or secrets are
  returned.
- No configured DB, label, model, detection, alert, or response state changes.
- Lifecycle remains conservative when any fixed gate is missing or failed.

## T9 API Contract

No new route. Existing supervised lifecycle output gains optional,
aggregate-only v5.7 candidate/evidence/validation/safety fields. Existing
clients remain compatible and no private row evidence enters the API.

## T10 Data Model / Migration

No schema or migration change. All derived evidence, prediction/review files,
lock audits, reports, and candidate manifests remain ignored under
`ml_baseline_reviews/` or disposable temporary storage.

## T11 Backend Plan / Changes

Add the v5.7 evaluator and CLI, role/artifact lock auditor, immutable candidate
manifest, evidence-contract qualifier, prediction freezer, blind review
package, one-shot reveal validator, metric/calibration/drift/stability
evaluation, advisory IsolationForest audit, and aggregate lifecycle summary.

## T12 Frontend Plan / Changes

Show concise aggregate status inside AI Governance technical details:
Frozen Diagnostic Candidate, Independent Evidence Pending/Available, Shadow
Observation, Rules Authoritative, and Response Automation Disabled. Hide blind
metrics until valid labels are revealed.

## T13 Security / Response / AI Safety

Private evidence remains outside Git and the configured database. Assisted
labels are rejected as ground truth. No active artifact is written or
replaced. Rules remain alert-authoritative. ML remains advisory. Response
automation and real blocking remain disabled.

## T14 Test Plan

Test lock integrity, ignored audit recording, candidate immutability,
reuse/leakage rejection, minimum chronology, overlap-audit requirements,
duplicate containment, prediction-blind packs, immutable freezes,
prediction-before-label, allowed provenance, one-time reveal, no guard
suppression, privacy, state preservation, aggregate lifecycle output, and
frontend statuses.

## T15 Implementation Summary

The evaluator freezes
`calibrated_hist_gradient_boosting` with sigmoid calibration, threshold
`0.3`, 40 features, and a threshold-only decision policy. It audits v5.3-v5.6
roles and artifacts, streams candidate evidence through disposable SQLite,
and rejects evidence that does not satisfy the independent contract.

The current private preflight parsed all 773,551 rows, found 120,000
configured-DB overlaps and 52,881 near duplicates, and matched reused v5.6
evidence. It correctly returned `independent_evidence_required` and did not
run blind supervised or IsolationForest evaluation.

## T16 Tests Run / Evidence

Taskboard render/check, whole-repository Ruff, compileall, React lint/build,
and Alembic drift check passed. Focused v5.7 tests passed `15`; full backend
tests passed `694 passed, 1 skipped`; Playwright passed `26 passed, 1 skipped`
(live-hardware skip); controlled scenarios passed `24/24`; layered validation
passed `288/288` with zero controlled FP/FN; assistant QA passed `20/20` with
zero side effects; replay dry-run wrote zero; and performance smoke had no
warnings (Overview `0.1593s`, cached `0.0114s`, AI Governance `1.1176s`).
The official release gate returned `ok: true` with no failed required checks.

An initial release-gate compile step encountered disposable malformed fixture
copies created under ignored processed output by the custom full-test
basetemp. Only that generated test directory was removed. The clean release
gate passed without source or configured-data changes.

## T17 PRD / Docs Updated

v5.7 status, this T1-T20 record, acquisition protocol, manifest template,
PRD, traceability, compliance checklist, AI training runbook, current AI/ML
status, docs index, taskboard, tests, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

- Current native PAN-OS evidence is one reused device/source collection.
- Existing final/rolling/external/private-future roles are already opened.
- No fresh native PAN-OS independently labeled corpus was found.
- Device independence cannot be inferred from source IPs; collection records
  and advisor confirmation are required.
- No blind metrics can be reported honestly.
- Decision: keep `shadow_observation`, no activation/promotion, and acquire
  valid evidence through the governed protocol.

## T19 Release / Rollback

No migration, configured-data write, active artifact write, commit, or push is
authorized. Rollback is a normal source/UI/docs revert. Ignored v5.7 outputs
can be removed without changing runtime state.

## T20 Final Handoff

v5.7 makes ATDR ready to receive and evaluate genuinely independent evidence;
it does not manufacture that evidence. The remaining work requires two real
devices, new time periods, independent human/provider labels, and advisor
approval. Until then, rules remain authoritative and ML remains shadow-only
decision support.
