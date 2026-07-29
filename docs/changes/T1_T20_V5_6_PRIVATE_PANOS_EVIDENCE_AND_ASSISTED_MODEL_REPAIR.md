# T1-T20: v5.6 Private PAN-OS Evidence And Assisted Model Repair

## T1 Change Title

v5.6 Private PAN-OS Chronological Evidence Expansion and Assisted Model
Repair.

## T2 Requirement

Process the complete private PAN-OS file safely, predeclare disjoint
chronological evidence roles, apply conservative assisted labels without
calling them human review, compare supervised and anomaly strategies, and
preserve rule authority and all active state.

## T3 Source Evidence

- v5.3/v5.4 evidence lock:
  `data/samples/benchmarks/v53_temporal_evidence_lock.json` and
  `atdr/app/detection/v54_temporal_evidence.py`.
- v5.5 development-only evaluator:
  `atdr/app/detection/v55_development_model_repair.py`.
- Parser, rules, and features:
  `atdr/app/parsers/paloalto_parser.py`,
  `atdr/app/detection/rules.py`, and `atdr/app/ml/features.py`.
- Configured database and active artifacts:
  `atdr/app/db/models.py`, `atdr/app/detection/supervised_detector.py`, and
  `atdr/app/detection/ml_detector.py`.
- Private evidence is supplied through a CLI argument and never named in
  tracked output.

## T4 Current Behavior

v5.5 reduced temporal queue noise but produced locked F1 `0.4925`,
suspicious recall `0.3824`, malicious recall `0.4143`, and ECE `0.5405`.
IsolationForest development FPR was `0.2773` with threat capture `0.0818`.
Only 1,467 governed development labels and one real source identity were
available.

## T5 Impacted Areas/Agents

Detection, supervised ML, anomaly scoring, evidence governance, backend CLI,
AI Governance UI, QA, security/privacy, documentation, and release
governance.

## T6 Scope

In scope: bounded private streaming, read-only overlap detection, chronological
roles, duplicate containment, conservative assisted labeling, lower assisted
weights, nested development comparison, candidate freeze, one untouched
future evaluation, IsolationForest diagnostics, aggregate telemetry, tests,
and docs.

Out of scope: human-label fabrication, configured-database import, active
artifact replacement, activation/promotion, authoritative alert changes,
automatic response, real blocking, production claims, and fabricated devices.

## T7 Functional Requirements

1. Fail closed if the v5.4 evidence lock changes.
2. Stream the complete private file through bounded disposable storage.
3. Exclude configured-database overlap and keep duplicate families in one role.
4. Partition before labels are calculated.
5. Seal future labels until candidate freeze.
6. Mark every assisted decision non-human with explicit provenance.
7. Exclude ambiguous rows and lower assisted sample weights.
8. Compare six supervised and four IsolationForest diagnostics.
9. Write only ignored diagnostic artifacts.
10. Preserve configured database, active artifacts, alert authority, and
    response state.

## T8 Acceptance Criteria

- All 773,551 rows are streamed with bounded memory.
- Parser failures and cross-role duplicate families are reported.
- v5.3 final/rolling/external/quarantine labels remain excluded.
- Private paths, raw logs, IPs, secrets, and reusable fingerprints are absent.
- No private assisted label is marked human-reviewed.
- Candidate freeze precedes future label access.
- No configured DB or active artifact write occurs.
- Conservative readiness remains enforced when calibration, independence, or
  ground truth is insufficient.
- Full verification and hygiene checks pass.

## T9 API Contract

No new route. Existing supervised lifecycle output gains an optional,
aggregate-only v5.6 summary. No private row evidence or identifiers enter the
API. Existing clients remain compatible.

## T10 Data Model / Migration

No schema or migration change. Disposable SQLite is deleted after each run.
Ignored v5.6 reports and the optional diagnostic candidate remain under
`ml_baseline_reviews/`.

## T11 Backend Plan / Changes

Add a complete-file streaming evaluator and CLI, read-only configured-DB
fingerprint index, chronological role allocator, behavior grouping,
conservative assisted policy, representative sampler, nested model comparison,
candidate freeze, one-shot future evaluator, IsolationForest audit, lifecycle
aggregate, and sparse-class calibration fallback.

## T12 Frontend Plan / Changes

Show concise aggregate v5.6 private-evidence, candidate, future metrics,
IsolationForest, safety, and blocker status inside AI Governance technical
details. Do not show raw/private evidence or activation controls.

## T13 Security / Response / AI Safety

The private path is CLI-only. Reports expose aggregates only. Assisted labels
remain weak/non-human and are not imported. Rules remain alert-authoritative.
No model, label, alert, detection, response, user, firewall, or active artifact
mutation is permitted.

## T14 Test Plan

Test bounded streaming and redaction, evidence lock, role/family isolation,
conservative labeling, non-human provenance, lower assisted weights, future
seal, no configured DB/artifact mutation, no activation/response, lifecycle
privacy, and sparse chronological calibration.

## T15 Implementation Summary

v5.6 streamed 773,551 rows with zero parser failures, quarantined 120,626
rows including 120,000 configured-DB overlaps, and kept exact/near families
role-contained. It produced 409,741 high-confidence training-eligible assisted
events and excluded 131,180 ambiguous events.

HistGradientBoosting ranked first but passed 0/3 complete development gates.
Its 3,400-row private future result was F1 `0.9889`, FPR `0.0211`,
suspicious/malicious recall `1.0/1.0`, and ECE `0.0155`, but maximum
confidence gap `0.8143` failed. This is single-device weak-policy agreement,
not independent accuracy. IsolationForest contamination `0.02` yielded future
FPR `0.0057` and threat capture `0.4576`, with suspicious recall only `0.16`.

## T16 Tests Run / Evidence

The governed v5.6 run completed in `291.1052s`. The first full run exposed a
sparse-class calibration `IndexError`; the fix now skips calibration
explicitly when a chronological role lacks a fitted class. The combined
v4.9/v5.6 focused suite then passed `21/21`.

Whole-repo Ruff/compileall and Alembic passed. Full backend and official
release-gate suites each passed `679 passed, 1 skipped`. React lint/build
passed; Playwright passed `26 passed, 1 skipped`; controlled detection passed
`24/24`; layered validation passed `288/288`; assistant QA passed `20/20`;
replay wrote zero; performance smoke had no warnings; the release gate
returned `ok: true`; and repository hygiene/redaction/diff checks passed.

## T17 PRD / Docs Updated

v5.6 status, this T1-T20 record, exact allowlist, PRD, traceability,
compliance checklist, AI training runbook, current AI/ML status, docs index,
and taskboard.

## T18 Risks / Blockers / Assumptions / Decisions

- All private evidence represents one device and a short collection period.
- Private decisions are assisted labels, not independent ground truth.
- Confidence bucket gaps fail despite low aggregate ECE.
- IsolationForest misses most assisted suspicious rows.
- Existing locked external evidence remains unavailable for tuning.
- Decision: freeze one ignored diagnostic candidate, keep lifecycle
  `shadow_observation`, and do not activate or promote.

## T19 Release / Rollback

No migration, configured-data write, active artifact write, commit, or push is
authorized. Rollback is a normal source/UI/docs revert. Ignored reports and
candidate artifacts can be discarded without changing runtime state.

## T20 Final Handoff

v5.6 establishes a scalable, privacy-safe private evidence workflow and shows
substantial source-specific assisted-policy consistency. It does not close the
independent evidence, cross-device, human ground-truth, or calibration gates.
The next valid phase is independently governed multi-source/chronological
review evidence and a new untouched external validation, while preserving
shadow-only operation.
