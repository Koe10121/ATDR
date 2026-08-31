# T1-T20: v5.47 Prediction-Blind Manual-Anchor Acquisition

## T1 Change Title

v5.47 Prediction-Blind Manual-Anchor Acquisition.

## T2 Requirement

Create a governed, review-efficient source of new development-only human
anchors for the v5.46 transfer failures without exposing predictions,
fabricating human decisions, opening future evidence, or changing authority.

## T3 Source Evidence

ATDR source and tests, v5.39-v5.46 custody records, existing manual-anchor
families, and the private PAN-OS file supplied only through a CLI argument.

## T4 Current Behavior

v5.46 passes `0/3` mandatory views. Manual suspicious recall and calibration
are unsafe, while repeated tuning over the same evidence is no longer valid.

## T5 Impacted Areas / Agents

Detection/ML, evidence governance, backend/API, React AI Governance,
privacy/security, QA, Release/Ops, and documentation.

## T6 Scope

Custody revalidation, disposable private parsing, development-role and
duplicate containment, prediction-blind stratified selection, immutable pack
sealing, human-review validation, aggregate API/UI, tests, governance, and an
exact allowlist. Automatic labeling/import, training, candidate freeze,
activation, response, commit, and push are out of scope.

## T7 Functional Requirements

- Use only development roles and keep reserved-future labels sealed.
- Exclude existing manual-anchor, duplicate, quarantined, and future families.
- Select without predictions, model scores, or assisted labels.
- Cover the known unknown-transport, incomplete/80, scan-like, low-signal,
  QUIC/443, high-risk, and benign-control boundaries.
- Reject automated reviewer identities and incomplete human decisions.
- Expose aggregate status only and perform no automatic import.
- Keep deterministic rules authoritative and supervised ML in shadow mode.

## T8 Acceptance Criteria

The sealed pack reaches its selection and coverage gates; private values and
predictions remain absent; no configured state changes; the API is
authenticated and aggregate-only; review stays blocked until genuine human
completion and class support; tests and repository verification pass.

## T9 API Contract

Operator CLI:
`python -m atdr.scripts.run_v547_manual_anchor_acquisition`.
Authenticated read-only status:
`GET /api/evidence-review/manual-anchor-acquisition/status`.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. Disposable SQLite and generated review
artifacts remain ignored under `ml_baseline_reviews/`.

## T11 Backend Plan / Changes

Add the acquisition/validator module, safe CLI, aggregate status projection,
schema/router contract, and focused custody/privacy/no-mutation tests.

## T12 Frontend Plan / Changes

Add a compact AI Governance panel for pack coverage, human-review progress,
source breadth, fixed-revalidation readiness, prediction withholding, and
no-auto-import state.

## T13 Security / Response / AI Safety

No raw log, IP, source identity, path, fingerprint, prediction, assisted
label, reviewer identity, or secret is exposed. No model, alert, label, job,
or response state is changed. Response automation and real blocking stay off.

## T14 Test Plan

Cover strata classification, role/manual/duplicate exclusions, forbidden pack
columns, automated-reviewer rejection, aggregate redaction, authenticated API,
frontend status/overflow behavior, streaming-counter contract, and complete
no-mutation invariants.

## T15 Implementation Summary

Implemented the sealed 120-row workspace, deterministic seven-stratum
selection, human-only review contract, aggregate API/UI, safe CLI, tests,
measured private-file run, governance records, and cumulative allowlist.

## T16 Tests Run / Evidence

The private preflight passed all custody and safety checks. The measured run
selected `120/120` rows across seven strata, excluded 18,994 duplicate and
44,741 reserved-role families, opened zero future labels, and changed zero
configured or authoritative state. It parsed `773,551/773,551` private rows
with zero failures in `220.4093s`. Taskboard checks, Ruff, canonical compileall,
and Alembic passed; backend/release testing passed `997 passed, 1 skipped`;
React lint/build passed; Playwright passed `35` with one intentional live-source
skip; controlled source and layered `288/288` acceptance passed; Assistant QA
passed `20/20`; replay and warning-free performance passed; and the release
gate completed successfully on the final source state in `459.6s`.

## T17 PRD / Docs Updated

v5.47 status, this change record, PRD, traceability, compliance checklist, AI
runbook, current AI/ML status, taskboard, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

The 120 decisions still require a genuine human reviewer. One real device
cannot prove source generalization. Development review cannot replace a later
untouched independent evaluation. AI-generated labels cannot be represented as
human truth.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes v5.47 code/API/UI/tests/docs
and the ignored v5.47 workspace; no configured data or active artifact needs
rollback.

## T20 Final Handoff

Keep `shadow_observation`, rules authoritative, review predictions withheld,
and automatic import disabled. Complete genuine review, then run one fixed
development-only revalidation. Obtain a second genuine source before any
activation decision.
