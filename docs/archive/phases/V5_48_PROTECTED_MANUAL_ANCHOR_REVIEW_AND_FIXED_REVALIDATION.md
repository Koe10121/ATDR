# v5.48 Protected Manual-Anchor Review And Fixed Revalidation

## Status

v5.48 is implemented and fail-closed. It adds an authenticated,
prediction-blind review workspace for the sealed v5.47 development pack and
locks the revalidation protocol before the first human decision. No evaluation
has run because genuine review remains `0/120`.

- lifecycle: `shadow_observation`
- fixed protocol: locked and valid
- eligible roles: development fit, calibration, and threshold
- candidate strategies: `8`
- human review: `0/120`
- evaluation executions: `0`
- model activated or promoted: no
- deterministic rules alert-authoritative: yes
- automatic response and real firewall blocking: disabled

## Protected Review Workspace

Authenticated analysts and administrators can open **Evidence Review > Manual
Anchors**. The first reviewer claims the workspace. Other users cannot inspect
or change its private rows. Each save requires the current optimistic revision,
a supported decision, confidence, rationale, and explicit human confirmation.
The reviewer may revise decisions while the review is open; formal closure
makes all decisions immutable.

Only approved aggregate evidence fields are displayed. The API and React UI do
not expose predictions, model scores, assisted labels, raw logs, IP addresses,
source identities, fingerprints, private paths, reviewer identities, or
secrets. The workspace remains non-import-ready and performs no label import,
training, model activation, alert creation, or response action.

## Fixed Revalidation Protocol

The immutable protocol is bound to the sealed v5.47 pack before review starts.
It fixes:

- the eligible evidence roles and deterministic partition membership;
- the feature schema;
- eight candidate strategies;
- calibration, threshold, and evaluation partitions;
- the unchanged v5.42 quality gates; and
- one permitted development-only execution after formal review closure.

Partition assignment does not inspect human decisions. Protocol, pack, or
review-state binding changes fail closed. The revalidation remains blocked
until every row is valid and minimum support reaches 20 benign-like, 15
suspicious, and 10 malicious decisions. Execution also requires the explicit
confirmation `RUN_FIXED_DEVELOPMENT_REVALIDATION`.

## API And CLI

Authenticated routes:

- `GET /api/evidence-review/manual-anchors/revalidation-status`
- `GET /api/evidence-review/manual-anchors/status`
- `POST /api/evidence-review/manual-anchors/start`
- `GET /api/evidence-review/manual-anchors/items`
- `GET /api/evidence-review/manual-anchors/items/{row_index}`
- `POST /api/evidence-review/manual-anchors/items/{row_index}`
- `POST /api/evidence-review/manual-anchors/close`

Safe status/preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v548_manual_anchor_fixed_revalidation `
  --preflight-only --use-temp-db --pretty
```

One-time revalidation, only after genuine closure and class support:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v548_manual_anchor_fixed_revalidation `
  --use-temp-db --confirm-fixed-revalidation --pretty
```

## Measured Preflight

The real private workspace preflight passed: protocol locked and valid,
strategy count `8`, quality gates unchanged, evaluation labels unopened, and
review progress `0/120` with zero invalid rows. Evaluation was not attempted.
No configured label, model run, detection run, alert, response action, active
artifact, or private evidence was written or exposed.

## Verification Result

- Taskboard render/standard, Ruff, canonical source compileall, and Alembic
  no-drift checks passed.
- Focused v5.48 backend tests passed `8/8`.
- Full backend and release-gate testing passed `1005 passed, 1 skipped`.
  Existing scikit-learn diagnostic warnings remain visible but are not test
  failures or v5.48 activation evidence.
- React lint/build passed; Playwright passed `36`, with one intentional
  live-source skip. The protected Manual Anchors workspace passed responsive,
  prediction-blind save-and-next coverage.
- The isolated port-scan scenario parsed `10/10`, created one critical alert
  and one case, and created zero response actions.
- Layered detection passed `288/288` with zero controlled false positives and
  false negatives.
- Assistant QA passed `20/20`, all answer budgets and citation/refusal checks,
  and zero side effects.
- Replay dry-run parsed `2/2` and wrote zero rows.
- Performance smoke passed without warnings: Overview `0.1740s`, cached
  Overview `0.0102s`, ML Governance `0.2488s`, Alerts `0.0315s`, and Cases
  `0.0539s`.
- The final canonical release gate returned `ok: true` in `460.7s`.

## Repository Hygiene

The cumulative v5.43-v5.48 worktree contains exactly the 58 paths listed in
`docs/V5_48_COMMIT_ALLOWLIST.md`. Staging is empty and `git diff --check`
passes. Private review/protocol/result state remains ignored under
`ml_baseline_reviews/`; no tracked `.env`, database, private log, model
artifact, generated evidence/report, prediction, fingerprint, private path,
or secret is included. No commit or push is authorized.

## Remaining Gate

The next action is genuine human review in the protected dashboard workspace.
ATDR must not replace that evidence with Codex, Gemini, rule, or model output.
After valid closure, run exactly one fixed development revalidation. Even a
passing development result would not prove source generalization: a second
genuine source and later untouched independent validation remain required
before supervised activation can be reconsidered.
