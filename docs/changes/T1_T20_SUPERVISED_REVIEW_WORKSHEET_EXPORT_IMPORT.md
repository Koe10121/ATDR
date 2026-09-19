# T1-T20: Supervised Review CSV Worksheet Export/Import

## T1 Change Title

- Title: CSV worksheet export/import for the v5.62/v5.63 supervised review
  workspaces, as an offline-spreadsheet alternative to the one-row-at-a-time
  review UI
- Date: 2026-09-19
- Owner / acting agent: Claude (Sonnet 5) under project-owner direction
- Related phase: none assigned; additive tooling around the existing v5.62/
  v5.63 review contract, no change to that contract's behavior.

## T2 Requirement

The project owner started using the keyboard-accelerated review UI and found
recording decisions one row at a time still too slow across the 1,000-row
combined workspace. They asked for a spreadsheet they could work from instead.
The judgment itself must remain exactly as independent and manual as before —
only the mechanical act of entering many decisions needed to get faster.

## T3 Source Evidence

Direct reading of `v562_supervised_qualification_review_service.py` and
`v563_supervised_expansion_review_service.py` (the exact functions the web UI
calls: `list_qualification_review_items`, `save_qualification_review_item`,
`get_qualification_review_status`, and their v5.63 batch-scoped equivalents),
and `atdr/app/schemas/evidence_review.py` (confirmed `human_confirmed:
Literal[True]` is enforced only at the FastAPI request-schema layer, not
inside the service functions themselves — the router validates it and never
forwards it further).

## T4 Current Behavior (before this change)

No CSV export/import path existed. The only way to record a decision was one
HTTP request per row through the web review form.

## T5 Impacted Areas / Agents

New `atdr/app/services/supervised_review_worksheet_service.py`, new
`atdr/scripts/export_supervised_review_worksheet.py`, new
`atdr/scripts/import_supervised_review_worksheet.py`, new
`atdr/tests/test_supervised_review_worksheet_service.py`. No existing file
touched — this is a thin, purely additive layer that calls the same service
functions the router already calls.

## T6 Scope

In scope: exporting pending (optionally all) rows from both workspaces to one
CSV, with columns identical to what the review UI already shows plus blank
input cells for the reviewer to fill in, and importing that filled CSV back by
calling the *same* per-row save function the UI uses — same single-owner
lock, same revision-based optimistic concurrency, same prediction-blind
evidence, same decision/confidence/rationale/attack-type validation. Out of
scope, explicitly: anything that infers, suggests, or pre-fills a decision;
anything that writes directly to the working CSV instead of going through the
audited save function; any change to the review contract itself.

## T7 Functional Requirements

- Export never populates `decision`/`attack_type`/`confidence`/`rationale`/
  `confirm` — every one of those cells is always blank on export, even when
  `--include-reviewed` is used for an audit listing.
- Import requires a literal `yes` in a `confirm` column before a row is
  submitted at all. A row with a decision filled in but no `yes` in `confirm`
  is reported separately as `awaiting_confirmation`, not silently applied and
  not counted as a failure. This is a deliberate second, distinct field the
  reviewer must type — the CSV-medium equivalent of the review UI's
  `human_confirmed: Literal[True]` gate and its separate `C`-key confirmation
  toggle (see `docs/changes/T1_T20_SUPERVISED_REVIEW_KEYBOARD_ACCELERATION.md`,
  which established the same "never one action confirms and submits together"
  principle for the UI).
- Every accepted row is applied by calling
  `save_qualification_review_item`/`save_expansion_review_item` directly —
  the real, audited service function — never by writing to the working CSV
  file. Revision numbers are tracked and advanced exactly as the web UI does,
  per workspace (v5.62) or per batch (v5.63).
- Rows already marked reviewed are skipped by default (`skipped_already_reviewed`)
  unless `--overwrite-existing` is passed, to prevent accidentally reapplying
  an old worksheet over newer decisions.
- A validation failure on one row (bad decision value, missing attack type,
  confidence out of range, rationale too short) is reported per-row and does
  not abort the rest of the import — each row's outcome is independent, exactly
  matching what would happen if each were submitted as a separate UI form.
- For v5.63, a batch with no assigned owner is skipped on export unless
  `--auto-start-batches` is passed, in which case the tool self-assigns it to
  the same reviewer — the identical effect of clicking "Start" in the UI, gated
  behind an explicit flag rather than happening silently.

## T8 Acceptance Criteria

New tests prove: export lists only pending rows by default and all rows with
`--include-reviewed`, with every decision-input column blank regardless;
import refuses to submit a row without the `yes` confirm token; import applies
a confirmed row and silently ignores a fully-blank one; import skips an
already-reviewed row by default and applies it only with
`--overwrite-existing`; a batch of rows with one invalid decision reports that
row as failed while still applying the valid ones; the v5.63 path correctly
skips not-started batches, self-starts them under `--auto-start-batches`, and
tracks revision independently per batch; `resolve_reviewer` auto-detects the
already-assigned v5.62 owner when no `--user-id`/`--username` is given.

## T9 API Contract

None — CLI-only, no HTTP endpoint. Two new CLIs:
`atdr.scripts.export_supervised_review_worksheet` (`--output`, `--workspace`,
`--user-id`/`--username`, `--include-reviewed`, `--auto-start-batches`) and
`atdr.scripts.import_supervised_review_worksheet` (`--input`,
`--user-id`/`--username`, `--overwrite-existing`, `--dry-run`).

## T10 Data Model / Migration

None. No new persisted state; the CSV worksheet is a disposable, user-owned
file outside the review workspace's own protected files.

## T11 Backend Plan / Changes

`supervised_review_worksheet_service.py` calls the existing public review
service functions (`list_qualification_review_items`,
`get_qualification_review_status`, `save_qualification_review_item`,
`list_expansion_review_items`, `get_expansion_review_status`,
`start_expansion_review_batch`, `save_expansion_review_item`) — it does not
reimplement or bypass any of their validation, locking, or revision logic.
`resolve_reviewer` reads the v5.62 review-state file directly only to
auto-detect the already-assigned owner when no explicit identity is given,
using the same private accessor (`v562_supervised_qualification_campaign
._workspace_paths`) the review service itself uses.

## T12 Frontend Plan / Changes

None. This is a CLI-only workflow accelerant for the project owner, not a UI
feature — the review UI and its keyboard shortcuts are unchanged and remain
the primary, officially supported review surface.

## T13 Security / Response / AI Safety

No detection, response, or Assistant authority is touched. No model artifact
is written. The confirm-token gate exists specifically to prevent a
half-filled or draft row from being auto-submitted, preserving the "distinct
deliberate action per row" principle already established for the UI. Every
save still goes through `_assert_human_reviewer`, which rejects an identity
matching the AI-reviewer pattern — this tool cannot be used to attribute
AI-authored decisions to a human account any more than the UI can.

## T14 Test Plan

`atdr/tests/test_supervised_review_worksheet_service.py`: 8 new tests covering
export column blankness, pending-vs-all filtering, confirm-token gating,
successful submission, already-reviewed skip/overwrite, per-row failure
isolation, v5.63 batch ownership/auto-start, and reviewer auto-detection. Full
backend suite re-run afterward.

## T15 Implementation Summary

One new ~250-line service module, two ~55-line CLI wrappers, one new test
file (8 tests). Zero changes to any existing file.

## T16 Tests Run / Evidence

`atdr/tests/test_supervised_review_worksheet_service.py`: `8 passed`. Export
CLI manually verified against the real (currently unreviewed) v5.62 workspace:
correctly produced all `300` pending rows with blank decision columns and
zero warnings. Import CLI manually verified in `--dry-run` mode against that
same real, unfilled export: correctly reported zero submissions (nothing to
apply), confirming the tool does not touch the real protected workspace
without a human first typing real decisions and the `yes` confirm token.
`ruff check .` and `compileall` clean across the full repository. Full backend
suite result recorded in `docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

This change record only. No claim about supervised qualification status
changes — the review contract, its fixed gates, and the `0/1,000` reviewed
count are exactly as before; this only changes how fast the project owner can
record their own decisions.

## T18 Risks / Blockers / Assumptions / Decisions

Chose CSV over a generated `.xlsx` (`openpyxl`/`xlsxwriter` are not existing
dependencies, and CSV opens directly in Excel, Google Sheets, and Numbers
without adding one) — the tradeoff is no in-cell dropdown validation for the
`decision` column, mitigated by the CLI printing the allowed values and rules
on every export. `--include-reviewed` currently still exports blank decision
cells even for already-reviewed rows (it only changes which rows are listed,
useful for an audit count, not for re-presenting an existing decision for
editing) — acceptable for the current need; revisit if the project owner later
wants to review/correct existing decisions from the sheet instead of the UI.

## T19 Release / Rollback

Fully reversible: delete the three new files. No migration, no data written,
no artifact touched, no existing file's behavior changed.

## T20 Final Handoff

Ready for immediate use. Real export already produced at
`ml_baseline_reviews/review_worksheet.csv` (300 pending v5.62 rows, gitignored
directory). The project owner fills in `decision`/`attack_type`/`confidence`/
`rationale`/`confirm` for as many rows as they choose, then runs the import
CLI (optionally with `--dry-run` first) to replay those decisions through the
exact same audited save path the web UI uses.
