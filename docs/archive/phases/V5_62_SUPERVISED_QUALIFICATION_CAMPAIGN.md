# v5.62 Supervised ML Qualification Campaign

Date: 2026-09-16

## Decision

v5.62 establishes a fresh, prediction-blind supervised qualification
campaign. It does not qualify, activate, promote, or write an active
supervised model. The immutable v5.49b negative decision remains consumed
exactly once, and every reconstructed row and duplicate family bound to that
decision is excluded from the new campaign.

Current runtime truth remains:

- deterministic rules: `active_authoritative`;
- IsolationForest and hybrid output: advisory only;
- supervised runtime: `unqualified`;
- lifecycle: `shadow_observation`;
- response: `simulation_only`;
- automatic response and real firewall blocking: disabled.

## Evidence Preparation

The private PAN-OS source was supplied only as a CLI argument and processed in
disposable SQLite. No configured database import occurred. Public output and
tracked documentation contain aggregate counts only.

| Measure | Result |
| --- | ---: |
| Source records streamed | 773,551 |
| Parser successes | 773,551 |
| Parser failures | 0 |
| Fresh eligible records | 298,963 |
| Consumed review rows reconstructed | 180 |
| Overlapping event rows rejected | 228 |
| Exact duplicate rows | 0 |
| Near-duplicate rows contained | 52,881 |
| Independent chronological windows | 19 |
| Verified physical source identities | 1 |
| Selected protected review rows | 300 |

The current source is sufficient to prepare development evidence, but it is
not sufficient to qualify a model by itself. The fixed source gate requires at
least two physical sources, and the fixed comparable-evidence gate requires at
least 1,000 independently comparable rows.

## Immutable Evidence Roles

Roles were assigned chronologically before any new labels were opened:

| Role | Rows | Model-development visibility |
| --- | ---: | --- |
| Development fit | 150 | Available only after review closure |
| Calibration | 60 | Available only after review closure |
| Threshold selection | 45 | Available only after review closure |
| Untouched future evaluation | 45 | Sealed from development code |
| Second-source validation | 0 | Placeholder only; never fabricated |

Duplicate families cannot cross roles. Rows cannot move after label opening.
The sealed source pack and protected working copy are ignored generated
evidence under `ml_baseline_reviews/` and must never be committed.

## Protected Review Workspace

Authenticated analysts and administrators can open **Evidence Review ->
Supervised Qualification**. One genuine human reviewer owns the workspace.
The interface displays only approved normalized evidence fields and withholds:

- model predictions and scores;
- rule recommendations and suggested labels;
- raw records and IP addresses;
- source identities and fingerprints;
- evaluation-role class support; and
- private paths and secrets.

Allowed decisions are `benign`, `benign_unusual`, `needs_context`,
`suspicious`, and `malicious`. Every decision requires confidence, a rationale,
and explicit human confirmation. Suspicious and malicious decisions also
require an attack type. Closure is immutable. Review never imports labels into
the application database and never runs evaluation or training.

Current workload is `0/300` reviewed, `300` remaining, and `0` invalid. The
project owner or another genuine human analyst must review all 300 rows and
close the workspace without changing decisions to satisfy quotas.

## Fixed Qualification Gates

The existing gates are unchanged:

- independently comparable rows >= 1,000;
- rows per binary class >= 100;
- real physical sources >= 2;
- independent time windows >= 2;
- queue F1 >= 0.85;
- threat recall >= 0.80;
- benign-like FPR <= 0.05;
- suspicious recall >= 0.70;
- malicious recall >= 0.70;
- ECE <= 0.10; and
- confidence/accuracy gap <= 0.15.

Only the time-window gate currently passes (`19/2`). Human-label, comparable
row, binary-class, and source gates fail. Evaluation-class and model-quality
gates remain blocked because future labels are sealed and no candidate has
been evaluated.

## Development Repair Contract

The campaign locks the same eight governed strategies and 40-feature schema.
The development preflight checks review closure, feature and strategy
integrity, chronological roles, duplicate isolation, provenance, binary-class
support, calibration support, threshold support, and time-window support.

Development rows cannot be loaded until the human review is formally closed.
Untouched future-evaluation rows are never returned by the development loader.
Current preflight is `blocked_insufficient_fresh_development_support` with:

- training allowed: false;
- training executed: false;
- calibration outcomes accessed: false;
- threshold outcomes accessed: false;
- evaluation labels accessed: false;
- evaluation rows loaded: 0;
- candidate frozen: false; and
- active artifact written: false.

## Operator Commands

Public aggregate status:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v562_supervised_qualification_campaign --status-only --pretty
```

Private-source preflight defaults to no writes. Supply the private path only at
runtime:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v562_supervised_qualification_campaign `
  --sample-path "<private-panos-log>" `
  --preflight-only `
  --pretty
```

Protected preparation requires disposable processing and the exact phrase
`PREPARE_V562_SUPERVISED_QUALIFICATION_CAMPAIGN`. Do not rerun preparation over
the existing immutable workspace.

## Verification

- Taskboard render and standard checks pass.
- Ruff and compileall pass.
- Focused v5.62 backend tests pass `6/6`.
- Full backend tests pass `1108 passed, 1 skipped`.
- Alembic reports no new upgrade operations.
- React lint and build pass; Playwright passes `44 passed, 1 skipped` with the
  intentional live-source skip.
- The controlled port-scan source parses `10/10`, creates the expected
  rule-authoritative alert, and creates zero response actions.
- Layered detection passes `288/288` mode runs with zero controlled false
  positives or false negatives.
- Assistant QA passes all 30 quality cases and its follow-up sequence with no
  authoritative side effects.
- Governed hybrid validation confirms rules authoritative, IsolationForest
  advisory, supervised unqualified, and response `simulation_only`.
- Replay dry-run, repository surface audit, security acceptance, performance
  smoke, and the independent release gate pass. Performance smoke reports one
  non-failing cold Overview warning (`1.1947s` against the `1.0s` local target)
  while the cached path remains fast at `0.0150s`.
- The repository surface has no broken or non-portable references; the
  tracked-source security scan reports zero findings across 1,433 text paths.
- `git diff --check` passes. No v5.62 path is staged, committed, or pushed.

The exact tracked publication boundary is the 23-path list in
`docs/V5_62_COMMIT_ALLOWLIST.md`.

## Remaining Qualification Work

1. A genuine human reviewer completes and closes all 300 current decisions.
2. Acquire enough fresh, prediction-blind comparable evidence to reach 1,000
   rows without reusing consumed v5.49b evidence.
3. Obtain evidence from a second independently verified physical source.
4. Run development-only repair after every development support check passes.
5. Freeze at most one diagnostic candidate before opening any new untouched
   evaluation labels.
6. Perform one governed blind evaluation against fixed gates.
7. Require a separate explicit activation decision before `active_shadow`.

No supervised qualification claim is permitted during v5.62.
