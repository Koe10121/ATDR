# v5.59 Repository Consolidation Plan

Date: 2026-09-05

## Purpose

Reduce the active repository surface after v5.58 while preserving audit
history, reproducibility, university workflow evidence, and every supported
runtime. v5.59 is a dependency-led consolidation, not a broad deletion pass.

No file is deleted during v5.58.

## Measured Inventory

| Area | Current count | Initial classification |
| --- | ---: | --- |
| Root `docs/*.md` | 335 | Merge active truth; archive historical phases |
| Root version-phase docs | 273 | 26 v0/v1, 103 v3, 22 v4, 122 v5 |
| Commit allowlists/change manifests | 74 | Archive as immutable release audit |
| `docs/changes/*.md` | 162 | Archive as implementation audit |
| Files under `docs/tasks/` | 3 | Keep; compact the active Markdown/HTML board |
| Python files under `atdr/scripts/` | 252 | Keep current operator interfaces; review historical CLIs by dependency |
| Versioned `run_v*.py` scripts | 104 | Archive/remove only after import, CI, doc-link, and test analysis |
| Presentation/status/runbook-like docs | 19 across the tree | Merge or archive around canonical operator docs |

These counts are inventory evidence, not a deletion authorization.

## Classification

### Keep Active

- `README.md`
- `docs/CURRENT_SYSTEM_STATE_LOCK.md`
- `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/QUICKSTART_FOR_TEAM.md`
- `docs/V5_54_OPERATOR_HANDOFF.md` until merged into the quickstart/operations
  set
- `docs/OPERATIONS_RUNBOOK.md`
- `docs/LAB_RUNBOOK.md`
- `docs/AI_TRAINING_RUNBOOK.md`
- `docs/DETECTION_RULE_CATALOG.md`
- `docs/tasks/README.md`, `tasklist-progress.md`, and generated HTML
- current security, deployment, MFU IAM, field-evidence, and external-owner
  contracts that operators still execute
- v5.58 runtime contract and its change record

### Merge

- Merge startup/setup/troubleshooting overlap from Quickstart, Team One Command
  Start, Lab Runbook, Operations Runbook, and v5.54 Operator Handoff into a
  short canonical operator set with links rather than copied commands.
- Merge current release, AI/ML, and final-system claims into the two current
  truth locks. Historical documents must link to those locks for current state.
- Replace the expanding taskboard phase ledger with one current task table and
  one archived historical ledger.
- Merge Demo Day, Final Demo, weekly presentation, supervisor summary, and
  progress-status material into one optional presentation brief; archive the
  originals.
- Replace repeated AI training narratives with one current workflow and a
  historical model-experiment appendix.

### Archive

- Move superseded root phase documents for v0, v1, v3, and v4 to a versioned
  historical-doc archive after rewriting inbound links.
- Archive v5.1-v5.49b implementation narratives after preserving the v5.49b
  immutable aggregate decision in the current AI/ML lock.
- Keep v5.50-v5.58 active until their current claims are merged and cross-links
  are verified; then archive those that are no longer operator inputs.
- Archive all 74 historical allowlists/manifests under a dedicated audit path.
  Git history remains the source of authorization; archived files retain exact
  content.
- Archive all superseded T1-T20 records under a dedicated change-history path.
- Preserve `docs/reference/NewSystem/` as reference-only evidence unless the
  final link audit proves no university requirement depends on it.

### Remove

Removal is allowed only for exact duplicates, generated copies, empty obsolete
stubs, or source modules proven unreachable. A removal candidate must have:

1. no import from runtime, tests, scripts, migrations, CI, or packaging;
2. no dynamic import/registry/CLI entry-point use;
3. no active documentation or operator command reference;
4. a named replacement for any retained behavior;
5. focused tests before removal and full verification after removal; and
6. an exact path-by-path approval allowlist.

No runtime module or historical script is currently pre-approved for removal.

## Historical Script Decision

The 104 versioned CLIs are treated as compatibility interfaces until proven
otherwise. v5.59 should build a static import/reference graph and classify each
path individually:

- **keep:** called by CI, release/security gates, an active operator runbook, or
  current tests;
- **merge:** multiple CLIs wrap the same supported service and can be replaced
  by one compatibility-preserving command;
- **archive:** reproducibility-only evaluator with no current runtime role;
- **remove:** unreachable duplicate with no unique test/evidence contract.

Wrappers must not be removed before callers and documentation are migrated.

## Unreferenced Module Audit

Build an AST-based import graph for `atdr/app`, `atdr/scripts`, `atdr/tests`,
Alembic, and runtime entry points. Supplement it with searches for string-based
registries, module execution (`python -m`), route inclusion, job dispatch,
plugin-like lookup, and subprocess calls. Dynamic references override an
apparent static orphan.

Produce a machine-readable inventory containing path, inbound references,
runtime role, replacement, classification, and reason. Do not treat zero static
imports as proof of removal for routers, migrations, CLIs, or entry points.

## Execution Order

1. Freeze a clean v5.58 baseline and exact inventory.
2. Build doc-link and Python import/entry-point graphs.
3. Create the archive layout and mapping manifest.
4. Consolidate current truth and operator docs.
5. Rewrite all tracked Markdown links and command references.
6. Move historical phase/change/allowlist records without editing their body.
7. Consolidate scripts in small dependency-tested batches.
8. Remove only proven duplicates/orphans.
9. Compact the taskboard and regenerate HTML.
10. Run the complete backend, frontend, detection, Assistant, deployment,
    security, release, link, and hygiene matrix.

## Acceptance Gates

- zero broken tracked Markdown links;
- zero missing referenced operator commands;
- zero Python import failures;
- all migrations and router/job registries intact;
- full tests and release/security gates green;
- normal setup/start/stop commands unchanged;
- v5.58 runtime states unchanged;
- protected/private/generated evidence still ignored;
- exact path allowlist and empty staging before any commit request.

## Rollback

Perform consolidation in reviewable batches. File moves must preserve history
where possible. If any active reference, import, CLI, test, migration, or
runtime behavior breaks, revert only that batch and retain the prior canonical
path until its callers are migrated.

## Expected Finish Line

After v5.59, locally implementable product work is rounded up. Remaining work
is owner-backed acceptance: real devices and independent future evidence, MFU
IAM lifecycle approval, Gemini institutional governance, approved shared-host
deployment, and physical teammate/usability acceptance. Those tracks remain
test-ready and fail closed when unavailable.
