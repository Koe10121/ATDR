# ATDR Repository Cleanup Plan

Date: 2026-06-26

Purpose: Phase 3 productization cleanup plan. This document classifies current repository and local-workspace material as keep, update, move to reference, delete later, or ignore. It is a planning artifact only. No files were deleted or moved while creating this plan.

Completion update (2026-07-18): the proposed v4.8.1 cleanup executed the
approved planning sequence in the worktree. Selected references are archived,
the unused tracked runtime copy is removed from the index, and the exact change
boundary awaits separate commit/push approval. See
`docs/V4_8_1_REPOSITORY_CONSOLIDATION_REPORT.md`.

## Source Evidence

| Evidence | Result |
| --- | --- |
| Active goal prompt | `<USER_REQUEST_ATTACHMENT>` |
| Current state lock | `docs/CURRENT_SYSTEM_STATE_LOCK.md` |
| Template gap analysis | `docs/PRODUCTIZATION_TEMPLATE_GAP_ANALYSIS.md` |
| Productization roadmap | `docs/ATDR_PRODUCTIZATION_ROADMAP.md` |
| Ignore rules | `.gitignore` |
| Tracked top-level inventory | `git ls-files` |
| Ignored local inventory | `git status --ignored --short` |
| Official supervisor template | `<MFU_SHELL_ROOT>` |
| Archived in-repo template evidence | `docs/reference/NewSystem/` |

Secret values were not inspected, printed, or copied. `.env` files are classified as protected local configuration.

## Current Hygiene Summary

- The repository tracks the active ATDR backend, frontend, migrations, safe sample data, docs, scripts, and CI files.
- The pre-cleanup repository tracked a 526-file `NewSystem/` copy. The proposed
  cleanup preserves 9 files from that copy and removes the other 517 tracked
  runtime files.
- The official supervisor template exists outside the repository at `<MFU_SHELL_ROOT>`.
- The workspace contains ignored local/private/generated artifacts such as `.env`, `atdr.db`, virtual environments, caches, model artifacts, processed logs, `ml_baseline_reviews/`, `demo_exports/`, frontend build output, and template `.env` / `node_modules` folders.
- `.gitignore` already protects the major sensitive/generated categories: `.env`, `**/.env.local`, `**/.env.preprod`, `**/.env.prod`, DB files, SQLite files, logs, model artifacts, processed data, frontend build/test output, `demo_exports/`, `ml_baseline_reviews/`, and `node_modules/`.

## Cleanup Classification

### Keep

| Path / area | Reason |
| --- | --- |
| `atdr/` source excluding generated caches/artifacts | Active FastAPI backend, parser, detection, ML, assistant, IAM, response, tests, and scripts. |
| `frontend/` source excluding `node_modules`, `dist`, and test output | Active React dashboard. |
| `migrations/` | Alembic source of truth for schema changes. |
| `data/samples/` | Safe synthetic/sample logs and scenario corpora used by tests and demos. |
| `.github/workflows/ci.yml` | Current GitHub CI gate. |
| `scripts/render-tasklist-progress-html.js` and `scripts/check-tasklist-progress-standard.js` | Supervisor-style progress-board compliance scripts adapted to ATDR. |
| `README.md`, `.env.example`, `.env.lab.example`, `.env.production.example`, `requirements.txt`, `alembic.ini`, `Dockerfile`, `docker-compose.yml`, `ruff.toml` | Active project setup, validation, and optional deployment files. |
| Active ATDR docs | `docs/ATDR_AI_WORKFLOW.md`, `docs/prd/PRD-ATDR.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md`, `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`, `docs/AI-DOCS-INDEX.md`, `docs/tasks/*`, `docs/security/*`, current v3 productization docs. |

### Update

| Path / area | Needed update |
| --- | --- |
| Older Streamlit-era docs | Several older docs still describe Streamlit as a primary flow. Update or label them as legacy/historical when they are touched. |
| Older presentation/final academic docs | Keep as evidence, but move under a future docs archive/index if the main docs folder becomes noisy. |
| `docs/ATDR_TEMPLATE_MANIFEST.json` | Completed: points to the archive scope and the separate companion-shell contract. |
| `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` | Completed: distinguishes the archive from the separate companion shell. |
| `docs/reference/NewSystem/workflow/*` | Completed: original NewSystem-specific workflow files are grouped under the reference archive. |
| `README.md` docs map | Add the productization roadmap/cleanup plan once this phase is finalized. |

### Moved To `docs/reference/`

The proposed v4.8.1 worktree completed these moves without committing them.

| Source | Target idea | Reason |
| --- | --- | --- |
| Selected template root docs/manifests | `docs/reference/NewSystem/` | Preserved without the full Node/Vue/Mongo runtime. |
| Selected IAM/security guidance | `docs/reference/NewSystem/backend-node/docs/` | Preserved for school-email/IAM and security traceability. |
| Original NewSystem workflow/PRD/T1-T20/agent examples | `docs/reference/NewSystem/workflow/` | Separated from active ATDR workflow, PRD, template, and agent model. |
| Archive boundary | `docs/reference/NewSystem/REFERENCE_SCOPE.md` | Defines authority, provenance, sanitization, and safe use. |

### Delete Later With Explicit Approval

Do not delete these automatically. These are candidates only.

| Path / area | Why it is a delete candidate | Required precondition |
| --- | --- | --- |
| Tracked `NewSystem/` runtime source | Completed in proposed v4.8.1 cleanup after dependency proof and reference preservation. | Separate exact-allowlist approval is still required before commit/push. |
| Ignored `NewSystem/**/node_modules/` | Large local dependency folders; never needed in Git. | Confirm no one is running the template from inside this repo; then remove locally if disk cleanup is desired. |
| Ignored `NewSystem/.env*` and `NewSystem/**/.env*` | Sensitive local configuration. | Never commit or print. Delete locally only if backed up or no longer needed. |
| Ignored `.pytest_tmp/`, `.pytest_cache/`, `.tmp/`, `.ruff_cache/`, `tmp/`, pytest cache folders | Generated test/cache output. | Safe local cleanup with approval; some folders showed permission-denied warnings and may need closed processes/admin shell. |
| Ignored `atdr/data/processed/*` logs and pytest folders | Runtime/test output. | Safe local cleanup with approval; preserve any evidence the user still needs. |
| Ignored `frontend/dist/`, `frontend/test-results/` | Build/test output. | Safe local cleanup with approval. |
| Ignored `demo_exports/` | Generated reports/evidence. | Delete only after user confirms exports are no longer needed. |
| Ignored `ml_baseline_reviews/` | Review samples, local label work, generated ML reports. | Do not delete without explicit backup approval. |
| Ignored model artifacts under `atdr/models/` | Local model files may be needed for current experiments. | Do not delete unless backed up and user approves. |
| Ignored local official-template copy inside repo root: `mfu-ai-driven-log-based-threat-detection-and-response/` | Duplicate of the official supervisor template under Downloads, currently ignored. | Confirm the Downloads copy remains available and no local notes exist only in the root copy. |

### Ignore / Protect

These should remain ignored and untracked.

| Path / pattern | Reason |
| --- | --- |
| `.env`, `frontend/.env`, `**/.env.local`, `**/.env.preprod`, `**/.env.prod` | Secrets, provider config, IAM/LLM keys. |
| `atdr.db`, `*.sqlite`, `*.sqlite3` | Local database files. |
| `*.log`, `atdr/data/processed/*` | Runtime logs and generated output. |
| `atdr/models/*.joblib`, `atdr/models/**/*.joblib`, `atdr/models/*.report.md` | Model artifacts and generated reports. |
| `ml_baseline_reviews/` | Local label review and generated ML analysis outputs. |
| `demo_exports/` | Generated evidence/report bundles. |
| `.venv/`, `.uv-cache/`, `.uv-python/`, `frontend/node_modules/`, `**/node_modules/` | Local dependencies and tool caches. |
| `frontend/dist/`, `frontend/playwright-report/`, `frontend/test-results/` | Build/test output. |

## Sensitive Data Check

Current tracked scan patterns found tracked JSON/HTML/package files, but no tracked `.env`, DB, SQLite, `.joblib`, `ml_baseline_reviews/`, `demo_exports/`, or real `paloalto-firewall(1).log` paths. Tracked JSON/HTML files include safe sample manifests, package manifests, the generated tasklist HTML, and NewSystem template reference JSON.

This does not prove every file is harmless forever. Before a cleanup or release commit, run:

```powershell
git status --short --untracked-files=all
git status --ignored --short
git ls-files | Select-String -Pattern '\.env$|\.sqlite$|\.sqlite3$|\.db$|\.joblib$|ml_baseline_reviews|demo_exports|paloalto-firewall|processed'
```

Do not print `.env` contents.

## Recommended Cleanup Sequence

### Step 1: Freeze Reference Truth

- Keep `<MFU_SHELL_ROOT>` as the canonical supervisor template.
- Update ATDR docs to point to that path for live template reference.
- Keep `docs/CURRENT_SYSTEM_STATE_LOCK.md`, `docs/PRODUCTIZATION_TEMPLATE_GAP_ANALYSIS.md`, and `docs/ATDR_PRODUCTIZATION_ROADMAP.md` as active productization memory.

### Step 2: Create `docs/reference/NewSystem/` - Complete

- Copy only selected reference docs/manifests, not full runtime source and not `.env`.
- Suggested reference set:
  - template README/TEMPLATE/ENVIRONMENTS;
  - template manifest/IAM template without secret values;
  - IAM docs;
  - tasklist/progress-board docs;
  - any permission matrix documentation.

### Step 3: Update References - Complete

- Update `docs/AI-DOCS-INDEX.md`.
- Update `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`.
- Update `docs/ATDR_TEMPLATE_MANIFEST.json`.
- Search for `NewSystem/` references and classify each as active ATDR adaptation, reference-only, or stale.

### Step 4: Remove The Tracked `NewSystem/` Runtime Copy - Proposed Complete

- Dependency proof passed and the tracked runtime copy is removed from the
  proposed worktree.
- The external/versioned companion shell was not touched.
- Ignored/private `.env`, local dependencies, databases, logs, reviews, exports,
  and models were not touched.
- Publication still requires separate approval of the exact allowlist.

### Step 5: Local Artifact Cleanup

Optional local cleanup, not required for Git:

- remove caches and build outputs after closing running processes;
- preserve DB, reviews, exports, and models unless the user explicitly approves deletion or backup.

## Proposed Future Cleanup Commands

These commands are examples for a future approved cleanup phase. Do not run them until the user approves.

Dry-run/reference discovery:

```powershell
git ls-files NewSystem
rg -n "NewSystem/|docs/reference/NewSystem/workflow/AI-WORKFLOW.md|PRD-NewSystem|backend-node|frontend-vue" README.md docs atdr frontend scripts
```

Potential local artifact cleanup after approval:

```powershell
# Example only. Do not run without approval.
Remove-Item -Recurse -Force .ruff_cache, frontend\dist, frontend\test-results
```

Potential tracked-template removal after reference archive is created and reviewed:

```powershell
# Example only. Do not run without approval.
git rm -r NewSystem
```

## Current Decision

- Keep active ATDR runtime, migrations, tests, and historical ATDR evidence.
- Keep all sensitive/generated local data ignored and untouched.
- Keep selected template evidence under `docs/reference/NewSystem/` only.
- Keep the versioned MFU companion package and `config/mfu-shell-contract.json`
  as the normal outer-shell distribution boundary.
- Do not migrate ATDR to Node, Vue, or MongoDB.
- Do not commit or push the v4.8.1 cleanup until the repository owner explicitly
  approves `docs/V4_8_1_COMMIT_ALLOWLIST.md`.
