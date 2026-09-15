# v3.88 Changeset Manifest

Date: 2026-07-12

Purpose: define the exact intended ATDR commit set without staging private, generated, unrelated, or external-template state.

## Classification

### Intended Runtime And Configuration Examples

| Files | Purpose |
| --- | --- |
| `.env.example`, `.env.lab.example`, `.env.production.example` | Safe disabled-by-default template-shell/assistant settings and a committed safe sample path; no real values. |
| `.github/workflows/ci.yml` | Python 3.11/safe SQLite backend checks plus pinned Node 20.19, tasklist validation, dependency audit, React build, and Playwright without private providers. |
| `atdr/app/core/config.py` | MFU template aliases, shell settings, and bounded assistant reliability settings. |
| `atdr/app/routers/assistant.py`, `atdr/app/schemas/assistant.py` | Authenticated conversation/status/history contracts and clean rate-limit handling. |
| `atdr/app/schemas/auth.py` | Safe non-secret template-shell readiness/status contract. |
| `atdr/app/services/assistant_llm.py`, `atdr/app/services/assistant_service.py` | Structured provider answers, safe context, actor-scoped conversation state, fallback, redaction, auditing, and no-action behavior. |
| `atdr/app/services/mfu_iam_service.py`, `atdr/app/services/mfu_iam_validation.py`, `atdr/app/services/template_bridge_contract.py` | Optional template-session identity validation, local mapping, safe readiness/probe behavior, and source contract. |
| `atdr/scripts/config_doctor.py` | Non-secret IAM/template readiness diagnostics. |
| `atdr/scripts/apply_template_atdr_launcher.py`, `atdr/scripts/use_template_shell_config.py`, `atdr/scripts/validate_template_bridge_contract.py`, `atdr/scripts/validate_template_shell_runtime.py` | Dry-run-first template launcher/config helpers and non-mutating validation. |
| `atdr/scripts/test_assistant_llm_provider.py`, `atdr/scripts/test_assistant_chat_provider.py` | Secret-safe provider and full service-path probes. |
| `frontend/src/pages/LoginPage.tsx`, `frontend/src/pages/UserAdmin.tsx` | Template handoff receiver/fallback and safe IAM readiness UI. |
| `frontend/src/pages/AssistantPage.tsx`, `frontend/src/types/api.ts` | Backend-authoritative context, reset, provider/fallback telemetry, citations, and safe assistant UX. |
| `frontend/package.json`, `frontend/package-lock.json` | Node `>=20.19.0` contract and non-breaking audited dependency lock updates. |

### Intended Tests

- `atdr/tests/test_api.py`
- `atdr/tests/test_assistant.py`
- `atdr/tests/test_dev_onboarding.py`
- `atdr/tests/test_hardening_and_ingestion.py`
- `atdr/tests/test_mfu_iam_validation.py`
- `atdr/tests/test_template_atdr_launcher.py`
- `atdr/tests/test_template_bridge_contract.py`
- `atdr/tests/test_template_shell_runtime.py`
- `frontend/tests/smoke.spec.ts`

These cover local login, email login, template handoff success/fallback, domain/role mapping, token hiding, assistant context isolation/reset, structured provider/fallback behavior, prompt injection, privacy, rate limiting, citations, and no action side effects.

### Intended Documentation

- `README.md`
- `frontend/README.md`
- `docs/QUICKSTART_FOR_TEAM.md`
- `docs/CURRENT_SYSTEM_STATE_LOCK.md`
- `docs/ATDR_PRODUCTIZATION_ROADMAP.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/LAB_RUNBOOK.md`
- `docs/prd/PRD-ATDR.md`
- `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md`
- `docs/ATDR_TEMPLATE_MERGE_ANALYSIS.md`
- `docs/ATDR_TEMPLATE_SHELL_INTEGRATION_PLAN.md`
- `docs/V3_65_MFU_IAM_AND_REAL_ASSISTANT_HARNESS.md`
- `docs/V3_79_TEMPLATE_TO_ATDR_HANDOFF_RECEIVER.md`
- `docs/V3_80_SUPERVISOR_TEMPLATE_RUNTIME_BRIDGE.md`
- `docs/V3_81_TEMPLATE_ATDR_LAUNCHER_HELPER.md`
- `docs/V3_82_TEMPLATE_LAUNCHER_APPLIED_RUNTIME_PREP.md`
- `docs/V3_83_TEMPLATE_SHELL_SESSION_ADAPTER.md`
- `docs/V3_84_TEMPLATE_SHELL_RUNTIME_VALIDATION.md`
- `docs/V3_85_TEMPLATE_SHELL_CONFIG_HELPER.md`
- `docs/V3_86_TEMPLATE_SHELL_LIVE_RUNTIME_CHECK.md`
- `docs/V3_87_REAL_LLM_SOC_ASSISTANT.md`
- `docs/V3_88_PRODUCT_BASELINE_CHECKPOINT.md`
- `docs/V3_88_CHANGESET_MANIFEST.md`
- `docs/changes/T1_T20_V3_78_TEMPLATE_SHELL_INTEGRATION_PLAN.md`
- `docs/changes/T1_T20_V3_79_TEMPLATE_TO_ATDR_HANDOFF_RECEIVER.md`
- `docs/changes/T1_T20_V3_80_SUPERVISOR_TEMPLATE_RUNTIME_BRIDGE.md`
- `docs/changes/T1_T20_V3_81_TEMPLATE_ATDR_LAUNCHER_HELPER.md`
- `docs/changes/T1_T20_V3_82_TEMPLATE_LAUNCHER_APPLIED_RUNTIME_PREP.md`
- `docs/changes/T1_T20_V3_83_TEMPLATE_SHELL_SESSION_ADAPTER.md`
- `docs/changes/T1_T20_V3_84_TEMPLATE_SHELL_RUNTIME_VALIDATION.md`
- `docs/changes/T1_T20_V3_85_TEMPLATE_SHELL_CONFIG_HELPER.md`
- `docs/changes/T1_T20_V3_86_TEMPLATE_SHELL_LIVE_RUNTIME_CHECK.md`
- `docs/changes/T1_T20_V3_87_REAL_LLM_SOC_ASSISTANT.md`
- `docs/changes/T1_T20_V3_88_PRODUCT_BASELINE_CHECKPOINT.md`
- `docs/tasks/tasklist-progress.md`

### Generated But Intentionally Tracked

- `docs/tasks/tasklist-progress.html`: generated from the canonical Markdown progress board and required by the supervisor-style tasklist workflow.

### Ignored / Private / Never Stage

- `.env`, `frontend/.env`, and all template private `.env*` files
- `atdr.db`, `*.sqlite`, `*.sqlite3`
- private/real firewall logs and `data/private/`, `real_logs/`
- `atdr/data/processed/` except its existing `.gitkeep`
- `atdr/models/*.joblib`, candidate artifacts, and generated model reports
- `ml_baseline_reviews/`
- `demo_exports/`
- `.venv/`, `node_modules/`, `frontend/dist/`, Playwright output
- `.tmp/`, `.pytest_tmp/`, caches, runtime logs, and backups
- ignored in-repo copies of the supervisor template and `NewSystem` private/local artifacts

### Unrelated User Changes

No unrelated visible tracked/untracked source change was identified during the v3.88 audit. If Git status changes before staging, re-run the classification and do not use `git add .`.

### Suspicious Or Accidental Artifacts

No suspicious non-ignored artifact was found. Numerous permission-denied warnings came from old ignored pytest temporary directories; they are not commit candidates and were not deleted.

## External Supervisor-Template Change

Outside the ATDR repository:

```text
<MFU_SHELL_ROOT>\frontend-vue\src\views\Dashboard.vue
```

The file contains the `Open ATDR SOC Dashboard` launcher. The external template folder is not a Git repository and the v3.88 audit did not find a current `Dashboard.vue.bak-*` file. Before future edits, preserve a clean advisor archive or create a new versioned backup outside ATDR. Do not stage this external file in the ATDR commit.

## Rollback

- Immediate assistant rollback: set `ASSISTANT_LLM_ENABLED=false` in private `.env`; deterministic fallback remains.
- Immediate template-handoff rollback: set `MFU_IAM_ENABLED=false` or `MFU_IAM_TEMPLATE_SHELL_ENABLED=false`; local login remains.
- ATDR code rollback after commit: revert the relevant commit; no migration or data rollback is required for v3.78-v3.88.
- External template rollback: restore `Dashboard.vue` from a clean advisor archive or remove only the marked ATDR launcher block after inspection.
- Do not restore, overwrite, reset, or delete the current database.

## Known Risks

- The external template launcher is outside version control in the audited folder.
- Any IAM credential previously shared outside approved secret storage should be rotated before shared deployment.
- Template Redis availability and template npm vulnerabilities remain separate operational work.
- SQLite, synchronous long-running operations, real-device validation, production IAM lifecycle, provider quota/privacy, observability, and ML generalization remain open productization risks.

## Exact Staging Commands

Run from `<ATDR_ROOT>` after reviewing `git status`:

```powershell
$v388Files = @(
  '.env.example',
  '.env.lab.example',
  '.env.production.example',
  '.github/workflows/ci.yml',
  'README.md',
  'frontend/README.md',
  'frontend/package.json',
  'frontend/package-lock.json',
  'atdr/app/core/config.py',
  'atdr/app/routers/assistant.py',
  'atdr/app/schemas/assistant.py',
  'atdr/app/schemas/auth.py',
  'atdr/app/services/assistant_llm.py',
  'atdr/app/services/assistant_service.py',
  'atdr/app/services/mfu_iam_service.py',
  'atdr/app/services/mfu_iam_validation.py',
  'atdr/app/services/template_bridge_contract.py',
  'atdr/scripts/apply_template_atdr_launcher.py',
  'atdr/scripts/config_doctor.py',
  'atdr/scripts/test_assistant_chat_provider.py',
  'atdr/scripts/test_assistant_llm_provider.py',
  'atdr/scripts/use_template_shell_config.py',
  'atdr/scripts/validate_template_bridge_contract.py',
  'atdr/scripts/validate_template_shell_runtime.py',
  'atdr/tests/test_api.py',
  'atdr/tests/test_assistant.py',
  'atdr/tests/test_dev_onboarding.py',
  'atdr/tests/test_hardening_and_ingestion.py',
  'atdr/tests/test_mfu_iam_validation.py',
  'atdr/tests/test_template_atdr_launcher.py',
  'atdr/tests/test_template_bridge_contract.py',
  'atdr/tests/test_template_shell_runtime.py',
  'frontend/src/pages/AssistantPage.tsx',
  'frontend/src/pages/LoginPage.tsx',
  'frontend/src/pages/UserAdmin.tsx',
  'frontend/src/types/api.ts',
  'frontend/tests/smoke.spec.ts',
  'docs/AI-DOCS-INDEX.md',
  'docs/ATDR_PRODUCTIZATION_ROADMAP.md',
  'docs/ATDR_REQUIREMENT_TRACEABILITY.md',
  'docs/ATDR_TEMPLATE_MERGE_ANALYSIS.md',
  'docs/ATDR_TEMPLATE_SHELL_INTEGRATION_PLAN.md',
  'docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md',
  'docs/CURRENT_SYSTEM_STATE_LOCK.md',
  'docs/LAB_RUNBOOK.md',
  'docs/QUICKSTART_FOR_TEAM.md',
  'docs/V3_65_MFU_IAM_AND_REAL_ASSISTANT_HARNESS.md',
  'docs/V3_79_TEMPLATE_TO_ATDR_HANDOFF_RECEIVER.md',
  'docs/V3_80_SUPERVISOR_TEMPLATE_RUNTIME_BRIDGE.md',
  'docs/V3_81_TEMPLATE_ATDR_LAUNCHER_HELPER.md',
  'docs/V3_82_TEMPLATE_LAUNCHER_APPLIED_RUNTIME_PREP.md',
  'docs/V3_83_TEMPLATE_SHELL_SESSION_ADAPTER.md',
  'docs/V3_84_TEMPLATE_SHELL_RUNTIME_VALIDATION.md',
  'docs/V3_85_TEMPLATE_SHELL_CONFIG_HELPER.md',
  'docs/V3_86_TEMPLATE_SHELL_LIVE_RUNTIME_CHECK.md',
  'docs/V3_87_REAL_LLM_SOC_ASSISTANT.md',
  'docs/V3_88_PRODUCT_BASELINE_CHECKPOINT.md',
  'docs/V3_88_CHANGESET_MANIFEST.md',
  'docs/changes/T1_T20_V3_78_TEMPLATE_SHELL_INTEGRATION_PLAN.md',
  'docs/changes/T1_T20_V3_79_TEMPLATE_TO_ATDR_HANDOFF_RECEIVER.md',
  'docs/changes/T1_T20_V3_80_SUPERVISOR_TEMPLATE_RUNTIME_BRIDGE.md',
  'docs/changes/T1_T20_V3_81_TEMPLATE_ATDR_LAUNCHER_HELPER.md',
  'docs/changes/T1_T20_V3_82_TEMPLATE_LAUNCHER_APPLIED_RUNTIME_PREP.md',
  'docs/changes/T1_T20_V3_83_TEMPLATE_SHELL_SESSION_ADAPTER.md',
  'docs/changes/T1_T20_V3_84_TEMPLATE_SHELL_RUNTIME_VALIDATION.md',
  'docs/changes/T1_T20_V3_85_TEMPLATE_SHELL_CONFIG_HELPER.md',
  'docs/changes/T1_T20_V3_86_TEMPLATE_SHELL_LIVE_RUNTIME_CHECK.md',
  'docs/changes/T1_T20_V3_87_REAL_LLM_SOC_ASSISTANT.md',
  'docs/changes/T1_T20_V3_88_PRODUCT_BASELINE_CHECKPOINT.md',
  'docs/prd/PRD-ATDR.md',
  'docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md',
  'docs/tasks/tasklist-progress.md',
  'docs/tasks/tasklist-progress.html'
)

git add -- $v388Files
git status --short
git diff --cached --check
git diff --cached --stat
```

Never use `git add .` for this checkpoint.

## Suggested Commit Grouping

Preferred single checkpoint commit after all checks pass:

```text
feat: consolidate MFU shell handoff and real SOC assistant
```

Alternative two-commit grouping:

1. `feat: integrate MFU template shell handoff`
2. `feat: harden real SOC assistant and checkpoint docs`

Because several shared files contain both IAM and assistant configuration/tests, the single checkpoint commit is less error-prone.

## Exact Commit And Push Commands

After the staging commands above, inspect the staged diff and commit deliberately:

```powershell
git diff --cached --check
git diff --cached --stat
git diff --cached --name-status
git commit -m "feat: consolidate MFU shell handoff and real SOC assistant"
git status --short
git push origin HEAD
```

Do not run `git push` unless the commit succeeded and the post-commit status contains only known ignored/private state. The source is ready to stage; it is not ready to push until the user performs and reviews the commit.
