# Tasklist: ATDR System Progress And Readiness

| Field | Value |
| --- | --- |
| Date | 2026-09-15 |
| Project | MFU AI-Driven Log-Based Threat Detection and Response System |
| Module / Feature | v5.60 Clean-Machine End-to-End Release Candidate Acceptance |
| Requirement | Prove a fresh Windows clone can install, start through the MFU shell, recover, run a safe analyst workflow, and clean up without private state. |
| Active Change Record | `docs/changes/T1_T20_V5_60_CLEAN_MACHINE_RELEASE_CANDIDATE_ACCEPTANCE.md` |
| Overall Status | complete_locally |
| Overall Progress | 100% |
| Progress Type | Evidence-backed local release-candidate acceptance; not production certification |

## T1. Source Evidence

| Area | Source Evidence |
| --- | --- |
| Published baseline | v5.59 commit `d020f1a973f005c192eba3256357f76618542cab` from `origin/main` |
| Backend entry and API | `atdr/app/main.py`, `atdr/app/routers/*.py` |
| Frontend entry and API client | `frontend/src/App.tsx`, `frontend/src/lib/api.ts` |
| Clean-machine harness | `atdr/app/services/v560_clean_machine_acceptance_service.py`, `atdr/scripts/run_v560_clean_machine_acceptance.py` |
| Lifecycle | `scripts/setup_team.ps1`, `scripts/start_system.ps1`, `scripts/check_system.ps1`, `scripts/stop_system.ps1` |
| Shell contract | `config/mfu-shell-contract.json`, approved versioned shell package, authenticated handoff tests |
| Analyst workflow | `atdr/scripts/run_e2e_workflow_validation.py`, v5.57 acceptance services |
| Detection authority | `atdr/app/detection/runtime_contract.py`, `atdr/scripts/run_v558_governed_hybrid_runtime.py` |
| Tests | `atdr/tests/test_v560_clean_machine_acceptance.py`, backend and frontend regression suites |
| Safety | repository surface audit, security acceptance, ignore policy, disposable storage checks |

## T2. Progress Calculation

| Readiness Area | Weight | Earned | Basis |
| --- | ---: | ---: | --- |
| Baseline and preflight | 10 | 10 | Published commit, remote, tools, package, ports, and provider prerequisites checked without secret output. |
| Disposable harness and privacy | 20 | 20 | Genuine remote clone, pristine-state checks, synthetic profile, constrained cleanup, and redacted reporting passed. |
| Setup and shell contract | 20 | 20 | First setup, provider-missing failure, repeat setup, four dependency trees, SQLite, and handoff contracts passed. |
| Lifecycle and recovery | 20 | 20 | Start/check/idempotence/stop/restart/stale-state/occupied-port/local-recovery checks passed. |
| Analyst workflow and safety | 15 | 15 | Ingest, normalize, detect, explain, related evidence, recommendations, Assistant follow-ups, and zero-side-effect gates passed. |
| Verification, docs, and handoff | 15 | 15 | Full backend/frontend/detection/Assistant/security/performance/release matrix and current guidance completed. |
| **Total** | **100** | **100** | v5.60 is complete locally; owner-backed external acceptance remains open. |

## T3. Active Tasklist

| Task ID | Task | Agent | Owner | Depends On | Status | Progress % | Progress Basis | Source Evidence | Tests Evidence | Blocker | Next Action | Output |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| ATDR-TASKLIST-001 | v5.60 clean-machine release-candidate acceptance | Codex | Project owner | Published v5.59 baseline and approved shell package | complete | 100 | All 27 harness gates and complete local verification passed | v5.60 service, CLI, test, status, and operator docs | 27/27 clean-room; 1,091 backend; 42 Playwright; 288 layered; 30 Assistant cases | Real university/provider/hardware/shared-host acceptance remains external | Consider v5.61 advisory anomaly bootstrap; obtain separate approval before publication | v5.60 harness, status, T1-T20, taskboard, exact allowlist |

## T4. Verification Log

| Command / Check | Result | Evidence |
| --- | --- | --- |
| v5.60 focused and related tests | pass | 40 passed; seven directly exercise v5.60 boundaries |
| genuine clean-machine harness | pass | 27/27 stages; remote clone, lifecycle, recovery, workflow, and cleanup |
| backend Ruff and compileall | pass | No lint or compilation failures |
| full backend tests | pass | 1,091 passed, one skipped; known dependency/model warnings only |
| Alembic drift | pass | No new upgrade operations detected |
| frontend lint and build | pass | 2,300 modules built successfully |
| Playwright | pass | 42 passed; one intentionally skipped live-hardware scenario |
| controlled source scenario | pass | 10 parsed, one expected port-scan alert, zero response actions |
| layered detection validation | pass | 288/288 mode runs across 24 scenarios |
| SOC Assistant QA | pass | 30/30 cases and one conversation sequence; 100% citation pass rate |
| governed runtime inspection | pass | Rules authoritative, anomaly/hybrid advisory, supervised unqualified, response simulation-only |
| replay dry-run | pass | Two sample rows parsed, zero writes or sends |
| performance smoke | pass with observation | Overall gate passed; cold Overview 1.0477s versus 1.0s advisory budget, cached 0.014s |
| repository and security audits | pass | Zero broken links/commands/parse errors and zero tracked-secret findings |
| release gate | pass | Config, compile, 1,091-test rerun, Alembic, and deployment operations green |
| repository hygiene | pass | Staging empty; private/generated artifacts remain ignored; diff check clean |

## T5. Blockers And Risks

| ID | Type | Status | Evidence | Impact | Next Action |
| --- | --- | --- | --- | --- | --- |
| R-560-01 | risk | mitigated | Clean clones intentionally contain no ignored IsolationForest artifact. | Anomaly reports unavailable and hybrid abstains until an artifact is governed locally. | v5.61 may add explicit operator-guided advisory bootstrap without committing an artifact. |
| R-560-02 | risk | observed | Cold Overview measured 1.0477s against a 1.0s advisory budget; cached path was 0.014s. | First dashboard load can vary slightly on the large local SQLite database. | Retain monitoring; no release-gate failure or urgent runtime change is justified. |
| B-EXT-01 | blocker | open | Synthetic provider wiring is not a real MFU sign-in. | University IAM lifecycle is not production-accepted. | University owner validates account, groups, 2FA, recovery, and deprovisioning. |
| B-EXT-02 | blocker | open | No second physical source or new prediction-blind future evidence. | Supervised runtime remains unqualified. | Detection owners acquire governed independent evidence. |
| B-EXT-03 | blocker | open | Institutional Gemini approval and representative provider evaluation are absent. | External Assistant mode is not institutionally accepted. | Provider owner approves privacy, quota, billing, retention, and key rotation. |
| B-EXT-04 | blocker | open | No approved shared host or physical teammate acceptance. | Shared deployment and independent usability remain unqualified. | Deployment/teammate owners run preserved acceptance procedures. |

## T6. Decision

v5.60 establishes a reproducible controlled local release candidate from a
genuine remote clone. Normal startup remains the MFU shell, local recovery is
explicit, rules remain `active_authoritative`, supervised ML remains
`unqualified`, the Assistant remains read-only, response remains
`simulation_only`, and no model, label, protected evidence, automatic response,
or real block was created. No commit or push is authorized by this record.
