# Tasklist: ATDR System Progress And Readiness

| Field | Value |
| --- | --- |
| Date | 2026-09-16 |
| Project | MFU AI-Driven Log-Based Threat Detection and Response System |
| Module / Feature | v5.61 Governed Advisory IsolationForest Bootstrap |
| Requirement | Reproduce the optional anomaly capability explicitly on a clean clone without silent training, private evidence exposure, model authority, or committed artifacts. |
| Active Change Record | `docs/changes/T1_T20_V5_61_GOVERNED_ANOMALY_BOOTSTRAP.md` |
| Overall Status | complete_locally |
| Overall Progress | 100% |
| Progress Type | Evidence-backed capability closure; not threat-accuracy or production certification |

## T1. Source Evidence

| Area | Source Evidence |
| --- | --- |
| Published baseline | v5.60 commit `da7c2434962eec10c0fd7c6bbd9266c5dbebf2c6` from `origin/main` |
| Backend entry | `atdr/app/main.py`, ML router and schemas |
| Frontend entry | `frontend/src/App.tsx`, `frontend/src/lib/api.ts`, AI Governance page |
| Anomaly training/scoring | `atdr/app/detection/ml_detector.py`, `atdr/app/services/ml_service.py` |
| Governed bootstrap | `atdr/app/services/v561_anomaly_bootstrap_service.py`, `atdr/scripts/run_v561_governed_anomaly_bootstrap.py` |
| Operator wrapper | `scripts/bootstrap_advisory_anomaly.ps1`, `.cmd` |
| Runtime authority | `atdr/app/services/detection_service.py`, `atdr/app/detection/runtime_contract.py` |
| Setup/start | `scripts/setup_team.ps1`, `scripts/start_system.ps1` |
| Clean machine | v5.60 harness plus explicit v5.61 optional stages |
| UI | `frontend/src/pages/MLGovernance.tsx`, API types and Playwright |
| Tests | v5.61 focused tests, v5.60 extension tests, API and frontend regression suites |

## T2. Progress Calculation

| Readiness Area | Weight | Earned | Basis |
| --- | ---: | ---: | --- |
| Source audit and contract | 10 | 10 | Training, status, authority, startup, clean-machine, and UI paths inspected. |
| Safe evidence preflight | 20 | 20 | Schema, parser, support, duplicate, provenance, and privacy gates implemented. |
| Explicit disposable bootstrap | 25 | 25 | Confirmation, temporary SQLite, deterministic manifest, ignored destinations, and rollback implemented. |
| Runtime and UI honesty | 15 | 15 | Exact availability wording, corrective command, authority, and accuracy caveat implemented. |
| Clean-machine extension | 10 | 10 | Default 27 stages preserved; five explicit v5.61 stages added. |
| Tests, docs, and complete verification | 20 | 20 | Full local matrix passed; exact 31-path allowlist prepared. |
| **Total** | **100** | **100** | Local implementation and verification are complete; publication remains separately controlled. |

## T3. Active Tasklist

| Task ID | Task | Agent | Owner | Depends On | Status | Progress % | Progress Basis | Source Evidence | Tests Evidence | Blocker | Next Action | Output |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| ATDR-TASKLIST-001 | v5.61 governed advisory anomaly bootstrap | Codex | Project owner | Published v5.60 baseline | complete | 100 | Runtime, CLI, wrapper, UI, clean-machine extension, tests, docs, and full local verification complete | v5.61 service/CLI/wrappers/status/UI/docs | 1,102/1 backend, 43/1 Playwright, 288/288 layered, 30-case Assistant QA, 27/27 published clean-machine, and isolated bootstrap pass | Extended genuine remote-clone option requires separately approved publication; external accuracy evidence remains unavailable | Seek separate allowlist approval, then rerun the 32-stage option from published `origin/main` | v5.61 capability closure and approval-ready handoff |

## T4. Verification Log

| Command / Check | Result | Evidence |
| --- | --- | --- |
| committed synthetic preflight | pass | 45 unique rows parsed; 41 eligible; four unresolved-app rows excluded; zero writes |
| v5.61 focused backend tests | pass | confirmation, evidence gates, ignored paths, disposable execution, manifest, authority, cleanup, and redaction |
| isolated explicit bootstrap | pass | 45 rows scored; two advisory signals; valid manifest; zero alerts, suppressions, labels, model/detection runs, or responses; outputs cleaned |
| complete backend and release gate | pass | 1,102 passed, one skipped; config, migrations, and deployment checks passed |
| frontend lint/build/Playwright | pass | lint/build green; 43 passed, one skipped; availability, corrective command, and overflow contracts pass |
| controlled and layered detection | pass | source scenario passed; 288/288 layered checks, zero controlled FP/FN and response actions |
| Assistant QA | pass | 30/30 cases plus contextual sequence; grounded, concise, read-only |
| genuine published clean machine | pass | 27/27 stages; pristine anomaly unavailable; rules authoritative; complete cleanup |
| repository/security/taskboard | pass | 1,425 intended paths, zero secret findings, no broken references, rendered board valid |
| replay and performance | pass | replay parsed two rows with zero writes; 145,232-row smoke met every budget |

## T5. Blockers And Risks

| ID | Type | Status | Evidence | Impact | Next Action |
| --- | --- | --- | --- | --- | --- |
| R-561-01 | risk | controlled | Current workspace has an ignored pre-v5.61 artifact without a governed manifest. | Capability is available locally but provenance is legacy. | Leave untouched unless owner deliberately runs replacement after preflight. |
| R-561-02 | risk | controlled | Synthetic bootstrap data contains no independent threat labels. | Capability success cannot support accuracy or maliciousness claims. | Keep anomaly advisory and obtain external evidence separately. |
| R-561-03 | risk | controlled | Extended 32-stage genuine remote-clone run needs v5.61 to exist on `origin/main`. | Pre-publication verification cannot execute the new CLI from a remote clone. | Run the opt-in extension after separately approved publication; local disposable execution and focused tests currently prove the contract. |
| B-EXT-01 | blocker | open | No second physical source or untouched future evidence. | Supervised runtime remains unqualified and anomaly accuracy remains unvalidated. | Detection owners acquire governed independent evidence. |
| B-EXT-02 | blocker | open | University/provider/shared-host acceptance remains pending. | Production certification is unavailable. | External owners complete the preserved acceptance tracks. |

## T6. Decision

v5.61 implementation preserves deterministic rules as alert authority,
supervised runtime as `unqualified`, IsolationForest/hybrid as advisory,
response as `simulation_only`, and model training as an explicit operator
action. No commit or push is authorized by this taskboard.
