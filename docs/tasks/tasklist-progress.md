# Tasklist: ATDR System Progress And Readiness

| Field | Value |
| --- | --- |
| Date | 2026-09-17 |
| Project | MFU AI-Driven Log-Based Threat Detection and Response System |
| Module / Feature | v5.63.1 Controlled-Lab Detection and Advisor Demonstration Reliability Lock |
| Requirement | Make the complete advisor-facing workflow accurate, safe, concise, and reproducible with currently available resources. |
| Active Change Record | `docs/changes/T1_T20_V5_63_1_ADVISOR_DEMO_RELIABILITY_LOCK.md` |
| Overall Status | complete_advisor_demo_ready |
| Overall Progress | 100% |
| Progress Type | Controlled-lab reliability and advisor acceptance; not production certification |

## T1. Source Evidence

| Area | Source Evidence |
| --- | --- |
| Published baseline | v5.63 commit `cf106d6` from `origin/main` |
| Backend entry | `atdr/app/main.py`, ML services, v5.63.1 evaluator, and disposable acceptance CLI |
| Frontend entry | `frontend/src/App.tsx`, AI Governance, Detection Tuning, and SOC Assistant routes |
| Detection authority | nineteen deterministic rules, v5.58 runtime contract, and layered detection suites |
| Anomaly runtime | ignored legacy IsolationForest artifact, v5.61 bootstrap contract, ML service telemetry |
| Private evaluation | CLI-only bounded PAN-OS input; aggregate output without path, raw records, addresses, identities, or fingerprints |
| Assistant | bounded service context, deterministic fallback, Gemini adapter, QA corpus, contextual follow-up contract |
| Advisor workflow | `atdr/scripts/run_v5631_advisor_demo_acceptance.py` with disposable in-memory storage |
| Frontend | AI Governance and Detection Tuning pages with explicit anomaly denominator and coverage wording |
| Safety | rules authoritative, anomaly/hybrid advisory, supervised unqualified, response simulation-only |

## T2. Progress Calculation

| Readiness Area | Weight | Earned | Basis |
| --- | ---: | ---: | --- |
| Anomaly telemetry correctness | 15 | 15 | Scored-row rate, database coverage, and all-row prevalence are separated. |
| Development-only anomaly audit | 20 | 20 | Eight fixed variants compared; unqualified candidates refused. |
| Assistant and Gemini reliability | 20 | 20 | Thirty intent cases, follow-up continuity, citations, privacy, and bounded live probe pass. |
| Advisor end-to-end acceptance | 20 | 20 | Ten stages and 24 workflow checks pass in disposable storage. |
| UI and analyst wording | 10 | 10 | Governance and tuning views name the anomaly denominator and advisory authority. |
| Full verification and governance | 15 | 15 | Full backend/frontend, migration, scenario, security, performance, and release checks pass. |
| **Total** | **100** | **100** | v5.63.1 implementation and local verification are complete. |

## T3. Active Tasklist

| Task ID | Task | Agent | Owner | Depends On | Status | Progress % | Progress Basis | Source Evidence | Tests Evidence | Blocker | Next Action | Output |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| ATDR-TASKLIST-001 | v5.63.1 advisor reliability lock | Codex | Project owner | published v5.63 baseline | complete | 100 | Runtime, UI, CLIs, tests, status, runbook, full verification, and exact allowlist complete | v5.63.1 source and status docs | backend `1119 passed, 1 skipped`; browser `45 passed, 1 skipped`; advisor acceptance `10/10`, workflow `24/24` | none | seek separate publication approval only when desired | approval-ready advisor reliability baseline |
| ATDR-TASKLIST-002 | Window-aware anomaly redesign | Codex / future reviewer | Project owner | new development evidence | planned | 0 | Current candidates fail threat-capture gates | v5.63.1 reliability report | candidate decision is no-selection | trustworthy context features and independent evidence | collect new development windows under a new protocol | improved advisory candidate or honest no-candidate result |
| ATDR-TASKLIST-003 | Governed supervised qualification | Human reviewer + Codex | Project owner | fresh review closure and second-source evidence | blocked_external | 0 | effective runtime remains `unqualified` | v5.62-v5.63 qualification campaign | fail-closed runtime and leakage tests pass | genuine labels and second source | complete review and external evidence without forcing quotas | separately approved shadow candidate decision |

## T4. Verification Log

| Command / Check | Result | Evidence |
| --- | --- | --- |
| focused v5.61/v5.63.1 backend tests | pass | `14 passed`; telemetry, privacy, manifest, install refusal, acceptance composition |
| private anomaly evidence preflight | pass | 50,000/50,000 parsed; 99.77% feature completeness; 30,832 eligible; output aggregate-only |
| anomaly candidate comparison | pass with no candidate | eight variants evaluated; all failed fixed threat-capture gates; zero artifact install |
| disposable advisor acceptance | pass | 10/10 stages; 24/24 workflow checks; configured database not accessed |
| Assistant QA | pass | 30 cases plus follow-up continuity; average/max 56.1/110 words; zero authoritative writes |
| bounded live Gemini probe | pass | external provider used; structured output valid; raw logs false; redaction true; secrets false |
| taskboard / Ruff / compileall / Alembic | pass | board rendered and validated; lint/bytecode clean; no migration drift |
| full backend suite | pass | `1119 passed, 1 skipped`; repeated successfully inside the release gate |
| React lint / build / Playwright | pass | production build clean; `45 passed, 1 skipped` |
| controlled source / layered detection | pass | source workflow succeeded; layered `288/288`, zero controlled FP/FN |
| replay / performance | pass | dry-run wrote zero rows; performance `ok: true`, anomaly rate 2.36%, no warnings |
| repository / security audit | pass | no broken/non-portable references; zero findings across 1,449 scanned text paths |
| release gate | pass | `ok: true`; config, compileall, backend, Alembic, and deployment operations all pass |

## T5. Blockers And Risks

| ID | Type | Status | Evidence | Impact | Next Action |
| --- | --- | --- | --- | --- | --- |
| R-5631-01 | anomaly quality | controlled | legacy benign anomaly rate 17.78%; suspicious/malicious capture 57.14%/50.00% | anomaly remains supporting evidence only | redesign with new development windows; do not install current candidates |
| R-5631-02 | supervised evidence | deferred/external | effective runtime `unqualified`; v5.63 campaign not yet reviewed | no supervised runtime inference | finish genuine review and obtain second physical source later |
| R-5631-03 | external acceptance | deferred by owner | MFU provider, real firewall, and shared host evidence unavailable | no production or field-certification claim | retain ready-to-test contracts and resume when owners/hardware exist |
| R-5631-04 | provider governance | external | live Gemini adapter works; institutional privacy/quota/key acceptance pending | controlled demo only | obtain provider-owner acceptance before shared deployment |

## T6. Decision

ATDR is implementation-ready for a controlled advisor demonstration. Rules
remain alert-authoritative, anomaly and hybrid output remain advisory,
supervised runtime remains `unqualified`, and response remains
`simulation_only`. The anomaly telemetry defect is corrected without changing
predictions. No new candidate passed the fixed gates, so no model was installed.
No commit or push is authorized by this taskboard.
