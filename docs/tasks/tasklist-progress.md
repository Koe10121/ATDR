# Tasklist: ATDR System Progress And Readiness

| Field | Value |
| --- | --- |
| Date | 2026-09-17 |
| Project | MFU AI-Driven Log-Based Threat Detection and Response System |
| Module / Feature | v5.63 Fresh Comparable Evidence Expansion |
| Requirement | Reach the fixed 1,000-row selected capacity without changing v5.62 custody, exposing evaluation evidence, or running a model. |
| Active Change Record | `docs/changes/T1_T20_V5_63_FRESH_COMPARABLE_EVIDENCE_EXPANSION.md` |
| Overall Status | ready_for_batched_human_review |
| Overall Progress | 100% implementation; 0/1,000 genuine review decisions |
| Progress Type | Evidence capacity and protected workflow; not supervised qualification |

## T1. Source Evidence

| Area | Source Evidence |
| --- | --- |
| Published baseline | v5.61 commit `df8f3b8` from `origin/main` |
| Backend entry | `atdr/app/main.py`, evidence-review router, and v5.62-v5.63 campaign/review services |
| Frontend entry | `frontend/src/App.tsx`, Evidence Review page, API client, and query hooks |
| Original campaign | immutable v5.62 protocol, 300-row pack, consumed-evidence exclusion, and fixed gates |
| Runtime authority | v5.58 rules-authoritative hybrid runtime and v5.61 advisory anomaly contract |
| Expansion | `atdr/app/detection/v563_fresh_evidence_expansion.py` |
| CLI | `atdr/scripts/run_v563_fresh_evidence_expansion.py` |
| Protected review | v5.63 batch service, evidence-review router/schemas, and React panel |
| Private preparation | 773,551 rows parsed in disposable SQLite; aggregate output only |
| Tests | v5.63 custody/API/source tests and Playwright batched-review workflow |

## T2. Progress Calculation

| Readiness Area | Weight | Earned | Basis |
| --- | ---: | ---: | --- |
| v5.62 append-only custody | 15 | 15 | All 300 rows, roles, gates, and sealed evaluation evidence preserved. |
| Fresh supplemental selection | 20 | 20 | 700 unique development-safe families selected; overlap and added evaluation rows both zero. |
| Batched protected review | 20 | 20 | Seven owner-isolated 100-row batches support resume, validation, revisions, and immutable closure. |
| Second-source intake readiness | 15 | 15 | CLI-only disposable preflight rejects same-device evidence and returns aggregates only. |
| Aggregate gates and safety | 10 | 10 | All fixed gates shown honestly; no training/evaluation/activation or authoritative writes. |
| Tests, docs, and verification | 20 | 20 | Focused checks pass; complete matrix is recorded in T4 after final execution. |
| **Total** | **100** | **100** | v5.63 implementation is complete; human review and real second-source evidence remain external work. |

## T3. Active Tasklist

| Task ID | Task | Agent | Owner | Depends On | Status | Progress % | Progress Basis | Source Evidence | Tests Evidence | Blocker | Next Action | Output |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| ATDR-TASKLIST-001 | v5.63 evidence expansion and intake readiness | Codex | Project owner | immutable v5.62 campaign | complete | 100 | Backend, CLI, API/UI, tests, private preparation, full verification, and governance complete | v5.63 source and status doc | backend `1114 passed, 1 skipped`; browser `45 passed, 1 skipped`; full matrix in T4 | none for implementation | Seek separate publication approval only when desired | approval-ready cumulative v5.62-v5.63 source baseline |
| ATDR-TASKLIST-002 | Complete original protected review | Human analyst | Project owner | v5.62 workspace | ready | 0 | `0/300`, zero invalid, future evaluation sealed | private ignored v5.62 review state | owner/redaction/closure tests pass | genuine human judgment required | review and close 300 rows without forcing quotas | immutable original decisions |
| ATDR-TASKLIST-003 | Complete supplemental review batches | Human analyst(s) | Project owner | v5.63 workspace | ready | 0 | `0/700`; seven batches open; zero invalid | private ignored v5.63 review state | owner/revision/batch-closure tests pass | genuine human judgment required | review and close all seven batches | immutable supplemental decisions |
| ATDR-TASKLIST-004 | Prove second physical source | Hardware owner | Project owner / advisor | source device access | blocked_external | 0 | one real source versus fixed minimum two | aggregate v5.63 source gate | same-device rejection and distinct-device synthetic tests pass | second physical device unavailable | run guarded preflight on genuine new-device logs | independent source evidence |

## T4. Verification Log

| Command / Check | Result | Evidence |
| --- | --- | --- |
| v5.62 boundary revalidation | pass | 300 rows and roles unchanged; 45 future rows sealed; decisions not accessed |
| private v5.63 preparation | pass | 773,551 parsed, zero failures, 700 selected, zero original overlap, seven batches, zero writes |
| focused backend v5.63 tests | pass | `6/6`; custody, overlap, auth, owner, revisions, closure, source identity, redaction, no-write |
| focused frontend workflow | pass | React lint/build and Playwright qualification/expansion `2/2` |
| taskboard render / standard check | pass | generated HTML is current and required ATDR sections validate |
| Ruff / compileall / Alembic | pass | lint and bytecode checks clean; no new upgrade operations |
| full backend suite | pass | `1114 passed, 1 skipped`; repeated successfully by release gate |
| React lint / build / Playwright | pass | production build clean; `45 passed, 1 skipped` |
| controlled source / layered detection | pass | source `10/10`; expected alert and zero responses; layered `288/288`, zero controlled FP/FN |
| Assistant / governed hybrid | pass | 30 quality cases plus follow-ups; rules authoritative, anomaly advisory, supervised unqualified, response simulation-only |
| replay / performance | pass | replay wrote zero rows; performance `ok: true`, no warnings, cached Overview `0.0105s` |
| repository / security audit | pass | no broken/non-portable references; zero findings across 1,441 tracked text paths |
| release gate | pass | config, compileall, backend, Alembic, and deployment-operations checks all pass |

## T5. Blockers And Risks

| ID | Type | Status | Evidence | Impact | Next Action |
| --- | --- | --- | --- | --- | --- |
| B-563-01 | human | open | combined review `0/1,000` | comparable and class-support gates fail | complete genuine review without forced labels |
| B-563-02 | hardware | open | one verified physical source | provenance gate fails | obtain independently verified second source |
| B-563-03 | evaluation | controlled | future labels remain sealed | no quality metric may be claimed | preserve seal until a candidate is frozen under a later protocol |
| R-563-01 | integrity | controlled | large duplicate population exists | leakage if family locks change | keep immutable family/role exclusion records |
| R-563-02 | interpretation | controlled | selected capacity equals 1,000 but reviewed count is zero | capacity could be mistaken for qualification | always report selected and reviewed counts separately |

## T6. Decision

v5.63 is implementation-complete and ready for genuine batched human review.
It reaches the selected 1,000-row capacity but does not qualify supervised ML.
No training, evaluation, freeze, activation, promotion, authoritative alert
change, automatic response, or real blocking occurred. No commit or push is
authorized by this taskboard.
