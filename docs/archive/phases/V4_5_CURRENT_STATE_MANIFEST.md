# v4.5 Current State Manifest

## Source Baseline

| Item | State |
| --- | --- |
| Branch | `main` |
| Published v4.5 source baseline | `dd6ff014fc09d02b224d11be2b0663c2d26c3495` (`feat: establish reproducible ATDR product baseline`) |
| Final CI closure | `1535a3182d2813b6136a2ee0073c4901fb19d675` (`ci: expose pwsh for portability tests`) |
| Public verification | GitHub Actions CI #55 passed all backend, frontend, and PostgreSQL jobs |
| Local change boundary | v3.97 through v4.5 is published; the source worktree was clean at final verification |
| Backend | FastAPI, SQLAlchemy, Alembic, Python 3.11 |
| Python dependency baseline | Direct dependencies in `requirements.txt`; exact resolved environment in `requirements.lock.txt` |
| Main dashboard | React, TypeScript, Vite, shared MFU-token SOC page surfaces |
| Local database | SQLite, current configured DB at Alembic head `b4c5d6e7f8a9` |
| Optional shared database | PostgreSQL references and validators; approved-host acceptance remains open |
| Normal identity entry | Separately supplied MFU Vue/Node shell with one-time ATDR handoff |
| Normal local launcher | `.\scripts\start_system.cmd` after one-time setup |
| Response state | Simulation only; automation disabled |
| ML state | IsolationForest assistive signal; supervised candidates are decision support and not promoted |
| Assistant state | Read-only, evidence-grounded, deterministic fallback plus optional private Gemini provider |

## Runtime Capability Manifest

- File import, replay, synthetic scenarios, UDP/TCP syslog lab receivers, raw evidence preservation, normalization, parser fallback, source tracking, and resumable queued ingestion.
- Rule detection, anomaly scoring, supervised diagnostic evaluation, explainable alerts, deduplication, case grouping, source-aware investigation, and analyst labeling.
- RBAC-protected dashboard, audit history, simulated response controls, operations/jobs, health, metrics, and release verification.
- Summary-first Overview, Alerts, Investigation, AI Governance, and Assistant headers share one reusable responsive page contract. Overview and AI Governance display the same canonical ML evidence snapshot; historical validation runs are not selected through fallback chains.
- Persistent browser-tab assistant context with reusable bounded answer/citation rendering, IP redaction, raw-log exclusion, and zero mutation tools.

## Canonical Operational States

| Area | Current truth |
| --- | --- |
| Rule detection | Active for analyst-run detection |
| IsolationForest | Assistive anomaly pipeline; operational state shown separately |
| Supervised active artifact | Artifact may exist, but registry metadata is unknown unless registered |
| v4.1 diagnostic candidate | Development-only, candidate-only, not activated or promoted |
| Assistant external provider | Configured privately on this workstation; deterministic fallback remains available |
| MFU IAM proxy | Private proxy fields configured in the approved shell copy |
| Google/MFU provider acceptance | Blocked: approved client fields and real account acceptance are not complete |

## Data And Performance Snapshot

The configured database was not mutated for this manifest. Final read-only smoke observed 145,232 raw logs, 145,232 normalized logs, 3,231 alerts, and 2,672 supervised labels. The repeat warm run measured Overview at `0.4065s`, cached Overview at `0.0059s`, ML Governance at `1.1306s`, alert list at `0.0312s`, case summary at `0.0719s`, and feature generation at `0.2692s`, with no warnings. A separate cold-disk run measured uncached Overview at `9.12s`; large-SQLite cold-start latency remains a documented capacity risk.

## Distribution Boundary

ATDR source is versionable, but a complete teammate runtime also needs the separately approved MFU shell, its private environment files, MongoDB for that shell, and university-approved provider configuration. The shell contract is versioned; the external package itself is not yet published as a companion repository or checksummed release. This is a distribution blocker, not an excuse to embed private shell credentials in ATDR.

The final public clone verification used `1535a3182d2813b6136a2ee0073c4901fb19d675`. It found zero tracked protected artifacts, zero personal-machine paths, a clean worktree, successful Python compilation, and `63 passed` focused reproducibility/auth/assistant tests.

## Source Truth

- Backend routes: `atdr/app/main.py`, `atdr/app/routers/`.
- Data model: `atdr/app/db/models.py`, `migrations/versions/`.
- Detection and ML: `atdr/app/detection/`, `atdr/app/ml/`, `atdr/app/services/ml_evidence_snapshot_service.py`.
- Dashboard: `frontend/src/App.tsx`, `frontend/src/pages/`, `frontend/src/components/`.
- Setup lifecycle: `scripts/setup_team.ps1`, `scripts/start_system.ps1`, `scripts/check_system.ps1`, `scripts/stop_system.ps1`.
- Tests and release gate: `atdr/tests/`, `frontend/tests/`, `atdr/scripts/verify_release.py`.
