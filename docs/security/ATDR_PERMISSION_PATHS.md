# ATDR Permission Paths

This document adapts the NewSystem permission-path style to ATDR. It is a registry for route/page permissions, not a separate external IAM system.

ATDR currently enforces permissions through FastAPI dependencies:

- `require_admin`
- `require_analyst_or_admin`
- `get_current_user`

Frontend route hiding and disabled controls improve UX, but backend dependencies remain the authority.

## Source Evidence

| Area | Source |
| --- | --- |
| Auth dependencies | `atdr/app/core/security.py` |
| Mounted routers | `atdr/app/main.py` |
| Backend route guards | `atdr/app/routers/*.py` |
| React routes | `frontend/src/App.tsx` |
| Role-aware navigation | `frontend/src/components/AppShell.tsx` |
| Full role matrix | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |

## Actions

| Action | Meaning In ATDR |
| --- | --- |
| `view` | Read/list/detail access. |
| `edit` | Update analyst workflow state, labels, notes, or non-destructive settings. |
| `action` | Run detection, export evidence, perform simulated response, or trigger a lab operation. |
| `admin` | Admin-only local lab operation such as users, source create/update, demo controls, model training, or imports. |
| `logs` | Audit or operational log visibility. |

## Permission Registry

| Permission Path | Primary UI / API | Admin | Analyst | Notes |
| --- | --- | --- | --- | --- |
| `/overview` | `GET /api/dashboard/summary`, `/overview` | `view` | `view` | SOC status, health, sources, and summaries. |
| `/alerts` | `GET /api/alerts`, `/alerts` | `view/edit/action` | `view/edit/action` | Analysts can triage and update lifecycle. |
| `/logs` | `GET /api/logs`, `/logs` | `view` | `view` | Investigation / Log Explorer. |
| `/logs/import` | `POST /api/logs/import` | `admin` | Not allowed | Import is admin-only to protect local data. |
| `/sources` | `GET /api/sources` | `view` | `view` | Source visibility and health. |
| `/sources/manage` | `POST/PATCH /api/sources` | `admin` | Not allowed | Disable is non-destructive. |
| `/ingestion/runs` | `GET /api/ingestion/runs` | `view` | `view` | Run history visibility. |
| `/detection/run` | `POST /api/detection/run` | `action` | `action` | Detection run only; no response automation. |
| `/detection/runs` | `GET /api/detection/runs` | `view` | `view` | Detection history visibility. |
| `/ml` | `GET /api/ml/status`, `/ml` | `view` | `view` | AI Governance summary and reports. |
| `/ml/labels` | label APIs | `view/edit/action` | `view/edit/action` | Label review/import/export. |
| `/ml/train` | `POST /api/ml/train`, `POST /api/ml/score` | `admin` | Not allowed | IsolationForest train/score admin-only. |
| `/ml/supervised/train` | `POST /api/ml/supervised/train` | `admin` | Not allowed | Supervised training admin-only. |
| `/response` | `GET /api/response/blocked-ips`, `/response` | `view/action` | `view` | Simulated response actions are admin-only. |
| `/response/block` | `POST /api/response/block-ip` | `admin/action` | Not allowed | Requires evidence, note, protected-IP checks, and audit. |
| `/response/unblock` | `POST /api/response/unblock-ip` | `admin/action` | Not allowed | Requires note and audit. |
| `/audit` | `GET /api/audit` | `logs/view` | `logs/view` | Audit trail visibility. |
| `/controls` | suppressions/watchlists | `view/edit/admin` | `view` | Analysts can view; admin manages controls. |
| `/tuning` | detection tuning page | `view` | `view` | Tuning visibility; destructive actions remain controlled by backend. |
| `/users` | `GET/POST /api/users`, `/users` | `admin` | Not allowed | Admin-only user management. |
| `/demo` | `/api/demo/*`, `/demo` | `admin` | Not allowed | Admin-only lab/demo controls. |

## Future External IAM Mapping

If ATDR later integrates with a university IAM provider, these paths can be registered as scoped permission paths. Until then, they document and verify the current local JWT/RBAC behavior.

