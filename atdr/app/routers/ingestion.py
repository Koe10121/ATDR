from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from atdr.app.core.security import require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.operations import IngestionRunRead
from atdr.app.services.operation_run_service import get_ingestion_run, ingestion_run_to_dict, list_ingestion_runs

router = APIRouter(prefix="/api/ingestion", tags=["ingestion"])


@router.get("/runs", response_model=list[IngestionRunRead])
def api_list_ingestion_runs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    return [ingestion_run_to_dict(run) for run in list_ingestion_runs(db, limit=limit, offset=offset)]


@router.get("/runs/{run_id}", response_model=IngestionRunRead)
def api_get_ingestion_run(
    run_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    run = get_ingestion_run(db, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Ingestion run not found.")
    return ingestion_run_to_dict(run)
