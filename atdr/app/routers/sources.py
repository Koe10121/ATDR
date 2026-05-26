from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.schemas.sources import LogSourceCreate, LogSourceRead, LogSourceUpdate, SourceHealthRead
from atdr.app.services.source_service import create_source, get_source, list_sources, source_health, source_to_dict, update_source

router = APIRouter(prefix="/api/sources", tags=["sources"])


@router.get("", response_model=list[LogSourceRead])
def get_sources(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    include_disabled: bool = True,
    source_type: str | None = None,
    parser_profile: str | None = None,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    return [
        source_to_dict(source)
        for source in list_sources(
            db,
            include_disabled=include_disabled,
            source_type=source_type,
            parser_profile=parser_profile,
            status=status,
            limit=limit,
            offset=offset,
        )
    ]


@router.get("/{source_id}", response_model=LogSourceRead)
def get_source_detail(
    source_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    source = get_source(db, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Log source not found.")
    return source_to_dict(source, include_quality=True, db=db)


@router.get("/{source_id}/health", response_model=SourceHealthRead)
def get_source_health(
    source_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    source = get_source(db, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Log source not found.")
    return source_health(source)


@router.post("", response_model=LogSourceRead)
def post_source(
    request: LogSourceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    try:
        source = create_source(
            db,
            name=request.name,
            source_type=request.source_type,
            parser_profile=request.parser_profile,
            host=request.host,
            port=request.port,
            enabled=request.enabled,
        )
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A source with this name already exists.") from exc
    return source_to_dict(source)


@router.patch("/{source_id}", response_model=LogSourceRead)
def patch_source(
    source_id: int,
    request: LogSourceUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    source = get_source(db, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Log source not found.")
    try:
        source = update_source(db, source, request.model_dump(exclude_unset=True))
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A source with this name already exists.") from exc
    return source_to_dict(source, include_quality=True, db=db)
