import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings, validate_runtime_settings
from atdr.app.core.logging import configure_logging
from atdr.app.core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from atdr.app.core.request_context import get_request_id
from atdr.app.db.database import check_database_connection, get_db, init_db
from atdr.app.routers import (
    alerts,
    audit,
    auth,
    dashboard,
    demo,
    detection,
    ingestion,
    logs,
    ml,
    response,
    sources,
    suppressions,
    users,
    watchlists,
)

settings = get_settings()
configure_logging(settings.log_level, settings.log_format)
logger = logging.getLogger("atdr.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    config_issues = validate_runtime_settings(settings)
    if config_issues:
        raise RuntimeError("Unsafe ATDR runtime configuration: " + " ".join(config_issues))
    if settings.auto_create_tables:
        init_db()
    logger.info(
        "application startup complete",
        extra={"event": "startup", "service_version": settings.service_version, "environment": settings.environment},
    )
    yield


app = FastAPI(title=settings.app_name, version=settings.service_version, lifespan=lifespan)

app.add_middleware(RequestContextMiddleware)
if settings.security_headers_enabled:
    app.add_middleware(SecurityHeadersMiddleware, enable_hsts=settings.environment.lower() == "production")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    database_check = check_database_connection(db)
    model_path = settings.resolved_model_path
    checks = {
        "database": database_check,
        "ml_model": {
            "status": "ready" if model_path.exists() else "missing",
            "path": str(model_path),
        },
        "response_mode": {
            "status": "simulation" if settings.response_simulation else "pending_connector",
            "provider": settings.response_provider,
        },
    }
    overall_status = "ok" if database_check["status"] == "ok" else "degraded"
    return {
        "status": overall_status,
        "service": settings.app_name,
        "version": settings.service_version,
        "environment": settings.environment,
        "checks": checks,
    }


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "request_id": get_request_id()},
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "request_id": get_request_id()},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception(
        "unhandled exception",
        extra={"event": "unhandled_exception", "error_type": exc.__class__.__name__, "path": request.url.path},
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error.", "request_id": get_request_id()},
    )


app.include_router(logs.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(alerts.router)
app.include_router(suppressions.router)
app.include_router(watchlists.router)
app.include_router(sources.router)
app.include_router(ingestion.router)
app.include_router(detection.router)
app.include_router(ml.router)
app.include_router(response.router)
app.include_router(audit.router)
app.include_router(dashboard.router)
app.include_router(demo.router)
