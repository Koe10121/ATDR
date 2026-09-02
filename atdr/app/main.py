import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings, validate_runtime_settings
from atdr.app.core.logging import configure_logging
from atdr.app.core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware, TrustedProxyHeadersMiddleware
from atdr.app.core.request_context import get_request_id
from atdr.app.db.database import check_database_connection, get_db, init_db
from atdr.app.routers import (
    alerts,
    assistant,
    audit,
    auth,
    dashboard,
    demo,
    detection,
    evidence_review,
    ingestion,
    jobs,
    logs,
    ml,
    observability,
    response,
    sources,
    suppressions,
    users,
    watchlists,
)
from atdr.app.services.observability_service import build_readiness

settings = get_settings()
configure_logging(settings.log_level, settings.log_format)
logger = logging.getLogger("atdr.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    config_issues = validate_runtime_settings(settings)
    app.state.configuration_issues = tuple(config_issues)
    if config_issues:
        logger.error(
            "startup configuration is incomplete; operational routes are unavailable",
            extra={
                "event": "startup_configuration_blocked",
                "issue_count": len(config_issues),
                "auth_mode": settings.normalized_auth_mode,
            },
        )
        yield
        return
    if settings.auto_create_tables:
        init_db()
    database_check = check_database_connection()
    if database_check["status"] != "ok":
        logger.error(
            "database connection check failed",
            extra={
                "event": "startup_database_check_failed",
                "detail": database_check.get("detail"),
                "environment": settings.environment,
            },
        )
    logger.info(
        "application startup complete",
        extra={"event": "startup", "service_version": settings.service_version, "environment": settings.environment},
    )
    yield


app = FastAPI(title=settings.app_name, version=settings.service_version, lifespan=lifespan)

app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    TrustedProxyHeadersMiddleware,
    enabled=settings.trust_proxy_headers,
    trusted_cidrs=settings.trusted_proxy_cidr_list,
)


@app.middleware("http")
async def configuration_readiness_guard(request: Request, call_next):
    issues = tuple(getattr(request.app.state, "configuration_issues", ()))
    allowed_paths = {
        "/health/live",
        "/health/ready",
        "/api/auth/mfu-iam/public-status",
    }
    if issues and request.url.path not in allowed_paths:
        return JSONResponse(
            status_code=503,
            content={
                "detail": "ATDR configuration is incomplete. Run scripts/check_system.ps1 and correct the reported field names.",
                "issue_count": len(issues),
                "request_id": get_request_id(),
                "secrets_exposed": False,
            },
        )
    return await call_next(request)
if settings.security_headers_enabled:
    app.add_middleware(SecurityHeadersMiddleware, enable_hsts=settings.environment.lower() == "production")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=settings.cors_methods,
    allow_headers=settings.cors_headers,
    expose_headers=settings.cors_expose_headers,
)


@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    database_check = check_database_connection(db)
    model_path = settings.resolved_model_path
    checks = {
        "database": database_check,
        "ml_model": {
            "status": "ready" if model_path.exists() else "missing",
            "artifact_exists": model_path.exists(),
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


@app.get("/health/live")
def health_live() -> dict:
    """Process-only liveness. This endpoint intentionally performs no database work."""

    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.service_version,
        "secrets_exposed": False,
    }


@app.get("/health/ready")
def health_ready(db: Session = Depends(get_db)) -> JSONResponse:
    payload, ready = build_readiness(db, settings)
    return JSONResponse(status_code=200 if ready else 503, content=jsonable_encoder(payload))


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
        content=jsonable_encoder({"detail": exc.errors(), "request_id": get_request_id()}),
    )


@app.exception_handler(OperationalError)
async def database_operational_exception_handler(request: Request, exc: OperationalError) -> JSONResponse:
    logger.error(
        "database unavailable",
        extra={
            "event": "database_unavailable",
            "error_type": exc.__class__.__name__,
            "path": request.url.path,
        },
    )
    return JSONResponse(
        status_code=503,
        content={
            "detail": "Database unavailable. Check DATABASE_URL and make sure the configured database service is running.",
            "request_id": get_request_id(),
        },
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
app.include_router(observability.router)
app.include_router(jobs.router)
app.include_router(detection.router)
app.include_router(evidence_review.router)
app.include_router(ml.router)
app.include_router(response.router)
app.include_router(assistant.router)
app.include_router(audit.router)
app.include_router(dashboard.router)
app.include_router(demo.router)
