import logging
import time
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from atdr.app.core.request_context import request_id_context


logger = logging.getLogger("atdr.request")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id to each request and emit one structured access log."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid4())
        token = request_id_context.set(request_id)
        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            client_ip = request.client.host if request.client else None
            logger.info(
                "request completed",
                extra={
                    "event": "http_request",
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "client_ip": client_ip,
                },
            )
            request_id_context.reset(token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add conservative browser security headers to API responses."""

    def __init__(self, app, *, enable_hsts: bool = False):
        super().__init__(app)
        self.enable_hsts = enable_hsts

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if self.enable_hsts:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response
