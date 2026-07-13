import logging
from ipaddress import ip_address, ip_network
import re
import time
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from atdr.app.core.request_context import request_id_context
from atdr.app.services.metrics_service import record_http_request


logger = logging.getLogger("atdr.request")
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_FORWARDED_PROTO_VALUES = {"http", "https"}


def safe_request_id(value: str | None) -> str:
    """Accept only a small log-safe correlation token; replace all other input."""

    candidate = (value or "").strip()
    return candidate if _REQUEST_ID_PATTERN.fullmatch(candidate) else str(uuid4())


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id to each request and emit one structured access log."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = safe_request_id(request.headers.get("X-Request-ID"))
        request.state.request_id = request_id
        token = request_id_context.set(request_id)
        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            duration_seconds = time.perf_counter() - start
            duration_ms = round(duration_seconds * 1000, 2)
            record_http_request(
                method=request.method,
                status_code=status_code,
                duration_seconds=duration_seconds,
            )
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


class TrustedProxyHeadersMiddleware(BaseHTTPMiddleware):
    """Honor forwarded client/protocol data only from explicitly trusted direct peers."""

    def __init__(self, app, *, enabled: bool = False, trusted_cidrs: list[str] | None = None):
        super().__init__(app)
        self.enabled = enabled
        self.trusted_networks = tuple(ip_network(value, strict=False) for value in (trusted_cidrs or []))

    def _peer_is_trusted(self, host: str | None) -> bool:
        if not self.enabled or not host:
            return False
        try:
            peer = ip_address(host)
        except ValueError:
            return False
        return any(peer in network for network in self.trusted_networks)

    async def dispatch(self, request: Request, call_next) -> Response:
        peer_host = request.client.host if request.client else None
        trusted = self._peer_is_trusted(peer_host)
        request.state.proxy_headers_trusted = trusted
        request.state.direct_peer_ip = peer_host
        if trusted:
            proto = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
            if proto in _FORWARDED_PROTO_VALUES:
                request.scope["scheme"] = proto
            forwarded_for = request.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
            try:
                client_ip = str(ip_address(forwarded_for)) if forwarded_for else None
            except ValueError:
                client_ip = None
            if client_ip:
                client_port = request.client.port if request.client else 0
                request.scope["client"] = (client_ip, client_port)
        return await call_next(request)


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
