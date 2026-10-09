"""Serves the dashboard's built files, the way deploy/nginx/atdr.conf.example does for a server install.

`npm run build` puts the dashboard in frontend/dist. On a team laptop ATDR used to run Vite's development server
instead, which serves the source files one at a time and reloads the page when one changes: the Overview took about
ten seconds to open, and every edit to the source was live at once, tested or not.

This is that static web server: a file when the path names one, index.html for the dashboard's own routes
(/alerts, /overview), the same security headers as the API, and a cache lifetime that fits each file.
"""

from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, PlainTextResponse, Response
from starlette.routing import Route

from atdr.app.core.config import PROJECT_ROOT

DASHBOARD_DIRECTORY = PROJECT_ROOT / "frontend" / "dist"
# The dashboard reads the API on the page's own host name, port 8000 (frontend/src/lib/api.ts).
API_ORIGINS = ("http://127.0.0.1:8000", "http://localhost:8000")
# Vite names these after their content, so a changed file has a new name and an old one never changes.
HASHED_FILES = "assets"
FOREVER = "public, max-age=31536000, immutable"
# index.html names the current files, so the browser must ask for it every time.
ASK_EVERY_TIME = "no-cache"
NOT_BUILT = (
    "The ATDR dashboard has not been built on this machine. Start ATDR with scripts\\start_system.cmd, which "
    "builds it, or run: python -m atdr.scripts.build_dashboard"
)


def security_headers(api_origins: tuple[str, ...] = API_ORIGINS) -> dict[str, str]:
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": (
            "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' " + " ".join(api_origins)
        ),
    }


def create_dashboard_app(directory: Path = DASHBOARD_DIRECTORY, *, api_origins: tuple[str, ...] = API_ORIGINS) -> Starlette:
    root = directory.resolve()
    headers = security_headers(api_origins)

    async def serve(request: Request) -> Response:
        relative = request.path_params.get("path", "")
        candidate = (root / relative).resolve()
        inside = candidate == root or root in candidate.parents
        # A name that starts with a dot is the build's own record, not part of the dashboard.
        if inside and any(part.startswith(".") for part in candidate.relative_to(root).parts):
            return PlainTextResponse("Not found.", status_code=404, headers=headers)
        if inside and candidate.is_file():
            hashed = candidate.parent != root and candidate.relative_to(root).parts[0] == HASHED_FILES
            return FileResponse(candidate, headers={**headers, "Cache-Control": FOREVER if hashed else ASK_EVERY_TIME})
        # A path with an extension names a file. Answering index.html for a script that is gone (an old page open
        # across an update) would hand the browser HTML where it asked for JavaScript.
        if not inside or Path(relative).suffix:
            return PlainTextResponse("Not found.", status_code=404, headers=headers)
        index = root / "index.html"
        if not index.is_file():
            return PlainTextResponse(NOT_BUILT, status_code=503, headers=headers)
        return FileResponse(index, headers={**headers, "Cache-Control": ASK_EVERY_TIME})

    return Starlette(
        routes=[Route("/{path:path}", serve, methods=["GET", "HEAD"])],
        middleware=[Middleware(GZipMiddleware, minimum_size=1024)],
    )
