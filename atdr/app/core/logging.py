import json
import logging
from datetime import datetime, timezone
from typing import Any

from atdr.app.core.request_context import get_request_id


class JsonFormatter(logging.Formatter):
    """Small JSON log formatter for API and worker observability."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = get_request_id()
        if request_id:
            payload["request_id"] = request_id

        for key in (
            "method",
            "path",
            "status_code",
            "duration_ms",
            "client_ip",
            "event",
            "error_type",
        ):
            if hasattr(record, key):
                payload[key] = getattr(record, key)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", log_format: str = "json") -> None:
    root = logging.getLogger()
    root.handlers.clear()

    handler = logging.StreamHandler()
    if log_format.lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    logging.getLogger("uvicorn.access").disabled = log_format.lower() == "json"
