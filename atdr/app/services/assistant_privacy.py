"""Privacy boundary for Assistant transcripts, hosted requests, and persisted summaries."""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable

from atdr.app.core.config import Settings
from atdr.app.core.redaction import IP_PATTERN


_CREDENTIAL = re.compile(
    r'''(?i)(["']?\b[\w-]*(?:api[_-]?key|secret|password|token|authorization)["']?\s*[:=]\s*)'''
    r'''(?:"[^"\n]*"|'[^'\n]*'|(?:Bearer\s+)?[^\s,;]+)'''
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RAW_FIELD = re.compile(r"(?i)\braw[_ ](?:log|line)(?:[_ ]line)?\s*[:=]")


def assistant_secret_values(settings: Settings) -> list[str]:
    return [
        value for name in type(settings).model_fields
        if any(term in name for term in ("secret", "password", "api_key", "private_key"))
        and isinstance(value := getattr(settings, name), str) and len(value) >= 8
    ]


def sanitize_assistant_text(
    value: str, *, forbidden_values: Iterable[str] = (),
    redact_ips: bool = True, ip_replacement: str | Callable[[re.Match], str] = "[redacted-ip]",
) -> str:
    text = value
    for secret in sorted(set(forbidden_values), key=len, reverse=True):
        if secret and len(secret) >= 8:
            text = text.replace(secret, "[redacted-secret]")
    text = _CREDENTIAL.sub(lambda match: match[1] + "[redacted-secret]", text)
    text = _BEARER.sub("Bearer [redacted-secret]", text)
    text = _EMAIL.sub("[redacted-email]", text)
    lines = []
    for line in text.splitlines():
        if _RAW_FIELD.search(line) or (
            line.count(",") >= 10 and re.search(r"\b(?:TRAFFIC|THREAT|SYSTEM)\b", line)
        ) or re.match(r"\s*<\d{1,3}>", line):
            lines.append("[redacted-log]")
        else:
            lines.append(line)
    text = "\n".join(lines)
    return IP_PATTERN.sub(ip_replacement, text) if redact_ips else text


def sanitize_assistant_structure(value: Any, **kwargs: Any) -> Any:
    if isinstance(value, str):
        return sanitize_assistant_text(value, **kwargs)
    if isinstance(value, list):
        return [sanitize_assistant_structure(item, **kwargs) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_assistant_structure(item, **kwargs) for key, item in value.items()}
    return value
