from __future__ import annotations

import re

# Redaction safety net shared by every service that must strip identifying
# detail before evidence leaves the system boundary (an external LLM
# provider, an acceptance-evidence export, a privacy pre-flight check). The
# IPv6 alternation is the standard full/compressed/mixed-form pattern; the
# lookaround guards prevent partial matches inside longer hex tokens (hashes,
# session IDs) and MAC addresses while still catching a trailing zone id
# (`fe80::1%eth0`). Independently re-derived copies of this pattern have
# twice silently diverged in this codebase (an IPv4-only variant, and a
# variant whose IPv6 branch could not match compressed notation) — import
# this module rather than redefining the pattern locally.
_IPV6_CORE = (
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})"
    r"|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)"
)
IP_PATTERN = re.compile(
    r"\b(?:(?:\d{1,3}\.){3}\d{1,3})\b"
    r"|(?<![0-9A-Za-z:])(?:" + _IPV6_CORE + r")(?:%[0-9A-Za-z]+)?(?![0-9A-Za-z:])"
)

# Gates whether an evidence-review sign-off counts as human or AI-generated.
# Three independently written copies of this pattern existed before this
# module: two omitted "language model", so a reviewer string like "reviewed
# via language model" was rejected by one gate and silently accepted as
# human by the other two. Import this module rather than redefining the
# pattern locally.
AI_REVIEWER_PATTERN = re.compile(
    r"(?:assistant|automated|bot|chatgpt|claude|codex|gemini|heuristic|language model|llm|model|openai|synthetic)",
    re.IGNORECASE,
)
