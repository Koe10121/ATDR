"""Answer counting, ranking, and trend questions straight from the database.

The keyword router answers a fixed set of topics. Questions such as "how many
high alerts today?" or "which source IPs have the most alerts this week?" need
a count, a ranking, or a per-day trend with filters. This module turns such a
question into a small, whitelisted, read-only query over alerts or logs, runs
it, and describes exactly what it counted.

Values from the question only ever reach SQL as bound parameters. A question
this module does not clearly understand returns ``None`` so the regular router
handles it; guessing would reproduce the old failure where any question that
mentioned "alert" was answered with an unrelated alert explanation.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, NormalizedLog
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules
from atdr.app.detection.rule_catalog import rule_spec

Subject = Literal["alerts", "logs"]
Intent = Literal["count", "top", "trend", "list"]

MAX_ALERT_SCAN_ROWS = 50_000
DEFAULT_LIST_LIMIT = 5
MAX_LIST_LIMIT = 10
MAX_TREND_LINES = 8

SEVERITIES = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}

# Longest phrases first so "needs more context" wins over "context".
STATUS_PHRASES: tuple[tuple[str, str], ...] = (
    (r"\bfalse[ -]positives?\b", "false_positive"),
    (r"\bneeds? (?:more )?context\b", "needs_more_context"),
    (r"\bunder investigation\b|\binvestigating\b", "investigating"),
    (r"\bcontained\b", "contained"),
    (r"\bresolved\b", "resolved"),
    (r"\bopen\b|\bunresolved\b", "open"),
)

STATUS_LABELS = {
    "open": "open",
    "investigating": "investigating",
    "needs_more_context": "needing more context",
    "contained": "contained",
    "resolved": "resolved",
    "false_positive": "false positive",
}

ATTACK_PHRASES: tuple[tuple[str, str], ...] = (
    (r"\bport[ -]?scans?\b|\bscans?\b|\bscanning\b|\bprob(?:e|es|ing)\b", "port_scan"),
    (r"\bbrute[ -]?force\b|\bpassword guess|\blogin attempts?\b", "brute_force"),
    (r"\bd?dos\b|\bdenial[ -]of[ -]service\b|\bfloods?\b|\bflooding\b", "dos_ddos"),
    (r"\bmalware\b|\bc2\b|\bcommand[ -]and[ -]control\b|\bbeacon", "malware_c2"),
    (r"\bexfil|\bdata theft\b|\bdata leak|\blarge uploads?\b", "data_exfiltration_suspicion"),
    (r"\bpolicy violations?\b", "policy_violation"),
    (r"\bunclassified\b|\bunknown attack", "unknown_anomaly"),
)

ATTACK_LABELS = {
    "port_scan": "port scan",
    "brute_force": "brute force",
    "dos_ddos": "flood / denial of service",
    "malware_c2": "malware / C2",
    "data_exfiltration_suspicion": "possible data exfiltration",
    "policy_violation": "policy violation",
    "unknown_anomaly": "unclassified",
    "normal": "normal",
}

LOG_ACTIONS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (r"\bden(?:y|ied)\b|\bdrop(?:ped)?\b|\bblocked\b", ("deny", "drop"), "denied or dropped"),
    (r"\ballow(?:ed)?\b|\bpermitted\b", ("allow",), "allowed"),
)

IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"

# Questions about one specific record, its evidence, or how to use the UI
# belong to the existing routes, which carry that context.
EXCLUDE_PATTERNS = (
    r"\b(?:alert|log|case|source)\s*#?\s*\d+\b",
    r"#\d+",
    r"\b(?:this|that|these|those)\s+(?:alert|alerts|log|logs|case|source|ip)\b",
    r"\b(?:related|linked|evidence)\b",
    r"\bwhy\b|\bexplain\b|\bflagged\b|\bshould i\b|\bnext steps?\b|\bbrief\b",
    r"\bhow (?:do|can|should|would) (?:i|we)\b|\bhow to\b",
)


@dataclass(frozen=True, slots=True)
class TimeWindow:
    phrase: str
    start: datetime | None = None
    end: datetime | None = None

    @property
    def bounded(self) -> bool:
        return self.start is not None


ALL_TIME = TimeWindow("in total")


@dataclass(frozen=True, slots=True)
class DataQuestion:
    subject: Subject
    intent: Intent
    window: TimeWindow = ALL_TIME
    severity: str | None = None
    status: str | None = None
    attack_type: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    any_ip: str | None = None
    actions: tuple[str, ...] = ()
    action_label: str | None = None
    min_app_risk: int | None = None
    group_by: str | None = None
    limit: int = DEFAULT_LIST_LIMIT


@dataclass(slots=True)
class DataAnswer:
    """Plain facts for assistant_service to wrap; no redaction applied yet."""

    summary: str
    lines: list[str]
    basis: str
    context: str
    followups: list[str] = field(default_factory=list)
    counts: dict[str, Any] = field(default_factory=dict)


def _local_now() -> datetime:
    return datetime.now().astimezone()


def _midnight(value: datetime) -> datetime:
    return value.replace(hour=0, minute=0, second=0, microsecond=0)


def _parse_window(text: str, now: datetime) -> TimeWindow:
    today = _midnight(now)
    relative = re.search(r"\b(?:last|past|previous)\s+(\d{1,3})\s*(hours?|hrs?|days?|weeks?)\b", text)
    if relative:
        amount = int(relative.group(1))
        unit = relative.group(2)
        if unit.startswith("h"):
            amount = max(1, min(amount, 720))
            return TimeWindow(f"in the last {amount} hour{'s' if amount != 1 else ''}", now - timedelta(hours=amount), None)
        if unit.startswith("w"):
            amount = max(1, min(amount, 52))
            return TimeWindow(f"in the last {amount} week{'s' if amount != 1 else ''}", now - timedelta(weeks=amount), None)
        amount = max(1, min(amount, 365))
        return TimeWindow(f"in the last {amount} day{'s' if amount != 1 else ''}", now - timedelta(days=amount), None)
    if re.search(r"\b(?:last|past)\s+hour\b", text):
        return TimeWindow("in the last hour", now - timedelta(hours=1), None)
    if re.search(r"\btoday\b|\bso far today\b", text):
        return TimeWindow("today", today, None)
    if re.search(r"\byesterday\b", text):
        return TimeWindow("yesterday", today - timedelta(days=1), today)
    week_start = today - timedelta(days=today.weekday())
    if re.search(r"\bthis week\b", text):
        return TimeWindow(f"this week (since Monday {week_start:%d %b})", week_start, None)
    if re.search(r"\b(?:last|previous) week\b", text):
        return TimeWindow(f"last week ({week_start - timedelta(days=7):%d %b} to {week_start - timedelta(days=1):%d %b})", week_start - timedelta(days=7), week_start)
    if re.search(r"\bpast week\b", text):
        return TimeWindow("in the last 7 days", now - timedelta(days=7), None)
    month_start = today.replace(day=1)
    if re.search(r"\bthis month\b", text):
        return TimeWindow(f"this month (since {month_start:%d %b})", month_start, None)
    if re.search(r"\b(?:last|previous) month\b", text):
        previous_start = (month_start - timedelta(days=1)).replace(day=1)
        return TimeWindow(f"last month ({previous_start:%B})", previous_start, month_start)
    return ALL_TIME


def _intent(text: str) -> Intent | None:
    # "most recent" / "latest" ask for a list, not a ranking.
    text = re.sub(r"\bmost recent\b|\blatest\b|\bnewest\b", "recent", text)
    if re.search(r"\b(?:per|each|every|a) day\b|\bdaily\b|\bby day\b|\btrend\b|\bover time\b|\bday by day\b", text):
        return "trend"
    if re.search(
        r"\bmost\b|\btop\b|\bhighest number\b|\bbusiest\b|\bbreak ?down\b|\bbroken down\b|\bgroup(?:ed)? by\b|"
        r"\bdistribution\b|\b(?:by|per) (?:severity|status|attack|type|rule|source|destination|ip|app|application|action|port|country)",
        text,
    ):
        return "top"
    if re.search(r"\bhow many\b|\bnumber of\b|\bcount\b|\btotal\b|\bhow much\b", text):
        return "count"
    if re.search(r"^(?:please\s+)?(?:show|list|find|give me|get)\b|\b(?:which|what) alerts\b|\bany alerts\b", text):
        return "list"
    return None


def _group_by(text: str, subject: Subject) -> str | None:
    if subject == "logs" and re.search(r"\bports?\b", text):
        return "dst_port"
    if re.search(r"\bsource countr|\bcountr(?:y|ies) (?:of|by) source", text):
        return "src_country"
    if re.search(r"\bcountr", text):
        return "dst_country"
    if re.search(r"\bdestination|\bdst\b|\btarget", text):
        return "dst_ip"
    if re.search(r"\bsource ip|\bsrc ip|\bsource address|\battacker|\bips?\b|\baddress", text):
        return "src_ip"
    if subject == "alerts":
        if re.search(r"\battack", text):
            return "attack_type"
        if re.search(r"\brules?\b|\balert types?\b|\bdetections?\b", text):
            return "rule"
        if re.search(r"\bseverit", text):
            return "severity"
        if re.search(r"\bstatus", text):
            return "status"
        return None
    if re.search(r"\bapps?\b|\bapplications?\b", text):
        return "app"
    if re.search(r"\bactions?\b", text):
        return "action"
    return None


def parse_data_question(question: str, *, now: datetime | None = None) -> DataQuestion | None:
    """Return the structured query a question asks for, or None when unsure."""

    text = " ".join(question.lower().replace("?", " ").split())
    if not text or any(re.search(pattern, text) for pattern in EXCLUDE_PATTERNS):
        return None
    intent = _intent(text)
    if intent is None:
        return None

    # "high-risk app" is an application risk, not an alert severity.
    severity = next((value for word, value in SEVERITIES.items() if re.search(rf"\b{word}\b(?![ -]risk)", text)), None)
    status = next((value for pattern, value in STATUS_PHRASES if re.search(pattern, text)), None)
    attack_type = next((value for pattern, value in ATTACK_PHRASES if re.search(pattern, text)), None)
    mentions_alerts = bool(re.search(r"\balerts?\b|\bincidents?\b", text))
    mentions_logs = bool(re.search(r"\blogs?\b|\blog lines\b|\bevents?\b|\btraffic\b|\bconnections?\b|\bsessions?\b", text))

    subject: Subject | None
    if mentions_alerts or severity or status or attack_type:
        subject = "alerts"
    elif mentions_logs:
        subject = "logs"
    elif intent == "top" and re.search(r"\battack|\brules?\b", text):
        subject = "alerts"
    else:
        return None

    group_by = _group_by(text, subject) if intent == "top" else None
    if intent == "top" and group_by is None:
        group_by = "attack_type" if subject == "alerts" else "app"
    if subject == "alerts" and group_by in {"app", "action", "dst_port", "src_country", "dst_country"}:
        return None

    actions: tuple[str, ...] = ()
    action_label = None
    min_app_risk = None
    if subject == "logs":
        if re.search(r"\bhigh[ -]risk\b|\brisky\b", text):
            min_app_risk = 4
        for pattern, values, label in LOG_ACTIONS:
            if re.search(pattern, text):
                actions, action_label = values, label
                break

    src_ip = dst_ip = any_ip = None
    ip_match = re.search(IPV4, text)
    if ip_match:
        ip = ip_match.group(0)
        before = text[: ip_match.start()]
        if re.search(r"(?:\bto|\btoward|\btowards|\bdestination|\btargeting|\bagainst|\bdst)\s*(?:ip\s*)?$", before):
            dst_ip = ip
        elif re.search(r"(?:\bfrom|\bsource|\bsrc|\bby)\s*(?:ip\s*)?$", before):
            src_ip = ip
        else:
            any_ip = ip

    # A plain list of the default views ("show latest critical alerts",
    # "show open alerts") already has a dedicated route; only take list
    # questions that need a filter that route cannot express.
    if intent == "list":
        now_value = now or _local_now()
        window = _parse_window(text, now_value)
        needs_query = (
            window.bounded
            or attack_type is not None
            or bool(src_ip or dst_ip or any_ip)
            or severity in {"High", "Medium", "Low"}
            or status not in {None, "open"}
        )
        if not needs_query or subject != "alerts":
            return None

    limit_match = re.search(r"\btop\s+(\d{1,2})\b", text)
    limit = DEFAULT_LIST_LIMIT
    if limit_match:
        limit = max(1, min(int(limit_match.group(1)), MAX_LIST_LIMIT))

    window = _parse_window(text, now or _local_now())
    return DataQuestion(
        subject=subject,
        intent=intent,
        window=window,
        severity=severity if subject == "alerts" else None,
        status=status if subject == "alerts" else None,
        attack_type=attack_type if subject == "alerts" else None,
        src_ip=src_ip,
        dst_ip=dst_ip,
        any_ip=any_ip,
        actions=actions,
        action_label=action_label,
        min_app_risk=min_app_risk,
        group_by=group_by,
        limit=limit,
    )


# ---------------------------------------------------------------- execution


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count:,} {singular if count == 1 else (plural or singular + 's')}"


def _utc_bound(db: Session, value: datetime) -> datetime:
    utc_value = value.astimezone(UTC)
    # SQLite stores naive UTC text; PostgreSQL compares aware timestamps.
    return utc_value.replace(tzinfo=None) if db.get_bind().dialect.name == "sqlite" else utc_value


def _as_local(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(_local_now().tzinfo)


def _offset_label() -> str:
    offset = _local_now().utcoffset() or timedelta(0)
    minutes = int(offset.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    return f"UTC{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"


def _alert_noun(dq: DataQuestion) -> str:
    parts = []
    if dq.status:
        parts.append(STATUS_LABELS.get(dq.status, dq.status))
    if dq.severity:
        parts.append(dq.severity)
    if dq.attack_type:
        parts.append(ATTACK_LABELS.get(dq.attack_type, dq.attack_type))
    return " ".join([*parts, "alert"]).strip()


def _alert_filters_text(dq: DataQuestion) -> str:
    parts = [
        f"severity {dq.severity}" if dq.severity else "any severity",
        f"status {STATUS_LABELS.get(dq.status, dq.status)}" if dq.status else "any status",
    ]
    if dq.attack_type:
        parts.append(f"attack type {ATTACK_LABELS.get(dq.attack_type, dq.attack_type)}")
    if dq.src_ip:
        parts.append(f"source IP {dq.src_ip}")
    if dq.dst_ip:
        parts.append(f"destination IP {dq.dst_ip}")
    if dq.any_ip:
        parts.append(f"source or destination IP {dq.any_ip}")
    return ", ".join(parts)


def _alert_statement(db: Session, dq: DataQuestion, *, with_window: bool = True):
    statement = select(
        Alert.id,
        Alert.severity,
        Alert.status,
        Alert.alert_type,
        Alert.src_ip,
        Alert.dst_ip,
        Alert.threat_score,
        Alert.created_at,
        Alert.matched_rules_json,
    )
    if dq.severity:
        statement = statement.where(Alert.severity == dq.severity)
    if dq.status:
        statement = statement.where(Alert.status == dq.status)
    if dq.src_ip:
        statement = statement.where(Alert.src_ip == dq.src_ip)
    if dq.dst_ip:
        statement = statement.where(Alert.dst_ip == dq.dst_ip)
    if dq.any_ip:
        statement = statement.where(or_(Alert.src_ip == dq.any_ip, Alert.dst_ip == dq.any_ip))
    if with_window and dq.window.start is not None:
        statement = statement.where(Alert.created_at >= _utc_bound(db, dq.window.start))
    if with_window and dq.window.end is not None:
        statement = statement.where(Alert.created_at < _utc_bound(db, dq.window.end))
    return statement


def _alert_rows(db: Session, dq: DataQuestion, *, with_window: bool = True) -> tuple[list[Any], bool]:
    rows = list(db.execute(_alert_statement(db, dq, with_window=with_window).limit(MAX_ALERT_SCAN_ROWS + 1)))
    truncated = len(rows) > MAX_ALERT_SCAN_ROWS
    rows = rows[:MAX_ALERT_SCAN_ROWS]
    if dq.attack_type:
        rows = [row for row in rows if infer_attack_type_from_rules(row.matched_rules_json or []) == dq.attack_type]
    return rows, truncated


def _rule_label(code: str | None) -> str:
    spec = rule_spec(code or "")
    return spec.title if spec else (code or "unknown rule")


def _alert_group_value(row: Any, group_by: str) -> str:
    if group_by == "attack_type":
        return ATTACK_LABELS.get(infer_attack_type_from_rules(row.matched_rules_json or []), "unclassified")
    if group_by == "rule":
        return _rule_label(row.alert_type)
    if group_by == "status":
        return STATUS_LABELS.get(row.status, row.status or "unknown")
    value = getattr(row, group_by, None)
    return str(value) if value not in (None, "") else "unknown"


def _latest_line(rows: list[Any]) -> str | None:
    if not rows:
        return None
    latest = max(rows, key=lambda row: (row.created_at or datetime.min, row.id))
    when = _as_local(latest.created_at)
    return f"Most recent: alert #{latest.id} ({latest.severity}) on {when:%d %b %Y %H:%M}." if when else None


def _alert_basis(dq: DataQuestion, window_text: str, truncated: bool) -> str:
    basis = f"Counted alerts with {_alert_filters_text(dq)}, created {window_text}. Times are server local time ({_offset_label()})."
    if truncated:
        basis += f" Only the first {MAX_ALERT_SCAN_ROWS:,} matching rows were scanned."
    return basis


def _created(count: int, window: TimeWindow) -> str:
    if not window.bounded:
        return ""
    return "was created " if count == 1 else "were created "


def _window_text(window: TimeWindow) -> str:
    return "at any time" if not window.bounded else window.phrase


def _answer_alerts(db: Session, dq: DataQuestion) -> DataAnswer:
    rows, truncated = _alert_rows(db, dq)
    noun = _alert_noun(dq)
    total = len(rows)
    window_phrase = dq.window.phrase
    basis = _alert_basis(dq, _window_text(dq.window), truncated)
    followups: list[str] = []

    if dq.intent == "count":
        summary = f"{_plural(total, noun)} {_created(total, dq.window)}{window_phrase}."
        lines: list[str] = []
        if total:
            if not dq.status:
                statuses = Counter(STATUS_LABELS.get(row.status, row.status) for row in rows)
                lines.append("By status: " + ", ".join(f"{name} {count:,}" for name, count in statuses.most_common()))
            if not dq.severity:
                severities = Counter(row.severity for row in rows)
                order = ["Critical", "High", "Medium", "Low"]
                lines.append("By severity: " + ", ".join(f"{name} {severities[name]:,}" for name in order if severities.get(name)))
            latest = _latest_line(rows)
            if latest:
                lines.append(latest)
        elif dq.window.bounded:
            earlier, _ = _alert_rows(db, dq, with_window=False)
            latest = _latest_line(earlier)
            lines.append(latest or f"There are no {noun}s at any time either.")
        followups = [
            f"Which source IPs have the most {noun}s{' ' + window_phrase if dq.window.bounded else ''}?",
            f"How many {noun}s per day this week?",
        ]
        return DataAnswer(summary, lines, basis, "alert_query", followups, {"total": total})

    if dq.intent == "top":
        group_labels = {
            "src_ip": "source IPs",
            "dst_ip": "destination IPs",
            "attack_type": "attack types",
            "rule": "rules",
            "severity": "severities",
            "status": "statuses",
        }
        group = dq.group_by or "attack_type"
        counter = Counter(_alert_group_value(row, group) for row in rows)
        missing = 0
        if group in {"src_ip", "dst_ip"}:
            # An alert without an address is not a "top source"; count it aside.
            missing = counter.pop("unknown", 0)
        example: dict[str, int] = {}
        for row in sorted(rows, key=lambda item: (-(item.threat_score or 0), -item.id)):
            example.setdefault(_alert_group_value(row, group), row.id)
        ranked = counter.most_common(dq.limit)
        label = group_labels.get(group, "groups")
        summary = (
            (
                f"Top {len(ranked)} {label} for {noun}s {window_phrase}, out of {total:,}:"
                if dq.window.bounded
                else f"Top {len(ranked)} {label} across all {_plural(total, noun)}:"
            )
            if ranked
            else f"No {noun}s {'were created ' if dq.window.bounded else ''}{window_phrase}, so there is nothing to rank."
        )
        lines = [
            f"{value}: {_plural(count, 'alert')} ({round(100 * count / total)}%), e.g. alert #{example[value]}"
            for value, count in ranked
        ]
        if missing:
            side = "source" if group == "src_ip" else "destination"
            basis += f" {_plural(missing, 'alert')} had no {side} IP and {'is' if missing == 1 else 'are'} not ranked."
        if not total and dq.window.bounded:
            earlier, _ = _alert_rows(db, dq, with_window=False)
            latest = _latest_line(earlier)
            if latest:
                lines.append(latest)
        return DataAnswer(summary, lines, basis, "alert_query", [f"How many {noun}s per day this week?"], {"total": total, "ranked": ranked})

    if dq.intent == "trend":
        window = dq.window if dq.window.bounded else TimeWindow("in the last 7 days", _midnight(_local_now()) - timedelta(days=6), None)
        dq_window = replace(dq, window=window)
        rows, truncated = _alert_rows(db, dq_window)
        per_day = Counter(local.date() for row in rows if (local := _as_local(row.created_at)) is not None)
        busy_days = sorted(per_day.items(), reverse=True)
        summary = f"{_plural(len(rows), noun)} {window.phrase}, on {_plural(len(per_day), 'day')} with activity."
        lines = [f"{day:%a %d %b}: {_plural(count, 'alert')}" for day, count in busy_days[:MAX_TREND_LINES]]
        if len(busy_days) > MAX_TREND_LINES:
            lines.append(f"{len(busy_days) - MAX_TREND_LINES} earlier days with activity are not listed.")
        if not rows:
            earlier, _ = _alert_rows(db, dq, with_window=False)
            latest = _latest_line(earlier)
            if latest:
                lines.append(latest)
        basis = _alert_basis(dq, window.phrase, truncated) + " Days with no alerts are left out."
        return DataAnswer(summary, lines, basis, "alert_query", [], {"total": len(rows), "per_day": {str(k): v for k, v in per_day.items()}})

    # list
    ordered = sorted(rows, key=lambda row: (-(row.threat_score or 0), -row.id))[: dq.limit]
    summary = (
        f"{_plural(total, noun)} {_created(total, dq.window)}{window_phrase}. The {len(ordered)} highest scoring:"
        if ordered
        else f"No {noun}s {'were created ' if dq.window.bounded else ''}{window_phrase}."
    )
    lines = [
        f"Alert #{row.id}: {row.severity}, {ATTACK_LABELS.get(infer_attack_type_from_rules(row.matched_rules_json or []), 'unclassified')}, "
        f"source {row.src_ip or 'unknown'}, score {row.threat_score}, {STATUS_LABELS.get(row.status, row.status)}"
        for row in ordered
    ]
    if not ordered and dq.window.bounded:
        earlier, _ = _alert_rows(db, dq, with_window=False)
        latest = _latest_line(earlier)
        if latest:
            lines.append(latest)
    return DataAnswer(summary, lines, basis, "alert_query", [], {"total": total, "alert_ids": [row.id for row in ordered]})


def _log_filters(dq: DataQuestion) -> list[Any]:
    conditions: list[Any] = []
    if dq.actions:
        conditions.append(NormalizedLog.action.in_(dq.actions))
    if dq.min_app_risk is not None:
        conditions.append(NormalizedLog.app_risk >= dq.min_app_risk)
    if dq.src_ip:
        conditions.append(NormalizedLog.src_ip == dq.src_ip)
    if dq.dst_ip:
        conditions.append(NormalizedLog.dst_ip == dq.dst_ip)
    if dq.any_ip:
        conditions.append(or_(NormalizedLog.src_ip == dq.any_ip, NormalizedLog.dst_ip == dq.any_ip))
    # Firewall event times are stored as the firewall's local wall-clock time.
    if dq.window.start is not None:
        conditions.append(NormalizedLog.generated_time >= dq.window.start.replace(tzinfo=None))
    if dq.window.end is not None:
        conditions.append(NormalizedLog.generated_time < dq.window.end.replace(tzinfo=None))
    return conditions


def _log_basis(dq: DataQuestion, window_text: str) -> str:
    parts = [dq.action_label or "any action"]
    if dq.min_app_risk is not None:
        parts.append(f"application risk {dq.min_app_risk} or higher")
    if dq.src_ip:
        parts.append(f"source IP {dq.src_ip}")
    if dq.dst_ip:
        parts.append(f"destination IP {dq.dst_ip}")
    if dq.any_ip:
        parts.append(f"source or destination IP {dq.any_ip}")
    return f"Counted firewall logs with {', '.join(parts)}, by event time {window_text} (firewall local time)."


def _latest_log_line(db: Session, dq: DataQuestion) -> str | None:
    undated = replace(dq, window=ALL_TIME)
    latest = db.scalar(select(func.max(NormalizedLog.generated_time)).where(*_log_filters(undated)))
    return f"Most recent matching log event: {latest:%d %b %Y %H:%M}." if latest else None


def _answer_logs(db: Session, dq: DataQuestion) -> DataAnswer:
    noun = f"{dq.action_label} log" if dq.action_label else "log"
    conditions = _log_filters(dq)
    basis = _log_basis(dq, _window_text(dq.window))

    if dq.intent == "count":
        total = int(db.scalar(select(func.count(NormalizedLog.id)).where(*conditions)) or 0)
        summary = f"{_plural(total, noun)} {window_phrase(dq)}."
        lines = []
        if not total and dq.window.bounded:
            latest = _latest_log_line(db, dq)
            if latest:
                lines.append(latest)
        return DataAnswer(summary, lines, basis, "log_query", [f"Which apps have the most {noun}s?"], {"total": total})

    if dq.intent == "top":
        columns = {
            "src_ip": NormalizedLog.src_ip,
            "dst_ip": NormalizedLog.dst_ip,
            "app": NormalizedLog.app,
            "action": NormalizedLog.action,
            "dst_port": NormalizedLog.dst_port,
            "src_country": NormalizedLog.src_country,
            "dst_country": NormalizedLog.dst_country,
        }
        labels = {
            "src_ip": "source IPs",
            "dst_ip": "destination IPs",
            "app": "applications",
            "action": "actions",
            "dst_port": "destination ports",
            "src_country": "source countries",
            "dst_country": "destination countries",
        }
        column = columns[dq.group_by or "app"]
        count = func.count(NormalizedLog.id)
        ranked = [
            (value, int(total))
            for value, total in db.execute(
                select(column, count)
                .where(*conditions, column.is_not(None))
                .group_by(column)
                .order_by(desc(count))
                .limit(dq.limit)
            )
        ]
        overall = int(db.scalar(select(func.count(NormalizedLog.id)).where(*conditions)) or 0)
        label = labels[dq.group_by or "app"]
        summary = (
            (
                f"Top {len(ranked)} {label} for {noun}s {window_phrase(dq)}, out of {overall:,}:"
                if dq.window.bounded
                else f"Top {len(ranked)} {label} across all {_plural(overall, noun)}:"
            )
            if ranked
            else f"No {noun}s {window_phrase(dq)}, so there is nothing to rank."
        )
        lines = [
            f"{value if value not in (None, '') else 'unknown'}: {_plural(total, 'log')} ({round(100 * total / overall) if overall else 0}%)"
            for value, total in ranked
        ]
        if not ranked and dq.window.bounded:
            latest = _latest_log_line(db, dq)
            if latest:
                lines.append(latest)
        return DataAnswer(summary, lines, basis, "log_query", [], {"total": overall, "ranked": ranked})

    window = dq.window if dq.window.bounded else TimeWindow("in the last 7 days", _midnight(_local_now()) - timedelta(days=6), None)
    windowed = replace(dq, window=window)
    day = func.date(NormalizedLog.generated_time)
    per_day = [
        (str(value), int(total))
        for value, total in db.execute(
            select(day, func.count(NormalizedLog.id)).where(*_log_filters(windowed)).group_by(day).order_by(desc(day))
        )
        if value is not None
    ]
    total = sum(count for _, count in per_day)
    summary = f"{_plural(total, noun)} {window.phrase}, on {_plural(len(per_day), 'day')} with activity."
    lines = [f"{value}: {_plural(count, 'log')}" for value, count in per_day[:MAX_TREND_LINES]]
    if not per_day:
        latest = _latest_log_line(db, dq)
        if latest:
            lines.append(latest)
    return DataAnswer(summary, lines, _log_basis(dq, window.phrase) + " Days with no logs are left out.", "log_query", [], {"total": total})


def window_phrase(dq: DataQuestion) -> str:
    return dq.window.phrase


def answer_data_question(db: Session, dq: DataQuestion) -> DataAnswer:
    return _answer_alerts(db, dq) if dq.subject == "alerts" else _answer_logs(db, dq)
