"""The read-only tools the conversational assistant may call.

Each tool wraps a service the dashboard already uses (the data query, the
alert explanation, the playbook, the rule catalog, the how-to guides), so the
agent sees the same facts, with the same IP redaction, as every other screen.
No tool writes anything. A tool rejects arguments it does not understand with
a ``ValueError`` naming the allowed values, which the agent loop hands back to
the model so it can call again correctly.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import Settings
from atdr.app.db.models import Alert, DetectionRun, NormalizedLog, WatchlistItem
from atdr.app.detection.attack_mapping import ATTACK_TYPE_MAPPINGS
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.detection.playbooks import PLAYBOOK_GUIDANCE, build_alert_playbook
from atdr.app.detection.rule_catalog import RULE_CATALOG
from atdr.app.detection.scoring import severity_from_score
from atdr.app.services import assistant_service as core
from atdr.app.services.alert_service import ALERT_DEDUP_WINDOW_MINUTES, SLA_TARGETS, alert_sla, get_alert
from atdr.app.services.assistant_agent import AgentTool, ToolOutput
from atdr.app.services.assistant_data_query import (
    ALL_TIME,
    ATTACK_LABELS,
    DataQuestion,
    TimeWindow,
    _as_local,
    _local_now,
    _parse_window,
    answer_data_question,
)
from atdr.app.services.assistant_help import HELP_TOPICS, answer_help_question, answer_rule_question
from atdr.app.services.threat_intel_service import stored_log_matches
from atdr.app.services.watchlist_service import list_watchlist_items, watchlist_feed_summary
from atdr.app.services.detection_service import SUPPORTING_ONLY_RULES
from atdr.app.services.log_service import get_log

TIME_WINDOWS = {
    "all_time": None,
    "today": "today",
    "yesterday": "yesterday",
    "last_hour": "last hour",
    "last_24_hours": "last 24 hours",
    "last_7_days": "last 7 days",
    "this_week": "this week",
    "last_week": "last week",
    "this_month": "this month",
    "last_month": "last month",
}
SEVERITIES = ("Critical", "High", "Medium", "Low")
STATUSES = ("open", "investigating", "needs_more_context", "contained", "resolved", "false_positive")
ATTACK_TYPES = tuple(key for key in ATTACK_LABELS if key != "normal")
ALERT_GROUPS = ("src_ip", "dst_ip", "attack_type", "rule", "severity", "status")
LOG_GROUPS = ("src_ip", "dst_ip", "app", "action", "dst_port", "src_country", "dst_country")
LOG_ACTIONS = {"denied": (("deny", "drop"), "denied or dropped"), "allowed": (("allow",), "allowed")}
SYSTEM_AREAS = ("ml", "detection_runs", "operations", "sources", "recent_changes", "failed_jobs")

ATTACK_CONCEPTS = {
    "port_scan": "A port scan is one source probing many ports or many hosts to find services it can reach. A vertical scan hits many ports on one host; a horizontal scan hits the same port on many hosts. It is usually the first step before an attack.",
    "brute_force": "Brute force is repeatedly trying passwords or connections against a login service (SSH, RDP, web logins) until one works. In firewall logs it shows up as many short or denied attempts from one source to one service.",
    "dos_ddos": "A denial-of-service flood sends so much traffic at a service that real users cannot reach it. Many sources doing it at once is a DDoS.",
    "malware_c2": "Command-and-control (C2) is how malware on an infected host talks to its operator. It often beacons: it connects to the same outside server again and again at a steady interval to ask for instructions.",
    "data_exfiltration_suspicion": "Data exfiltration is data being taken out of the network. In firewall logs the sign is unusually large uploads from an internal host to an outside destination.",
    "exploit_attempt": "An exploit attempt is traffic aimed at a known weakness in a service, such as a web server path traversal or a remote code execution bug. The firewall recognises it by a vulnerability signature; the attempt may still have been blocked, or the service may not be vulnerable.",
    "policy_violation": "A policy violation is traffic that breaks the firewall or acceptable-use policy, such as risky applications or connections the rules deny. It is not an attack by itself.",
}
CONCEPT_ALIASES = {
    "horizontal_scan": "port_scan",
    "scan": "port_scan",
    "beaconing": "malware_c2",
    "c2": "malware_c2",
    "malware": "malware_c2",
    "dos_flood": "dos_ddos",
    "flood": "dos_ddos",
    "exfiltration": "data_exfiltration_suspicion",
    "data_exfiltration": "data_exfiltration_suspicion",
    "exploit": "exploit_attempt",
    "exploitation": "exploit_attempt",
}
OTHER_CONCEPTS = (
    "mitre_attack",
    "severity_and_score",
    "sla",
    "false_positive",
    "alert_grouping",
    "supporting_signals",
    "ml_models",
    "simulated_response",
    "privacy_redaction",
    "data_sources",
    "atdr_overview",
)
CONCEPTS = (*ATTACK_CONCEPTS, *CONCEPT_ALIASES, *OTHER_CONCEPTS)


def _choice(args: dict[str, Any], key: str, allowed: tuple[str, ...], default: str | None = None) -> str | None:
    value = args.get(key)
    if value in (None, ""):
        return default
    text = str(value).strip()
    for option in allowed:
        if text.lower() == option.lower():
            return option
    raise ValueError(f"{key} must be one of: {', '.join(allowed)}")


def _integer(args: dict[str, Any], key: str, *, low: int, high: int, default: int | None = None) -> int:
    value = args.get(key, default)
    try:
        number = int(str(value).lstrip("#"))
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a whole number") from None
    if not low <= number <= high:
        raise ValueError(f"{key} must be between {low} and {high}")
    return number


def _window(args: dict[str, Any], default: str = "all_time") -> TimeWindow:
    key = _choice(args, "time_window", tuple(TIME_WINDOWS), default)
    phrase = TIME_WINDOWS[key or default]
    return ALL_TIME if phrase is None else _parse_window(phrase, _local_now())


def _ip_filters(args: dict[str, Any]) -> dict[str, str | None]:
    ip = str(args.get("ip") or "").strip() or None
    role = _choice(args, "ip_role", ("source", "destination", "either"), "either")
    return {
        "src_ip": ip if role == "source" else None,
        "dst_ip": ip if role == "destination" else None,
        "any_ip": ip if role == "either" else None,
    }


def _when(value: datetime | None) -> str:
    local = _as_local(value)
    return f"{local:%d %b %Y %H:%M}" if local else "unknown"


def _log_when(value: datetime | None) -> str:
    # Firewall event times are stored as the firewall's own wall-clock time, not UTC.
    return f"{value:%d %b %Y %H:%M}" if value else "unknown"


class AssistantToolbox:
    """Builds the tool list for one question, bound to one database session."""

    def __init__(self, db: Session, *, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.redacted = settings.assistant_redact_ips
        self.context_limit = min(max(1, settings.assistant_max_context_rows), 50)

    def _text(self, value: str) -> str:
        return core._text(value, redacted=self.redacted)

    def _data(self, question: DataQuestion) -> str:
        return core._data_result(answer_data_question(self.db, question), redacted=self.redacted).answer

    def _alerts(self, question: DataQuestion) -> str:
        answer = answer_data_question(self.db, question)
        text = core._data_result(answer, redacted=self.redacted).answer
        if question.window.bounded and not answer.counts.get("total"):
            # A window filters by creation date, and "0 created today" is easily misread as "none open now";
            # give the same count over all time beside it.
            overall = core._data_result(answer_data_question(self.db, replace(question, window=ALL_TIME)), redacted=self.redacted).answer
            text += "\nCreated at any time instead:\n" + overall
        return text

    def _logs(self, question: DataQuestion) -> str:
        answer = answer_data_question(self.db, question)
        text = core._data_result(answer, redacted=self.redacted).answer
        if question.window.bounded and not answer.counts.get("total"):
            # Stored firewall logs are historical, so a recent window is often empty; show the whole record too.
            overall = core._data_result(answer_data_question(self.db, replace(question, window=ALL_TIME)), redacted=self.redacted).answer
            text += "\nAcross all stored logs instead:\n" + overall
        return text

    # ------------------------------------------------------------ tools

    def query_alerts(self, args: dict[str, Any]) -> ToolOutput:
        intent = _choice(args, "intent", ("count", "top", "trend", "list"), "count")
        question = DataQuestion(
            subject="alerts",
            intent=intent,
            window=_window(args),
            severity=_choice(args, "severity", SEVERITIES),
            status=_choice(args, "status", STATUSES),
            attack_type=_choice(args, "attack_type", ATTACK_TYPES),
            group_by=_choice(args, "group_by", ALERT_GROUPS, "attack_type") if intent == "top" else None,
            limit=_integer(args, "limit", low=1, high=10, default=5),
            **_ip_filters(args),
        )
        return ToolOutput(self._alerts(question), [("Alert records", "/api/alerts", None)])

    def query_logs(self, args: dict[str, Any]) -> ToolOutput:
        intent = _choice(args, "intent", ("count", "top", "trend"), "count")
        action = _choice(args, "action", tuple(LOG_ACTIONS))
        actions, action_label = LOG_ACTIONS[action] if action else ((), None)
        min_risk = args.get("min_app_risk")
        question = DataQuestion(
            subject="logs",
            intent=intent,
            window=_window(args),
            actions=actions,
            action_label=action_label,
            min_app_risk=_integer(args, "min_app_risk", low=1, high=5) if min_risk not in (None, "") else None,
            group_by=_choice(args, "group_by", LOG_GROUPS, "app") if intent == "top" else None,
            limit=_integer(args, "limit", low=1, high=10, default=5),
            **_ip_filters(args),
        )
        return ToolOutput(self._logs(question), [("Firewall log records", "/api/logs", None)])

    def security_overview(self, args: dict[str, Any]) -> ToolOutput:
        window = _window(args, "today")
        db = self.db
        parts = [f"Security overview for alerts created {window.phrase if window.bounded else 'at any time'}."]
        parts.append(self._alerts(DataQuestion(subject="alerts", intent="count", window=window)))
        parts.append(self._data(DataQuestion(subject="alerts", intent="count", status="open")))
        parts.append(self._data(DataQuestion(subject="alerts", intent="top", window=window, group_by="attack_type", limit=4)))
        parts.append(self._data(DataQuestion(subject="alerts", intent="top", window=window, group_by="src_ip", limit=3)))
        open_list = DataQuestion(subject="alerts", intent="list", window=window, status="open", limit=5)
        text = self._data(open_list)
        if text.startswith("No "):
            text = self._data(DataQuestion(subject="alerts", intent="list", status="open", limit=5))
        parts.append("Open alerts to look at first (highest score first):\n" + text)

        total_logs = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
        first, last = db.execute(select(func.min(NormalizedLog.generated_time), func.max(NormalizedLog.generated_time))).one()
        log_line = f"Stored firewall logs: {total_logs:,}, with event times from {_log_when(first)} to {_log_when(last)} (firewall local time)."
        if window.bounded:
            log_line += "\n" + self._data(DataQuestion(subject="logs", intent="count", window=window))
        parts.append(log_line)
        new_alerts = answer_data_question(db, DataQuestion(subject="alerts", intent="count", window=window)).counts.get("total")
        if window.bounded and not new_alerts:
            # A quiet period once led to "we are not under attack" while Critical alerts sat open.
            still_open = int(db.scalar(select(func.count(Alert.id)).where(Alert.status == "open")) or 0)
            critical = int(db.scalar(select(func.count(Alert.id)).where(Alert.status == "open", Alert.severity == "Critical")) or 0)
            parts.insert(1, (
                f"No new alerts {window.phrase} is not an all-clear: {still_open:,} alerts are still open ({critical:,} Critical), "
                f"and the newest stored firewall log is from {_log_when(last)} (firewall local time), so ATDR has seen no "
                "traffic since then."
            ))
        run = db.scalar(select(DetectionRun).order_by(DetectionRun.started_at.desc(), DetectionRun.id.desc()).limit(1))
        if run is not None:
            parts.append(
                f"Latest detection run #{run.id}: {run.status}, started {_when(run.started_at)}, "
                f"checked {run.logs_evaluated:,} logs, created {run.alerts_created:,} alerts and merged {run.alerts_deduplicated:,} repeats."
            )
        return ToolOutput(
            self._text("\n\n".join(parts)),
            [("Alert records", "/api/alerts", None), ("Firewall log records", "/api/logs", None)],
            ["Which alert should I look at first?", "What should I do about the top alert?"],
        )

    def _alert(self, args: dict[str, Any]) -> Alert:
        alert_id = _integer(args, "alert_id", low=1, high=10**9)
        alert = get_alert(self.db, alert_id)
        if alert is None:
            low, high = self.db.execute(select(func.min(Alert.id), func.max(Alert.id))).one()
            raise ValueError(f"there is no alert #{alert_id}; alert IDs run from {low} to {high}")
        return alert

    def get_alert(self, args: dict[str, Any]) -> ToolOutput:
        alert = self._alert(args)
        result = core._answer_alert_question(self.db, f"Explain alert {alert.id}", alert_id=alert.id, redacted=self.redacted)
        record = result.details.get("alert") or {}
        summary = result.details.get("detection_summary") or {}
        mapping = summary.get("attack_mapping") or {}
        sla = alert_sla(alert)
        lines = [
            f"Alert #{alert.id}: {alert.severity}, {ATTACK_LABELS.get(summary.get('attack_type'), summary.get('attack_type') or 'unclassified')}, "
            f"risk score {alert.threat_score}, status {alert.status}, assigned to {alert.assigned_to or 'nobody'}.",
            f"Created {_when(alert.created_at)}. Response target: {sla['label']} (state: {sla['state'].replace('_', ' ')}).",
            f"Flow: source {record.get('src_ip') or 'unknown'} to destination {record.get('dst_ip') or 'unknown'}; "
            f"{record.get('evidence_count', 0)} evidence logs, {record.get('related_log_count', 0)} related logs.",
            f"Why flagged: {summary.get('why_flagged') or alert.explanation}",
            "Rules matched: " + (", ".join(record.get("matched_rule_names") or []) or "none recorded"),
            f"MITRE ATT&CK: {mapping.get('tactic', 'Unknown')} / {mapping.get('technique', 'Needs investigation')} ({mapping.get('technique_id', 'N/A')}).",
            f"Evidence strength: {record.get('confidence_label', 'unknown')}.",
        ]
        evidence = [str(item) for item in summary.get("top_evidence_points") or [] if item][:4]
        if evidence:
            lines.append("Evidence:\n" + "\n".join(f"- {item}" for item in evidence))
        caveats = [*(record.get("false_positive_notes") or [])[:3], *(record.get("missing_evidence_notes") or [])[:2]]
        if caveats:
            lines.append("Could be harmless or unclear because:\n" + "\n".join(f"- {item}" for item in caveats))
        checks = (result.details.get("answer_sections") or {}).get("what_to_check_next") or []
        if checks:
            lines.append("What to check next:\n" + "\n".join(f"- {item}" for item in checks[:4]))
        history = record.get("response_history") or []
        lines.append(
            "Responses recorded: "
            + ("; ".join(f"{item['action_type']} -> {item['status']}" for item in history[:3]) if history else "none")
        )
        return ToolOutput(
            self._text("\n".join(lines)),
            [("Alert detail", "/api/alerts/{alert_id}", str(alert.id))],
            [f"What should I do about alert {alert.id}?", f"Is alert {alert.id} a false positive?"],
        )

    def get_alert_playbook(self, args: dict[str, Any]) -> ToolOutput:
        alert = self._alert(args)
        playbook = build_alert_playbook(alert, build_alert_detection_summary(self.db, alert))
        mitre = playbook["mitre"]
        lines = [
            f"Response playbook for alert #{alert.id} ({playbook['label']}). Goal: {playbook['objective']}",
            f"MITRE ATT&CK: {mitre.get('tactic')} / {mitre.get('technique')} ({mitre.get('technique_id')}).",
        ]
        for phase in playbook["phases"]:
            lines.append(f"{phase['title']} ({phase['goal']}):")
            lines.extend(f"- {step['text']}{' [done]' if step['done'] else ''}" for step in phase["steps"])
        guide = playbook["decision_guide"]
        lines.append(f"False positive when: {guide['false_positive']}")
        lines.append(f"Resolved when: {guide['resolved']}")
        lines.append(f"Escalate when: {guide['escalate']}")
        lines.append(playbook["safety_note"])
        return ToolOutput(
            self._text("\n".join(lines)),
            [("Alert detail", "/api/alerts/{alert_id}", str(alert.id))],
            [f"Is alert {alert.id} a false positive?"],
        )

    def get_log(self, args: dict[str, Any]) -> ToolOutput:
        log_id = _integer(args, "log_id", low=1, high=10**10)
        if get_log(self.db, log_id) is None:
            raise ValueError(f"there is no log #{log_id}")
        result = core._answer_log_triage_question(self.db, f"Why was log {log_id} flagged?", log_id=log_id, redacted=self.redacted)
        return ToolOutput(result.answer, [("Log detail", "/api/logs/{log_id}", str(log_id))])

    def explain_detection_rules(self, args: dict[str, Any]) -> ToolOutput:
        topic = str(args.get("rule") or "").strip()
        network = [spec for spec in RULE_CATALOG.values() if spec.code != "ml_anomaly_detected"]
        if not topic or topic.lower() in {"all", "list", "every rule", "rules"}:
            answer = answer_rule_question("how many rules")
        else:
            answer = answer_rule_question(f"what does the {topic} rule check") or answer_rule_question(f"{topic} rules")
        lines = [answer.summary, *[f"- {line}" for line in answer.lines]] if answer else [f"No rule matched {topic!r}."]
        codes = answer.codes if answer else []
        supporting = [RULE_CATALOG[code].title for code in codes if code in SUPPORTING_ONLY_RULES]
        if supporting:
            lines.append(
                "These only add points to an alert raised by a behaviour rule; they never raise an alert alone: "
                + ", ".join(supporting) + "."
            )
        if not answer or len(codes) > 1:
            lines.append("All rules: " + "; ".join(f"{spec.title} ({spec.rule_id})" for spec in network))
        return ToolOutput("\n".join(lines), [("Detection rule catalog", "docs/DETECTION_RULE_CATALOG.md", None)])

    def dashboard_how_to(self, args: dict[str, Any]) -> ToolOutput:
        task = str(args.get("task") or "").strip()
        if not task:
            raise ValueError("task must describe what the analyst wants to do")
        answer = answer_help_question(task if task.lower().startswith("how") else f"how do i {task}")
        if answer is None:
            return ToolOutput(
                "No guide matches that task. Guides exist for: " + "; ".join(topic.title for topic in HELP_TOPICS) + "."
            )
        lines = [answer.summary, *[f"{index}. {step}" for index, step in enumerate(answer.steps, 1)]]
        if answer.note:
            lines.append(answer.note)
        return ToolOutput(self._text("\n".join(lines)), [(answer.citation[0], answer.citation[1], None)])

    def explain_concept(self, args: dict[str, Any]) -> ToolOutput:
        topic = _choice(args, "topic", CONCEPTS)
        if topic is None:
            raise ValueError(f"topic must be one of: {', '.join(CONCEPTS)}")
        topic = CONCEPT_ALIASES.get(topic, topic)
        if topic in ATTACK_CONCEPTS:
            return ToolOutput(self._attack_concept(topic), [("Detection rule catalog", "docs/DETECTION_RULE_CATALOG.md", None)])
        return ToolOutput(self._other_concept(topic))

    def _attack_concept(self, attack_type: str) -> str:
        mapping = ATTACK_TYPE_MAPPINGS[attack_type]
        guidance = PLAYBOOK_GUIDANCE[attack_type]
        rules = [spec for spec in RULE_CATALOG.values() if spec.attack_type == attack_type and spec.code != "ml_anomaly_detected"]
        # ATDR's own rule and its numbers come straight after the definition: further down, the local model
        # summarised the textbook definition instead and answered "what does the brute force rule check?"
        # without the rule ("multiple failed logins from one IP or user account").
        lines = [
            ATTACK_CONCEPTS[attack_type],
            "How ATDR detects it: "
            + (
                "; ".join(f'the "{spec.title}" rule ({spec.rule_id}) checks: {spec.condition}' for spec in rules)
                if rules
                else "no rule looks for it directly"
            )
            + ".",
            f"MITRE ATT&CK: {mapping['tactic']} / {mapping['technique']} ({mapping['technique_id']}). {mapping['claim_boundary']}",
            f"How ATDR's playbook handles it: {guidance.objective} {' '.join(guidance.containment)}",
            f"Usually harmless when: {guidance.false_positive_when}",
        ]
        return "\n".join(lines)

    def _other_concept(self, topic: str) -> str:
        if topic == "mitre_attack":
            table = "; ".join(
                f"{ATTACK_LABELS.get(key, key)} -> {value['technique']} ({value['technique_id']})"
                for key, value in ATTACK_TYPE_MAPPINGS.items()
                if key not in {"normal", "unknown_anomaly", "policy_violation"}
            )
            return (
                "MITRE ATT&CK is a public catalogue of real attacker behaviour, grouped into tactics (the goal, such as "
                "Discovery) and techniques (how, such as Network Service Discovery, T1046). SOC teams use the IDs as a shared "
                f"language. ATDR maps each alert's attack type to one technique: {table}. Policy violations are ATDR's own "
                "category, not an ATT&CK technique."
            )
        if topic == "severity_and_score":
            bands, start = [], 0
            for score in range(0, 101):
                if score == 100 or severity_from_score(score + 1) != severity_from_score(score):
                    bands.append(f"{severity_from_score(score)} {start}-{score}")
                    start = score + 1
            return (
                "Each rule that matches a log adds points to a risk score from 0 to 100. The score sets the severity: "
                + ", ".join(bands) + ". "
                f"A log needs at least {self.settings.min_alert_score} points, including a behaviour rule, to become an alert. "
                "Context signals (risky app, busy source, inbound direction, large transfer) add points but never raise an alert alone."
            )
        if topic == "sla":
            targets = ", ".join(f"{severity} {label.lower()} ({_duration(delta)})" for severity, (label, delta) in SLA_TARGETS.items())
            return (
                f"The SLA is how fast an alert should be handled after it is created: {targets}. "
                "An alert is overdue when it is still not resolved or marked false positive after that time, "
                "and needs an owner when nobody is assigned."
            )
        if topic == "false_positive":
            return (
                "A false positive is an alert on traffic that turns out to be harmless, such as an approved scanner or a "
                "backup job. Check the alert's evidence and the playbook's 'false positive when' guide. If it is harmless, "
                "open the alert and click False positive under Analyst Actions, and add a note saying why. Repeated harmless "
                "patterns can be suppressed by an admin in Threat Controls."
            )
        if topic == "alert_grouping":
            return (
                "ATDR looks at traffic in 5-minute windows per source, so a scan spread over many logs becomes one alert "
                "with all the logs attached as evidence. A new match from the same source and alert type within "
                f"{ALERT_DEDUP_WINDOW_MINUTES} minutes of a still-active alert is merged into it instead of creating a duplicate. "
                "Alerts with the same source, destination and attack type within 24 hours are grouped into one case."
            )
        if topic == "supporting_signals":
            names = ", ".join(sorted(RULE_CATALOG[code].title for code in SUPPORTING_ONLY_RULES if code in RULE_CATALOG))
            return (
                f"Some rules only describe context: {names}. They add points to an alert raised by a behaviour rule "
                "(scan, brute force, flood, beaconing, threat log and so on) but never raise an alert alone, because on "
                "MFU traffic they were mostly normal activity."
            )
        if topic == "ml_models":
            from atdr.app.services import behavior_findings_service as findings

            status = findings.model_status(findings.load_model())
            role = (
                "No attack type has passed the quality bar the team declared before training, and there is no more MFU traffic "
                "to test on, so the team switched every type on as an experimental exception: where the rules raise no alert, "
                "the model raises its own, each marked experimental and low confidence. It never triggers a response on its own."
                if status.get("alerting_types") else
                "It is advisory: until an attack type passes the quality bar the team declared before training, the rules "
                "decide every alert."
            )
            return (
                "ATDR's alerts come mainly from its fixed rules. The machine-learning (ML) model that matters is the MFU "
                "behaviour model: trained only on MFU's own firewall traffic, it reads each device's five minutes of traffic, "
                "suggests the likely attack type to investigate and explains why, on the Overview and on each alert. The "
                "percentage it shows is its non-normal estimate (1 minus its probability that the traffic is normal), not "
                "confidence in the attack type. The quality bar asks that its extra finds (flagged with no rule alert) be "
                "confirmed real in a blind review, that it find at least 90% of fresh simulated attacks, and that rules plus "
                f"model be no less accurate than the rules alone on the blind-check labels. {role} "
                # "Advisory only" for both once read as "the supervised model is used"; it never runs.
                "Two earlier models are not part of detection: the anomaly model (IsolationForest) at most marks unusual logs "
                "as a hint beside the rule evidence, and the supervised classifier is not used at all: it never passed its "
                "qualification, so its runtime state is unqualified and it refuses to score. "
                f"{status['data_limit']}"
            )
        if topic == "simulated_response":
            return (
                "Responses such as blocking an IP are simulated by default: ATDR records the action and its reason in the "
                "audit trail, but nothing changes on the real firewall unless an admin turns on real enforcement. Only admins "
                "can block or unblock, and the assistant never takes any action."
            )
        if topic == "privacy_redaction":
            return (
                "The assistant shows IP addresses as [redacted-ip] and never shares raw firewall log lines, passwords or keys. "
                "Analysts can see full details on the Alerts and Investigation pages, which require a login."
            )
        if topic == "data_sources":
            db = self.db
            total = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
            first, last = db.execute(select(func.min(NormalizedLog.generated_time), func.max(NormalizedLog.generated_time))).one()
            alerts = int(db.scalar(select(func.count(Alert.id))) or 0)
            return (
                "Everything the assistant says comes from ATDR's own database: Palo Alto firewall logs imported from MFU's "
                f"firewall ({total:,} logs, event times {_log_when(first)} to {_log_when(last)}), the {alerts:,} alerts ATDR's rules "
                "created from them, analyst notes and actions, and ATDR's rule catalog and guides. It does not browse the "
                "internet."
            )
        return (
            "ATDR (Automated Threat Detection and Response) is the MFU security team's system for firewall logs. It imports "
            "Palo Alto logs, checks them with fixed detection rules, groups findings into alerts with evidence, MITRE "
            "ATT&CK mapping and a response playbook, and helps analysts investigate, record decisions and simulated "
            "responses. Machine learning gives advisory scores."
        )

    def behavior_model_view(self, args: dict[str, Any]) -> ToolOutput:
        from atdr.app.services import behavior_findings_service as findings

        model = findings.load_model()
        status = findings.model_status(model)
        citation = [("MFU behaviour model", "/api/ml/behavior/findings", None)]
        if not status["available"]:
            return ToolOutput(status["detail"], citation)
        role = (
            "Where the rules raise no alert it raises its own experimental alerts, marked low confidence."
            if status.get("alerting_types") else "It is advisory: it creates no alerts, ATDR's rules do."
        )
        lines = [
            f"The MFU behaviour model ({status['version']}) was trained only on MFU's own firewall traffic "
            f"({status['trained_on']}). {role} {status['detail']}"
        ]
        view = findings.window_findings(self.db, None, model=model)
        window, summary = view.get("window"), view.get("summary")
        if window and summary:
            start = datetime.fromisoformat(window["start"])
            names = ", ".join(f"{ATTACK_NAMES.get(kind, kind)} {count:,}" for kind, count in summary["by_type"].items()) or "none"
            lines.append(
                f"Latest 5-minute window with traffic, {_log_when(start)}-{start + timedelta(minutes=5):%H:%M}: it checked "
                f"{summary['sources_checked']:,} sources and sees attack behaviour from {summary['flagged']:,} ({names}); "
                f"{summary['model_only']:,} of those had no rule alert."
            )
            if window.get("in_training_data"):
                lines.append("That window was part of its training data, so it shows what the model learned rather than a fair test.")
            for finding in view["findings"][:3]:
                found_by = (
                    "the rules alerted too" if finding["found_by"] == "rules_and_model"
                    else "found only by the model, raised as an experimental alert" if finding.get("model_alert_ids")
                    else "found only by the model"
                )
                why = "; ".join(finding["reasons"][:2]) or "no single feature stands out"
                first_step = (finding["response"].get("containment") or ["see the playbook"])[0]
                lines.append(f"- {finding['source']}: possible {finding['attack_label']} (non-normal estimate {finding['confidence']:.0%}, not attack-type confidence), {found_by}. "
                             f"Why: {why}. First response step: {first_step}")
            probing = summary["background_probing"]
            lines.append(f"Internet background probing, summarised rather than alerted: {probing['sources']:,} hosts made "
                         f"{probing['connections']:,} unanswered connections to {probing['mfu_hosts_touched']:,} MFU addresses.")
            p2p = summary.get("p2p_policy")
            if p2p and p2p["sources"]:
                lines.append(f"Peer-to-peer file sharing, policy activity rather than an attack: {p2p['sources']:,} devices, "
                             f"{p2p['connections']:,} connections.")
        bar = status.get("quality_bar")
        if bar:
            standing = "; ".join(f"{ATTACK_NAMES.get(kind, kind)}: {_bar_text(entry)}" for kind, entry in bar["types"].items())
            lines.append("Quality bar (a type may raise its own alerts only after passing it): " + standing + ".")
        lines.append(status["data_limit"])
        return ToolOutput(self._text("\n".join(lines)), citation)

    def watchlist_lookup(self, args: dict[str, Any]) -> ToolOutput:
        feeds = watchlist_feed_summary(self.db)
        manual = list_watchlist_items(self.db, active_only=True, manual_only=True)
        feed_text = ", ".join(f"{feed['source']} ({feed['active']:,} active addresses)" for feed in feeds) or "none"
        citation = [("Watchlist", "/api/watchlists", None)]
        ip = str(args.get("ip") or "").strip()
        if not ip:
            return ToolOutput(
                f"ATDR's watchlist has {len(manual):,} hand-added indicators and these threat intelligence feeds: {feed_text}. "
                "An MFU host contacting a listed address raises a watchlist alert.",
                citation,
            )
        items = list(self.db.scalars(select(WatchlistItem).where(func.lower(WatchlistItem.indicator_value) == ip.lower())))
        lines = []
        for item in items:
            origin = f"from the {item.source} feed" if item.source else f"added by hand by {item.created_by} on {item.created_at:%d %b %Y}"
            state = "active" if item.active else "disabled"
            lines.append(f"{ip} is on ATDR's watchlist ({item.indicator_type}, {origin}, {state}, +{item.severity_boost} points): "
                         f"{item.description}")
        if not items:
            lines.append(f"{ip} is not on ATDR's watchlist (feeds loaded: {feed_text}). ATDR has no internet reputation "
                         "lookup, so not listed does not mean safe.")
        contacted = stored_log_matches(self.db, [ip])
        sent = int(self.db.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.src_ip == ip)) or 0)
        lines.append(f"Stored logs: {contacted['logs']:,} connections to it from {contacted['sources']:,} sources; {sent:,} logs from it.")
        alerts = list(self.db.execute(
            select(Alert.id, Alert.severity, Alert.alert_type, Alert.status)
            .where((Alert.dst_ip == ip) | (Alert.src_ip == ip)).order_by(Alert.threat_score.desc()).limit(5)
        ))
        if alerts:
            lines.append("Alerts: " + ", ".join(f"#{alert_id} {severity} {kind} ({status})" for alert_id, severity, kind, status in alerts) + ".")
        return ToolOutput(self._text("\n".join(lines)), citation)

    def system_status(self, args: dict[str, Any]) -> ToolOutput:
        area = _choice(args, "area", SYSTEM_AREAS, "operations")
        db, redacted = self.db, self.redacted
        if area == "ml":
            result = core._answer_ml_question(db, redacted=redacted)
        elif area == "detection_runs":
            result = core._answer_detection_runs_question(db, redacted=redacted)
        elif area == "sources":
            result = core._answer_source_question(db, source_id=None, limit=self.context_limit, redacted=redacted)
        elif area == "recent_changes":
            result = core._answer_recent_changes(db, limit=self.context_limit, redacted=redacted)
        elif area == "failed_jobs":
            result = core._answer_failed_jobs(db, settings=self.settings, redacted=redacted)
        else:
            result = core._answer_operations_question(db, settings=self.settings, redacted=redacted)
        citations = [(item.label, item.source, item.reference_id) for item in result.citations[:4]]
        return ToolOutput(result.answer, citations)

    # ------------------------------------------------------------ registry

    def tools(self) -> list[AgentTool]:
        window = {"type": "string", "enum": list(TIME_WINDOWS), "description": "Time range. Default all_time."}
        ip = {"type": "string", "description": "An IP address the analyst typed, to filter by."}
        ip_role = {"type": "string", "enum": ["source", "destination", "either"]}
        limit = {"type": "integer", "minimum": 1, "maximum": 10, "description": "Rows for top/list. Default 5."}
        alert_id = {"type": "object", "properties": {"alert_id": {"type": "integer"}}, "required": ["alert_id"]}
        return [
            AgentTool(
                "security_overview",
                "Big picture: alerts by severity and status, top attack types, top sources, the open alerts to look at "
                "first, what logs are stored, and the latest detection run. Use for open questions like 'what is going on', "
                "'are we under attack', 'summarize today', 'biggest risks'.",
                {"type": "object", "properties": {"time_window": {**window, "description": "Default today."}}},
                self.security_overview,
            ),
            AgentTool(
                "query_alerts",
                "Count, rank, trend or list alerts with filters. intent=count for 'how many'; top to rank by group_by; "
                "trend for per-day counts; list for the highest-scoring matching alerts with their IDs. Alerts are dated "
                "by when ATDR created them, so time_window means created in that period: for what is open right now or "
                "currently, leave time_window out and set status=open.",
                {
                    "type": "object",
                    "properties": {
                        "intent": {"type": "string", "enum": ["count", "top", "trend", "list"]},
                        "time_window": window,
                        "severity": {"type": "string", "enum": list(SEVERITIES)},
                        "status": {"type": "string", "enum": list(STATUSES)},
                        "attack_type": {"type": "string", "enum": list(ATTACK_TYPES)},
                        "group_by": {"type": "string", "enum": list(ALERT_GROUPS), "description": "For intent=top."},
                        "ip": ip,
                        "ip_role": ip_role,
                        "limit": limit,
                    },
                    "required": ["intent"],
                },
                self.query_alerts,
            ),
            AgentTool(
                "query_logs",
                "Count, rank or trend firewall logs (not alerts), including how many logs are stored. Logs are dated by "
                "firewall event time. group_by ranks apps, ports, IPs, countries or actions.",
                {
                    "type": "object",
                    "properties": {
                        "intent": {"type": "string", "enum": ["count", "top", "trend"]},
                        "time_window": window,
                        "action": {"type": "string", "enum": list(LOG_ACTIONS)},
                        "min_app_risk": {"type": "integer", "minimum": 1, "maximum": 5},
                        "group_by": {"type": "string", "enum": list(LOG_GROUPS), "description": "For intent=top."},
                        "ip": ip,
                        "ip_role": ip_role,
                        "limit": limit,
                    },
                    "required": ["intent"],
                },
                self.query_logs,
            ),
            AgentTool(
                "get_alert",
                "Everything about one alert: severity, score, status, why it was flagged, matched rules, MITRE ATT&CK "
                "technique, evidence, false-positive caveats, SLA and what to check next.",
                alert_id,
                self.get_alert,
            ),
            AgentTool(
                "get_alert_playbook",
                "The step-by-step response for one alert (triage, investigate, contain, close) and when to call it a "
                "false positive, resolved, or escalate. Use when asked what to do, how to fix or respond to an alert.",
                alert_id,
                self.get_alert_playbook,
                provides_steps=True,
            ),
            AgentTool(
                "get_log",
                "Explain one firewall log: its fields and why it was or was not flagged.",
                {"type": "object", "properties": {"log_id": {"type": "integer"}}, "required": ["log_id"]},
                self.get_log,
            ),
            AgentTool(
                "explain_detection_rules",
                "ATDR's detection rules from the rule catalog: what a rule checks, which rules detect an attack type, "
                "or the full list and count (rule='all').",
                {"type": "object", "properties": {"rule": {"type": "string", "description": "A rule name, attack type, or 'all'."}}},
                self.explain_detection_rules,
            ),
            AgentTool(
                "explain_concept",
                "Plain explanations of security and ATDR concepts, tied to how ATDR handles them.",
                {"type": "object", "properties": {"topic": {"type": "string", "enum": list(CONCEPTS)}}, "required": ["topic"]},
                self.explain_concept,
            ),
            AgentTool(
                "dashboard_how_to",
                "Step-by-step dashboard instructions for a task, e.g. 'block an IP', 'mark an alert as false positive', "
                "'import logs', 'add to watchlist', 'suppress alerts', 'download a report', 'assign an alert'.",
                {"type": "object", "properties": {"task": {"type": "string"}}, "required": ["task"]},
                self.dashboard_how_to,
                provides_steps=True,
            ),
            AgentTool(
                "behavior_model_view",
                "The MFU behaviour model, trained only on MFU traffic: what it sees in the latest 5-minute window (attack "
                "behaviour per type, the top sources with reasons and first response step, background probing, file "
                "sharing) and where each attack type stands on its quality bar. Use for any question about the MFU model, "
                "the behaviour model, or what the model sees or found.",
                {"type": "object", "properties": {}},
                self.behavior_model_view,
            ),
            AgentTool(
                "watchlist_lookup",
                "Whether an IP address is on ATDR's watchlist or a threat intelligence feed (known malicious, e.g. a C2 "
                "server), why, and how often MFU contacted it. Without ip: which feeds and indicators are loaded.",
                {"type": "object", "properties": {"ip": {"type": "string", "description": "The IP address to look up."}}},
                self.watchlist_lookup,
            ),
            AgentTool(
                "system_status",
                "ATDR's own health: ml (the earlier anomaly model and supervised classifier, and why ML is advisory; for "
                "the MFU behaviour model use behavior_model_view), detection_runs, operations (jobs and worker), sources "
                "(log source health), recent_changes, failed_jobs.",
                {"type": "object", "properties": {"area": {"type": "string", "enum": list(SYSTEM_AREAS)}}, "required": ["area"]},
                self.system_status,
            ),
        ]


ATTACK_NAMES = {
    "port_scan": "port scan",
    "brute_force": "brute force",
    "dos_ddos": "flood",
    "malware_c2": "malware C2",
    "data_exfiltration_suspicion": "data exfiltration",
}


def _bar_text(entry: dict[str, Any]) -> str:
    review = entry["condition_1"]
    if entry["eligible"]:
        return "passes and may be switched on"
    if review["status"] == "pending":
        text = f"blind review of {review['model_only']} windows pending"
    elif review["status"] == "cannot_pass":
        text = f"only {review['model_only']} extra finds to review"
    else:
        text = f"review {review.get('threat', 0)} of {review.get('judged', 0)} real ({review['status'].replace('_', ' ')})"
    if not entry["condition_2"]["passes"]:
        text += f", finds {entry['condition_2']['found']:.1%} of simulated attacks (90% needed)"
    return text


def _duration(delta) -> str:
    hours = int(delta.total_seconds() // 3600)
    return f"{hours // 24} days" if hours >= 48 else f"{hours} hour{'s' if hours != 1 else ''}"


def build_assistant_tools(db: Session, *, settings: Settings) -> list[AgentTool]:
    return AssistantToolbox(db, settings=settings).tools()
