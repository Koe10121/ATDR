"""Attack-type response playbooks for a single alert.

A playbook turns one alert into an ordered SOC workflow: triage, investigate,
contain, close. Only the per-attack-type guidance (objective, containment,
closing criteria) lives here. Rule-specific checks come from
``RULE_ANALYST_CHECKS`` and the ATT&CK mapping from ``ATTACK_TYPE_MAPPINGS``
(both via the alert's detection summary), so the playbook cannot drift from
what the alert drawer shows.

Playbooks are guidance only: building one reads the alert and changes nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from atdr.app.db.models import Alert


@dataclass(frozen=True, slots=True)
class PlaybookGuidance:
    label: str
    objective: str
    containment: tuple[str, ...]
    false_positive_when: str
    resolved_when: str
    escalate_when: str


PLAYBOOK_GUIDANCE: dict[str, PlaybookGuidance] = {
    "port_scan": PlaybookGuidance(
        label="Port scan",
        objective="Decide whether this is approved scanning or someone mapping your services.",
        containment=(
            "If the source is outside your network and not an approved scanner, block it and watch it.",
            "If any probed port was allowed, check that service for follow-up sessions from the same source.",
        ),
        false_positive_when="The source is an approved vulnerability scanner or asset-discovery system.",
        resolved_when="The source is blocked or watched, and no probed service accepted follow-up traffic.",
        escalate_when="An allowed port later shows sessions or data transfer from the same source.",
    ),
    "brute_force": PlaybookGuidance(
        label="Brute force",
        objective="Decide whether someone is guessing logins against one service, or a client is misconfigured.",
        containment=(
            "Check the login system for failed and successful sign-ins from this source. Any success means a possible account compromise.",
            "If the source is outside your network, block it and watch it.",
        ),
        false_positive_when="A known client with a stale password, a health check, or a password manager retrying.",
        resolved_when="No login succeeded, and the source is blocked or has stopped.",
        escalate_when="Any login from this source succeeded, or it tried several accounts.",
    ),
    "dos_ddos": PlaybookGuidance(
        label="Flood / denial of service",
        objective="Decide whether the traffic volume actually hurt the service, or is a load test or busy client.",
        containment=(
            "Check the target service's health and response times for the same time window.",
            "If the service was affected and the source is outside your network, block it and tell the network team.",
        ),
        false_positive_when="An approved load test, health checks, or a high-volume API client.",
        resolved_when="Traffic is back to normal and the service was not affected, or the source is blocked.",
        escalate_when="The service showed errors or downtime during the window.",
    ),
    "malware_c2": PlaybookGuidance(
        label="Malware / command and control",
        objective="Decide whether an internal host is contacting an outside server the way malware would.",
        containment=(
            "Identify the internal host and its owner, and scan it with endpoint antivirus or EDR.",
            "If the firewall did not block the connection, block the destination and consider isolating the host.",
        ),
        false_positive_when="Approved telemetry, update checks, monitoring, or keep-alive traffic to a known vendor.",
        resolved_when="The host is checked and clean (or cleaned), and the destination is blocked.",
        escalate_when="Endpoint tools confirm malware, or other hosts contact the same destination.",
    ),
    "policy_violation": PlaybookGuidance(
        label="Policy violation",
        objective="Decide whether this breaks firewall or acceptable-use policy, and whether it matters.",
        containment=(
            "Confirm who owns the source and whether the app or destination is approved for them.",
            "For a repeat offender, watch the source or app and tell its owner.",
        ),
        false_positive_when="The app or traffic is approved for this user or system, or the deny is expected policy noise.",
        resolved_when="The owner is informed and the traffic stopped, or it is documented as allowed.",
        escalate_when="The same source also triggers scan, brute-force, or large-upload rules.",
    ),
    "data_exfiltration_suspicion": PlaybookGuidance(
        label="Possible data exfiltration",
        objective="Decide whether large uploads leaving the network are approved, or data being taken.",
        containment=(
            "Identify the internal host, its owner, and the destination, and ask the owner whether the transfer was expected.",
            "If nobody can explain it, block the destination and keep the linked logs as evidence.",
        ),
        false_positive_when="Approved backups, cloud sync, or a scheduled transfer to a known destination.",
        resolved_when="The transfer is confirmed as approved, or it is stopped and blocked.",
        escalate_when="The owner cannot explain it, or sensitive data may be involved.",
    ),
    "unknown_anomaly": PlaybookGuidance(
        label="Unclassified suspicious activity",
        objective="Work out what this activity is before giving it a label.",
        containment=(
            "Hold off on blocking until the investigation shows a clear threat.",
            "Watch the source so any stronger activity stands out.",
        ),
        false_positive_when="The activity matches normal business traffic for this source.",
        resolved_when="The cause is identified and written down in the alert notes.",
        escalate_when="Stronger rules start firing for the same source.",
    ),
}

DEFAULT_PLAYBOOK = "unknown_anomaly"
CLOSED_STATUSES = frozenset({"resolved", "false_positive"})


def playbook_guidance(attack_type: str | None) -> tuple[str, PlaybookGuidance]:
    key = attack_type if attack_type in PLAYBOOK_GUIDANCE else DEFAULT_PLAYBOOK
    return key, PLAYBOOK_GUIDANCE[key]


def _ask(question: str) -> dict[str, str]:
    return {"kind": "ask", "question": question}


def _open(path: str, label: str) -> dict[str, str]:
    return {"kind": "open", "path": path, "label": label}


def _step(step_id: str, text: str, *, action: dict[str, str] | None = None, done: bool = False) -> dict[str, Any]:
    return {"id": step_id, "text": text, "action": action, "done": done}


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def build_alert_playbook(alert: Alert, detection_summary: dict[str, Any]) -> dict[str, Any]:
    """Build the ordered playbook for one alert from its detection summary."""

    alert_id = int(alert.id)
    attack_type, guidance = playbook_guidance(detection_summary.get("attack_type"))
    mapping = detection_summary.get("attack_mapping") or {}
    traceability = detection_summary.get("traceability") or {}
    rule_names = [str(name) for name in detection_summary.get("matched_rule_names") or [] if str(name).strip()]
    rule_checks = [
        str(check)
        for check in detection_summary.get("prioritized_analyst_checks") or []
        if str(check).strip()
    ]
    related_logs = int(traceability.get("related_log_count") or 0)
    status = str(alert.status or "open")
    has_notes = bool(alert.notes)
    has_response = bool(alert.response_actions)
    alert_path = f"/alerts?alert={alert_id}"
    src_ip = alert.src_ip or None

    rules_text = ", ".join(rule_names[:3]) if rule_names else "the matched rules"
    triage = [
        _step(
            "triage-why",
            f"Read why it was flagged: {_plural(len(rule_names), 'rule')} matched ({rules_text}).",
            action=_ask(f"Why was alert {alert_id} flagged?"),
        ),
        _step(
            "triage-noise",
            "Check whether it could be noise or a false positive before spending more time.",
            action=_ask(f"Is alert {alert_id} likely a false positive?"),
        ),
        _step(
            "triage-claim",
            "Set the status to Investigating so the team knows it is taken.",
            action=_open(alert_path, "Open alert"),
            done=status != "open",
        ),
    ]

    investigate = [
        _step(f"investigate-check-{index}", check)
        for index, check in enumerate(rule_checks[:2], start=1)
    ]
    investigate.append(
        _step(
            "investigate-logs",
            f"Review the {_plural(related_logs, 'linked log')} behind this alert."
            if related_logs
            else "Review the logs linked to this alert.",
            action=_ask(f"What logs are related to alert {alert_id}?"),
        )
    )
    if src_ip:
        investigate.append(
            _step(
                "investigate-source-activity",
                f"Look for other activity from {src_ip} before and after the alert.",
                action=_open(f"/logs?src_ip={quote(src_ip, safe='')}", "Search logs"),
            )
        )

    contain = [
        _step(f"contain-guidance-{index}", text)
        for index, text in enumerate(guidance.containment, start=1)
    ]
    contain.append(
        _step(
            "contain-block",
            "To block, record the response from the alert's detail view. It is simulated unless an admin turned on real enforcement.",
            action=_open(alert_path, "Open alert"),
            done=has_response,
        )
    )
    if src_ip:
        contain.append(
            _step(
                "contain-watch",
                f"Add {src_ip} to a watchlist so its next activity stands out.",
                action=_open("/controls?tab=watchlists", "Open watchlists"),
            )
        )

    close = [
        _step(
            "close-notes",
            "Write what you found and why you decided it in the alert notes.",
            action=_open(alert_path, "Open alert"),
            done=has_notes,
        ),
        _step(
            "close-brief",
            "Create a hand-off brief for the next shift or your supervisor.",
            action=_ask(f"Create investigation brief for alert {alert_id}."),
        ),
        _step(
            "close-status",
            "Close the alert as Resolved or False positive, or escalate it, using the guide below.",
            action=_open(alert_path, "Open alert"),
            done=status in CLOSED_STATUSES or alert.escalated_at is not None,
        ),
    ]

    return {
        "alert_id": alert_id,
        "attack_type": attack_type,
        "label": guidance.label,
        "objective": guidance.objective,
        "mitre": {
            "tactic": mapping.get("tactic"),
            "technique": mapping.get("technique"),
            "technique_id": mapping.get("technique_id"),
        },
        "claim_boundary": mapping.get("claim_boundary"),
        "facts": {
            "severity": alert.severity,
            "score": alert.threat_score,
            "status": status,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "related_log_count": related_logs,
            "rule_names": rule_names,
        },
        "phases": [
            {"key": "triage", "title": "Triage", "goal": "Confirm the alert is real and worth your time.", "steps": triage},
            {"key": "investigate", "title": "Investigate", "goal": "Work out what happened and how far it goes.", "steps": investigate},
            {"key": "contain", "title": "Contain", "goal": "Limit harm, only when the evidence supports it.", "steps": contain},
            {"key": "close", "title": "Close", "goal": "Decide, write it down, and hand off.", "steps": close},
        ],
        "decision_guide": {
            "false_positive": guidance.false_positive_when,
            "resolved": guidance.resolved_when,
            "escalate": guidance.escalate_when,
        },
        "safety_note": "This playbook is guidance only. Opening it changes nothing, and the assistant never blocks or closes alerts.",
    }
