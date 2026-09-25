"""Answer "how do I ..." and "what does rule X check" questions.

Help answers describe the dashboard as it is: page names, tab names, and
button labels match the React pages, and each entry says when an action is
admin-only. Rule answers are read from the rule catalog and the analyst
checks the alert drawer already shows, so they cannot drift from detection.

Both functions return ``None`` when a question is not clearly theirs, so the
regular router still handles everything else.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from atdr.app.detection.explanations import RULE_ANALYST_CHECKS
from atdr.app.detection.rule_catalog import RULE_CATALOG, DetectionRuleSpec
from atdr.app.services.assistant_data_query import ATTACK_LABELS, ATTACK_PHRASES


@dataclass(frozen=True, slots=True)
class HelpTopic:
    key: str
    title: str
    patterns: tuple[str, ...]
    steps: tuple[str, ...]
    page: str
    note: str | None = None


@dataclass(slots=True)
class HelpAnswer:
    summary: str
    steps: list[str]
    note: str | None
    context: str
    citation: tuple[str, str]
    followups: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RuleAnswer:
    summary: str
    lines: list[str]
    basis: str
    context: str = "rule_catalog"
    codes: list[str] = field(default_factory=list)


HELP_INTENT = re.compile(
    r"\bhow (?:do|can|should|would) (?:i|we|you)\b|\bhow to\b|\bwhere (?:do|can|is|are) (?:i|we|the)?\b|"
    r"\bcan (?:i|we)\b|\bsteps? (?:to|for)\b|\bhelp me\b|\bwhat(?:'s| is) the way to\b|\bi want to\b|\bi need to\b"
)

HELP_TOPICS: tuple[HelpTopic, ...] = (
    HelpTopic(
        key="watchlist",
        title="Add something to a watchlist",
        patterns=(r"\bwatch ?lists?\b", r"\bwatch (?:an? |the )?(?:ip|app|application|country)\b"),
        steps=(
            "Open Threat Controls (left menu, under Response & Audit), then the Watchlists tab.",
            "Under Add Watchlist Item, pick the type: Source IP, Destination IP, Application, Source country or Destination country.",
            "Enter the value (for a country, the name as the firewall reports it, e.g. Germany) and click Create watchlist item.",
            "From the next detection run, matching logs get a Watchlist match rule with extra points, and the alert shows why.",
        ),
        page="Threat Controls",
        note="Only admins can create watchlist items; analysts can view them.",
    ),
    HelpTopic(
        key="suppression",
        title="Suppress noisy alerts",
        patterns=(r"\bsuppress", r"\bmute\b", r"\bsilence\b", r"\bstop (?:getting|seeing) (?:these |those |the )?alerts\b", r"\bnoisy alerts?\b"),
        steps=(
            "Open Threat Controls, then the Suppressions tab.",
            "Fill in what to match: Source IP criterion, App criterion and/or Alert type criterion, plus a Reason.",
            "Click Create suppression.",
            "Matching alert groups are no longer created on later detection runs. The logs themselves are still stored.",
        ),
        page="Threat Controls",
        note="Only admins can create or disable suppressions; analysts can review them.",
    ),
    HelpTopic(
        key="bulk",
        title="Update many alerts at once",
        patterns=(r"\bbulk\b", r"\b(?:many|multiple|several|all(?: the| these)?) alerts\b", r"\bat once\b", r"\bselect (?:all|many|multiple)\b"),
        steps=(
            "Open Alerts and tick the box at the start of each row, or the box in the header to select the whole page.",
            "A bar appears above the table: choose Investigating, Needs context, Resolve or False positive.",
            "Resolve and False positive ask you to confirm first.",
            "Each alert gets its own entry in the audit trail. Up to 200 alerts can be updated in one action.",
        ),
        page="Alerts",
    ),
    HelpTopic(
        key="status",
        title="Change an alert's status (including false positive)",
        patterns=(
            r"\bfalse[ -]positive\b",
            r"\bmark (?:an? |the |this )?alerts?\b",
            r"\b(?:change|update|set) (?:the |an? |alert )?status\b",
            r"\b(?:resolve|close|dismiss) (?:an? |the |this )?alerts?\b",
        ),
        steps=(
            "Open Alerts and click the alert's row to open its details.",
            "Under Analyst Actions, click Investigating, Needs context, Contained, Resolve or False positive.",
            "False positive asks you to confirm first. Add a note explaining why, so the next analyst knows.",
            "Every status change is recorded in the Audit Trail.",
        ),
        page="Alerts",
    ),
    HelpTopic(
        key="note",
        title="Add a note to an alert",
        patterns=(r"\bnotes?\b", r"\bcomments?\b"),
        steps=(
            "Open Alerts and click the alert's row to open its details.",
            "Type in the Analyst note box and click Add.",
            "Notes are saved with your name and the time, and the playbook marks its note step as done.",
        ),
        page="Alerts",
    ),
    HelpTopic(
        key="assign",
        title="Take ownership of an alert",
        patterns=(r"\bassign", r"\bclaim\b", r"\btake (?:an? |the |this )?alert\b", r"\bown(?:er|ership)\b"),
        steps=(
            "Open Alerts and click the alert's row to open its details.",
            "Under Analyst Actions, click Assign to me.",
            "Setting the status to Investigating also tells the team the alert is being worked on.",
        ),
        page="Alerts",
    ),
    HelpTopic(
        key="block",
        title="Block an IP (simulated by default)",
        patterns=(r"\bblock", r"\bcontain(?:ment)?\b(?! alerts?)", r"\bquarantine\b", r"\bisolate\b"),
        steps=(
            "From an alert: open it and click Simulated block source under Analyst Actions.",
            "Or open Response & Audit, enter the IP and a reason of at least 8 characters, and click Record simulated block.",
            "Blocks are simulated by default: nothing changes on a real firewall unless an admin turned on real enforcement.",
            "To undo from the alert, click Simulated unblock. Every block and unblock is recorded in the Audit Trail.",
        ),
        page="Response & Audit",
        note="Only admins can block or unblock. The assistant itself never blocks anything.",
    ),
    HelpTopic(
        key="report",
        title="Download an alert report",
        patterns=(r"\breports?\b", r"\bdownload\b", r"\bpdf\b", r"\bcsv\b", r"\bexport\b"),
        steps=(
            "Open Alerts and click the alert's row to open its details.",
            "Click Download CSV, Download HTML or Download PDF.",
            "For a full evidence bundle, an admin can use Export evidence bundle in Validation Controls.",
        ),
        page="Alerts",
    ),
    HelpTopic(
        key="run_detection",
        title="Run detection",
        patterns=(r"\brun (?:the )?detection\b", r"\b(?:start|trigger) (?:the )?detection\b", r"\bdetect (?:new )?alerts\b"),
        steps=(
            "Open Validation Controls (left menu, under Admin / Settings).",
            "Click Run detection. It checks recent logs against the 20 rules and creates or merges alerts.",
            "Open Alerts to see new or updated alerts; repeats are merged into open alerts instead of duplicated.",
        ),
        page="Validation Controls",
        note="Only admins can run detection from the dashboard. The assistant cannot run it for you.",
    ),
    HelpTopic(
        key="investigate",
        title="Investigate an IP in the logs",
        patterns=(
            r"\bsearch (?:the |for )?logs?\b",
            r"\bfind (?:the )?logs?\b",
            r"\b(?:look up|investigate|check|trace) (?:an? |the |this )?ip\b",
            r"\blogs? (?:for|from|of) (?:an? |the |this )?ip\b",
        ),
        steps=(
            "Open Investigation from the left menu.",
            "Type the IP into Source IP or Destination IP, or use the search box. Results update when you stop typing.",
            "Click a row to see the parsed fields and the original firewall line.",
            "Click Ask Assistant about this log to ask why it was or was not flagged.",
        ),
        page="Investigation",
    ),
    HelpTopic(
        key="playbook",
        title="Use the response playbook",
        patterns=(r"\bplaybooks?\b", r"\bwork (?:through|on) an alert\b", r"\bhandle an alert\b"),
        steps=(
            "Open SOC Assistant and scroll below the answer to the Response playbook panel.",
            "With an alert selected it shows four stages: Triage, Investigate, Contain, Close, for that alert's attack type.",
            "Each step has Ask the assistant or a link to the right page; steps tick themselves off from what is saved.",
            "With no alert selected, pick one from Most urgent open alerts, or follow the Start-of-shift routine.",
        ),
        page="SOC Assistant",
    ),
    HelpTopic(
        key="audit",
        title="See who did what (audit trail)",
        patterns=(r"\baudit", r"\bwho (?:did|changed|resolved|closed|blocked|created)\b", r"\bhistory of (?:actions|changes)\b"),
        steps=(
            "Open Audit Trail from the left menu.",
            "Filter by Actor, Action, Target type, Target value or dates. The list updates when you stop typing.",
            "Click a row to see the full details of that action.",
        ),
        page="Audit Trail",
    ),
    HelpTopic(
        key="users",
        title="Add a user or change a role",
        patterns=(
            r"\b(?:add|create|new) (?:an? )?(?:user|account|analyst|admin)\b",
            r"\b(?:change|set|update) (?:a |the |their |his |her )?role\b",
            r"\bmake \w+ (?:an? )?admin\b",
        ),
        steps=(
            "Open User Admin (left menu, under Admin / Settings).",
            "Fill in username, school email, full name and role, then click Create account.",
            "Existing users are listed below, where an admin can change their role or disable the account.",
        ),
        page="User Admin",
        note="Only admins can manage users.",
    ),
)

CAPABILITY_PATTERN = re.compile(
    r"\bwhat can (?:you|i) (?:do|ask)\b|\bwhat (?:questions|kind of questions) can\b|\bhow (?:do|can) i use (?:you|the assistant|this)\b|^help$|^help me$"
)

CAPABILITY_EXAMPLES = (
    "Counts and trends: \"How many High alerts today?\", \"Alerts per day this week\"",
    "Rankings: \"Which source IPs have the most alerts?\", \"What is the most common attack type?\"",
    "One alert: \"Why was alert 3224 flagged?\", \"What should I check first for alert 3224?\"",
    "Logs: \"How many denied connections in the last 24 hours?\", \"Top 5 apps by traffic\"",
    "Rules: \"What does the port scan rule check?\", \"How many rules are there?\"",
    "How-to: \"How do I add an IP to a watchlist?\", \"How do I mark an alert as false positive?\"",
)


def _normalize(question: str) -> str:
    return " ".join(question.lower().replace("?", " ").split())


def answer_help_question(question: str) -> HelpAnswer | None:
    text = _normalize(question)
    if not text:
        return None
    if CAPABILITY_PATTERN.search(text):
        return HelpAnswer(
            summary="I answer from ATDR's own records and guides. You can ask, for example:",
            steps=list(CAPABILITY_EXAMPLES),
            note="I only read data. I never block, delete, run detection or change alerts for you.",
            context="assistant_capabilities",
            citation=("SOC Assistant", "frontend/src/pages/AssistantPage.tsx"),
        )
    if not HELP_INTENT.search(text):
        return None
    scored = [
        (sum(1 for pattern in topic.patterns if re.search(pattern, text)), index, topic)
        for index, topic in enumerate(HELP_TOPICS)
    ]
    scored = [item for item in scored if item[0] > 0]
    if not scored:
        return None
    # Highest score wins; ties go to the earlier, more specific topic.
    _, _, topic = max(scored, key=lambda item: (item[0], -item[1]))
    return HelpAnswer(
        summary=f"{topic.title}:",
        steps=list(topic.steps),
        note=topic.note,
        context=f"dashboard_help:{topic.key}",
        citation=(f"{topic.page} page", "frontend/src/pages"),
        followups=["What can you do?"],
    )


# -------------------------------------------------------------------- rules

RULE_QUESTION = re.compile(r"\brules?\b|\bhow (?:do|does) (?:you|atdr|the system|it) detect\b|\bhow is .{2,40} detected\b")
RULE_LIST = re.compile(r"\bhow many rules\b|\b(?:list|show|what are) (?:all |the |your )?(?:detection )?rules\b|\bwhich rules\b|\bwhat rules\b")
STOPWORDS = {"rule", "rules", "the", "what", "does", "do", "how", "check", "checks", "work", "works", "is", "a", "an", "of", "for", "about", "tell", "me", "explain", "detect", "detection", "you", "your", "atdr"}


def _spec_words(spec: DetectionRuleSpec) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", f"{spec.title} {spec.code.replace('_', ' ')}".lower())) - STOPWORDS


def _rule_lines(spec: DetectionRuleSpec) -> list[str]:
    lines = [
        f"Checks: {spec.condition}.",
        f"Maps to: {ATTACK_LABELS.get(spec.attack_type, spec.attack_type)}"
        + (f" (MITRE ATT&CK {', '.join(spec.mitre_technique_ids)})" if spec.mitre_technique_ids else "")
        + f"; alert level {spec.level}, confidence {spec.confidence}.",
    ]
    if spec.false_positives:
        lines.append("Common harmless causes: " + ", ".join(spec.false_positives[:3]) + ".")
    checks = RULE_ANALYST_CHECKS.get(spec.code)
    if checks:
        lines.append(f"What an analyst checks: {checks[0]}")
    return lines


def answer_rule_question(question: str) -> RuleAnswer | None:
    text = _normalize(question)
    if not text or not RULE_QUESTION.search(text):
        return None
    specs = list(RULE_CATALOG.values())
    network = [spec for spec in specs if spec.code != "ml_anomaly_detected"]

    if RULE_LIST.search(text):
        by_type = Counter(ATTACK_LABELS.get(spec.attack_type, spec.attack_type) for spec in network)
        return RuleAnswer(
            summary=f"ATDR has {len(network)} fixed detection rules that decide alerts (plus 1 legacy machine-learning rule that no longer creates alerts).",
            lines=[f"{label}: {count} rule{'s' if count != 1 else ''}" for label, count in by_type.most_common()],
            basis="From the detection rule catalog. Ask \"What does the <name> rule check?\" for any one of them.",
            codes=[spec.code for spec in network],
        )

    exact = [spec for spec in specs if spec.code in text.replace(" ", "_") or spec.rule_id.lower() in text]
    attack_type = next((value for pattern, value in ATTACK_PHRASES if re.search(pattern, text)), None)
    words = set(re.findall(r"[a-z0-9]+", text)) - STOPWORDS
    if exact:
        matched = exact[:1]
    elif attack_type:
        matched = [spec for spec in network if spec.attack_type == attack_type]
        # Prefer rules whose own name matches the question ("brute force" -> the brute force rule).
        named = [spec for spec in matched if words & _spec_words(spec)]
        matched = named or matched
    else:
        scored = sorted(((len(words & _spec_words(spec)), spec) for spec in network), key=lambda item: -item[0])
        best = scored[0][0] if scored else 0
        matched = [spec for score, spec in scored if score == best and score >= 2][:1]
    if not matched:
        return None

    if len(matched) == 1:
        spec = matched[0]
        return RuleAnswer(
            summary=f"The \"{spec.title}\" rule ({spec.rule_id}):",
            lines=_rule_lines(spec),
            basis="From the detection rule catalog and the checks shown in the alert details.",
            codes=[spec.code],
        )
    label = ATTACK_LABELS.get(attack_type or "", attack_type or "this")
    return RuleAnswer(
        summary=f"{len(matched)} rules detect {label} activity:",
        lines=[f"{spec.title} ({spec.rule_id}): {spec.condition}." for spec in matched[:6]],
        basis="From the detection rule catalog. Ask about one rule by name for its details.",
        codes=[spec.code for spec in matched],
    )
