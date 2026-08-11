from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal


AssistantResponseMode = Literal[
    "direct_fact",
    "alert_explanation",
    "safe_next_step",
    "related_logs",
    "source_health",
    "list_summary",
    "case_handoff",
    "investigation_brief",
    "how_to",
    "governance",
]


@dataclass(frozen=True, slots=True)
class ResponseContract:
    mode: AssistantResponseMode
    word_limit: int
    max_followups: int = 3


@dataclass(frozen=True, slots=True)
class ResponsePresentation:
    answer: str
    sections: dict[str, list[str]]
    evidence_detail: dict[str, list[str]]
    word_limit: int
    word_count: int


RESPONSE_CONTRACTS: dict[AssistantResponseMode, ResponseContract] = {
    "direct_fact": ResponseContract("direct_fact", 80),
    "alert_explanation": ResponseContract("alert_explanation", 110),
    "safe_next_step": ResponseContract("safe_next_step", 100),
    "related_logs": ResponseContract("related_logs", 120),
    "source_health": ResponseContract("source_health", 100),
    "list_summary": ResponseContract("list_summary", 100),
    "case_handoff": ResponseContract("case_handoff", 120),
    "investigation_brief": ResponseContract("investigation_brief", 160),
    "how_to": ResponseContract("how_to", 180),
    "governance": ResponseContract("governance", 100),
}


_HEADING_ONLY = re.compile(
    r"^(?:summary|evidence|why flagged|related logs|risk interpretation|"
    r"what to check next|analyst next steps|safe next steps|safety(?: note)?|"
    r"references|missing information|limitations|requested action|safety boundary|"
    r"safe alternative|operational boundary|controlled validation command)$",
    re.IGNORECASE,
)


def response_contract(mode: AssistantResponseMode) -> ResponseContract:
    return RESPONSE_CONTRACTS[mode]


def infer_response_mode(question: str, context_used: list[str]) -> AssistantResponseMode:
    lowered = question.lower()
    contexts = set(context_used)
    if "investigation_brief" in contexts or any(
        term in lowered
        for term in [
            "investigation brief",
            "create brief",
            "leadership brief",
            "executive evidence summary",
            "tell my supervisor",
            "advisor summary",
        ]
    ):
        return "investigation_brief"
    if any(
        term in lowered
        for term in [
            "what should",
            "next step",
            "next steps",
            "check next",
            "check first",
            "verify before",
            "safe to approve",
            "safe to respond",
            "do next",
        ]
    ):
        return "safe_next_step"
    if any(term in lowered for term in ["related log", "what logs", "show logs", "linked logs", "evidence logs"]):
        return "related_logs"
    if any(term in lowered for term in ["how do i", "how to", "what command", "instructions", "run scenario", "import labels"]):
        return "how_to"
    if any(
        term in lowered
        for term in [
            "latest critical",
            "open alerts",
            "show alerts",
            "summarize failed jobs",
            "recent detection runs",
            "what changed recently",
            "which sources",
        ]
    ):
        return "list_summary"
    if "source_health" in contexts or any(term in lowered for term in ["source health", "source warning", "source risk", "parser health"]):
        return "source_health"
    if any(
        term in lowered
        for term in [
            "governance",
            "production promoted",
            "promotion",
            "model status",
            "ml status",
            "response safety",
            "safety rules",
        ]
    ) or contexts.intersection({"ml_governance", "promotion_gate", "supervised_model_report", "assistant_safety_guardrail"}):
        return "governance"
    if "alert_cases" in contexts or "case_grouping" in contexts:
        return "case_handoff"
    if contexts.intersection({"alert_detail", "why_flagged", "why_not_flagged", "alert_evidence", "log_detail"}):
        return "alert_explanation"
    return "direct_fact"


def _strings(value: Any, *, limit: int = 12) -> list[str]:
    if not isinstance(value, list):
        return []
    rows: list[str] = []
    for item in value[:limit]:
        clean = " ".join(str(item).strip().split())
        if clean:
            rows.append(clean[:1000])
    return rows


def _semantic_tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.lower())
        if len(token) > 2
        and token
        not in {
            "and",
            "are",
            "for",
            "from",
            "the",
            "this",
            "that",
            "with",
        }
    }


def _near_duplicate(left: str, right: str) -> bool:
    left_key = re.sub(r"\W+", " ", left.lower()).strip()
    right_key = re.sub(r"\W+", " ", right.lower()).strip()
    if left_key == right_key:
        return True
    left_tokens = _semantic_tokens(left)
    right_tokens = _semantic_tokens(right)
    if min(len(left_tokens), len(right_tokens)) < 4:
        return False
    overlap = len(left_tokens & right_tokens)
    containment = overlap / min(len(left_tokens), len(right_tokens))
    union = len(left_tokens | right_tokens)
    return containment >= 0.85 and bool(union) and overlap / union >= 0.65


def _dedupe(values: list[str]) -> list[str]:
    rows: list[str] = []
    for value in values:
        if not re.sub(r"\W+", " ", value.lower()).strip():
            continue
        if any(_near_duplicate(value, existing) for existing in rows):
            continue
        rows.append(value)
    return rows


def _fallback_lines(answer: str) -> list[str]:
    rows: list[str] = []
    for raw_line in answer.splitlines():
        clean = re.sub(r"^(?:[-*]|\d+[.)])\s*", "", raw_line.strip())
        if not clean or _HEADING_ONLY.fullmatch(clean):
            continue
        rows.extend(re.split(r"(?<=[.!?])\s+(?=[A-Z`])", clean))
    return _dedupe([" ".join(item.split()) for item in rows if item.strip()])


def _bounded_words(value: str, limit: int) -> str:
    words = value.split()
    if len(words) <= limit:
        return value.strip()
    return " ".join(words[:limit]).rstrip(" ,;:-") + "..."


def _shorten(value: str, limit: int) -> str:
    words = value.split()
    if len(words) <= limit:
        return value
    return " ".join(words[:limit]).rstrip(" ,;:-") + "..."


def _subject(active_context: dict[str, Any]) -> str:
    primary = active_context.get("primary")
    if primary == "alert" and active_context.get("alert_id"):
        return f"alert #{active_context['alert_id']}"
    if primary == "log" and active_context.get("log_id"):
        return f"log #{active_context['log_id']}"
    if primary == "source" and active_context.get("source_id"):
        return f"source #{active_context['source_id']}"
    if primary == "case" and active_context.get("case_id"):
        return f"case {active_context['case_id']}"
    return "this record"


def _section_sources(raw_sections: dict[str, Any], original_answer: str) -> dict[str, list[str]]:
    fallback = _fallback_lines(original_answer)
    summary = _strings(raw_sections.get("summary")) or fallback[:2]
    evidence = _dedupe(
        _strings(raw_sections.get("evidence"))
        + _strings(raw_sections.get("why_flagged_or_not"))
    )
    next_steps = _dedupe(
        _strings(raw_sections.get("what_to_check_next"))
        + _strings(raw_sections.get("safe_next_steps"))
    )
    return {
        "summary": summary,
        "evidence": evidence,
        "risk_interpretation": _strings(raw_sections.get("risk_interpretation")),
        "related_context": _strings(raw_sections.get("related_context")),
        "next_steps": next_steps,
        "limitations": _strings(raw_sections.get("limitations")),
        "safety": _dedupe(
            _strings(raw_sections.get("safety_note"))
            + _strings(raw_sections.get("safety_limitation"))
        ),
        "citations": _strings(raw_sections.get("citations"), limit=20),
        "fallback": fallback,
    }


def build_response_presentation(
    *,
    mode: AssistantResponseMode,
    question: str,
    original_answer: str,
    raw_sections: dict[str, Any],
    active_context: dict[str, Any],
    citation_references: list[str],
) -> ResponsePresentation:
    contract = response_contract(mode)
    source = _section_sources(raw_sections, original_answer)
    summary = [_shorten(item, 32) for item in source["summary"]] or ["No grounded ATDR result was available for this question."]
    evidence = [_shorten(item, 32) for item in source["evidence"]]
    risk = [_shorten(item, 28) for item in source["risk_interpretation"]]
    next_steps = [_shorten(item, 24) for item in source["next_steps"]]
    limitations = [_shorten(item, 24) for item in source["limitations"]]
    related = [_shorten(item, 28) for item in source["related_context"]]
    fallback = [_shorten(item, 35) for item in source["fallback"]]
    subject = _subject(active_context)
    sections: dict[str, list[str]] = {
        "response_mode": [mode],
        "citations": _dedupe(citation_references or source["citations"])[:8],
    }

    if mode == "alert_explanation":
        lowered = question.lower()
        if "false positive" in lowered or "noise" in lowered:
            key_evidence = _dedupe(risk + evidence)[:2]
        elif "missing" in lowered:
            key_evidence = _dedupe(limitations + evidence)[:2]
        else:
            key_evidence = evidence[:2]
        direct = summary[:1]
        if key_evidence:
            direct.append(key_evidence[0])
        answer = "Verdict: " + " ".join(direct)
        if len(key_evidence) > 1:
            answer += "\nKey evidence:\n" + "\n".join(f"- {item}" for item in key_evidence[1:2])
        if next_steps:
            answer += f"\nNext check: {next_steps[0]}"
        sections.update(
            {
                "direct_answer": direct,
                "summary": summary[:1],
                "key_evidence": key_evidence,
                "evidence": key_evidence,
                "next_steps": next_steps[:1],
                "what_to_check_next": next_steps[:1],
            }
        )
    elif mode == "safe_next_step":
        priorities = next_steps[:4] or fallback[:4]
        intro = f"Prioritized checks for {subject}:"
        answer = intro + ("\n" + "\n".join(f"{index}. {item}" for index, item in enumerate(priorities, 1)) if priorities else " No grounded next step is available.")
        sections.update(
            {
                "direct_answer": [intro],
                "next_steps": priorities,
                "what_to_check_next": priorities,
                "safe_next_steps": priorities,
            }
        )
    elif mode == "related_logs":
        log_rows = [
            item
            for item in _dedupe(evidence + related)
            if re.search(r"\blog\s*#?\d+", item, re.IGNORECASE)
        ][:5]
        count_summary = next((item for item in summary if "related log" in item.lower()), summary[0])
        answer = f"Related logs for {subject}: {count_summary}"
        if log_rows:
            answer += "\n" + "\n".join(f"- {item}" for item in log_rows)
        else:
            answer += f" No compact related-log rows are available for {subject}."
        sections.update(
            {
                "direct_answer": [count_summary],
                "related_logs": log_rows,
                "key_evidence": log_rows,
                "evidence": log_rows,
            }
        )
    elif mode == "source_health":
        issue = _dedupe(risk + limitations + evidence)[:1]
        direct = summary[:2]
        answer = " ".join(direct)
        if issue:
            answer += f"\nMain issue: {issue[0]}"
        if next_steps:
            answer += f"\nNext check: {next_steps[0]}"
        sections.update(
            {
                "direct_answer": direct,
                "summary": direct,
                "key_evidence": issue,
                "evidence": issue,
                "next_steps": next_steps[:1],
                "what_to_check_next": next_steps[:1],
            }
        )
    elif mode == "list_summary":
        items = _dedupe(evidence + related + summary[1:] + fallback)[:3]
        if not items:
            items = summary[:1]
        answer = summary[0]
        additional_items = [item for item in items if item != summary[0]]
        if additional_items:
            answer += "\n" + "\n".join(f"- {item}" for item in additional_items)
        sections.update(
            {
                "direct_answer": summary[:1],
                "summary": summary[:1],
                "list_items": items,
                "key_evidence": items,
                "evidence": items,
            }
        )
    elif mode == "case_handoff":
        key_evidence = _dedupe(evidence + related)[:3]
        handoff_steps = next_steps[:2]
        answer_parts = [summary[0]]
        if key_evidence:
            answer_parts.extend(f"- {item}" for item in key_evidence)
        if handoff_steps:
            answer_parts.append(f"Next check: {handoff_steps[0]}")
        if limitations:
            answer_parts.append(f"Limitation: {limitations[0]}")
        answer = "\n".join(answer_parts)
        sections.update(
            {
                "direct_answer": summary[:1],
                "summary": summary[:1],
                "key_evidence": key_evidence,
                "evidence": key_evidence,
                "next_steps": handoff_steps,
                "what_to_check_next": handoff_steps,
                "limitations": limitations[:1],
            }
        )
    elif mode == "investigation_brief":
        brief_summary = [_shorten(item, 24) for item in summary[:1]]
        key_evidence = [_shorten(item, 20) for item in evidence[:3]]
        brief_risk = [_shorten(item, 18) for item in risk[:1]]
        brief_steps = [_shorten(item, 16) for item in next_steps[:2]]
        brief_limitations = [_shorten(item, 16) for item in limitations[:1]]
        answer_parts = ["Investigation Brief", *[f"- {item}" for item in brief_summary]]
        if key_evidence:
            answer_parts.extend(["Key evidence", *[f"- {item}" for item in key_evidence]])
        if brief_risk:
            answer_parts.extend(["Assessment", *[f"- {item}" for item in brief_risk]])
        if brief_steps:
            answer_parts.extend(["Next checks", *[f"- {item}" for item in brief_steps]])
        if brief_limitations:
            answer_parts.extend(["Limitations", *[f"- {item}" for item in brief_limitations]])
        answer = "\n".join(answer_parts)
        sections.update(
            {
                "direct_answer": brief_summary,
                "summary": brief_summary,
                "key_evidence": key_evidence,
                "evidence": key_evidence,
                "assessment": brief_risk,
                "risk_interpretation": brief_risk,
                "next_steps": brief_steps,
                "what_to_check_next": brief_steps,
                "limitations": brief_limitations,
            }
        )
    elif mode == "how_to":
        steps = _dedupe(next_steps + fallback)[:5]
        answer = "\n".join(f"{index}. {item}" for index, item in enumerate(steps, 1))
        sections.update(
            {
                "direct_answer": steps[:1],
                "steps": steps,
                "next_steps": steps,
                "what_to_check_next": steps,
            }
        )
    elif mode == "governance":
        blocker = _dedupe(risk + limitations + evidence + fallback[1:])[:2]
        if not blocker:
            blocker = fallback[:1] or summary[:1]
        consequence = next_steps[:1]
        answer = " ".join(summary[:2])
        if blocker:
            answer += f"\nBlocker: {blocker[0]}"
        if consequence:
            answer += f"\nConsequence: {consequence[0]}"
        sections.update(
            {
                "direct_answer": summary[:2],
                "summary": summary[:2],
                "blockers": blocker,
                "key_evidence": blocker,
                "consequence": consequence,
            }
        )
    else:
        direct = summary[:2] or fallback[:2]
        answer = " ".join(direct)
        sections.update({"direct_answer": direct, "summary": direct})

    bounded_answer = _bounded_words(answer, contract.word_limit)
    evidence_detail = {
        key: values[:8]
        for key, values in source.items()
        if key not in {"fallback", "citations"} and values
    }
    return ResponsePresentation(
        answer=bounded_answer,
        sections=sections,
        evidence_detail=evidence_detail,
        word_limit=contract.word_limit,
        word_count=len(bounded_answer.split()),
    )


def contextual_followups(
    *,
    mode: AssistantResponseMode,
    active_context: dict[str, Any],
    existing: list[str],
) -> list[str]:
    primary = active_context.get("primary")
    generated: list[str] = []
    if primary == "alert" and active_context.get("alert_id"):
        alert_id = active_context["alert_id"]
        by_mode = {
            "alert_explanation": [
                f"What logs are related to alert {alert_id}?",
                f"What should an analyst check next for alert {alert_id}?",
                f"Is alert {alert_id} likely a false positive?",
            ],
            "related_logs": [
                f"Why was alert {alert_id} flagged?",
                f"What should an analyst check next for alert {alert_id}?",
            ],
            "safe_next_step": [
                f"Why was alert {alert_id} flagged?",
                f"What logs are related to alert {alert_id}?",
            ],
        }
        generated.extend(by_mode.get(mode, []))
    elif primary == "log" and active_context.get("log_id"):
        log_id = active_context["log_id"]
        generated.extend([f"Why was log {log_id} flagged or not flagged?", "Open linked alerts for this log."])
    elif primary == "source" and active_context.get("source_id"):
        source_id = active_context["source_id"]
        generated.extend([f"Which warnings affect source {source_id}?", f"What should an analyst check next for source {source_id}?"])
    elif primary == "case" and active_context.get("case_id"):
        case_id = active_context["case_id"]
        generated.extend(
            [
                f"What evidence is strongest in case {case_id}?",
                f"What should an analyst check next for case {case_id}?",
            ]
        )

    contract = response_contract(mode)
    return _dedupe(generated + existing)[: contract.max_followups]
