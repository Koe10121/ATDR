"""Conversational SOC assistant: a language model that answers only through tools.

The model never reads the database itself. It picks from a fixed set of
read-only ATDR tools (counts, one alert, a playbook, the rule catalog, how-to
guides), reads their text output, and writes the reply. Before a reply is
shown, ``verify_answer`` checks that every number in it appears in a tool
output, the question, or the conversation so far; that it names no IP address
the analyst did not type while redaction is on; that it leaks no configured
secret; and that it never claims to have taken an action. A reply that fails
gets one correction round. If it still fails, or the engine is unavailable,
the caller answers with the deterministic keyword router instead.

This module holds no database code: tools arrive as plain callables, so the
loop and the verifier are tested with a scripted engine.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol
from urllib.parse import urlparse

import requests

from atdr.app.core.config import Settings

OLLAMA_DEFAULT_URL = "http://127.0.0.1:11434"
OLLAMA_DEFAULT_MODEL = "qwen3:8b"
GEMINI_OPENAI_URL = "https://generativelanguage.googleapis.com/v1beta/openai"
GEMINI_DEFAULT_MODEL = "gemini-2.5-flash"
MAX_TOOL_CALLS_PER_ROUND = 4
MAX_TOOL_OUTPUT_CHARS = 3500
MAX_ANSWER_CHARS = 6000
# Numbers this small are ordinary words ("one or two checks", "3 steps").
FREE_NUMBERS = frozenset({"1", "2", "3"})

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
NUMBER = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?")
LIST_MARKER = re.compile(r"^\s*\d{1,2}[.)]\s+", re.MULTILINE)
# Dashboard directions ("click Resolve", "open the Alerts page") must come from a guide, not the model's memory.
DASHBOARD_STEP = re.compile(
    r"\b(?:click|tap|navigate to|go to the|open the|select the|tick|press)\b|\b(?:tab|button|menu)\b",
    re.IGNORECASE,
)
# "block 10.1.1.1", "please close these alerts": the analyst wants something done that only they can do.
ACTION_REQUEST = re.compile(
    r"^\s*(?:please\s+|pls\s+|can you\s+|could you\s+|would you\s+)?"
    r"(?:block|unblock|delete|remove|close|resolve|assign|suppress|mark|run|import|disable|enable|isolate|quarantine)\b",
    re.IGNORECASE,
)
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
# In a general-knowledge answer, a figure about ATDR's own data ("41 alerts", "alert #3676") must still be looked up.
ATDR_FIGURE = re.compile(
    r"#\d+|\balert\s+\d+|\b\d[\d,]*(?:\.\d+)?%?\s+(?:(?:open|new|critical|high|medium|low|unique|denied|allowed|"
    r"firewall|security|port[- ]scan|brute[- ]force)\s+){0,2}"
    r"(?:alerts?|logs?|incidents?|detections?|events?|connections?|sessions?|sources?|attacks?|attackers?)\b",
    re.IGNORECASE,
)
# Questions about ATDR's own data, pages or settings must be answered from the tools, never from memory.
ATDR_QUESTION = re.compile(
    r"\b(?:atdr|alerts?|logs?|detect\w*|(?:detection|atdr|the|which|this|that) rules?|rules? (?:fire|fires|fired|check|checks)|"
    r"rule catalog|dashboard|mfu|our network|the network|sla|severity|supervised|ml model|the model|ai model|anomal\w*|"
    r"healthy|system health|system status|block|unblock|suppress\w*|watch ?lists?|audit|assign\w*|playbooks?|sources?|"
    r"ips|(?:which|this|that|the) ip|traffic|ports?|false positives?|port[- ]?scans?|horizontal scans?|scann\w+|"
    r"brute[- ]?force|beacon\w*|mitre|att&ck|attacking us|under attack|attack types?|attackers?|exfiltration|malware|"
    r"c2|policy violations?|security situation|data come from|how many attacks?|right now|worry about|overview)\b"
    # Thai has no spaces between words, so these match anywhere: alert, (security) situation, log, attack.
    r"|แจ้งเตือน|สถานการณ์|ล็อก|โจมตี",
    re.IGNORECASE,
)
# "show me the raw logs / passwords / the API key": always refused, never looked up.
PRIVATE_REQUEST = re.compile(
    r"\braw log|\b(?:show|give|reveal|print|list|send|tell)\b.{0,40}\b(?:passwords?|api ?keys?|secrets?|credentials|tokens?)\b",
    re.IGNORECASE,
)
# Named screen elements: "the Add Note button", "the Settings menu", or anything in double quotes.
UI_TERM = re.compile(
    r"[\"\u201c]([^\"\u201d\n]{2,40})[\"\u201d]"
    r"|\b((?:[A-Z][\w&/-]*\s){0,3}[A-Z][\w&/-]*)\s+(?:section|button|menu|tab|page|box|panel|link)\b"
)
# Chat-template markup a local model sometimes leaks into its text.
MODEL_MARKUP = re.compile(r"<think>.*?</think>|<tool_call>.*?</tool_call>|</?(?:think|tool_call)>", re.IGNORECASE | re.DOTALL)
# Pages and controls of ATDR's own dashboard; general computer steps ("press Ctrl+Alt+Del") do not name these.
ATDR_UI = re.compile(
    r"\b(?:dashboard|atdr|alerts page|threat controls|validation controls|response & audit|audit trail|"
    r"analyst actions|investigation page|soc assistant)\b",
    re.IGNORECASE,
)
SAYS_CANNOT = re.compile(r"\b(?:cannot|can't|can not|unable to|not able to|only read)\b", re.IGNORECASE)
CANNOT_ACT = "I can't do that myself; I only read ATDR's data. Here is how you can do it:"
ACTION_CLAIM = re.compile(
    r"\b(?:i|i've|i have|we've|we have)\s+(?:now\s+|just\s+|already\s+|successfully\s+)?"
    r"(?:blocked|unblocked|deleted|closed|resolved|removed|disabled|isolated|quarantined|assigned|escalated|"
    r"marked|suppressed|changed|updated|executed)\b",
    re.IGNORECASE,
)


# ------------------------------------------------------------------ contracts


@dataclass(slots=True)
class ToolOutput:
    text: str
    citations: list[tuple[str, str, str | None]] = field(default_factory=list)
    followups: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AgentTool:
    name: str
    description: str
    parameters: dict[str, Any]
    run: Callable[[dict[str, Any]], ToolOutput]
    # True for tools whose output contains real dashboard steps an answer may repeat.
    provides_steps: bool = False

    def schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {"name": self.name, "description": self.description, "parameters": self.parameters},
        }


@dataclass(slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    malformed: bool = False


@dataclass(slots=True)
class EngineReply:
    content: str
    tool_calls: list[ToolCall]
    usage: dict[str, int] = field(default_factory=dict)


class AgentEngineError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AgentEngine(Protocol):
    name: str
    model: str

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> EngineReply: ...


@dataclass(slots=True)
class AgentOutcome:
    ok: bool
    answer: str | None
    fallback_reason: str | None
    engine: str
    model: str
    rounds: int = 0
    latency_ms: int = 0
    tool_trace: list[dict[str, Any]] = field(default_factory=list)
    citations: list[tuple[str, str, str | None]] = field(default_factory=list)
    followups: list[str] = field(default_factory=list)
    verifier_problems: list[str] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    # True when at least one tool returned ATDR data; False for a general-knowledge answer.
    grounded: bool = False

    def safe_details(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "model": self.model,
            "answered": self.ok,
            "grounded": self.grounded,
            "fallback_reason": self.fallback_reason,
            "rounds": self.rounds,
            "latency_ms": self.latency_ms,
            "tools_called": [{"name": item["name"], "arguments": item["arguments"]} for item in self.tool_trace],
            "verifier_problems": self.verifier_problems[:6],
            "usage": self.usage,
        }


# -------------------------------------------------------------------- engines


def _engine_failure(response: requests.Response) -> str:
    if response.status_code in {401, 403}:
        return "engine_authentication_failed"
    if response.status_code == 429:
        return "engine_rate_limited"
    if response.status_code >= 500:
        return "engine_unavailable"
    return "engine_request_rejected"


def _post(url: str, *, payload: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    try:
        response = requests.post(url, json=payload, headers={"Content-Type": "application/json", **headers}, timeout=timeout)
    except requests.Timeout as exc:
        raise AgentEngineError("engine_timeout") from exc
    except requests.RequestException as exc:
        raise AgentEngineError("engine_unreachable") from exc
    if response.status_code >= 400:
        raise AgentEngineError(_engine_failure(response))
    try:
        data = response.json()
    except ValueError as exc:
        raise AgentEngineError("engine_malformed_response") from exc
    if not isinstance(data, dict):
        raise AgentEngineError("engine_malformed_response")
    return data


def _parse_arguments(raw: Any) -> tuple[dict[str, Any], bool]:
    if isinstance(raw, dict):
        return raw, False
    if raw in (None, ""):
        return {}, False
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}, True
    return (value, False) if isinstance(value, dict) else ({}, True)


class OllamaEngine:
    """Ollama's native chat API: lets ATDR set the context size and turn thinking off."""

    name = "ollama"

    def __init__(self, *, base_url: str, model: str, timeout: float, context_tokens: int, keep_alive: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.context_tokens = context_tokens
        self.keep_alive = keep_alive

    def health(self, timeout: float = 1.5) -> tuple[str, str]:
        """Whether the model can answer now: "ready", "not_running" or "model_missing", with what to do about it.

        Configured is not the same as running: after a restart Ollama may not be up, and the assistant then
        answers from its built-in answers while claiming nothing is wrong.
        """
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=timeout)
            response.raise_for_status()
            models = response.json().get("models") or []
        except (requests.RequestException, ValueError, AttributeError):
            return "not_running", "Ollama is not running, so the assistant uses its built-in answers. Start the Ollama app."
        names = {str(item.get("name") or "") for item in models if isinstance(item, dict)}
        if self.model not in names and f"{self.model}:latest" not in names:
            return "model_missing", (
                f"Ollama is running but {self.model} is not downloaded, so the assistant uses its built-in answers. "
                f"Run: ollama pull {self.model}"
            )
        return "ready", ""

    @staticmethod
    def _messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        converted = []
        for message in messages:
            if message["role"] == "assistant" and message.get("tool_calls"):
                converted.append({
                    "role": "assistant",
                    "content": message.get("content") or "",
                    "tool_calls": [
                        {"function": {"name": call["function"]["name"], "arguments": json.loads(call["function"]["arguments"])}}
                        for call in message["tool_calls"]
                    ],
                })
            elif message["role"] == "tool":
                converted.append({"role": "tool", "content": message["content"], "tool_name": message.get("name", "")})
            else:
                converted.append({"role": message["role"], "content": message.get("content") or ""})
        return converted

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> EngineReply:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": self._messages(messages),
            "stream": False,
            "think": False,
            "keep_alive": self.keep_alive,
            "options": {"temperature": 0, "num_ctx": self.context_tokens},
        }
        if tools:
            payload["tools"] = tools
        data = _post(f"{self.base_url}/api/chat", payload=payload, headers={}, timeout=self.timeout)
        message = data.get("message")
        if not isinstance(message, dict):
            raise AgentEngineError("engine_malformed_response")
        calls = []
        for index, call in enumerate(message.get("tool_calls") or []):
            function = call.get("function") or {}
            arguments, malformed = _parse_arguments(function.get("arguments"))
            calls.append(ToolCall(str(call.get("id") or f"call_{index}"), str(function.get("name") or ""), arguments, malformed))
        usage = {"input_tokens": int(data.get("prompt_eval_count") or 0), "output_tokens": int(data.get("eval_count") or 0)}
        return EngineReply(str(message.get("content") or ""), calls, usage)


class OpenAICompatibleEngine:
    """Any OpenAI-style chat-completions endpoint with tool calling (Gemini's included)."""

    def __init__(self, *, name: str, base_url: str, model: str, api_key: str, timeout: float, extra: dict[str, Any] | None = None) -> None:
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.extra = extra or {}

    @staticmethod
    def _messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # The tool's name is kept internally for Ollama; this API identifies results by call ID only.
        return [
            {key: value for key, value in message.items() if not (message["role"] == "tool" and key == "name")}
            for message in messages
        ]

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> EngineReply:
        payload: dict[str, Any] = {"model": self.model, "messages": self._messages(messages), "temperature": 0, **self.extra}
        if tools:
            payload["tools"] = tools
        data = _post(
            f"{self.base_url}/chat/completions",
            payload=payload,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout,
        )
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AgentEngineError("engine_malformed_response") from exc
        calls = []
        for index, call in enumerate(message.get("tool_calls") or []):
            function = call.get("function") or {}
            arguments, malformed = _parse_arguments(function.get("arguments"))
            calls.append(ToolCall(str(call.get("id") or f"call_{index}"), str(function.get("name") or ""), arguments, malformed))
        usage_raw = data.get("usage") or {}
        usage = {
            "input_tokens": int(usage_raw.get("prompt_tokens") or 0),
            "output_tokens": int(usage_raw.get("completion_tokens") or 0),
        }
        return EngineReply(str(message.get("content") or ""), calls, usage)


def is_loopback_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def engine_from_settings(settings: Settings) -> AgentEngine | None:
    engine = settings.assistant_agent_engine.strip().lower()
    timeout = float(settings.assistant_agent_timeout_seconds)
    if engine == "ollama":
        return OllamaEngine(
            base_url=settings.assistant_agent_base_url.strip() or OLLAMA_DEFAULT_URL,
            model=settings.assistant_agent_model.strip() or OLLAMA_DEFAULT_MODEL,
            timeout=timeout,
            context_tokens=int(settings.assistant_agent_context_tokens),
            keep_alive=settings.assistant_agent_keep_alive.strip() or "30m",
        )
    api_key = settings.assistant_agent_api_key.strip() or settings.assistant_llm_api_key.strip()
    if engine == "gemini":
        return OpenAICompatibleEngine(
            name="gemini",
            base_url=settings.assistant_agent_base_url.strip() or GEMINI_OPENAI_URL,
            model=settings.assistant_agent_model.strip() or GEMINI_DEFAULT_MODEL,
            api_key=api_key,
            timeout=timeout,
            extra={"reasoning_effort": "none"},
        )
    if engine == "openai_compatible" and settings.assistant_agent_base_url.strip():
        return OpenAICompatibleEngine(
            name="openai_compatible",
            base_url=settings.assistant_agent_base_url.strip(),
            model=settings.assistant_agent_model.strip(),
            api_key=api_key,
            timeout=timeout,
        )
    return None


# ------------------------------------------------------------------- verifier


def _numbers(text: str) -> set[str]:
    """Numbers as normalised strings; a percentage keeps its "%" so "1%" is never a free small number."""

    values = set()
    stripped = IPV4.sub(" ", text)
    for match in NUMBER.finditer(stripped):
        raw = match.group(0).replace(",", "")
        value = str(float(raw)) if "." in raw else str(int(raw))
        percent = stripped[match.end():match.end() + 2].lstrip().startswith("%")
        values.add(value + "%" if percent else value)
        if percent:
            values.add(value)
    return values


def clean_answer(text: str) -> str:
    """Plain text for the dashboard, which shows the answer without a markdown renderer."""

    lines = []
    for line in MODEL_MARKUP.sub("", text or "").replace("\r\n", "\n").split("\n"):
        line = re.sub(r"^\s{0,3}#{1,6}\s*", "", line)
        line = re.sub(r"^(\s*)[*•]\s+", r"\1- ", line)
        lines.append(line.replace("**", "").replace("__", "").replace("`", ""))
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def verify_answer(
    answer: str,
    *,
    evidence: list[str],
    asked: list[str],
    redacted: bool,
    forbidden_values: list[str],
    tool_names: list[str] | None = None,
    steps_checked: bool = True,
    action_requested: bool = False,
    grounded: bool = True,
    about_atdr: bool = False,
    private_request: bool = False,
) -> list[str]:
    """Reasons an answer may not be shown; empty when it passes.

    A grounded answer (built from tool results) may only use numbers and IPs the tools returned. A
    general-knowledge answer may use ordinary facts ("TLS 1.3", "at least 12 characters"), but any
    figure about ATDR's own alerts or logs, and any ATDR dashboard direction, still needs a tool.
    """

    if not answer.strip():
        return ["empty answer"]
    problems = []
    if len(answer) > MAX_ANSWER_CHARS:
        problems.append("answer is too long")
    for secret in forbidden_values:
        if secret and len(secret) >= 8 and secret in answer:
            problems.append("answer contains a configured secret")
    known_text = "\n".join([*evidence, *asked])
    known_numbers = _numbers(known_text) | FREE_NUMBERS
    if grounded:
        typed_ips = {ip for text in asked for ip in IPV4.findall(text)}
        for ip in dict.fromkeys(IPV4.findall(answer)):
            if redacted and ip not in typed_ips:
                problems.append(f"names IP address {ip}, which is redacted in ATDR's records")
            elif not redacted and ip not in known_text:
                problems.append(f"names IP address {ip}, which no tool returned")
        unknown = sorted(
            _numbers(LIST_MARKER.sub("", answer)) - known_numbers,
            key=lambda value: float(value.rstrip("%")),
        )
        if unknown:
            problems.append("numbers not found in any tool result: " + ", ".join(unknown[:8]))
    elif about_atdr:
        problems.append("this question is about ATDR's own data, pages or settings, so answer it from ATDR's tools")
    else:
        figures = [match.group(0) for match in ATDR_FIGURE.finditer(answer) if not _numbers(match.group(0)) <= known_numbers]
        if figures:
            problems.append("states figures about ATDR's data without looking them up: " + ", ".join(figures[:5]))
    if grounded:
        known_lower = known_text.lower()
        invented = [
            term for match in UI_TERM.finditer(answer)
            if (term := (match.group(1) or match.group(2) or "").strip(" .,:;")) and term.lower() not in known_lower
        ]
        if invented:
            problems.append(
                "names screen elements the tool results did not mention: " + ", ".join(dict.fromkeys(invented[:5]))
                + " (use the guide's own page and button names)"
            )
    if private_request and not SAYS_CANNOT.search(answer):
        problems.append("the analyst asked for raw logs or secrets: say plainly that you cannot show them")
    claim = ACTION_CLAIM.search(answer)
    if claim:
        problems.append(f"claims an action was taken ({claim.group(0)!r}); the assistant can only read")
    named = [name for name in tool_names or [] if name in answer]
    if named:
        problems.append("mentions internal tool names: " + ", ".join(named))
    if not steps_checked and DASHBOARD_STEP.search(answer) and (grounded or ATDR_UI.search(answer)):
        problems.append("gives dashboard directions without checking the dashboard guide (dashboard_how_to)")
    elif not steps_checked and action_requested:
        problems.append(
            "the analyst asked for something to be done: say you cannot do it yourself, then give the real dashboard "
            "steps (call dashboard_how_to with the task)"
        )
    return problems


def drop_tool_mentions(answer: str, tool_names: list[str]) -> str:
    """Remove the sentences that talk about internal tools ("use get_alert to ...") and keep the rest."""

    if not any(name in answer for name in tool_names):
        return answer
    kept_lines = []
    for line in answer.split("\n"):
        if not any(name in line for name in tool_names):
            kept_lines.append(line)
            continue
        sentences = [part for part in SENTENCE_END.split(line) if not any(name in part for name in tool_names)]
        if sentences:
            kept_lines.append(" ".join(sentences))
    return re.sub(r"\n{3,}", "\n\n", "\n".join(kept_lines)).strip()


# ----------------------------------------------------------------------- loop

SYSTEM_PROMPT = """You are the ATDR security assistant for the Mae Fah Luang University (MFU) network security team. ATDR reads MFU's Palo Alto firewall logs, finds possible attacks with fixed detection rules, and helps analysts investigate and respond. Talk like a knowledgeable, friendly colleague.

For anything about ATDR or MFU's data (alerts, logs, counts, IPs, rules, ATDR's pages and settings, ATDR's own terms such as its severity, SLA or ML), always use the tools; never answer those from memory. Pick the tool by the question:
- How many / which / top / list for alerts: query_alerts. Which rule fires most: query_alerts with intent top and group_by rule. Per day, going up or down: query_alerts with intent trend. For logs, traffic, apps, ports or countries (including how many logs are stored): query_logs.
- What is going on, are we under attack, summaries, biggest risks, what to look at first: security_overview.
- One alert: get_alert. What to do about an alert, how to respond or fix it: get_alert_playbook.
- How to do something in ATDR's dashboard, including things you cannot do yourself (block an IP, close, delete or assign alerts, notes, suppression, audit trail, importing logs, running detection): dashboard_how_to, then give its steps. Never describe an ATDR page, button or step that the guide did not give; if there is no guide, say the dashboard has no such feature.
- Security terms ATDR uses (port scan, beaconing, MITRE ATT&CK), how ATDR's severity, SLA or ML work, where the data comes from: explain_concept. What a detection rule checks or how many rules exist: explain_detection_rules.
- ATDR's own health, jobs, sources, model status: system_status.

For general questions that are not about ATDR's data (security or networking concepts ATDR has no tool for, such as ransomware, phishing, VPNs, TCP vs UDP, good password rules; IT advice; writing help such as drafting an email or incident note; everyday conversation), answer from your own knowledge like a helpful colleague, and say briefly that it is general knowledge, not from ATDR's records. You have no internet access: for live facts such as weather, news or sports results, say you cannot look them up. Explain attacks only to help defend against them; do not help anyone attack, break into or bypass the security of any system.

Rules for the answer:
- When a tool gives you steps, page or button names, rule details or numbers, repeat them faithfully in your answer. Do not replace them with your own version or with what other software usually looks like.
- Never invent ATDR data: every number about alerts, logs or MFU's network must come from a tool result. If the tools do not have it, say so.
- Filter by time only when the analyst names a time ("today", "this week"). "Total", "in the system" or no time at all means all_time. "Right now", "currently" or "open" mean alerts that are open now (status open, all_time), not alerts created today.
- An alert is a possible attack found by ATDR's rules, not a confirmed attack. Do not say "we are under attack" as a fact. Do not say "we are not under attack" or that the network is safe either: ATDR only sees the firewall logs it has imported, so say what it found, what is still open, and how recent its newest log is.
- Put the direct answer first, then only the details that matter, usually under 150 words.
- Write plain text with "- " bullets. No markdown headings, bold or tables.
- Never mention tool names or tell the analyst to "use a tool". You call the tools yourself.
- You can only read. You cannot block IPs, change, assign or close alerts, delete anything or run detection. If asked, say you cannot do it yourself and give the dashboard steps from dashboard_how_to.
- IP addresses in ATDR's data appear as [redacted-ip]. Never guess them. If asked for raw log lines, passwords, keys or secrets, say you cannot show them for privacy and security reasons, and offer the alert and log summaries you can show.
- Never refer to steps or answers you did not give in this reply.
- Reply in the language the analyst writes in."""

CHECK_FIRST_ATDR = (
    "Before answering \"{question}\", look it up: it is about ATDR or MFU's data. Call the tool from your instructions "
    "that covers it (for a security term or ATDR concept, explain_concept), then answer from its result."
)

CORRECTION = (
    "Your answer was not shown to the analyst because: {problems}. "
    "Rewrite it so every fact about ATDR's data comes from a tool result (call a tool if you need one). "
    "Do not claim to have done anything, do not name tools, and do not include IP addresses from ATDR's data."
)


def _call_tool(tools: dict[str, AgentTool], call: ToolCall) -> tuple[str, ToolOutput | None]:
    tool = tools.get(call.name)
    if tool is None:
        return f"Error: there is no tool named {call.name!r}.", None
    if call.malformed:
        return "Error: the tool arguments were not valid JSON. Call the tool again with valid arguments.", None
    try:
        output = tool.run(call.arguments)
    except (TypeError, ValueError, KeyError) as error:
        return f"Error: {error}. Check the arguments and try again.", None
    text = output.text if len(output.text) <= MAX_TOOL_OUTPUT_CHARS else output.text[:MAX_TOOL_OUTPUT_CHARS] + "\n[output shortened]"
    return text, output


def run_agent(
    *,
    question: str,
    engine: AgentEngine,
    tools: list[AgentTool],
    history: list[dict[str, str]] | None = None,
    context_note: str | None = None,
    prefetch: list[tuple[str, dict[str, Any]]] | None = None,
    redacted: bool = True,
    forbidden_values: list[str] | None = None,
    max_rounds: int = 5,
) -> AgentOutcome:
    started = time.perf_counter()
    outcome = AgentOutcome(ok=False, answer=None, fallback_reason=None, engine=engine.name, model=engine.model)
    registry = {tool.name: tool for tool in tools}
    schemas = [tool.schema() for tool in tools]
    system = SYSTEM_PROMPT
    if context_note:
        system += f"\n{context_note}"
    messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
    asked = [question, *([context_note] if context_note else [])]
    for turn in history or []:
        messages.append({"role": "user", "content": turn.get("question", "")})
        messages.append({"role": "assistant", "content": turn.get("answer_summary", "")})
        asked.extend([turn.get("question", ""), turn.get("answer_summary", "")])
    messages.append({"role": "user", "content": question})
    evidence: list[str] = []
    corrected = False
    nudged = False
    private_request = bool(PRIVATE_REQUEST.search(question))
    about_atdr = not private_request and bool(ATDR_QUESTION.search(question) or IPV4.search(question))

    def run_calls(calls: list[ToolCall], content: str = "") -> None:
        messages.append({
            "role": "assistant",
            "content": content,
            "tool_calls": [
                {"id": call.id, "type": "function", "function": {"name": call.name, "arguments": json.dumps(call.arguments)}}
                for call in calls
            ],
        })
        for call in calls:
            text, output = _call_tool(registry, call)
            evidence.append(text)
            outcome.tool_trace.append({"name": call.name, "arguments": call.arguments, "output_chars": len(text)})
            if output is not None:
                outcome.grounded = True
                outcome.citations.extend(item for item in output.citations if item not in outcome.citations)
                outcome.followups.extend(item for item in output.followups if item not in outcome.followups)
            messages.append({"role": "tool", "tool_call_id": call.id, "name": call.name, "content": text})

    if prefetch:
        run_calls([ToolCall(f"prefetch_{index}", name, arguments) for index, (name, arguments) in enumerate(prefetch)])

    def finish(reason: str | None, answer: str | None = None) -> AgentOutcome:
        outcome.ok = reason is None
        outcome.answer = answer
        outcome.fallback_reason = reason
        outcome.latency_ms = int((time.perf_counter() - started) * 1000)
        return outcome

    for round_index in range(max_rounds):
        outcome.rounds = round_index + 1
        final_round = round_index == max_rounds - 1
        try:
            reply = engine.chat(messages, None if final_round else schemas)
        except AgentEngineError as error:
            return finish(error.reason)
        for key, value in reply.usage.items():
            outcome.usage[key] = outcome.usage.get(key, 0) + value

        if reply.tool_calls and not final_round:
            run_calls(reply.tool_calls[:MAX_TOOL_CALLS_PER_ROUND], reply.content or "")
            continue

        if about_atdr and not outcome.tool_trace and not nudged and not final_round:
            nudged = True
            messages.append({"role": "assistant", "content": reply.content or ""})
            messages.append({"role": "user", "content": CHECK_FIRST_ATDR.format(question=question)})
            continue

        answer = drop_tool_mentions(clean_answer(reply.content), list(registry))
        problems = verify_answer(
            answer,
            evidence=evidence,
            asked=asked,
            redacted=redacted,
            forbidden_values=forbidden_values or [],
            tool_names=list(registry),
            steps_checked=any(
                registry[item["name"]].provides_steps for item in outcome.tool_trace if item["name"] in registry
            ),
            action_requested=bool(ACTION_REQUEST.search(question)),
            grounded=outcome.grounded,
            about_atdr=about_atdr,
            private_request=private_request,
        )
        if not problems:
            if ACTION_REQUEST.search(question) and not SAYS_CANNOT.search(answer):
                # The analyst must never think the assistant carried out what they asked for.
                answer = f"{CANNOT_ACT}\n{answer}"
            return finish(None, answer)
        outcome.verifier_problems.extend(problems)
        if corrected or final_round:
            return finish("answer_failed_verification")
        corrected = True
        messages.append({"role": "assistant", "content": reply.content})
        messages.append({"role": "user", "content": CORRECTION.format(problems="; ".join(problems))})

    return finish("agent_round_limit")
