import type { AssistantActiveContext, AssistantChatResponse, AssistantCitation } from "../types/api";

const ASSISTANT_SESSION_KEY = "atdr.assistant.session.v1";
const DEFAULT_QUESTION = "What is the latest critical alert?";
const CONVERSATION_ID_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;

export interface AssistantSessionContext {
  alertId: number | null;
  logId: number | null;
  sourceId: number | null;
  caseId: string | null;
  primary: "alert" | "log" | "source" | "case" | null;
}

export interface AssistantSessionSnapshot {
  question: string;
  conversationId: string;
  context: AssistantSessionContext;
  response: AssistantChatResponse | null;
}

function boundedString(value: unknown, limit: number): string {
  return typeof value === "string" ? value.slice(0, limit) : "";
}

function boundedStrings(value: unknown, limit: number, itemLimit: number): string[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, limit).map((item) => boundedString(item, itemLimit)).filter(Boolean);
}

function positiveInteger(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : null;
}

function safePrimary(value: unknown): AssistantSessionContext["primary"] {
  return value === "alert" || value === "log" || value === "source" || value === "case" ? value : null;
}

function safeContext(value: unknown): AssistantSessionContext {
  const row = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  return {
    alertId: positiveInteger(row.alertId),
    logId: positiveInteger(row.logId),
    sourceId: positiveInteger(row.sourceId),
    caseId: boundedString(row.caseId, 120) || null,
    primary: safePrimary(row.primary)
  };
}

function safeCitation(value: unknown): AssistantCitation | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const label = boundedString(row.label, 120);
  const source = boundedString(row.source, 160);
  if (!label || !source) return null;
  return {
    label,
    source,
    reference_id: boundedString(row.reference_id, 120) || null
  };
}

function safeActiveContext(value: unknown): AssistantActiveContext {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const row = value as Record<string, unknown>;
  return {
    alert_id: positiveInteger(row.alert_id),
    log_id: positiveInteger(row.log_id),
    source_id: positiveInteger(row.source_id),
    case_id: boundedString(row.case_id, 120) || null,
    primary: safePrimary(row.primary)
  };
}

function safeAnswerSections(value: unknown): Record<string, string[]> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const rows = value as Record<string, unknown>;
  const sections: Record<string, string[]> = {};
  for (const key of [
    "summary",
    "what_happened",
    "why_flagged_or_not",
    "evidence",
    "risk_interpretation",
    "related_context",
    "what_to_check_next",
    "safe_next_steps",
    "limitations",
    "safety_note",
    "safety_limitation",
    "citations"
  ]) {
    sections[key] = boundedStrings(rows[key], 8, 700);
  }
  return sections;
}

function safeLlmDetails(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  return {
    used: row.used === true,
    provider: boundedString(row.provider, 40),
    model_configured: row.model_configured === true,
    fallback_reason: boundedString(row.fallback_reason, 120) || null,
    raw_log_context_included: false,
    secrets_exposed: false,
    context_characters: typeof row.context_characters === "number" ? row.context_characters : 0,
    prompt_contract: boundedString(row.prompt_contract, 120),
    provider_called: row.provider_called === true,
    answer_used: row.answer_used === true,
    answer_guard_reason: boundedString(row.answer_guard_reason, 120) || null,
    structured_output_valid: row.structured_output_valid === true,
    latency_ms: typeof row.latency_ms === "number" ? row.latency_ms : null,
    attempts: typeof row.attempts === "number" ? row.attempts : 0
  };
}

function safeGrounding(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  return {
    policy: boundedString(row.policy, 80),
    evidence_available: row.evidence_available === true,
    source_count: typeof row.source_count === "number" ? row.source_count : 0,
    source_types: boundedStrings(row.source_types, 8, 80),
    external_provider_role: boundedString(row.external_provider_role, 120),
    raw_logs_included: false
  };
}

function safeResponse(value: unknown): AssistantChatResponse | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (row.raw_log_context_included === true || row.redaction_applied !== true) return null;
  const answer = boundedString(row.answer, 16_000);
  const conversationId = boundedString(row.conversation_id, 64);
  if (!answer || !CONVERSATION_ID_PATTERN.test(conversationId)) return null;
  const citations = Array.isArray(row.citations)
    ? row.citations.slice(0, 20).map(safeCitation).filter((item): item is AssistantCitation => item !== null)
    : [];
  const rawDetails = row.details && typeof row.details === "object" && !Array.isArray(row.details)
    ? (row.details as Record<string, unknown>)
    : {};
  const details: Record<string, unknown> = {};
  const sections = safeAnswerSections(rawDetails.answer_sections);
  const llm = safeLlmDetails(rawDetails.llm);
  const grounding = safeGrounding(rawDetails.grounding);
  if (sections) details.answer_sections = sections;
  if (llm) details.llm = llm;
  if (grounding) details.grounding = grounding;
  if (typeof rawDetails.assistant_audit_id === "number" && rawDetails.assistant_audit_id > 0) {
    details.assistant_audit_id = rawDetails.assistant_audit_id;
  }
  return {
    answer,
    mode: boundedString(row.mode, 120) || "deterministic_local",
    external_provider_used: row.external_provider_used === true,
    safety: boundedStrings(row.safety, 12, 120),
    context_used: boundedStrings(row.context_used, 20, 120),
    citations,
    redaction_applied: row.redaction_applied === true,
    raw_log_context_included: false,
    suggested_followups: boundedStrings(row.suggested_followups, 8, 240),
    details,
    conversation_id: conversationId,
    active_context: safeActiveContext(row.active_context)
  };
}

export function loadAssistantSession(): AssistantSessionSnapshot | null {
  try {
    const raw = window.sessionStorage.getItem(ASSISTANT_SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const conversationId = boundedString(parsed.conversationId, 64);
    if (!CONVERSATION_ID_PATTERN.test(conversationId)) return null;
    return {
      question: boundedString(parsed.question, 2000) || DEFAULT_QUESTION,
      conversationId,
      context: safeContext(parsed.context),
      response: safeResponse(parsed.response)
    };
  } catch {
    window.sessionStorage.removeItem(ASSISTANT_SESSION_KEY);
    return null;
  }
}

export function saveAssistantSession(snapshot: AssistantSessionSnapshot): void {
  const response = safeResponse(snapshot.response);
  const context = safeContext(snapshot.context);
  const question = boundedString(snapshot.question, 2000) || DEFAULT_QUESTION;
  const conversationId = CONVERSATION_ID_PATTERN.test(snapshot.conversationId)
    ? snapshot.conversationId
    : "";
  if (!conversationId) return;
  const hasContext = Boolean(context.alertId || context.logId || context.sourceId || context.caseId);
  if (!response && !hasContext && question === DEFAULT_QUESTION) {
    clearAssistantSession();
    return;
  }
  window.sessionStorage.setItem(
    ASSISTANT_SESSION_KEY,
    JSON.stringify({ question, conversationId, context, response })
  );
}

export function clearAssistantSession(): void {
  window.sessionStorage.removeItem(ASSISTANT_SESSION_KEY);
}

export const assistantDefaultQuestion = DEFAULT_QUESTION;
export const assistantSessionStorageKey = ASSISTANT_SESSION_KEY;
