import type {
  AssistantActiveContext,
  AssistantAnswerProvenance,
  AssistantChatResponse,
  AssistantCitation,
  AssistantResponseMode
} from "../types/api";

const ASSISTANT_SESSION_KEY = "atdr.assistant.session.v1";
const DEFAULT_QUESTION = "What is the latest critical alert?";
const CONVERSATION_ID_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;
const MAX_SESSION_CHARACTERS = 180_000;

export const assistantConversationTurnLimit = 4;

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
  turns: AssistantConversationTurn[];
}

export interface AssistantConversationTurn {
  id: string;
  question: string;
  response: AssistantChatResponse;
  createdAt: number;
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

function safeResponseMode(value: unknown): AssistantResponseMode {
  const modes: AssistantResponseMode[] = [
    "direct_fact",
    "alert_explanation",
    "safe_next_step",
    "related_logs",
    "source_health",
    "list_summary",
    "case_handoff",
    "investigation_brief",
    "how_to",
    "governance"
  ];
  return modes.includes(value as AssistantResponseMode) ? value as AssistantResponseMode : "direct_fact";
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

function safeProvenance(
  value: unknown,
  options: { externalProviderUsed: boolean; citationCount: number }
): AssistantAnswerProvenance {
  const { externalProviderUsed, citationCount } = options;
  const row = value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
  const answerOrigin = row.answer_origin === "external_llm_synthesis" || externalProviderUsed
    ? "external_llm_synthesis"
    : "atdr_deterministic";
  return {
    answer_origin: answerOrigin,
    provider: boundedString(row.provider, 40) || null,
    evidence_scope: boundedStrings(row.evidence_scope, 8, 120),
    citation_count: typeof row.citation_count === "number" ? Math.max(0, row.citation_count) : citationCount,
    grounded: row.grounded === true || citationCount > 0,
    database_records_used: row.database_records_used === true,
    deterministic_rules_used: row.deterministic_rules_used === true,
    ml_evidence_used: row.ml_evidence_used === true,
    operational_data_used: row.operational_data_used === true,
    documentation_used: row.documentation_used === true,
    raw_logs_included: false,
    rules_authoritative: row.rules_authoritative !== false,
    ml_advisory_only: row.ml_advisory_only !== false
  };
}

function safeAnswerSections(value: unknown): Record<string, string[]> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const rows = value as Record<string, unknown>;
  const sections: Record<string, string[]> = {};
  for (const key of [
    "response_mode",
    "direct_answer",
    "key_evidence",
    "next_steps",
    "related_logs",
    "list_items",
    "steps",
    "assessment",
    "blockers",
    "consequence",
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
  const rawUsage = row.usage && typeof row.usage === "object" && !Array.isArray(row.usage)
    ? row.usage as Record<string, unknown>
    : {};
  return {
    used: row.used === true,
    provider: boundedString(row.provider, 40),
    model_configured: row.model_configured === true,
    fallback_reason: boundedString(row.fallback_reason, 120) || null,
    failure_category: boundedString(row.failure_category, 80) || null,
    raw_log_context_included: false,
    secrets_exposed: false,
    context_characters: typeof row.context_characters === "number" ? row.context_characters : 0,
    prompt_contract: boundedString(row.prompt_contract, 120),
    provider_called: row.provider_called === true,
    answer_used: row.answer_used === true,
    answer_guard_reason: boundedString(row.answer_guard_reason, 120) || null,
    structured_output_valid: row.structured_output_valid === true,
    latency_ms: typeof row.latency_ms === "number" ? row.latency_ms : null,
    attempts: typeof row.attempts === "number" ? row.attempts : 0,
    usage: {
      input_tokens: typeof rawUsage.input_tokens === "number" ? Math.max(0, rawUsage.input_tokens) : 0,
      output_tokens: typeof rawUsage.output_tokens === "number" ? Math.max(0, rawUsage.output_tokens) : 0,
      total_tokens: typeof rawUsage.total_tokens === "number" ? Math.max(0, rawUsage.total_tokens) : 0
    }
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
    raw_logs_included: false,
    answer_origin: boundedString(row.answer_origin, 64),
    evidence_scope: boundedStrings(row.evidence_scope, 8, 120),
    rules_authoritative: row.rules_authoritative !== false,
    ml_advisory_only: row.ml_advisory_only !== false
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
  const externalProviderUsed = row.external_provider_used === true;
  const rawDetails = row.details && typeof row.details === "object" && !Array.isArray(row.details)
    ? (row.details as Record<string, unknown>)
    : {};
  const details: Record<string, unknown> = {};
  const sections = safeAnswerSections(rawDetails.answer_sections);
  const llm = safeLlmDetails(rawDetails.llm);
  const grounding = safeGrounding(rawDetails.grounding);
  const evidenceDetail = safeAnswerSections(rawDetails.evidence_detail);
  if (sections) details.answer_sections = sections;
  if (llm) details.llm = llm;
  if (grounding) details.grounding = grounding;
  if (evidenceDetail) details.evidence_detail = evidenceDetail;
  if (rawDetails.response_contract && typeof rawDetails.response_contract === "object" && !Array.isArray(rawDetails.response_contract)) {
    const contract = rawDetails.response_contract as Record<string, unknown>;
    details.response_contract = {
      mode: safeResponseMode(contract.mode),
      word_limit: typeof contract.word_limit === "number" ? contract.word_limit : 80,
      word_count: typeof contract.word_count === "number" ? contract.word_count : 0,
      max_followups: typeof contract.max_followups === "number" ? contract.max_followups : 3
    };
  }
  if (typeof rawDetails.assistant_audit_id === "number" && rawDetails.assistant_audit_id > 0) {
    details.assistant_audit_id = rawDetails.assistant_audit_id;
  }
  return {
    answer,
    mode: boundedString(row.mode, 120) || "deterministic_local",
    response_mode: safeResponseMode(row.response_mode),
    external_provider_used: externalProviderUsed,
    safety: boundedStrings(row.safety, 12, 120),
    context_used: boundedStrings(row.context_used, 20, 120),
    citations,
    redaction_applied: row.redaction_applied === true,
    raw_log_context_included: false,
    suggested_followups: boundedStrings(row.suggested_followups, 8, 240),
    details,
    conversation_id: conversationId,
    active_context: safeActiveContext(row.active_context),
    provenance: safeProvenance(
      row.provenance,
      { externalProviderUsed, citationCount: citations.length }
    )
  };
}

function safeTurn(value: unknown): AssistantConversationTurn | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const response = safeResponse(row.response);
  const question = boundedString(row.question, 2000);
  if (!response || !question) return null;
  return {
    id: boundedString(row.id, 120) || `turn-${response.conversation_id}-${boundedString(row.createdAt, 20)}`,
    question,
    response,
    createdAt: typeof row.createdAt === "number" && Number.isFinite(row.createdAt)
      ? row.createdAt
      : Date.now()
  };
}

export function loadAssistantSession(): AssistantSessionSnapshot | null {
  try {
    const raw = window.sessionStorage.getItem(ASSISTANT_SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const conversationId = boundedString(parsed.conversationId, 64);
    if (!CONVERSATION_ID_PATTERN.test(conversationId)) return null;
    const response = safeResponse(parsed.response);
    const turns = Array.isArray(parsed.turns)
      ? parsed.turns.map(safeTurn).filter((item): item is AssistantConversationTurn => item !== null).slice(-assistantConversationTurnLimit)
      : [];
    if (!turns.length && response) {
      turns.push({
        id: `legacy-${conversationId}`,
        question: boundedString(parsed.question, 2000) || DEFAULT_QUESTION,
        response,
        createdAt: Date.now()
      });
    }
    return {
      question: boundedString(parsed.question, 2000) || DEFAULT_QUESTION,
      conversationId,
      context: safeContext(parsed.context),
      response,
      turns
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
  let turns = snapshot.turns
    .map(safeTurn)
    .filter((item): item is AssistantConversationTurn => item !== null)
    .filter((item) => item.response.conversation_id === conversationId)
    .slice(-assistantConversationTurnLimit);
  const hasContext = Boolean(context.alertId || context.logId || context.sourceId || context.caseId);
  if (!response && !turns.length && !hasContext && question === DEFAULT_QUESTION) {
    clearAssistantSession();
    return;
  }
  let serialized = JSON.stringify({ question, conversationId, context, response, turns });
  while (serialized.length > MAX_SESSION_CHARACTERS && turns.length > 1) {
    turns = turns.slice(1);
    serialized = JSON.stringify({ question, conversationId, context, response, turns });
  }
  if (serialized.length <= MAX_SESSION_CHARACTERS) {
    window.sessionStorage.setItem(ASSISTANT_SESSION_KEY, serialized);
  }
}

export function appendAssistantConversationTurn(
  turns: AssistantConversationTurn[],
  question: string,
  response: AssistantChatResponse,
  createdAt = Date.now()
): AssistantConversationTurn[] {
  const auditId = Number(response.details?.assistant_audit_id);
  const id = Number.isFinite(auditId) && auditId > 0
    ? `audit-${auditId}`
    : `${response.conversation_id}-${createdAt}`;
  return [
    ...turns.filter((item) => item.id !== id && item.response.conversation_id === response.conversation_id),
    { id, question: boundedString(question, 2000), response, createdAt }
  ].slice(-assistantConversationTurnLimit);
}

export function clearAssistantSession(): void {
  window.sessionStorage.removeItem(ASSISTANT_SESSION_KEY);
}

export const assistantDefaultQuestion = DEFAULT_QUESTION;
export const assistantSessionStorageKey = ASSISTANT_SESSION_KEY;
