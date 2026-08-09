import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Bot, Clock3, Send, ShieldCheck } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import {
  AssistantAnswerContent,
  AssistantCitationList,
  AssistantTechnicalContext
} from "../components/AssistantAnswerContent";
import { Badge } from "../components/Badge";
import { ErrorBanner } from "../components/ErrorBanner";
import { LoadingPanel } from "../components/LoadingPanel";
import { SafeSelect } from "../components/SafeSelect";
import { SocPageHeader } from "../components/SocPageHeader";
import {
  assistantDefaultQuestion,
  clearAssistantSession,
  loadAssistantSession,
  saveAssistantSession
} from "../lib/assistantSession";
import { useAuth } from "../hooks/useAuth";
import {
  useAssistantFeedbackMutation,
  useAssistantFeedbackRecent,
  useAssistantFeedbackSummary,
  useAssistantHistory,
  useAssistantMutation,
  useAssistantStatus
} from "../hooks/useApiQueries";
import type { AssistantChatResponse, AssistantFeedbackRating } from "../types/api";

interface AssistantContextState {
  alertId: number | null;
  logId: number | null;
  sourceId: number | null;
  caseId: string | null;
  primary: "alert" | "log" | "source" | "case" | null;
}

interface AssistantLlmDetails {
  used?: boolean;
  provider?: string;
  model_configured?: boolean;
  fallback_reason?: string | null;
  raw_log_context_included?: boolean;
  secrets_exposed?: boolean;
  context_characters?: number;
  prompt_contract?: string;
  provider_called?: boolean;
  answer_used?: boolean;
  answer_guard_reason?: string | null;
  structured_output_valid?: boolean;
  latency_ms?: number | null;
  attempts?: number;
  usage?: Record<string, number>;
}

const emptyAssistantContext: AssistantContextState = {
  alertId: null,
  logId: null,
  sourceId: null,
  caseId: null,
  primary: null
};

function createConversationId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `atdr-${Date.now()}-${Math.random().toString(36).slice(2, 12)}`;
}

const promptGroups = [
  {
    label: "SOC Playbook",
    prompts: [
      { label: "Latest Critical Alert", question: "Explain the latest critical alert.", resetContext: true },
      { label: "Explain Current Alert", question: "Why was this alert flagged?" },
      { label: "Investigation Brief", question: "Create investigation brief for this alert." },
      { label: "Source Health", question: "Summarize source health.", resetContext: true },
      { label: "AI Governance Summary", question: "What supervised ML output is safe?", resetContext: true },
      { label: "Controlled Validation Scenario", question: "How do I run a controlled validation scenario?", resetContext: true },
      { label: "Response Safety", question: "What are response safety rules?", resetContext: true }
    ]
  },
  {
    label: "Alert Triage",
    prompts: [
      { label: "Latest Critical", question: "Show latest critical alerts.", resetContext: true },
      { label: "Explain Current Alert", question: "Why was this alert flagged?" },
      { label: "Check First", question: "What should I check first for this alert?" },
      { label: "Evidence Missing", question: "What evidence is missing for this alert?" }
    ]
  },
  {
    label: "False Positive Review",
    prompts: [
      { label: "Likely False Positive?", question: "Is this likely a false positive?" },
      { label: "Noise Check", question: "Is this alert source noisy?" },
      { label: "Compare Logs", question: "Compare this alert with related logs." }
    ]
  },
  {
    label: "Source Health",
    prompts: [
      { label: "Source Health", question: "Summarize source health.", resetContext: true },
      { label: "Source Warnings", question: "Which sources have warnings?", resetContext: true },
      { label: "Source Risk", question: "Is this source risky?" },
      { label: "Source Noise", question: "Why is this source noisy?" }
    ]
  },
  {
    label: "Case Handoff",
    prompts: [
      { label: "Alert Brief", question: "Create investigation brief for this alert." },
      { label: "Case Handoff", question: "Summarize this case for handoff." },
      { label: "Leadership Brief", question: "Generate executive evidence summary for this alert." }
    ]
  },
  {
    label: "AI Governance",
    prompts: [
      { label: "ML Status", question: "Explain current ML model status.", resetContext: true },
      { label: "Promotion Gate", question: "Why is the model not production promoted?", resetContext: true }
    ]
  },
  {
    label: "How-To",
    prompts: [
      { label: "Detection Runs", question: "Summarize recent detection runs.", resetContext: true },
      { label: "Failed Jobs", question: "Summarize failed jobs.", resetContext: true },
      { label: "Import Labels", question: "How do I import reviewed labels?", resetContext: true },
      { label: "Controlled Scenario", question: "How do I run a controlled validation scenario?", resetContext: true }
    ]
  }
];

const feedbackOptions: Array<{ rating: AssistantFeedbackRating; label: string }> = [
  { rating: "helpful", label: "Helpful" },
  { rating: "not_helpful", label: "Not helpful" },
  { rating: "incorrect", label: "Incorrect" },
  { rating: "unsafe", label: "Unsafe" },
  { rating: "unclear", label: "Unclear" }
];

const feedbackRatingFilterOptions = [
  { value: "all", label: "All ratings" },
  ...feedbackOptions.map((option) => ({ value: option.rating, label: option.label }))
];

const feedbackContextFilterOptions = [
  { value: "all", label: "All contexts" },
  { value: "alert", label: "Alert" },
  { value: "log", label: "Log" },
  { value: "source", label: "Source" },
  { value: "case", label: "Case" },
  { value: "jobs", label: "Jobs" },
  { value: "ml", label: "AI Governance" },
  { value: "workflow", label: "Workflow" },
  { value: "general", label: "General" }
];

const feedbackSinceFilterOptions = [
  { value: "all", label: "All dates" },
  { value: "1", label: "Last 24 hours" },
  { value: "7", label: "Last 7 days" },
  { value: "30", label: "Last 30 days" },
  { value: "90", label: "Last 90 days" }
];

const feedbackLimitOptions = [
  { value: "8", label: "8 rows" },
  { value: "20", label: "20 rows" },
  { value: "50", label: "50 rows" },
  { value: "100", label: "100 rows" }
];

function normalizeFeedbackContext(context?: string | null): string | null {
  const value = (context ?? "").toLowerCase();
  if (!value) return null;
  if (value.includes("alert") || value.includes("case")) return value.includes("case") ? "case" : "alert";
  if (value.includes("log")) return "log";
  if (value.includes("source") || value.includes("parser")) return "source";
  if (value.includes("job") || value.includes("operation") || value.includes("detection_run")) return "jobs";
  if (value.includes("ml") || value.includes("model") || value.includes("governance")) return "ml";
  if (value.includes("workflow") || value.includes("runbook") || value.includes("import")) return "workflow";
  return "general";
}

function parseQuestionId(question: string, kind: "alert" | "log" | "source"): number | null {
  const aliases = {
    alert: "(?:alert|id|#)",
    log: "(?:log|row|event)",
    source: "(?:source|sensor)"
  }[kind];
  const match = question.match(new RegExp(`\\b${aliases}\\s*#?\\s*(\\d{1,10})\\b`, "i"));
  if (!match) return null;
  const value = Number(match[1]);
  return Number.isFinite(value) && value > 0 ? value : null;
}

function parseQuestionCaseId(question: string): string | null {
  const match = question.match(/\bcase\s*#?\s*([a-zA-Z0-9_-]{4,120})\b/i);
  return match?.[1] ?? null;
}

function citationNumber(response: AssistantChatResponse | null | undefined, source: string, labels: string[] = []): number | null {
  const citation = response?.citations.find((item) => {
    const label = item.label.toLowerCase();
    return item.source === source && (!labels.length || labels.some((needle) => label.includes(needle)));
  });
  if (!citation?.reference_id) return null;
  const value = Number(citation.reference_id);
  return Number.isFinite(value) && value > 0 ? value : null;
}

function citationString(response: AssistantChatResponse | null | undefined, source: string, labels: string[] = []): string | null {
  const citation = response?.citations.find((item) => {
    const label = item.label.toLowerCase();
    return item.source === source && (!labels.length || labels.some((needle) => label.includes(needle)));
  });
  return citation?.reference_id ?? null;
}

function primaryContextFromValues(context: Omit<AssistantContextState, "primary">): AssistantContextState["primary"] {
  if (context.alertId) return "alert";
  if (context.logId) return "log";
  if (context.sourceId) return "source";
  if (context.caseId) return "case";
  return null;
}

function primaryContextFromResponse(response: AssistantChatResponse): AssistantContextState["primary"] {
  const context = response.context_used.join(" ").toLowerCase();
  if (context.includes("log_detail") || context.includes("log_triage")) {
    return "log";
  }
  if (context.includes("alert_workflow") || context.includes("alert_detail") || context.includes("alert_evidence")) {
    return "alert";
  }
  if (context.includes("source_alerts") || context.includes("source_health") || context.includes("sources")) {
    return "source";
  }
  if (context.includes("alert_cases") || context.includes("case")) {
    return "case";
  }
  return null;
}

function primaryContextFromQuestion(
  lowered: string,
  ids: Omit<AssistantContextState, "primary">,
  fallback: AssistantContextState["primary"]
): AssistantContextState["primary"] {
  if (ids.alertId && /\balert\b/.test(lowered)) return "alert";
  if (ids.logId && /\b(?:log|row|event)\b/.test(lowered)) return "log";
  if (ids.sourceId && /\b(?:source|sensor)\b/.test(lowered)) return "source";
  if (ids.caseId && /\bcase\b/.test(lowered)) return "case";
  return fallback;
}

function shouldResetContextForQuestion(lowered: string): boolean {
  return [
    "latest critical alert",
    "latest critical alerts",
    "show latest critical",
    "show open alerts",
    "summarize open alerts",
    "summarize source health",
    "which sources have warnings",
    "current ml model",
    "supervised ml output",
    "model not production promoted",
    "recent detection runs",
    "failed jobs",
    "import reviewed labels",
    "controlled validation scenario",
    "response safety rules"
  ].some((term) => lowered.includes(term));
}

function llmDetails(response: AssistantChatResponse): AssistantLlmDetails | null {
  const raw = response.details?.llm;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return null;
  }
  return raw as AssistantLlmDetails;
}

function boolLabel(value: boolean | undefined, truthy: string, falsy: string, unknown = "Unknown") {
  if (value === true) return truthy;
  if (value === false) return falsy;
  return unknown;
}

function providerDisplayName(provider?: string | null) {
  const value = (provider ?? "").trim();
  if (!value) return "Local";
  const known: Record<string, string> = {
    gemini: "Gemini",
    google: "Google",
    openai: "OpenAI",
    claude: "Claude",
    anthropic: "Claude",
    disabled: "Disabled",
    mock: "Mock"
  };
  return known[value.toLowerCase()] ?? value;
}

function guardReasonLabel(reason?: string | null) {
  switch (reason) {
    case "provider_answer_too_short_for_evidence_context":
      return "Provider answer was guarded because it was too short for the available evidence.";
    case "provider_answer_implies_action_execution":
      return "Provider answer was guarded because it implied action execution.";
    case "provider_answer_lost_alert_context":
      return "Provider answer was guarded because it did not preserve the alert context.";
    case "provider_answer_contains_unsupported_alert_id":
    case "provider_answer_contains_unsupported_log_id":
    case "provider_answer_contains_unsupported_source_id":
    case "provider_answer_contains_unsupported_case_id":
      return "Provider answer referenced a record outside the supplied ATDR context.";
    case "provider_answer_missing_requested_next_steps":
      return "Provider answer omitted the requested next steps.";
    case "provider_answer_missing_brief_coverage":
      return "Provider answer omitted required investigation-brief evidence.";
    case "provider_answer_exceeds_response_budget":
      return "Provider answer exceeded the concise response limit.";
    case "provider_answer_lost_primary_alert_citation":
      return "Provider answer did not retain the primary alert citation.";
    case "empty_provider_answer":
      return "Provider answer was empty, so ATDR used the deterministic fallback.";
    case "malformed_provider_response":
      return "Provider output did not match the required SOC structure, so ATDR used the deterministic fallback.";
    case "provider_answer_contains_secret":
      return "Provider output failed the secret-disclosure guard, so ATDR used the deterministic fallback.";
    case "provider_call_failed":
    case "provider_request_failed":
      return "Provider call failed, so ATDR used the deterministic fallback.";
    case "unsafe_request_local_only":
      return "ATDR handled this safety-sensitive request locally and did not send it to an external provider.";
    default:
      return reason ? reason.replaceAll("_", " ") : "ATDR kept the local evidence-grounded answer.";
  }
}

function AssistantProviderTelemetry({ response }: { response: AssistantChatResponse }) {
  const llm = llmDetails(response);
  const providerCalled = Boolean(llm?.provider_called ?? response.external_provider_used);
  const answerUsed = Boolean(llm?.answer_used ?? (response.external_provider_used && response.mode.startsWith("external_llm_")));
  const guarded = providerCalled && !answerUsed && (Boolean(llm?.answer_guard_reason) || response.mode.includes("guarded"));
  const fallback = Boolean(llm?.fallback_reason) && !answerUsed && !guarded;
  const localSafetyGuard = llm?.fallback_reason === "unsafe_request_local_only";
  const provider = providerDisplayName(llm?.provider);
  const promptContract = llm?.prompt_contract ?? null;
  const rawLogContextIncluded = Boolean(llm?.raw_log_context_included ?? response.raw_log_context_included);
  const title = providerCalled && answerUsed
    ? `${provider} Assisted`
    : localSafetyGuard
      ? "Local Safety Guard"
      : guarded || fallback
        ? `${provider} Fallback: Local Evidence Assistant`
        : "Local Evidence Assistant";
  const status = localSafetyGuard
    ? "Safety-sensitive request was answered locally without contacting the external provider."
    : guarded
    ? "Provider was contacted, but ATDR kept the evidence-grounded local answer."
    : providerCalled && answerUsed
      ? "The provider summarized bounded ATDR evidence and passed the response guards."
      : fallback
        ? "Provider was unavailable, so deterministic ATDR context answered."
        : "ATDR services produced this evidence-grounded answer locally.";
  const accent = guarded || fallback ? "border-amber/50 bg-amber/10 text-amber" : providerCalled && answerUsed ? "border-success/40 bg-success/10 text-success" : "border-cyan/30 bg-cyan/10 text-cyan";

  return (
    <div className="rounded-lg border border-line bg-panel2 p-4" data-testid="assistant-provider-telemetry">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-xs font-black uppercase tracking-wide text-muted">Answer mode</div>
          <div className="mt-1 text-base font-black text-text">{title}</div>
          <p className="mt-1 text-sm font-semibold text-muted">{status}</p>
          {guarded || fallback ? <p className="mt-2 text-sm font-bold text-amber">{guardReasonLabel(llm?.answer_guard_reason ?? llm?.fallback_reason)}</p> : null}
        </div>
        <span className={`rounded-full border px-3 py-1 text-xs font-black uppercase tracking-wide ${accent}`}>{providerCalled ? provider : "Local"}</span>
      </div>
      <details className="mt-3 rounded-lg border border-line bg-white p-3">
        <summary className="cursor-pointer text-xs font-black uppercase tracking-wide text-muted">Provider Detail</summary>
        <div className="mt-3 grid gap-2 text-xs font-bold text-muted sm:grid-cols-2 lg:grid-cols-3">
          <div><span className="uppercase tracking-wide">Raw logs:</span> <span className="text-text">{rawLogContextIncluded ? "Included" : "Not included"}</span></div>
          <div><span className="uppercase tracking-wide">Redaction:</span> <span className="text-text">{boolLabel(response.redaction_applied, "Applied", "Not applied")}</span></div>
          <div><span className="uppercase tracking-wide">Secrets:</span> <span className="text-text">{boolLabel(llm?.secrets_exposed, "Check required", "Not exposed", "Not exposed")}</span></div>
          <div><span className="uppercase tracking-wide">Contract:</span> <span className="break-words text-text">{promptContract ?? "Local deterministic"}</span></div>
          <div><span className="uppercase tracking-wide">Output:</span> <span className="text-text">{providerCalled ? boolLabel(llm?.structured_output_valid, "Validated", "Fallback") : "Local"}</span></div>
          <div><span className="uppercase tracking-wide">Latency:</span> <span className="text-text">{typeof llm?.latency_ms === "number" ? `${llm.latency_ms} ms` : "Not called"}</span></div>
          <div><span className="uppercase tracking-wide">Attempts:</span> <span className="text-text">{llm?.attempts ?? 0}</span></div>
          <div><span className="uppercase tracking-wide">Output tokens:</span> <span className="text-text">{llm?.usage?.output_tokens ?? 0}</span></div>
        </div>
      </details>
    </div>
  );
}

export function AssistantPage() {
  const { isAdmin } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const status = useAssistantStatus();
  const history = useAssistantHistory();
  const assistant = useAssistantMutation();
  const feedback = useAssistantFeedbackMutation();
  const alertIdParam = Number(searchParams.get("alert"));
  const alertId = Number.isFinite(alertIdParam) && alertIdParam > 0 ? alertIdParam : null;
  const logIdParam = Number(searchParams.get("log"));
  const logId = Number.isFinite(logIdParam) && logIdParam > 0 ? logIdParam : null;
  const sourceIdParam = Number(searchParams.get("source"));
  const sourceId = Number.isFinite(sourceIdParam) && sourceIdParam > 0 ? sourceIdParam : null;
  const caseIdParam = searchParams.get("case");
  const caseId = caseIdParam?.trim() || null;
  const promptParam = searchParams.get("prompt");
  const hasRouteDirective = Boolean(promptParam || alertId || logId || sourceId || caseId);
  const initialQuestion =
    promptParam ||
    (alertId
      ? `Explain alert ${alertId} and what an analyst should check next.`
      : logId
        ? `Why was log ${logId} flagged or not flagged?`
        : sourceId
          ? `Summarize source ${sourceId} health and what an analyst should check next.`
          : caseId
            ? `Summarize case ${caseId} and related alert group.`
            : assistantDefaultQuestion);
  const restoredSessionRef = useRef<ReturnType<typeof loadAssistantSession> | undefined>(undefined);
  if (restoredSessionRef.current === undefined) {
    restoredSessionRef.current = loadAssistantSession();
  }
  const restoredSession = hasRouteDirective ? null : restoredSessionRef.current;
  const routeContext: AssistantContextState = {
    alertId,
    logId,
    sourceId,
    caseId,
    primary: primaryContextFromValues({ alertId, logId, sourceId, caseId })
  };
  const [question, setQuestion] = useState(() => restoredSession?.question ?? initialQuestion);
  const [copyStatus, setCopyStatus] = useState("");
  const [feedbackNote, setFeedbackNote] = useState("");
  const [feedbackStatus, setFeedbackStatus] = useState("");
  const [feedbackRatingFilter, setFeedbackRatingFilter] = useState("all");
  const [feedbackContextFilter, setFeedbackContextFilter] = useState("all");
  const [feedbackSinceFilter, setFeedbackSinceFilter] = useState("30");
  const [feedbackLimit, setFeedbackLimit] = useState("20");
  const [conversationId, setConversationId] = useState(() => restoredSession?.conversationId ?? createConversationId());
  const [lastContext, setLastContext] = useState<AssistantContextState>(() => restoredSession?.context ?? routeContext);
  const [persistedResponse, setPersistedResponse] = useState<AssistantChatResponse | null>(() => restoredSession?.response ?? null);
  const response = assistant.data ?? persistedResponse;
  const feedbackParams = useMemo(
    () => ({
      limit: Number(feedbackLimit),
      rating: feedbackRatingFilter === "all" ? null : feedbackRatingFilter,
      context_type: feedbackContextFilter === "all" ? null : feedbackContextFilter,
      since_days: feedbackSinceFilter === "all" ? null : Number(feedbackSinceFilter)
    }),
    [feedbackContextFilter, feedbackLimit, feedbackRatingFilter, feedbackSinceFilter]
  );
  const feedbackSummary = useAssistantFeedbackSummary(feedbackParams);
  const feedbackRecent = useAssistantFeedbackRecent(feedbackParams);
  const hasInvestigationContext = Boolean(lastContext.alertId || lastContext.logId || lastContext.sourceId || lastContext.caseId);
  const contextBriefQuestion = useMemo(() => {
    if (lastContext.alertId && lastContext.logId) return `Create investigation brief for alert ${lastContext.alertId} and related log ${lastContext.logId}.`;
    if (lastContext.alertId) return `Create investigation brief for alert ${lastContext.alertId}.`;
    if (lastContext.logId) return `Create investigation brief for log ${lastContext.logId}.`;
    if (lastContext.sourceId) return `Create investigation brief for source ${lastContext.sourceId}.`;
    if (lastContext.caseId) return `Create investigation brief for case ${lastContext.caseId}.`;
    return "Create investigation brief for the latest critical alert.";
  }, [lastContext]);

  const providerLabel = useMemo(() => {
    if (!status.data) return "Checking";
    const responseLlm = response ? llmDetails(response) : null;
    const providerAnswerUsed = Boolean(
      response?.external_provider_used
        && (responseLlm?.answer_used ?? response.mode.startsWith("external_llm_"))
    );
    if (providerAnswerUsed && response) {
      const answerProvider = providerDisplayName(responseLlm?.provider ?? status.data.provider);
      return `${answerProvider} Assisted`;
    }
    if (status.data.external_provider_configured) {
      return `${providerDisplayName(status.data.provider)} Configured`;
    }
    if (status.data.llm_enabled && status.data.llm_provider_configured) {
      return "Provider Not Configured";
    }
    return "Local Evidence Assistant";
  }, [response, status.data]);
  const activeContextLabel = useMemo(() => {
    if (lastContext.primary === "alert" && lastContext.alertId) return `Using alert #${lastContext.alertId}`;
    if (lastContext.primary === "log" && lastContext.logId) return `Using log #${lastContext.logId}`;
    if (lastContext.primary === "source" && lastContext.sourceId) return `Using source #${lastContext.sourceId}`;
    if (lastContext.primary === "case" && lastContext.caseId) return `Using case ${lastContext.caseId}`;
    if (lastContext.alertId) return `Using alert #${lastContext.alertId}`;
    if (lastContext.logId) return `Using log #${lastContext.logId}`;
    if (lastContext.sourceId) return `Using source #${lastContext.sourceId}`;
    if (lastContext.caseId) return `Using case ${lastContext.caseId}`;
    return null;
  }, [lastContext]);

  useEffect(() => {
    if (!hasRouteDirective) return;
    setQuestion(initialQuestion);
    setPersistedResponse(null);
  }, [hasRouteDirective, initialQuestion]);

  useEffect(() => {
    if (alertId || logId || sourceId || caseId) {
      setLastContext({ alertId, logId, sourceId, caseId, primary: primaryContextFromValues({ alertId, logId, sourceId, caseId }) });
    }
  }, [alertId, logId, sourceId, caseId]);

  useEffect(() => {
    if (assistant.data) {
      setPersistedResponse(assistant.data);
    }
  }, [assistant.data]);

  useEffect(() => {
    if (!response) return;
    const responsePrimary = response.active_context?.primary ?? primaryContextFromResponse(response);
    const responseAlertId = citationNumber(response, "/api/alerts/{alert_id}", ["alert"]);
    const responseLogId = citationNumber(response, "/api/logs/{log_id}", ["log", "related"]);
    const responseSourceId = citationNumber(response, "/api/sources/{source_id}", ["source"]);
    const responseCaseId = citationString(response, "/api/alerts/cases", ["case"]);
    setLastContext({
      alertId: response.active_context?.alert_id ?? responseAlertId ?? null,
      logId: response.active_context?.log_id ?? responseLogId ?? null,
      sourceId: response.active_context?.source_id ?? responseSourceId ?? null,
      caseId: response.active_context?.case_id ?? responseCaseId ?? null,
      primary: responsePrimary ?? null
    });
    if (response.conversation_id && response.conversation_id !== conversationId) {
      setConversationId(response.conversation_id);
    }
  }, [conversationId, response]);

  useEffect(() => {
    saveAssistantSession({
      question,
      conversationId,
      context: lastContext,
      response
    });
  }, [conversationId, lastContext, question, response]);

  function askQuestion(value: string, options: { resetContext?: boolean } = {}) {
    const trimmed = value.trim();
    if (!trimmed) return;
    setQuestion(trimmed);
    setPersistedResponse(null);
    assistant.reset();
    setCopyStatus("");
    setFeedbackStatus("");
    const lowered = trimmed.toLowerCase();
    const resetContext = Boolean(options.resetContext || shouldResetContextForQuestion(lowered));
    const explicitAlertId = parseQuestionId(trimmed, "alert");
    const explicitLogId = parseQuestionId(trimmed, "log");
    const explicitSourceId = parseQuestionId(trimmed, "source");
    const explicitCaseId = parseQuestionCaseId(trimmed);
    const rememberedAlertId = resetContext ? null : alertId ?? lastContext.alertId ?? citationNumber(response, "/api/alerts/{alert_id}", ["alert"]);
    const rememberedLogId = resetContext ? null : logId ?? lastContext.logId ?? citationNumber(response, "/api/logs/{log_id}", ["log", "related"]);
    const rememberedSourceId = resetContext ? null : sourceId ?? lastContext.sourceId ?? citationNumber(response, "/api/sources/{source_id}", ["source"]);
    const rememberedCaseId = resetContext ? null : caseId ?? lastContext.caseId ?? citationString(response, "/api/alerts/cases", ["case"]);
    const carriedAlertId = explicitAlertId ?? rememberedAlertId;
    const explicitAlertQuestion = explicitAlertId !== null;
    const asksRelatedLogs = ["related log", "logs are related", "what logs", "show logs", "linked logs", "evidence logs"].some((term) => lowered.includes(term));
    const asksSpecificLog = /\blog\b/.test(lowered) && !asksRelatedLogs;
    const isAlertFollowUp =
      Boolean(carriedAlertId) &&
      !asksSpecificLog &&
      [
        "why",
        "flagged",
        "alert",
        "related log",
        "logs are related",
        "what logs",
        "recommended next",
        "next step",
        "next steps",
        "what should",
        "verify before",
        "analyst verify",
        "check next",
        "check first",
        "safe to approve",
        "response safe",
        "attack mapping",
        "att&ck",
        "missing evidence",
        "evidence missing"
      ].some((term) => lowered.includes(term));
    const carriedLogId = explicitLogId ?? (explicitAlertQuestion || isAlertFollowUp ? null : rememberedLogId);
    const carriedSourceId = explicitSourceId ?? (explicitAlertQuestion || isAlertFollowUp ? null : rememberedSourceId);
    const carriedCaseId = explicitCaseId ?? (explicitAlertQuestion || isAlertFollowUp ? null : rememberedCaseId);
    const nextPrimary = primaryContextFromQuestion(
      lowered,
      {
        alertId: carriedAlertId,
        logId: carriedLogId,
        sourceId: carriedSourceId,
        caseId: carriedCaseId
      },
      isAlertFollowUp && carriedAlertId ? "alert" : lastContext.primary
    );
    setLastContext((current) =>
      resetContext
        ? {
            alertId: carriedAlertId,
            logId: carriedLogId,
            sourceId: carriedSourceId,
            caseId: carriedCaseId,
            primary: nextPrimary
          }
        : {
            alertId: carriedAlertId ?? current.alertId,
            logId: carriedLogId ?? current.logId,
            sourceId: carriedSourceId ?? current.sourceId,
            caseId: carriedCaseId ?? current.caseId,
            primary: nextPrimary ?? current.primary
          }
    );
    assistant.mutate({
      question: trimmed,
      alert_id: carriedAlertId,
      log_id: carriedLogId,
      source_id: carriedSourceId,
      case_id: carriedCaseId,
      include_recent_context: true,
      conversation_id: conversationId,
      reset_context: resetContext
    });
  }

  function clearContext() {
    clearAssistantSession();
    setLastContext(emptyAssistantContext);
    setConversationId(createConversationId());
    assistant.reset();
    setPersistedResponse(null);
    setQuestion(assistantDefaultQuestion);
    const next = new URLSearchParams(searchParams);
    ["alert", "log", "source", "case", "prompt"].forEach((key) => next.delete(key));
    setSearchParams(next);
  }

  function ask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    askQuestion(question);
  }

  async function copyBrief() {
    if (!response?.answer) return;
    try {
      if (!navigator.clipboard?.writeText) {
        setCopyStatus("Copy unavailable");
        return;
      }
      await navigator.clipboard.writeText(response.answer);
      setCopyStatus(response.response_mode === "investigation_brief" ? "Brief copied" : "Answer copied");
    } catch {
      setCopyStatus("Copy unavailable");
    }
  }

  function currentContextType(): string | null {
    if (lastContext.primary) return lastContext.primary;
    if (alertId || lastContext.alertId) return "alert";
    if (logId || lastContext.logId) return "log";
    if (sourceId || lastContext.sourceId) return "source";
    if (caseId || lastContext.caseId) return "case";
    return normalizeFeedbackContext(response?.context_used?.[0]);
  }

  function currentContextReference(): string | null {
    if (lastContext.primary === "alert" && lastContext.alertId) return String(lastContext.alertId);
    if (lastContext.primary === "log" && lastContext.logId) return String(lastContext.logId);
    if (lastContext.primary === "source" && lastContext.sourceId) return String(lastContext.sourceId);
    if (lastContext.primary === "case" && lastContext.caseId) return lastContext.caseId;
    if (alertId) return String(alertId);
    if (logId) return String(logId);
    if (sourceId) return String(sourceId);
    if (caseId) return caseId;
    return response?.citations?.[0]?.reference_id ?? null;
  }

  function submitFeedback(rating: AssistantFeedbackRating) {
    if (!response) return;
    setFeedbackStatus("");
    const auditId = Number(response.details?.assistant_audit_id);
    feedback.mutate(
      {
        question,
        answer: response.answer,
        rating,
        feedback_note: feedbackNote.trim() || null,
        context_type: currentContextType(),
        context_reference: currentContextReference(),
        external_provider_used: response.external_provider_used,
        raw_log_context_included: response.raw_log_context_included,
        action_requested: Boolean(response.details?.refused),
        assistant_audit_id: Number.isFinite(auditId) && auditId > 0 ? auditId : null
      },
      {
        onSuccess: () => {
          setFeedbackStatus("Feedback recorded");
          setFeedbackNote("");
        },
        onError: () => setFeedbackStatus("Feedback could not be recorded")
      }
    );
  }

  return (
    <div className="space-y-5" data-testid="assistant-page">
      <SocPageHeader
        eyebrow="SOC Assistant"
        title="Evidence-grounded analyst guidance"
        description="Bounded ATDR context, concise triage guidance, no action execution."
        icon={<Bot size={18} />}
        compact
        badges={[
          "Read Only",
          "Decision Support Only",
          "Response Automation Disabled",
          status.data?.raw_log_context_allowed ? "Raw Log Context Restricted" : "Raw Logs Disabled"
        ]}
        context={
          lastContext.alertId || lastContext.logId || lastContext.sourceId || lastContext.caseId ? (
            <div className="mt-3 flex flex-wrap gap-2">
              {lastContext.alertId ? (
                <div className="inline-flex rounded-full border border-cyan/30 bg-cyan/10 px-3 py-1 text-xs font-black uppercase tracking-wide text-cyan">
                  Alert context #{lastContext.alertId}
                </div>
              ) : null}
              {lastContext.logId ? (
                <div className="inline-flex rounded-full border border-cyan/30 bg-cyan/10 px-3 py-1 text-xs font-black uppercase tracking-wide text-cyan">
                  Log context #{lastContext.logId}
                </div>
              ) : null}
              {lastContext.sourceId ? (
                <div className="inline-flex rounded-full border border-cyan/30 bg-cyan/10 px-3 py-1 text-xs font-black uppercase tracking-wide text-cyan">
                  Source context #{lastContext.sourceId}
                </div>
              ) : null}
              {lastContext.caseId ? (
                <div className="inline-flex rounded-full border border-cyan/30 bg-cyan/10 px-3 py-1 text-xs font-black uppercase tracking-wide text-cyan">
                  Case context {lastContext.caseId}
                </div>
              ) : null}
            </div>
          ) : null
        }
      />

      <section className="grid gap-4 lg:grid-cols-4">
        <div className="metric-card">
          <div className="metric-label">Answer Provider</div>
          <div className="metric-value text-lg">{providerLabel}</div>
          <div className="metric-help">Gemini labels appear only on answers that used Gemini.</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Provider Health</div>
          <div className="metric-value text-lg capitalize">{status.data?.llm_operational?.status?.replaceAll("_", " ") ?? "Idle"}</div>
          <div className="metric-help">
            {status.data?.llm_operational?.calls_failed ?? 0} failures / {status.data?.llm_operational?.fallbacks ?? 0} fallbacks
          </div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Raw Log Context</div>
          <div className="metric-value text-lg">{status.data?.raw_log_context_allowed ? "Allowed" : "Disabled"}</div>
          <div className="metric-help">Raw logs are excluded by default.</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">IP Redaction</div>
          <div className="metric-value text-lg">{status.data?.redaction_enabled ? "Enabled" : "Off"}</div>
          <div className="metric-help">Applied before external provider context.</div>
        </div>
      </section>

      {status.isLoading ? <LoadingPanel label="Loading assistant status" /> : null}
      {status.isError ? <ErrorBanner error={status.error} fallback="Unable to load assistant status." /> : null}

      <section className="grid gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        <form className="rounded-xl border border-line bg-white p-5 shadow-panel" onSubmit={ask}>
          <label className="text-sm font-black uppercase tracking-wide text-muted" htmlFor="assistant-question">
            Analyst question
          </label>
          <textarea
            id="assistant-question"
            className="mt-3 min-h-36 w-full rounded-lg border border-line bg-white p-3 text-sm font-semibold text-text outline-none transition focus:border-danger"
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            placeholder="Ask about alerts, sources, ML governance, operations, or lab workflow."
          />
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button className="btn-primary flex items-center gap-2" type="submit" disabled={assistant.isPending || !question.trim()}>
              <Send size={16} />
              Ask assistant
            </button>
            {hasInvestigationContext ? (
              <button className="btn-secondary text-sm" type="button" disabled={assistant.isPending} onClick={() => askQuestion(contextBriefQuestion)}>
                Generate Brief
              </button>
            ) : null}
            <span className="text-xs font-semibold text-muted">Read-only answers with source references when available.</span>
            {activeContextLabel ? (
              <>
                <Badge value={activeContextLabel} />
                <button className="btn-secondary text-xs" type="button" onClick={clearContext}>
                  Clear context
                </button>
              </>
            ) : null}
          </div>
          <div className="mt-5 space-y-4" data-testid="assistant-presets">
            {promptGroups.slice(0, 1).map((group) => (
              <div key={group.label}>
                <div className="mb-2 text-[11px] font-black uppercase tracking-wide text-muted">{group.label}</div>
                <div className="flex flex-wrap gap-2">
                  {group.prompts.map((starter) => (
                    <button
                      key={starter.label}
                      className="btn-secondary text-xs"
                      type="button"
                      title={starter.question}
                      disabled={assistant.isPending}
                      onClick={() => askQuestion(starter.question, { resetContext: Boolean(starter.resetContext) })}
                    >
                      {starter.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
            <details className="rounded-lg border border-line bg-panel2 p-3">
              <summary className="cursor-pointer text-xs font-black uppercase tracking-wide text-muted">More analyst playbooks</summary>
              <div className="mt-4 space-y-4">
                {promptGroups.slice(1).map((group) => (
                  <div key={group.label}>
                    <div className="mb-2 text-[11px] font-black uppercase tracking-wide text-muted">{group.label}</div>
                    <div className="flex flex-wrap gap-2">
                      {group.prompts.map((starter) => (
                        <button
                          key={starter.label}
                          className="btn-secondary text-xs"
                          type="button"
                          title={starter.question}
                          disabled={assistant.isPending}
                          onClick={() => askQuestion(starter.question, { resetContext: Boolean(starter.resetContext) })}
                        >
                          {starter.label}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </details>
          </div>
        </form>

        <section className="rounded-xl border border-line bg-white p-5 shadow-panel" data-testid="assistant-response-panel">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-sm font-black uppercase tracking-wide text-muted">Assistant response</div>
            <div className="flex flex-wrap items-center gap-2">
              {response ? (
                <button className="btn-secondary text-xs" type="button" onClick={copyBrief}>
                  {response.response_mode === "investigation_brief" ? "Copy brief" : "Copy answer"}
                </button>
              ) : null}
              {copyStatus ? <span className="text-xs font-bold text-success">{copyStatus}</span> : null}
              <ShieldCheck className="text-success" size={20} />
            </div>
          </div>
          {assistant.isPending ? <LoadingPanel label="Building read-only context" /> : null}
          {assistant.isError ? <ErrorBanner error={assistant.error} fallback="Unable to ask assistant." /> : null}
          {!response && !assistant.isPending && !assistant.isError ? (
            <div className="mt-4 rounded-lg border border-line bg-panel2 p-4 text-sm font-semibold text-muted">
              Ask a question to summarize current ATDR context. The assistant will not trigger detection, response, model activation, or data changes.
            </div>
          ) : null}
          {response ? (
            <div className="mt-4 space-y-4">
              <AssistantAnswerContent response={response} />
              <div className="flex flex-wrap gap-2">
                {response.safety.filter((item) => ["Read Only", "Decision Support Only", "Response Automation Disabled"].includes(item)).map((item) => (
                  <Badge key={item} value={item} />
                ))}
              </div>
              <details className="rounded-lg border border-line bg-panel2 p-4" data-testid="assistant-grounding-detail">
                <summary className="cursor-pointer text-sm font-black uppercase tracking-wide text-muted">Sources and provider details</summary>
                <div className="mt-4 space-y-4">
                  <AssistantCitationList citations={response.citations} />
                  <AssistantProviderTelemetry response={response} />
                </div>
              </details>
              <details className="rounded-lg border border-line bg-panel2 p-4" data-testid="assistant-feedback-controls">
                <summary className="cursor-pointer text-sm font-black uppercase tracking-wide text-muted">Rate answer quality</summary>
                <div className="mt-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-black uppercase tracking-wide text-muted">Answer quality</div>
                    <p className="mt-1 text-sm font-semibold text-muted">
                      Feedback improves review quality only. It cannot trigger actions or change data.
                    </p>
                  </div>
                  <Badge value="Read Only" />
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {feedbackOptions.map((option) => (
                    <button
                      key={option.rating}
                      className="btn-secondary text-xs"
                      type="button"
                      disabled={feedback.isPending}
                      onClick={() => submitFeedback(option.rating)}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
                <label className="mt-3 block text-xs font-black uppercase tracking-wide text-muted" htmlFor="assistant-feedback-note">
                  Optional note
                </label>
                <textarea
                  id="assistant-feedback-note"
                  className="mt-2 min-h-20 w-full rounded-lg border border-line bg-white p-3 text-sm font-semibold text-text outline-none transition focus:border-danger"
                  value={feedbackNote}
                  onChange={(event) => setFeedbackNote(event.target.value)}
                  placeholder="Short note for answer-quality review."
                />
                {feedbackStatus ? (
                  <div className={`mt-2 text-sm font-bold ${feedback.isError ? "text-danger" : "text-success"}`}>{feedbackStatus}</div>
                ) : null}
                </div>
              </details>
              {response.suggested_followups.length ? (
                <div className="rounded-lg border border-line bg-panel2 p-4">
                  <div className="text-sm font-black uppercase tracking-wide text-muted">Suggested follow-ups</div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {response.suggested_followups.map((followup) => (
                      <button key={followup} className="btn-secondary text-xs" type="button" disabled={assistant.isPending} onClick={() => askQuestion(followup)}>
                        {followup}
                      </button>
                    ))}
                  </div>
                </div>
              ) : null}
              <AssistantTechnicalContext response={response} />
            </div>
          ) : null}
        </section>
      </section>

      <details className="rounded-xl border border-line bg-white p-5 shadow-panel presentation-technical" data-testid="assistant-history">
        <summary className="cursor-pointer text-sm font-black uppercase tracking-wide text-muted">Assistant activity</summary>
        <div className="mt-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-sm font-black uppercase tracking-wide text-muted">
              <Clock3 size={16} />
              Recent assistant questions
            </div>
            <p className="mt-1 text-sm font-semibold text-muted">Audit-derived summaries only; no raw logs or secrets.</p>
          </div>
          <Badge value="Read Only" />
        </div>
        {history.isLoading ? <LoadingPanel label="Loading assistant history" /> : null}
        {history.isError ? <ErrorBanner error={history.error} fallback="Unable to load assistant history." /> : null}
        {history.data?.length ? (
          <div className="mt-4 overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead>
                <tr className="border-b border-line text-xs font-black uppercase tracking-wide text-muted">
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">Actor</th>
                  <th className="px-3 py-2">Question</th>
                  <th className="px-3 py-2">Context</th>
                  <th className="px-3 py-2">Provider</th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((item) => (
                  <tr key={item.id} className="border-b border-line/70">
                    <td className="px-3 py-2 font-semibold text-muted">{item.created_at ? new Date(item.created_at).toLocaleString() : "-"}</td>
                    <td className="px-3 py-2 font-semibold text-text">{item.actor}</td>
                    <td className="max-w-xl px-3 py-2 font-semibold text-text break-words">{item.question}</td>
                    <td className="px-3 py-2 font-semibold text-muted">{item.context_used.join(", ") || "-"}</td>
                    <td className="px-3 py-2 font-semibold text-muted">{item.external_provider_used ? "External" : "Local"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : !history.isLoading && !history.isError ? (
          <div className="mt-4 rounded-lg border border-line bg-panel2 p-4 text-sm font-semibold text-muted">
            No assistant questions have been audited yet.
          </div>
        ) : null}
        </div>
      </details>

      <details className="rounded-xl border border-line bg-white p-5 shadow-panel presentation-technical" data-testid="assistant-feedback-summary">
        <summary className="cursor-pointer text-sm font-black uppercase tracking-wide text-muted">Feedback quality review</summary>
        <div className="mt-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-black uppercase tracking-wide text-muted">Feedback review</div>
            <p className="mt-1 text-sm font-semibold text-muted">
              {isAdmin ? "Admin view includes all assistant answer feedback." : "Analyst view shows only your assistant answer feedback."} Review only; no auto tuning.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge value="No Auto Tuning" />
            <Badge value="No Action Execution" />
          </div>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          <div>
            <label className="mb-1 block text-[11px] font-black uppercase tracking-wide text-muted">Rating</label>
            <SafeSelect value={feedbackRatingFilter} options={feedbackRatingFilterOptions} onChange={setFeedbackRatingFilter} ariaLabel="Feedback rating filter" />
          </div>
          <div>
            <label className="mb-1 block text-[11px] font-black uppercase tracking-wide text-muted">Context</label>
            <SafeSelect value={feedbackContextFilter} options={feedbackContextFilterOptions} onChange={setFeedbackContextFilter} ariaLabel="Feedback context filter" />
          </div>
          <div>
            <label className="mb-1 block text-[11px] font-black uppercase tracking-wide text-muted">Date</label>
            <SafeSelect value={feedbackSinceFilter} options={feedbackSinceFilterOptions} onChange={setFeedbackSinceFilter} ariaLabel="Feedback date filter" />
          </div>
          <div>
            <label className="mb-1 block text-[11px] font-black uppercase tracking-wide text-muted">Rows</label>
            <SafeSelect value={feedbackLimit} options={feedbackLimitOptions} onChange={setFeedbackLimit} ariaLabel="Feedback row limit" />
          </div>
        </div>
        {feedbackSummary.isLoading ? <LoadingPanel label="Loading assistant feedback" /> : null}
        {feedbackSummary.isError ? <ErrorBanner error={feedbackSummary.error} fallback="Unable to load assistant feedback." /> : null}
        {feedbackSummary.data ? (
          <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
            <div className="metric-card">
              <div className="metric-label">Total</div>
              <div className="metric-value text-lg">{feedbackSummary.data.total_count}</div>
              <div className="metric-help">{feedbackSummary.data.scope === "all" ? "All users" : "Your feedback"}</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Needs Review</div>
              <div className="metric-value text-lg">{feedbackSummary.data.needs_review_count}</div>
              <div className="metric-help">Not helpful, unclear, incorrect, unsafe</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Unsafe / Incorrect</div>
              <div className="metric-value text-lg">{feedbackSummary.data.unsafe_or_incorrect_count}</div>
              <div className="metric-help">Review recommended</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Actions Executed</div>
              <div className="metric-value text-lg">{feedbackSummary.data.action_executed_count}</div>
              <div className="metric-help">Must remain 0</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">External Context</div>
              <div className="metric-value text-lg">{feedbackSummary.data.external_provider_used_count}</div>
              <div className="metric-help">External provider used</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Raw Logs</div>
              <div className="metric-value text-lg">{feedbackSummary.data.raw_log_context_included_count}</div>
              <div className="metric-help">Raw context included</div>
            </div>
          </div>
        ) : null}
        {feedbackSummary.data?.review_warning ? (
          <div className="mt-4 rounded-lg border border-amber/40 bg-amber/10 p-4 text-sm font-bold text-amber">
            Review recommended: unsafe, incorrect, unclear, or not-helpful feedback exists. This is a manual QA signal only and does not tune the assistant automatically.
          </div>
        ) : null}
        {feedbackSummary.data ? (
          <details className="mt-4 rounded-lg border border-line bg-panel2 p-4">
            <summary className="cursor-pointer text-sm font-black uppercase tracking-wide text-muted">Rating breakdown</summary>
            <div className="mt-3 grid gap-3 sm:grid-cols-3 xl:grid-cols-5">
            {feedbackOptions.map((option) => (
              <div className="metric-card" key={option.rating}>
                <div className="metric-label">{option.label}</div>
                <div className="metric-value text-lg">{feedbackSummary.data?.rating_counts?.[option.rating] ?? 0}</div>
                <div className="metric-help">Recorded ratings</div>
              </div>
            ))}
            </div>
          </details>
        ) : null}
        {feedbackSummary.data?.latest_unsafe_or_incorrect?.length ? (
          <div className="mt-4 rounded-lg border border-amber/30 bg-amber/10 p-4" data-testid="assistant-feedback-priority">
            <div className="text-sm font-black uppercase tracking-wide text-amber">Priority feedback</div>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              {feedbackSummary.data.latest_unsafe_or_incorrect.map((item) => (
                <div key={`priority-${item.feedback_id}`} className="rounded-lg border border-amber/30 bg-white p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-black text-text">{item.rating.replaceAll("_", " ")}</span>
                    <Badge value="Review Recommended" />
                  </div>
                  <div className="mt-2 text-sm font-semibold text-text break-words">{item.question}</div>
                  <div className="mt-2 text-xs font-semibold text-muted break-words">{item.review_reason ?? "Review recommended."}</div>
                </div>
              ))}
            </div>
          </div>
        ) : null}
        {feedbackRecent.data?.length ? (
          <div className="mt-4 overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead>
                <tr className="border-b border-line text-xs font-black uppercase tracking-wide text-muted">
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">Actor</th>
                  <th className="px-3 py-2">Rating</th>
                  <th className="px-3 py-2">Context</th>
                  <th className="px-3 py-2">Question</th>
                  <th className="px-3 py-2">Answer summary</th>
                  <th className="px-3 py-2">Safety</th>
                  <th className="px-3 py-2">Review</th>
                </tr>
              </thead>
              <tbody>
                {feedbackRecent.data.map((item) => (
                  <tr key={item.feedback_id} className="border-b border-line/70">
                    <td className="px-3 py-2 font-semibold text-muted">{item.created_at ? new Date(item.created_at).toLocaleString() : "-"}</td>
                    <td className="px-3 py-2 font-semibold text-text">{item.actor_username}</td>
                    <td className="px-3 py-2 font-black text-text">{item.rating.replaceAll("_", " ")}</td>
                    <td className="px-3 py-2 font-semibold text-muted">
                      {item.context_type ?? "-"}
                      {item.context_reference ? ` #${item.context_reference}` : ""}
                    </td>
                    <td className="max-w-xl px-3 py-2 font-semibold text-text break-words">{item.question}</td>
                    <td className="max-w-lg px-3 py-2 font-semibold text-muted break-words">{item.answer_summary ?? "-"}</td>
                    <td className="px-3 py-2 font-semibold text-muted">
                      {item.action_executed ? "Action executed" : "No action"}
                      {item.raw_log_context_included ? " / raw context" : ""}
                      {item.external_provider_used ? " / external" : " / local"}
                    </td>
                    <td className="px-3 py-2 font-semibold text-muted">
                      {item.review_recommended ? <Badge value="Review Recommended" /> : <span className="text-xs font-bold text-muted">No flag</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : !feedbackRecent.isLoading && !feedbackRecent.isError ? (
          <div className="mt-4 rounded-lg border border-line bg-panel2 p-4 text-sm font-semibold text-muted">
            No assistant feedback has been recorded yet.
          </div>
        ) : null}
        </div>
      </details>
    </div>
  );
}
