import { Link } from "react-router-dom";
import type { AssistantChatResponse, AssistantCitation } from "../types/api";

interface AssistantAnswerSections {
  summary: string[];
  what_happened: string[];
  why_flagged_or_not: string[];
  evidence: string[];
  risk_interpretation: string[];
  related_context: string[];
  what_to_check_next: string[];
  safe_next_steps: string[];
  limitations: string[];
  safety_note: string[];
  safety_limitation: string[];
  citations: string[];
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean) : [];
}

function answerSections(response: AssistantChatResponse): AssistantAnswerSections | null {
  const rawSections = response.details?.answer_sections;
  if (!rawSections || typeof rawSections !== "object" || Array.isArray(rawSections)) {
    return null;
  }
  const sections = rawSections as Record<string, unknown>;
  return {
    summary: stringList(sections.summary),
    what_happened: stringList(sections.what_happened),
    why_flagged_or_not: stringList(sections.why_flagged_or_not),
    evidence: stringList(sections.evidence),
    risk_interpretation: stringList(sections.risk_interpretation),
    related_context: stringList(sections.related_context),
    what_to_check_next: stringList(sections.what_to_check_next),
    safe_next_steps: stringList(sections.safe_next_steps),
    limitations: stringList(sections.limitations),
    safety_note: stringList(sections.safety_note),
    safety_limitation: stringList(sections.safety_limitation),
    citations: stringList(sections.citations)
  };
}

function SectionCard({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return (
    <div
      className="rounded-lg border border-line bg-panel2 p-4"
      data-testid={`assistant-section-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`}
    >
      <div className="text-xs font-black uppercase tracking-wide text-muted">{title}</div>
      <ul className="mt-3 list-disc space-y-2 pl-5 text-sm font-semibold leading-relaxed text-text marker:text-danger">
        {items.map((item, index) => (
          <li key={`${title}-${index}`} className="break-words">
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

function citationHref(citation: AssistantCitation): string | null {
  const ref = citation.reference_id ? encodeURIComponent(citation.reference_id) : "";
  switch (citation.source) {
    case "/api/alerts/{alert_id}":
      return ref ? `/alerts?alert=${ref}` : "/alerts";
    case "/api/alerts/cases":
    case "/api/alerts":
      return "/alerts";
    case "/api/logs/{log_id}":
      return ref ? `/logs?log=${ref}` : "/logs";
    case "/api/logs":
      return "/logs";
    case "/api/sources/{source_id}":
      return ref ? `/overview?source=${ref}` : "/overview";
    case "/api/sources":
      return "/";
    case "/api/detection/runs/{run_id}":
      return ref ? `/?detection_run=${ref}` : "/";
    case "/api/detection/runs":
      return "/";
    case "/api/jobs/{job_id}":
      return ref ? `/?job=${ref}` : "/";
    case "/api/jobs":
    case "/api/jobs/summary":
      return "/";
    case "/api/ml/report":
    case "/api/ml/supervised/report":
    case "/api/ml/labels/import":
      return "/ml";
    default:
      return null;
  }
}

export function AssistantCitationList({ citations }: { citations: AssistantCitation[] }) {
  if (!citations.length) {
    return (
      <div
        className="rounded-lg border border-amber/40 bg-amber/10 p-4 text-sm font-semibold text-amber"
        data-testid="assistant-citations-empty"
      >
        No record-specific ATDR evidence was available for this answer.
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-line bg-panel2 p-4" data-testid="assistant-citations">
      <div className="text-sm font-black uppercase tracking-wide text-muted">Grounded In</div>
      <p className="mt-1 text-xs font-semibold text-muted">Bounded ATDR records, services, and documentation used for this answer.</p>
      <ul className="mt-3 space-y-2 text-sm font-semibold text-muted">
        {citations.map((citation) => {
          const href = citationHref(citation);
          const refLabel = citation.reference_id ? `#${citation.reference_id}` : "reference";
          return (
            <li
              key={`${citation.label}-${citation.source}-${citation.reference_id ?? ""}`}
              className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-white px-3 py-2"
            >
              <div className="min-w-0">
                <div className="break-words font-black text-text">{citation.label}</div>
                <div className="mt-1 break-all text-xs text-muted">
                  {citation.source}
                  {citation.reference_id ? <span className="ml-1 font-bold text-text">{refLabel}</span> : null}
                </div>
              </div>
              {href ? (
                <Link
                  className="btn-secondary shrink-0 text-xs"
                  to={href}
                  aria-label={`Open ${citation.label}${citation.reference_id ? ` ${citation.reference_id}` : ""}`}
                  data-testid={`assistant-citation-open-${citation.label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}${citation.reference_id ? `-${citation.reference_id}` : ""}`}
                >
                  Open
                </Link>
              ) : (
                <span className="shrink-0 rounded-full border border-line bg-shell px-3 py-1 text-xs font-bold text-muted">
                  Text reference
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function AssistantAnswerContent({ response }: { response: AssistantChatResponse }) {
  const sections = answerSections(response);
  if (!sections) {
    return (
      <div className="rounded-lg border border-cyan/30 bg-cyan/10 p-4 text-sm font-semibold leading-relaxed text-text whitespace-pre-wrap break-words">
        {response.answer}
      </div>
    );
  }
  return (
    <div className="space-y-3" data-testid="assistant-answer-sections">
      <div className="grid gap-3 lg:grid-cols-2">
        <SectionCard title="What happened" items={sections.summary.slice(0, 2)} />
        <SectionCard
          title="Why flagged / evidence"
          items={(sections.evidence.length ? sections.evidence : sections.why_flagged_or_not).slice(0, 3)}
        />
        <SectionCard title="Evidence strength" items={sections.risk_interpretation.slice(0, 2)} />
        <SectionCard title="Missing context" items={sections.limitations.slice(0, 2)} />
        <SectionCard
          title="Analyst next steps"
          items={(sections.what_to_check_next.length ? sections.what_to_check_next : sections.safe_next_steps).slice(0, 3)}
        />
        <SectionCard title="Safety" items={(sections.safety_note.length ? sections.safety_note : sections.safety_limitation).slice(0, 1)} />
      </div>
      <details className="rounded-lg border border-line bg-white p-3" data-testid="assistant-technical-detail">
        <summary className="cursor-pointer text-xs font-black uppercase tracking-wide text-muted">Technical Detail</summary>
        <div className="mt-3 space-y-3">
          <SectionCard title="Related context" items={sections.related_context.slice(0, 5)} />
          <div className="max-h-72 overflow-auto rounded-lg border border-line bg-panel2 p-4 text-sm font-semibold leading-relaxed text-muted whitespace-pre-wrap break-words">
            {response.answer}
          </div>
        </div>
      </details>
    </div>
  );
}

export function AssistantTechnicalContext({ response }: { response: AssistantChatResponse }) {
  return (
    <details className="rounded-lg border border-line bg-panel2 p-4">
      <summary className="cursor-pointer text-sm font-black uppercase tracking-wide text-muted">Technical context</summary>
      <pre
        className="mt-3 max-h-80 overflow-auto rounded-lg border border-line bg-white p-3 text-xs leading-relaxed text-muted whitespace-pre-wrap break-words"
        data-testid="assistant-technical-context"
      >
        {JSON.stringify(
          {
            mode: response.mode,
            context_used: response.context_used,
            redaction_applied: response.redaction_applied,
            raw_log_context_included: response.raw_log_context_included,
            external_provider_used: response.external_provider_used,
            details: response.details
          },
          null,
          2
        )}
      </pre>
    </details>
  );
}
