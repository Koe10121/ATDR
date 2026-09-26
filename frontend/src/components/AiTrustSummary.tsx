import clsx from "clsx";
import { Link } from "react-router-dom";
import type {
  AssistantStatusResponse,
  DetectionRuntimeStatus,
  FrozenEvaluationStatus,
  MLEvaluationReport
} from "../types/api";

type Tone = "good" | "caution" | "off";

const toneClass: Record<Tone, string> = {
  good: "border-success/30 bg-success/10 text-success",
  caution: "border-amber/30 bg-amber/10 text-amber",
  off: "border-slate-400/30 bg-slate-400/10 text-slate-300"
};

interface TrustRow {
  key: string;
  label: string;
  status: string;
  tone: Tone;
  text: string;
  link?: { to: string; label: string };
}

const count = (value: number | undefined | null) => (typeof value === "number" ? value.toLocaleString("en-US") : "-");
const capitalize = (value: string) => value.charAt(0).toUpperCase() + value.slice(1);

// One plain-language answer per AI component, built from the same status
// endpoints as the detailed sections below. It never changes model state.
export function AiTrustSummary({
  runtime,
  report,
  assistant,
  evaluation,
  bootstrapCommand
}: {
  runtime?: DetectionRuntimeStatus;
  report?: MLEvaluationReport;
  assistant?: AssistantStatusResponse;
  evaluation?: FrozenEvaluationStatus;
  bootstrapCommand: string;
}) {
  // The runtime state says whether it scores; a missing model file overrides
  // it. Incomplete bootstrap provenance is noted but does not mean "off".
  const anomalyOn = runtime?.anomaly.state === "active_advisory" && report?.model_status.artifact_exists !== false;
  const provenanceNote = report?.model_status.bootstrap_required
    ? " Its training provenance is incomplete; details are in the research history."
    : "";
  const supervisedOn = runtime?.supervised.state === "active_shadow";
  const reviewDone = Boolean(evaluation?.reviews_closed);
  const rows: TrustRow[] = [
    {
      key: "anomaly",
      label: "Anomaly model (IsolationForest)",
      status: anomalyOn ? "Hint only" : "Off",
      tone: anomalyOn ? "caution" : "off",
      text: anomalyOn
        ? `Marks unusual logs (${report?.anomaly_rate ?? "-"}% of ${count(report?.scored_log_count)} scored logs) next to the rule evidence. It cannot create alerts or change their scores, and its threat accuracy is not validated.${provenanceNote}`
        : `Not scoring right now. Rules still create every alert. To turn the hint back on, run ${bootstrapCommand}`
    },
    {
      key: "supervised",
      label: "Supervised classifier",
      status: supervisedOn ? "Shadow only" : "Not in use",
      tone: supervisedOn ? "caution" : "off",
      text: supervisedOn
        ? "Scores logs in the background for comparison only. Its output is never shown as a decision."
        : `No candidate has passed an independent test yet (${String(runtime?.supervised.reason_code ?? "no qualified candidate").replaceAll("_", " ")}), so it stays off.`
    },
    {
      key: "review",
      label: "Independent human review",
      status: reviewDone ? "Complete" : evaluation ? "In progress" : "Unavailable",
      tone: reviewDone ? "good" : "caution",
      text: evaluation
        ? `People reviewed ${evaluation.detection.reviewed}/${evaluation.detection.total} detection cases and ${evaluation.assistant.reviewed}/${evaluation.assistant.total} assistant answers without seeing the model's predictions. ${evaluation.activation_decision.model_activated ? "A model was activated." : "No model was activated."}`
        : "Review status is unavailable right now.",
      link: { to: "/evidence-review", label: "Open review records" }
    },
    {
      key: "assistant",
      label: "SOC Assistant (Gemini)",
      status: assistant?.llm_ready ? "Rewords only" : "Local answers",
      tone: assistant?.llm_ready ? "caution" : "off",
      text: `${assistant?.llm_ready ? `${capitalize(assistant.llm_provider_name)} may reword answers built from ATDR data; it cannot add facts or take actions.` : "Answers come straight from ATDR data with no external model."} IP redaction ${assistant?.redaction_enabled ? "on" : "off"}; raw logs ${assistant?.raw_log_context_allowed ? "allowed after review" : "never sent"}.`,
      link: { to: "/assistant", label: "Open assistant" }
    }
  ];

  return (
    <section className="panel" data-testid="ai-trust-summary" aria-label="AI trust summary">
      <ul className="divide-y divide-line">
        {rows.map((row) => (
          <li key={row.key} className="grid gap-2 py-3 first:pt-0 last:pb-0 md:grid-cols-[230px_140px_1fr] md:items-baseline" data-testid={`ai-trust-${row.key}`}>
            <div className="font-bold text-text">{row.label}</div>
            <div>
              <span className={clsx("inline-flex rounded-full border px-2.5 py-0.5 text-xs font-extrabold uppercase tracking-wide", toneClass[row.tone])}>
                {row.status}
              </span>
            </div>
            <div className="min-w-0 break-words text-sm text-muted">
              {row.text}
              {row.link ? (
                <>
                  {" "}
                  <Link className="font-bold text-cyan hover:underline" to={row.link.to}>
                    {row.link.label}
                  </Link>
                </>
              ) : null}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
