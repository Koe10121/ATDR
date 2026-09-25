import { CheckCircle2, Circle, ExternalLink, MessageSquare, X } from "lucide-react";
import { Link } from "react-router-dom";
import { Badge } from "./Badge";
import { ErrorBanner } from "./ErrorBanner";
import { LoadingPanel } from "./LoadingPanel";
import { useAlertPlaybook, useAlerts } from "../hooks/useApiQueries";
import type { AlertPlaybookStep } from "../types/api";

type AskHandler = (question: string, options?: { resetContext?: boolean }) => void;

function PlaybookStepRow({ step, onAsk, askDisabled }: { step: AlertPlaybookStep; onAsk: AskHandler; askDisabled: boolean }) {
  const action = step.action;
  return (
    <li className="flex gap-2.5 border-t border-line py-2.5 first:border-t-0 first:pt-0" data-testid={`playbook-step-${step.id}`}>
      {step.done ? (
        <CheckCircle2 className="mt-0.5 shrink-0 text-success" size={16} aria-label="Done" />
      ) : (
        <Circle className="mt-0.5 shrink-0 text-muted" size={16} aria-hidden="true" />
      )}
      <div className="min-w-0 flex-1">
        <p className={step.done ? "text-sm font-semibold text-muted" : "text-sm font-semibold text-text"}>{step.text}</p>
        {action?.kind === "ask" ? (
          <button
            className="mt-1.5 inline-flex items-center gap-1.5 text-xs font-black text-cyan hover:underline disabled:opacity-50"
            type="button"
            aria-label={`Ask the assistant: ${action.question}`}
            title={action.question}
            disabled={askDisabled}
            onClick={() => onAsk(action.question)}
          >
            <MessageSquare size={13} aria-hidden="true" />
            Ask the assistant
          </button>
        ) : null}
        {action?.kind === "open" ? (
          <Link className="mt-1.5 inline-flex items-center gap-1.5 text-xs font-black text-cyan hover:underline" to={action.path}>
            <ExternalLink size={13} aria-hidden="true" />
            {action.label}
          </Link>
        ) : null}
      </div>
    </li>
  );
}

export function AlertPlaybookPanel({
  alertId,
  onAsk,
  askDisabled,
  onClose
}: {
  alertId: number;
  onAsk: AskHandler;
  askDisabled: boolean;
  onClose: () => void;
}) {
  const playbook = useAlertPlaybook(alertId);
  const data = playbook.data && Array.isArray(playbook.data.phases) ? playbook.data : undefined;
  const allSteps = data?.phases.flatMap((phase) => phase.steps) ?? [];
  const doneCount = allSteps.filter((step) => step.done).length;

  return (
    <section className="rounded-xl border border-line bg-panel2 p-5 shadow-panel" data-testid="alert-playbook" aria-label={`Response playbook for alert ${alertId}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-xs font-black uppercase tracking-wide text-muted">Response playbook · Alert #{alertId}</div>
          <h2 className="mt-1 text-2xl font-black text-text">{data?.label ?? "Loading playbook"}</h2>
          {data ? <p className="mt-1 max-w-3xl text-sm font-semibold text-muted">{data.objective}</p> : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {data?.mitre.technique_id && !["N/A", "Unknown", "Internal"].includes(data.mitre.technique_id) ? (
            <span className="rounded-md border border-cyan/30 bg-cyan/10 px-2 py-0.5 text-xs font-black text-cyan" title={data.mitre.tactic ?? undefined}>
              {data.mitre.technique_id} · {data.mitre.technique}
            </span>
          ) : null}
          {data ? <Badge value={data.facts.severity} /> : null}
          {data ? <Badge value={data.facts.status} /> : null}
          <button className="btn-secondary inline-flex items-center gap-1 text-xs" type="button" onClick={onClose}>
            <X size={14} aria-hidden="true" />
            Hide
          </button>
        </div>
      </div>

      {playbook.isLoading ? <LoadingPanel label="Loading playbook" /> : null}
      {playbook.isError ? <ErrorBanner error={playbook.error} fallback="Unable to load the playbook for this alert." /> : null}

      {data ? (
        <>
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs font-bold text-muted">
            {data.facts.src_ip ? (
              <span className="font-mono">
                {data.facts.src_ip}
                {data.facts.dst_ip ? ` → ${data.facts.dst_ip}` : ""}
              </span>
            ) : null}
            <span>Score {data.facts.score}</span>
            <span>{data.facts.related_log_count} linked logs</span>
            <span data-testid="playbook-progress">
              {doneCount} of {allSteps.length} steps done
            </span>
          </div>

          <ol className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {data.phases.map((phase, index) => (
              <li key={phase.key} className="rounded-lg border border-line bg-panel p-4" data-testid={`playbook-phase-${phase.key}`}>
                <div className="flex items-baseline gap-2">
                  <span className="font-mono text-xs font-black text-cyan">{index + 1}</span>
                  <h3 className="text-sm font-black uppercase tracking-wide text-text">{phase.title}</h3>
                </div>
                <p className="mt-1 text-xs font-semibold text-muted">{phase.goal}</p>
                <ul className="mt-3">
                  {phase.steps.map((step) => (
                    <PlaybookStepRow key={step.id} step={step} onAsk={onAsk} askDisabled={askDisabled} />
                  ))}
                </ul>
              </li>
            ))}
          </ol>

          <div className="mt-4 grid gap-3 md:grid-cols-3" data-testid="playbook-decision-guide">
            <div className="rounded-lg border border-line bg-panel p-3">
              <div className="text-[11px] font-black uppercase tracking-wide text-muted">Mark false positive when</div>
              <p className="mt-1 text-sm font-semibold text-text">{data.decision_guide.false_positive}</p>
            </div>
            <div className="rounded-lg border border-success/30 bg-success/5 p-3">
              <div className="text-[11px] font-black uppercase tracking-wide text-success">Resolve when</div>
              <p className="mt-1 text-sm font-semibold text-text">{data.decision_guide.resolved}</p>
            </div>
            <div className="rounded-lg border border-danger/30 bg-danger/5 p-3">
              <div className="text-[11px] font-black uppercase tracking-wide text-danger">Escalate when</div>
              <p className="mt-1 text-sm font-semibold text-text">{data.decision_guide.escalate}</p>
            </div>
          </div>

          <p className="mt-3 text-xs font-semibold text-muted">
            {data.claim_boundary ? `${data.claim_boundary} ` : ""}
            {data.safety_note}
          </p>
        </>
      ) : null}
    </section>
  );
}

const SHIFT_ROUTINE: Array<{ text: string; question: string }> = [
  { text: "Check that every log source is healthy, so a quiet dashboard isn't just missing data.", question: "Summarize source health." },
  { text: "See which alerts are critical right now.", question: "Show latest critical alerts." },
  { text: "Check for failed imports or detection runs.", question: "Summarize failed jobs." },
  { text: "Before you hand off, review what changed during your shift.", question: "What changed recently?" }
];

export function PlaybookStarter({ onOpen, onAsk, askDisabled }: { onOpen: (alertId: number) => void; onAsk: AskHandler; askDisabled: boolean }) {
  const urgent = useAlerts({ status: "open", sort_by: "score", limit: 3 });
  const alerts = Array.isArray(urgent.data) ? urgent.data : [];

  return (
    <section className="rounded-xl border border-line bg-panel2 p-5 shadow-panel" data-testid="playbook-starter" aria-label="Response playbook">
      <div className="text-xs font-black uppercase tracking-wide text-muted">Response playbook</div>
      <h2 className="mt-1 text-2xl font-black text-text">Pick an alert to work through</h2>
      <p className="mt-1 max-w-3xl text-sm font-semibold text-muted">
        Each alert gets a step-by-step playbook for its attack type: triage, investigate, contain, close.
      </p>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-line bg-panel p-4">
          <h3 className="text-sm font-black uppercase tracking-wide text-text">Most urgent open alerts</h3>
          {urgent.isLoading ? <LoadingPanel label="Loading open alerts" /> : null}
          {urgent.isError ? <ErrorBanner error={urgent.error} fallback="Unable to load open alerts." /> : null}
          {!urgent.isLoading && !urgent.isError && !alerts.length ? (
            <p className="mt-2 text-sm font-semibold text-muted">No open alerts. Nothing needs a playbook right now.</p>
          ) : null}
          <ul className="mt-2">
            {alerts.map((alert) => (
              <li key={alert.id} className="flex flex-wrap items-center justify-between gap-2 border-t border-line py-2.5 first:border-t-0">
                <div className="min-w-0">
                  <div className="truncate text-sm font-bold text-text">
                    #{alert.id} {alert.title}
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs font-semibold text-muted">
                    <Badge value={alert.severity} />
                    <span>Score {alert.threat_score}</span>
                    {alert.src_ip ? <span className="font-mono">{alert.src_ip}</span> : null}
                  </div>
                </div>
                <button className="btn-secondary text-xs" type="button" onClick={() => onOpen(alert.id)}>
                  Open playbook
                </button>
              </li>
            ))}
          </ul>
        </div>
        <div className="rounded-lg border border-line bg-panel p-4">
          <h3 className="text-sm font-black uppercase tracking-wide text-text">Start-of-shift routine</h3>
          <ol className="mt-2">
            {SHIFT_ROUTINE.map((item, index) => (
              <li key={item.question} className="flex gap-2.5 border-t border-line py-2.5 first:border-t-0">
                <span className="mt-0.5 font-mono text-xs font-black text-cyan">{index + 1}</span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-text">{item.text}</p>
                  <button
                    className="mt-1.5 inline-flex items-center gap-1.5 text-xs font-black text-cyan hover:underline disabled:opacity-50"
                    type="button"
                    aria-label={`Ask the assistant: ${item.question}`}
                    title={item.question}
                    disabled={askDisabled}
                    onClick={() => onAsk(item.question, { resetContext: true })}
                  >
                    <MessageSquare size={13} aria-hidden="true" />
                    Ask the assistant
                  </button>
                </div>
              </li>
            ))}
          </ol>
        </div>
      </div>
    </section>
  );
}
