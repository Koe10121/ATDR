import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorBanner } from "./ErrorBanner";
import { useBehaviorAlertOpinion, useBehaviorFindings } from "../hooks/useApiQueries";
import type { BehaviorFinding } from "../types/api";

const VISIBLE_FINDINGS = 6;

function windowLabel(start: string, logs?: number): string {
  const from = new Date(start);
  const to = new Date(from.getTime() + 5 * 60_000);
  const day = from.toLocaleDateString("en-GB", { day: "numeric", month: "short" });
  const time = (value: Date) => value.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  return `${day} ${time(from)}-${time(to)}${logs === undefined ? "" : ` (${logs.toLocaleString()} logs)`}`;
}

function percent(value: number): string {
  return `${(value * 100).toFixed(value >= 0.999 ? 2 : 1)}%`;
}

function capitalise(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function FoundBy({ finding }: { finding: BehaviorFinding }) {
  return finding.found_by === "rules_and_model" ? (
    <span className="rounded-full border border-success/40 bg-success/10 px-2 py-0.5 text-xs font-black uppercase tracking-wide text-success">
      Rules and model agree
    </span>
  ) : (
    <span className="rounded-full border border-amber/50 bg-amber/10 px-2 py-0.5 text-xs font-black uppercase tracking-wide text-amber">
      Model only
    </span>
  );
}

function FindingCard({ finding }: { finding: BehaviorFinding }) {
  const mitre = finding.response.mitre;
  return (
    <article className="rounded-lg border border-line bg-panel2 p-4" data-testid="behavior-finding">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-base font-black text-text">
          {capitalise(finding.attack_label)} <span className="text-sm font-bold text-muted">{percent(finding.confidence)}</span>
        </div>
        <FoundBy finding={finding} />
      </div>
      <div className="mt-1 text-sm font-semibold text-muted">
        Source <span className="font-bold text-text">{finding.source}</span>, {finding.connections.toLocaleString()} connections in five minutes
        {finding.alert_ids.length ? (
          <>
            {" "}· alerts{" "}
            {finding.alert_ids.slice(0, 3).map((alertId, index) => (
              <span key={alertId}>
                {index ? ", " : ""}
                <Link className="font-bold text-cyan hover:underline" to={`/alerts?alert=${alertId}`}>#{alertId}</Link>
              </span>
            ))}
          </>
        ) : null}
      </div>
      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <div>
          <div className="text-xs font-black uppercase tracking-wide text-muted">Why the model thinks so</div>
          <ul className="mt-1 list-disc space-y-1 pl-4 text-sm font-semibold text-text">
            {(finding.reasons.length ? finding.reasons : ["Its overall behaviour matches the attacks the model learned, although no single measure stands out."]).map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
          {mitre.technique ? (
            <div className="mt-2 text-xs font-bold text-muted">
              MITRE ATT&CK: {mitre.tactic} / {mitre.technique} ({mitre.technique_id})
            </div>
          ) : null}
        </div>
        <div>
          <div className="text-xs font-black uppercase tracking-wide text-muted">What to do</div>
          {finding.response.objective ? <p className="mt-1 text-sm font-semibold text-text">{finding.response.objective}</p> : null}
          <ol className="mt-1 list-decimal space-y-1 pl-4 text-sm font-semibold text-text">
            {finding.response.containment.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          {finding.response.escalate_when ? (
            <p className="mt-2 text-xs font-bold text-muted">Escalate when: {finding.response.escalate_when}</p>
          ) : null}
        </div>
      </div>
    </article>
  );
}

export function BehaviorModelPanel() {
  const [windowStart, setWindowStart] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);
  const query = useBehaviorFindings(windowStart);
  const data = query.data;
  const summary = data?.summary;
  const probing = summary?.background_probing;
  const p2p = summary?.p2p_policy;
  const findings = data?.findings ?? [];
  const visible = showAll ? findings : findings.slice(0, VISIBLE_FINDINGS);

  return (
    <section className="panel" data-testid="behavior-model-panel">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-sm font-extrabold uppercase tracking-wide text-muted">What the MFU model sees</div>
          <p className="mt-1 text-sm font-semibold text-muted">
            A behaviour model trained only on MFU traffic names the attack each source is carrying out, explains why, and shows how to respond.
            It is advisory: it does not create alerts until an attack type passes the quality bar.
          </p>
        </div>
        {data?.windows?.length ? (
          <label className="flex items-center gap-2 text-xs font-bold uppercase tracking-wide text-muted">
            Window
            <select
              className="input py-1 text-sm normal-case"
              aria-label="Behaviour model window"
              value={windowStart ?? data.window?.start ?? ""}
              onChange={(event) => {
                setWindowStart(event.target.value || null);
                setShowAll(false);
              }}
            >
              {data.windows.map((item) => (
                <option key={item.start} value={item.start}>{windowLabel(item.start, item.logs)}</option>
              ))}
            </select>
          </label>
        ) : null}
      </div>

      {query.isLoading ? <p className="mt-4 text-sm font-semibold text-muted">Running the model over the latest traffic...</p> : null}
      {query.isError ? <ErrorBanner error={query.error} fallback="The behaviour model's view is unavailable." /> : null}
      {data && !data.model?.available ? (
        <p className="mt-4 rounded-lg border border-line bg-panel2 p-4 text-sm font-semibold text-muted" data-testid="behavior-model-missing">
          {data.model?.detail ?? "The behaviour model's view is unavailable."}
        </p>
      ) : null}

      {data?.model?.available && data.window ? (
        <div className="mt-4 space-y-4">
          {data.window.in_training_data ? (
            <div className="rounded-lg border border-amber/50 bg-amber/10 px-4 py-3 text-sm font-bold text-amber" data-testid="behavior-training-window">
              This window was part of the model's training data, so it shows what the model learned rather than a fair test.
              The fair test used traffic the model never saw (docs/detection/ML_QUALITY_BAR.md).
            </div>
          ) : null}
          {summary ? (
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" data-testid="behavior-summary">
              <div className="rounded-lg border border-line bg-panel2 p-3">
                <div className="text-xs font-bold uppercase tracking-wide text-muted">Sources checked</div>
                <div className="mt-1 text-xl font-black text-text">{summary.sources_checked.toLocaleString()}</div>
                <div className="text-xs font-semibold text-muted">{windowLabel(data.window.start)}</div>
              </div>
              <div className="rounded-lg border border-line bg-panel2 p-3">
                <div className="text-xs font-bold uppercase tracking-wide text-muted">Attack behaviour found</div>
                <div className="mt-1 text-xl font-black text-text">{summary.flagged.toLocaleString()}</div>
                <div className="text-xs font-semibold text-muted">
                  {(summary.flagged - summary.model_only).toLocaleString()} also alerted by the rules, {summary.model_only.toLocaleString()} found only by the model
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel2 p-3">
                <div className="text-xs font-bold uppercase tracking-wide text-muted">Internet background probing</div>
                <div className="mt-1 text-xl font-black text-text">{probing?.sources.toLocaleString() ?? 0} hosts</div>
                <div className="text-xs font-semibold text-muted">
                  probed {probing?.mfu_hosts_touched.toLocaleString() ?? 0} MFU addresses with {probing?.connections.toLocaleString() ?? 0} unanswered connections
                  {probing?.top_ports.length ? `; top ports ${probing.top_ports.map((item) => item.port).join(", ")}` : ""}. Normal internet noise, summarised instead of alerted.
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel2 p-3" data-testid="behavior-p2p-policy">
                <div className="text-xs font-bold uppercase tracking-wide text-muted">Peer-to-peer file sharing (policy)</div>
                <div className="mt-1 text-xl font-black text-text">{p2p?.sources.toLocaleString() ?? 0} devices</div>
                <div className="text-xs font-semibold text-muted">
                  {p2p?.connections.toLocaleString() ?? 0} connections to {p2p?.peers.toLocaleString() ?? 0} peers
                  {p2p?.apps.length ? ` (${p2p.apps.map((item) => item.app).join(", ")})` : ""}. A policy matter, not an attack: not counted as attack behaviour, alerted only with malicious evidence.
                </div>
              </div>
            </div>
          ) : null}
          {findings.length ? (
            <div className="space-y-3">
              {visible.map((finding) => (
                <FindingCard key={`${finding.source}-${finding.window_start}`} finding={finding} />
              ))}
              {findings.length > VISIBLE_FINDINGS ? (
                <button className="btn-secondary text-xs" type="button" onClick={() => setShowAll((value) => !value)}>
                  {showAll ? "Show fewer" : `Show all ${findings.length} findings`}
                </button>
              ) : null}
            </div>
          ) : (
            <p className="text-sm font-semibold text-muted" data-testid="behavior-no-findings">The model sees no attack behaviour in this window.</p>
          )}
          <p className="text-xs font-semibold text-muted">
            Model {data.model.version}, trained on {data.model.trained_on}. {data.model.detail}
          </p>
        </div>
      ) : null}
    </section>
  );
}

export function BehaviorAlertOpinionCard({ alertId }: { alertId: number }) {
  const query = useBehaviorAlertOpinion(alertId);
  const opinion = query.data;
  if (!opinion) return null;
  const verdict = opinion.background_probe
    ? "sees internet background probing from this source, which it summarises rather than alerts on"
    : opinion.p2p_policy
      ? "sees mostly peer-to-peer file sharing from this source, which is policy activity rather than an attack"
      : opinion.wrong_direction
        ? `finds this closest to ${opinion.attack_label}, but that needs traffic leaving MFU and this source's traffic mostly comes in, so it does not flag it`
        : opinion.flagged
      ? `sees ${opinion.attack_label} behaviour (${percent(opinion.confidence)})`
      : `does not see clear attack behaviour from this source (attack score ${percent(opinion.confidence)})`;
  return (
    <section className="rounded-lg border border-line bg-panel2 p-4" data-testid="behavior-alert-opinion">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-extrabold uppercase tracking-wide text-muted">MFU behaviour model</div>
        {opinion.flagged ? (
          <span className={`rounded-full border px-2 py-0.5 text-xs font-black uppercase tracking-wide ${opinion.agrees_with_rules ? "border-success/40 bg-success/10 text-success" : "border-amber/50 bg-amber/10 text-amber"}`}>
            {opinion.agrees_with_rules ? "Agrees with the rules" : "Sees a different attack type"}
          </span>
        ) : null}
      </div>
      <p className="mt-1 text-sm font-semibold text-text">The model {verdict}.</p>
      {opinion.reasons.length ? (
        <ul className="mt-2 list-disc space-y-1 pl-4 text-sm font-semibold text-text">
          {opinion.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      ) : null}
      <p className="mt-2 text-xs font-semibold text-muted">Advisory only: the rules decide alerts.</p>
    </section>
  );
}
