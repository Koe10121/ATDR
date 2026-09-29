import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorBanner } from "./ErrorBanner";
import { useBehaviorAlertOpinion, useBehaviorFindings, useBehaviorModelStatus } from "../hooks/useApiQueries";
import type { BehaviorFinding, BehaviorQualityBar, BehaviorQualityBarType } from "../types/api";

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
  if (finding.model_alert_ids?.length) {
    return (
      <span className="rounded-full border border-amber/50 bg-amber/10 px-2 py-0.5 text-xs font-black uppercase tracking-wide text-amber">
        Model only: experimental alert
      </span>
    );
  }
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
        {finding.model_alert_ids?.length ? (
          <>
            {" "}· experimental alert{" "}
            <Link className="font-bold text-cyan hover:underline" to={`/alerts?alert=${finding.model_alert_ids[0]}`}>
              #{finding.model_alert_ids[0]}
            </Link>
          </>
        ) : null}
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
            {data?.model?.alerting_types?.length
              ? " Where the rules raise no alert it raises its own experimental alerts, marked low confidence: no attack type passed its quality bar."
              : " It is advisory: it does not create alerts until an attack type passes the quality bar."}
          </p>
          {data?.model?.data_limit ? (
            <p className="mt-1 text-xs font-bold text-amber" data-testid="data-limit-note">{data.model.data_limit}</p>
          ) : null}
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


const ATTACK_TYPE_NAMES: Record<string, string> = {
  port_scan: "Port scan",
  brute_force: "Brute force",
  dos_ddos: "Flood / denial of service",
  malware_c2: "Malware C2 beaconing",
  data_exfiltration_suspicion: "Data exfiltration"
};

function reviewText(entry: BehaviorQualityBarType, bar: BehaviorQualityBar): { text: string; ok: boolean | null } {
  const review = entry.condition_1;
  const counted = `${review.threat ?? 0} of ${review.judged ?? 0} judged real`;
  switch (review.status) {
    case "pending":
      return { text: `Blind review in progress (${review.model_only} windows)`, ok: null };
    case "cannot_pass":
      return review.model_only === 0
        ? { text: "Nothing to review: it found nothing the rules missed", ok: false }
        : { text: `Only ${review.model_only} model-only windows; ${bar.min_reviewed} needed`, ok: false };
    case "pass":
      return { text: counted, ok: true };
    case "needs_person":
      return { text: `${counted}, but a person must do or check the review`, ok: false };
    default: {
      // Unsure rows are not judged, so a type can miss the bar on the count alone.
      const judged = review.judged ?? 0;
      if (judged < bar.min_reviewed) {
        const unsure = review.model_only - judged;
        return { text: `${counted}; ${bar.min_reviewed} judged needed${unsure > 0 ? ` (${unsure} unsure)` : ""}`, ok: false };
      }
      return { text: `${counted} (90% needed)`, ok: false };
    }
  }
}

function TrafficFigure({ label, value, detail }: { label: string; value: number; detail: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-line bg-panel2 p-3">
      <div className="text-xs font-extrabold uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-1 text-2xl font-black text-text">{value.toLocaleString("en-US")}</div>
      <div className="mt-1 text-xs font-semibold text-muted">{detail}</div>
    </div>
  );
}

function Mark({ ok }: { ok: boolean | null }) {
  if (ok === null) return <span className="text-xs font-black uppercase text-amber">Pending</span>;
  return ok ? <span className="text-xs font-black uppercase text-success">Passes</span> : <span className="text-xs font-black uppercase text-danger">Not met</span>;
}

/** The AI Governance lead: the MFU-trained model and where each attack type stands on its quality bar. */
export function BehaviorModelGovernance() {
  const query = useBehaviorModelStatus();
  const status = query.data;
  const bar = status?.quality_bar;
  const windows = bar?.windows.map((window) => `${window.start.slice(11, 16)}-${window.end.slice(11, 16)}`).join(" and ");
  // Types that fail nothing yet: only the team's blind review of their extra finds is outstanding.
  const canStillPass = bar
    ? Object.entries(bar.types)
        .filter(([, entry]) => !entry.eligible && entry.condition_2.passes && bar.condition_3.passes)
        .filter(([, entry]) => entry.condition_1.status === "pending" || entry.condition_1.status === "needs_person")
        .map(([type]) => ATTACK_TYPE_NAMES[type] ?? type)
    : [];
  const traffic = bar?.real_traffic;
  return (
    <section className="panel space-y-4" data-testid="governance-mfu-model">
      <div>
        <div className="text-xs font-extrabold uppercase tracking-wide text-cyan">Start here</div>
        <h2 className="mt-1 text-2xl font-black text-text">The MFU behaviour model</h2>
        <p className="mt-1 text-sm text-muted">
          Trained only on MFU's own firewall traffic. For each device's five minutes of traffic it names the attack, explains why and shows how
          to respond, on the Overview and on every alert. It may raise alerts on its own only for attack types that pass the quality bar
          declared before training; until then it advises and the rules decide.
        </p>
      </div>
      {query.isError ? <ErrorBanner error={query.error} fallback="The behaviour model's status is unavailable." /> : null}
      {status?.data_limit ? <p className="text-sm font-bold text-amber" data-testid="governance-data-limit">{status.data_limit}</p> : null}
      {status && !status.available ? <p className="text-sm font-semibold text-muted">{status.detail}</p> : null}
      {status?.available ? (
        <p className="text-sm font-semibold text-text">
          {status.version}, trained on {status.trained_on}. {status.detail}
          {bar
            ? canStillPass.length
              ? ` ${canStillPass.join(" and ")} can still pass this round, if the team's blind review confirms the extra finds.`
              : " No attack type can pass this round."
            : ""}
        </p>
      ) : null}
      {status?.experimental_alerting ? (
        <p className="rounded-lg border border-amber/50 bg-amber/10 px-4 py-3 text-sm font-semibold text-amber" data-testid="governance-experimental">
          Experimental model alerts are on for {status.experimental_alerting.types.map((type) => ATTACK_TYPE_NAMES[type] ?? type).join(", ")}:
          switched on by {status.experimental_alerting.enabled_by} on {status.experimental_alerting.enabled_at.slice(0, 10)}.{" "}
          {status.experimental_alerting.reason} Each such alert says it is experimental and low confidence, and none triggers a response.
        </p>
      ) : null}
      {status?.available && traffic ? (
        <div className="grid gap-3 sm:grid-cols-3" data-testid="governance-real-traffic">
          <TrafficFigure
            label="Device-windows scored"
            value={traffic.windows}
            detail={`Five minutes of one device's traffic each, 20 May ${windows}: traffic the model never trained on.`}
          />
          <TrafficFigure
            label="Flagged by the model"
            value={traffic.model_flagged}
            detail={`${(traffic.model_flagged - traffic.model_only).toLocaleString("en-US")} of them also raised a rule alert.`}
          />
          <TrafficFigure
            label="Extra finds"
            value={traffic.model_only}
            detail="Flagged with no rule alert. The team's blind review decides whether they are real."
          />
        </div>
      ) : null}
      {status?.available && bar ? (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm" data-testid="governance-quality-bar">
              <thead className="text-xs uppercase tracking-wide text-muted">
                <tr>
                  <th className="py-2 pr-4">Attack type</th>
                  <th className="py-2 pr-4">1. Its extra finds are real (blind review, 90%+)</th>
                  <th className="py-2 pr-4">2. Finds fresh simulated attacks (90%+)</th>
                  <th className="py-2 pr-4">Model alerts</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(bar.types).map(([type, entry]) => {
                  const review = reviewText(entry, bar);
                  return (
                    <tr key={type} className="border-t border-line align-top">
                      <td className="py-2 pr-4 font-bold">{ATTACK_TYPE_NAMES[type] ?? type}</td>
                      <td className="py-2 pr-4">
                        <Mark ok={review.ok} /> <span className="text-muted">{review.text}</span>
                      </td>
                      <td className="py-2 pr-4">
                        <Mark ok={entry.condition_2.passes} /> <span className="text-muted">{(entry.condition_2.found * 100).toFixed(1)}% found</span>
                      </td>
                      <td className="py-2 pr-4 font-bold">
                        {entry.eligible ? "Can be switched on" : status.alerting_types?.includes(type) ? "Experimental" : "Advisory"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p className="text-xs font-semibold text-muted">
            3. Rules or model must not lower accuracy on the blind-check labels: F1 {bar.condition_3.rules_or_model_f1 === null ? "-" : percent(bar.condition_3.rules_or_model_f1)} vs
            rules alone {bar.condition_3.rules_f1 === null ? "-" : percent(bar.condition_3.rules_f1)} ({bar.condition_3.passes ? "holds" : "not met"}). Tested on 20 May{" "}
            {windows}, traffic the model never trained on. The bar is in docs/detection/ML_QUALITY_BAR.md; the full record in ML_MODEL_CARD.md.
          </p>
        </>
      ) : null}
      {status?.available && !bar ? <p className="text-sm font-semibold text-muted">No quality-bar evaluation is recorded for this model yet.</p> : null}
    </section>
  );
}
