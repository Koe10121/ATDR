import { FormEvent, useState } from "react";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { MetricCard } from "../components/MetricCard";
import { useAuth } from "../hooks/useAuth";
import { useBlockedIps, useDetectionTuning, useResponseMutations, useSuppressions, useThreatControlMutations, useWatchlists } from "../hooks/useApiQueries";

type Tab = "suppressions" | "watchlists" | "blocked" | "policy";

export function ThreatControls() {
  const { isAdmin } = useAuth();
  const [tab, setTab] = useState<Tab>("suppressions");
  const suppressions = useSuppressions();
  const watchlists = useWatchlists();
  const blocked = useBlockedIps();
  const tuning = useDetectionTuning();
  const controls = useThreatControlMutations();
  const response = useResponseMutations();

  const [suppression, setSuppression] = useState({ src_ip: "", app: "", alert_type: "", reason: "" });
  const [watchlist, setWatchlist] = useState({ indicator_type: "src_ip", indicator_value: "", description: "", severity_boost: 30 });
  const [block, setBlock] = useState({ target_ip: "", reason: "SOC analyst-approved simulated containment." });

  function createSuppression(event: FormEvent) {
    event.preventDefault();
    controls.createSuppression.mutate({
      src_ip: suppression.src_ip || undefined,
      app: suppression.app || undefined,
      alert_type: suppression.alert_type || undefined,
      reason: suppression.reason
    });
  }

  function createWatchlist(event: FormEvent) {
    event.preventDefault();
    controls.createWatchlist.mutate(watchlist);
  }

  function blockIp(event: FormEvent) {
    event.preventDefault();
    if (block.target_ip && window.confirm(`Record simulated block for ${block.target_ip}?`)) {
      response.blockIp.mutate({ targetIp: block.target_ip, reason: block.reason });
    }
  }

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: "suppressions", label: "Suppressions" },
    { id: "watchlists", label: "Watchlists" },
    { id: "blocked", label: "Simulated Blocked IPs" },
    { id: "policy", label: "Detection Policy" }
  ];

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Threat Controls</div>
        <h1 className="mt-2 text-3xl font-black">Govern alert noise, watchlists, and simulated containment.</h1>
        <p className="mt-2 text-muted">Controls are audited. Real firewall enforcement remains disabled.</p>
      </section>

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Active Suppressions" value={(suppressions.data ?? []).filter((item) => item.active).length} detail="Noise controls" tone="amber" />
        <MetricCard label="Watchlist Items" value={(watchlists.data ?? []).filter((item) => item.active).length} detail="Priority indicators" tone="danger" />
        <MetricCard label="Blocked IPs" value={blocked.data?.length ?? "-"} detail="Simulation mode only" tone="danger" />
        <MetricCard label="Admin Controls" value={isAdmin ? "Enabled" : "Read-only"} detail="RBAC enforced by backend" tone="cyan" />
      </div>

      <div className="flex flex-wrap gap-2">
        {tabs.map((item) => (
          <button key={item.id} className={tab === item.id ? "btn-primary" : "btn-secondary"} onClick={() => setTab(item.id)}>
            {item.label}
          </button>
        ))}
      </div>

      {tab === "suppressions" ? (
        <div className="grid gap-4 xl:grid-cols-[0.8fr_1.2fr]">
          <form className="panel space-y-3" onSubmit={createSuppression}>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Add Suppression</div>
            <input className="input" placeholder="Source IP criterion" value={suppression.src_ip} onChange={(event) => setSuppression({ ...suppression, src_ip: event.target.value })} disabled={!isAdmin} />
            <input className="input" placeholder="App criterion" value={suppression.app} onChange={(event) => setSuppression({ ...suppression, app: event.target.value })} disabled={!isAdmin} />
            <input className="input" placeholder="Alert type criterion" value={suppression.alert_type} onChange={(event) => setSuppression({ ...suppression, alert_type: event.target.value })} disabled={!isAdmin} />
            <textarea className="input min-h-24" placeholder="Reason" value={suppression.reason} onChange={(event) => setSuppression({ ...suppression, reason: event.target.value })} disabled={!isAdmin} />
            <button className="btn-primary w-full" disabled={!isAdmin || controls.createSuppression.isPending}>Create suppression</button>
            {!isAdmin ? <div className="text-xs text-muted">Analysts can review suppressions but cannot create or disable them.</div> : null}
          </form>
          <section className="panel space-y-3">
            {suppressions.isError ? <ErrorBanner error={suppressions.error} /> : null}
            {(suppressions.data ?? []).map((item) => (
              <div key={item.id} className="rounded-lg border border-line bg-panel2 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-bold">#{item.id} {item.alert_type ?? item.app ?? item.src_ip ?? "generic suppression"}</div>
                  <Badge value={item.active ? item.review_status : "false_positive"} />
                </div>
                <div className="mt-2 text-sm text-muted">{item.reason}</div>
                <div className="mt-2 text-xs text-muted">Created by {item.created_by} | Suppressed hits {item.suppressed_count}</div>
                <div className="mt-3 flex gap-2">
                  <button className="btn-secondary" disabled={!isAdmin || !item.active} onClick={() => controls.reviewSuppression.mutate({ id: item.id, status: "reviewed", notes: "Reviewed from React SOC console." })}>Mark reviewed</button>
                  <button className="btn-secondary" disabled={!isAdmin || !item.active} onClick={() => window.confirm("Disable this suppression?") && controls.disableSuppression.mutate(item.id)}>Disable</button>
                </div>
              </div>
            ))}
            {!suppressions.isLoading && !(suppressions.data ?? []).length ? <EmptyState title="No suppressions" body="No suppression controls are configured." /> : null}
          </section>
        </div>
      ) : null}

      {tab === "watchlists" ? (
        <div className="grid gap-4 xl:grid-cols-[0.8fr_1.2fr]">
          <form className="panel space-y-3" onSubmit={createWatchlist}>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Add Watchlist Item</div>
            <select className="input" value={watchlist.indicator_type} onChange={(event) => setWatchlist({ ...watchlist, indicator_type: event.target.value })} disabled={!isAdmin}>
              <option value="src_ip">Source IP</option>
              <option value="dst_ip">Destination IP</option>
              <option value="app">Application</option>
            </select>
            <input className="input" placeholder="Indicator value" value={watchlist.indicator_value} onChange={(event) => setWatchlist({ ...watchlist, indicator_value: event.target.value })} disabled={!isAdmin} />
            <textarea className="input min-h-24" placeholder="Description" value={watchlist.description} onChange={(event) => setWatchlist({ ...watchlist, description: event.target.value })} disabled={!isAdmin} />
            <input className="input" type="number" min={5} max={60} value={watchlist.severity_boost} onChange={(event) => setWatchlist({ ...watchlist, severity_boost: Number(event.target.value) })} disabled={!isAdmin} />
            <button className="btn-primary w-full" disabled={!isAdmin || controls.createWatchlist.isPending}>Create watchlist item</button>
          </form>
          <section className="panel space-y-3">
            {(watchlists.data ?? []).map((item) => (
              <div key={item.id} className="rounded-lg border border-line bg-panel2 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-bold">{item.indicator_type}: {item.indicator_value}</div>
                  <Badge value={item.active ? "available" : "false_positive"} />
                </div>
                <div className="mt-2 text-sm text-muted">{item.description}</div>
                <div className="mt-2 text-xs text-muted">Boost {item.severity_boost} | Matches {item.match_count} | Created by {item.created_by}</div>
                <button className="btn-secondary mt-3" disabled={!isAdmin || !item.active} onClick={() => window.confirm("Disable this watchlist item?") && controls.disableWatchlist.mutate(item.id)}>Disable</button>
              </div>
            ))}
            {!watchlists.isLoading && !(watchlists.data ?? []).length ? <EmptyState title="No watchlist items" body="No priority indicators are configured." /> : null}
          </section>
        </div>
      ) : null}

      {tab === "blocked" ? (
        <div className="grid gap-4 xl:grid-cols-[0.8fr_1.2fr]">
          <form className="panel space-y-3" onSubmit={blockIp}>
            <Badge value="ready" />
            <div className="text-sm text-muted">Simulation Mode: records containment evidence only. No firewall devices are modified.</div>
            <input className="input" placeholder="IP address" value={block.target_ip} onChange={(event) => setBlock({ ...block, target_ip: event.target.value })} disabled={!isAdmin} />
            <textarea className="input min-h-24" value={block.reason} onChange={(event) => setBlock({ ...block, reason: event.target.value })} disabled={!isAdmin} />
            <button className="btn-primary w-full" disabled={!isAdmin || response.blockIp.isPending}>Record simulated block</button>
          </form>
          <section className="panel space-y-3">
            {(blocked.data ?? []).map((item) => (
              <div key={item.id} className="rounded-lg border border-line bg-panel2 p-4">
                <div className="font-bold">{item.ip_address}</div>
                <div className="mt-1 text-sm text-muted">{item.reason ?? "No reason"} | by {item.created_by}</div>
                <button className="btn-secondary mt-3" disabled={!isAdmin} onClick={() => window.confirm(`Unblock ${item.ip_address}?`) && response.unblockIp.mutate({ targetIp: item.ip_address, reason: "Removed from Threat Controls." })}>Unblock</button>
              </div>
            ))}
            {!blocked.isLoading && !(blocked.data ?? []).length ? <EmptyState title="No simulated blocks" body="The simulated containment list is empty." /> : null}
          </section>
        </div>
      ) : null}

      {tab === "policy" ? (
        <section className="panel space-y-3">
          <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Detection Thresholds / Policy Overview</div>
          {(tuning.data?.production_readiness ?? []).map((item) => (
            <div key={item.name} className="rounded-lg border border-line bg-panel2 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="font-bold">{item.name}</div>
                <Badge value={item.status} />
              </div>
              <div className="mt-2 text-sm text-muted">{item.detail}</div>
              {item.recommendation ? <div className="mt-2 text-xs text-amber">{item.recommendation}</div> : null}
            </div>
          ))}
          {!tuning.isLoading && !(tuning.data?.production_readiness ?? []).length ? <EmptyState title="No policy data" body="Run detection tuning after importing logs." /> : null}
        </section>
      ) : null}
    </div>
  );
}
