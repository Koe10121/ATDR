import { FormEvent, useState } from "react";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { MetricCard } from "../components/MetricCard";
import { useAuth } from "../hooks/useAuth";
import { useBlockedIps, useHealth, useResponseMutations } from "../hooks/useApiQueries";

export function ResponseCenter() {
  const { isAdmin } = useAuth();
  const health = useHealth();
  const blocked = useBlockedIps();
  const { blockIp, unblockIp } = useResponseMutations();
  const [targetIp, setTargetIp] = useState("");
  const [reason, setReason] = useState("Analyst-reviewed containment action.");
  const responseMode = health.data?.checks.response_mode?.status ?? "unknown";

  function onBlock(event: FormEvent) {
    event.preventDefault();
    if (targetIp.trim()) {
      blockIp.mutate({ targetIp: targetIp.trim(), reason });
    }
  }

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Response Center</div>
        <h1 className="mt-2 text-3xl font-black">Containment actions stay simulated by default.</h1>
        <p className="mt-2 text-muted">This console records block/unblock actions, blocked IP state, and audit evidence without changing a real firewall.</p>
      </section>

      <div className="grid gap-4 md:grid-cols-3">
        <MetricCard label="Response Mode" value={responseMode} detail="Real enforcement remains unsupported" tone={responseMode === "simulation" ? "success" : "danger"} />
        <MetricCard label="Active Blocked IPs" value={blocked.data?.length ?? "-"} detail="Simulated containment list" tone="danger" />
        <MetricCard label="Admin Actions" value={isAdmin ? "Enabled" : "Read-only"} detail="Role-gated response controls" tone="amber" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[0.8fr_1.2fr]">
        <form onSubmit={onBlock} className="panel">
          <div className="mb-4 flex items-center justify-between">
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Simulated Block</div>
            <Badge value={responseMode === "simulation" ? "ready" : "blocked"} />
          </div>
          <input className="input" placeholder="IP address" value={targetIp} onChange={(event) => setTargetIp(event.target.value)} disabled={!isAdmin} />
          <textarea className="input mt-3 min-h-24" value={reason} onChange={(event) => setReason(event.target.value)} disabled={!isAdmin} />
          <button className="btn-primary mt-4 w-full" disabled={!isAdmin || blockIp.isPending}>
            {blockIp.isPending ? "Recording..." : "Record simulated block"}
          </button>
          {blockIp.data ? <div className="mt-3 rounded-lg border border-success/30 bg-success/10 p-3 text-sm text-success">{blockIp.data.result_message}</div> : null}
          {!isAdmin ? <div className="mt-3 text-xs text-muted">Only admins can record block/unblock actions.</div> : null}
        </form>

        <section className="panel">
          <div className="mb-4 text-sm font-extrabold uppercase tracking-wide text-muted">Active Simulated Blocks</div>
          <div className="space-y-3">
            {(blocked.data ?? []).map((item) => (
              <div key={item.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-panel2 p-3">
                <div>
                  <div className="font-bold">{item.ip_address}</div>
                  <div className="text-sm text-muted">{item.reason ?? "No reason recorded"} | by {item.created_by}</div>
                </div>
                <button
                  className="btn-secondary"
                  disabled={!isAdmin || unblockIp.isPending}
                  onClick={() => unblockIp.mutate({ targetIp: item.ip_address, reason: "Operator removed simulated containment." })}
                >
                  Unblock
                </button>
              </div>
            ))}
            {!blocked.isLoading && !(blocked.data ?? []).length ? <EmptyState title="No active blocks" body="No simulated containment entries are active." /> : null}
          </div>
        </section>
      </div>
    </div>
  );
}
