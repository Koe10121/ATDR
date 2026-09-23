import { FormEvent, useState } from "react";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { MetricCard } from "../components/MetricCard";
import { SafeSelect } from "../components/SafeSelect";
import { useAuth } from "../hooks/useAuth";
import { useBlockedIps, useHealth, useResponseMutations } from "../hooks/useApiQueries";

const DURATION_OPTIONS = [
  { label: "Until manually removed", minutes: null },
  { label: "15 minutes", minutes: 15 },
  { label: "1 hour", minutes: 60 },
  { label: "4 hours", minutes: 240 },
  { label: "24 hours", minutes: 1440 }
];

function timeRemaining(expiresAt?: string | null): string | null {
  if (!expiresAt) return null;
  const deltaMs = new Date(expiresAt).getTime() - Date.now();
  if (deltaMs <= 0) return "expiring";
  const minutes = Math.round(deltaMs / 60000);
  if (minutes < 60) return `${minutes}m left`;
  const hours = Math.round(minutes / 60);
  return `${hours}h left`;
}

export function ResponseCenter() {
  const { isAdmin } = useAuth();
  const health = useHealth();
  const blocked = useBlockedIps();
  const { blockIp, unblockIp } = useResponseMutations();
  const [targetIp, setTargetIp] = useState("");
  const [reason, setReason] = useState("Analyst-reviewed containment action.");
  const [durationMinutes, setDurationMinutes] = useState<number | null>(null);
  const responseMode = health.data?.checks.response_mode?.status ?? "unknown";
  const isRealEnforcement = health.data?.checks.response_mode?.real_enforcement_possible === true;

  const headline = isRealEnforcement
    ? "Containment actions really block traffic on this host."
    : responseMode === "pending_connector"
      ? "A firewall connector is configured but not implemented; actions are recorded only."
      : "Containment actions stay simulated by default.";
  const subhead = isRealEnforcement
    ? "Blocking creates a real, reversible Windows Firewall rule on the machine running ATDR. It does not affect any other device."
    : "Record analyst-approved simulated actions and audit evidence.";

  function onBlock(event: FormEvent) {
    event.preventDefault();
    const cleanTarget = targetIp.trim();
    const cleanReason = reason.trim();
    if (cleanTarget && cleanReason.length >= 8) {
      const durationLabel = DURATION_OPTIONS.find((option) => option.minutes === durationMinutes)?.label ?? "until manually removed";
      const confirmationBody = isRealEnforcement
        ? `Create a REAL Windows Firewall block for ${cleanTarget} (${durationLabel}) on this host?\n\nThis will actually drop inbound/outbound traffic to this address on the ATDR backend machine. Audit will record this action with your user account and reason.`
        : `Record a simulated block for ${cleanTarget}?\n\nNo real firewall device will be changed. Audit will record this action with your user account and reason.`;
      const confirmed = window.confirm(confirmationBody);
      if (confirmed) {
        blockIp.mutate({ targetIp: cleanTarget, reason: cleanReason, durationMinutes });
      }
    }
  }

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-danger">Response & Audit</div>
        <h1 className="mt-2 text-3xl font-black">{headline}</h1>
        <p className="mt-2 text-muted">{subhead}</p>
      </section>

      {health.isError || blocked.isError ? (
        <ErrorBanner
          error={health.error ?? blocked.error}
          fallback="Response status is temporarily unavailable. No action was executed."
        />
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <MetricCard
          label="Response Mode"
          value={isRealEnforcement ? "Real enforcement" : responseMode}
          detail={isRealEnforcement ? "Windows Firewall on this host" : "Real enforcement remains unsupported"}
          tone={isRealEnforcement ? "amber" : responseMode === "simulation" ? "success" : "danger"}
        />
        <MetricCard label="Active Blocks" value={blocked.data?.length ?? "-"} detail={isRealEnforcement ? "Real + simulated containment list" : "Simulated containment list"} tone="danger" />
        <MetricCard label="Admin Actions" value={isAdmin ? "Enabled" : "Read-only"} detail="Role-gated response controls" tone="amber" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[0.8fr_1.2fr]">
        <form onSubmit={onBlock} className="panel">
          <div className="mb-4 flex items-center justify-between">
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">
              {isRealEnforcement ? "Real Response Approval" : "Simulated Response Approval"}
            </div>
            <Badge value={responseMode === "simulation" || isRealEnforcement ? "ready" : "blocked"} />
          </div>
          <input aria-label="Response target IP address" className="input" placeholder="IP address" value={targetIp} onChange={(event) => setTargetIp(event.target.value)} disabled={!isAdmin} />
          <textarea aria-label="Response justification" className="input mt-3 min-h-24" value={reason} onChange={(event) => setReason(event.target.value)} disabled={!isAdmin} />
          <label className="mt-3 block text-xs font-bold uppercase tracking-wide text-muted">
            Timeout
            <SafeSelect
              className="mt-1"
              disabled={!isAdmin}
              value={durationMinutes ?? ""}
              options={DURATION_OPTIONS.map((option) => ({ value: String(option.minutes ?? ""), label: option.label }))}
              onChange={(next) => setDurationMinutes(next === "" ? null : Number(next))}
              ariaLabel="Response block timeout"
            />
          </label>
          <div className="mt-2 text-xs text-muted">
            A justification note is required. Internal/management ranges and the ATDR host itself are protected from blocks.
          </div>
          <button className="btn-primary mt-4 w-full" disabled={!isAdmin || blockIp.isPending || !targetIp.trim() || reason.trim().length < 8}>
            {blockIp.isPending ? "Recording..." : isRealEnforcement ? "Apply real block" : "Record simulated block"}
          </button>
          {blockIp.data ? (
            <div
              className={`mt-3 rounded-lg border p-3 text-sm ${
                blockIp.data.status === "denied" || blockIp.data.status === "enforcement_failed"
                  ? "border-danger/30 bg-danger/10 text-danger"
                  : "border-success/30 bg-success/10 text-success"
              }`}
            >
              {blockIp.data.result_message}
            </div>
          ) : null}
          {blockIp.error ? <div className="mt-3"><ErrorBanner error={blockIp.error} /></div> : null}
          {!isAdmin ? <div className="mt-3 text-xs text-muted">Only admins can record block/unblock actions.</div> : null}
        </form>

        <section className="panel">
          <div className="mb-4 text-sm font-extrabold uppercase tracking-wide text-muted">Active Blocks</div>
          <div className="space-y-3">
            {(blocked.data ?? []).map((item) => {
              const remaining = timeRemaining(item.expires_at);
              return (
                <div key={item.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-panel2 p-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold">{item.ip_address}</span>
                      <Badge value={item.enforcement === "windows_firewall" ? "Real Block" : "Simulated"} />
                      {remaining ? <span className="text-xs font-semibold text-amber">{remaining}</span> : null}
                    </div>
                    <div className="text-sm text-muted">{item.reason ?? "No reason recorded"} | by {item.created_by}</div>
                  </div>
                  <button
                    className="btn-secondary"
                    disabled={!isAdmin || unblockIp.isPending}
                    onClick={() => {
                      const body = item.enforcement === "windows_firewall"
                        ? `Remove the real Windows Firewall block for ${item.ip_address}? Traffic to/from this address will be allowed again. This will be audited.`
                        : `Remove the simulated block for ${item.ip_address}? This will be audited.`;
                      if (window.confirm(body)) {
                        unblockIp.mutate({ targetIp: item.ip_address, reason: "Operator removed containment after analyst review." });
                      }
                    }}
                  >
                    Unblock
                  </button>
                </div>
              );
            })}
            {!blocked.isLoading && !(blocked.data ?? []).length ? <EmptyState title="No active blocks" body="No containment entries are active." /> : null}
          </div>
        </section>
      </div>
    </div>
  );
}
