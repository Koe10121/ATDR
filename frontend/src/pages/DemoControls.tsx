import { useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Upload } from "lucide-react";
import { ActionResultCard } from "../components/ActionResultCard";
import { Badge } from "../components/Badge";
import { ErrorBanner } from "../components/ErrorBanner";
import { MetricCard } from "../components/MetricCard";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { useDashboardSummary, useDemoMutations, useDetectionCoverage, useHealth, useMlReport, useQueuedImportMutation } from "../hooks/useApiQueries";
import { api } from "../lib/api";
import type { AutomaticDetectionStatus, LiveFeedStatus } from "../types/api";

const count = (value: number) => value.toLocaleString("en-US");
const plural = (value: number, one: string, many: string) => `${count(value)} ${value === 1 ? one : many}`;
const clock = (value: string | null) =>
  value ? new Date(value).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }) : "";

function secondsAgo(value: string | null): string {
  if (!value) return "";
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${plural(seconds, "second", "seconds")} ago`;
  const minutes = Math.round(seconds / 60);
  return minutes < 60 ? `${plural(minutes, "minute", "minutes")} ago` : `at ${clock(value)}`;
}

function liveFeedText(feed: LiveFeedStatus, automaticChecksRunning: boolean): { state: string; detail: string } {
  const lost = feed.dropped ? `${plural(feed.dropped, "line", "lines")} lost` : "none lost";
  // Only logs detection has checked are deleted, so without automatic checks nothing would go.
  const kept = !feed.keep_hours
    ? ""
    : automaticChecksRunning
      ? ` Logs are kept for ${plural(feed.keep_hours, "hour", "hours")}, then summarised by hour; alert evidence stays.`
      : ` Logs are meant to be kept for ${plural(feed.keep_hours, "hour", "hours")}, but only checked logs are deleted and automatic checks are not running, so they pile up.`;
  if (feed.state === "receiving" && feed.disk_low) {
    return {
      state: "Live syslog is paused: the disk is almost full.",
      detail: `Less than ${count(feed.min_free_disk_gb ?? 0)} GB is free${
        feed.free_disk_gb === null || feed.free_disk_gb === undefined ? "" : ` (${feed.free_disk_gb.toFixed(1)} GB now)`
      }, so new lines are counted as lost instead of saved: ${plural(feed.dropped_disk_low ?? 0, "line", "lines")} so far. Saving resumes by itself when space is freed.`
    };
  }
  switch (feed.state) {
    case "off":
      return { state: "Live syslog is off.", detail: "Logs arrive only through imports." };
    case "not_started":
      return { state: "Live syslog is on, but the receiver has not started.", detail: "Firewall logs sent now are not received. Restart ATDR to start it." };
    case "not_reporting":
      return {
        state: "Live syslog is on, but the receiver has stopped reporting.",
        detail: `Its last report was at ${clock(feed.reported_at)}. Firewall logs may not be received; restart ATDR.`
      };
    case "stopped":
      return {
        state: "Live syslog is on, but the receiver is stopped.",
        detail: `It stopped${feed.finished_at ? ` at ${clock(feed.finished_at)}` : ""} after receiving ${plural(feed.received, "line", "lines")}, ${lost}. Restart ATDR to start it again.`
      };
    default: {
      const rate = feed.lines_per_second === null ? "" : `About ${count(Math.round(feed.lines_per_second))} lines a second. `;
      const last = feed.last_received_at ? ` Last line ${secondsAgo(feed.last_received_at)}.` : " No line has arrived yet.";
      return {
        state: `Live syslog is receiving on UDP port ${feed.port}.`,
        detail: `${rate}Since ${clock(feed.started_at)}: ${plural(feed.received, "line", "lines")} received, ${count(feed.saved)} saved, ${lost}.${last}${kept}`
      };
    }
  }
}

function automaticChecksText(automatic: AutomaticDetectionStatus): { state: string; detail: string } {
  if (!automatic.enabled) {
    return { state: "Automatic checks are off.", detail: "New logs wait here until you check them." };
  }
  if (!automatic.worker_running) {
    return {
      state: "Automatic checks are on, but the background worker is not running.",
      detail: "New logs wait until it starts, or until you check them here."
    };
  }
  const quiet = automatic.quiet_seconds % 60 === 0 ? plural(automatic.quiet_seconds / 60, "minute", "minutes") : `${count(automatic.quiet_seconds)} seconds`;
  const last = automatic.last_check;
  const when = last?.finished_at ? new Date(last.finished_at) : null;
  const stamp = when
    ? `${when.toLocaleDateString("en-GB", { day: "numeric", month: "short" })}, ${when.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}`
    : "";
  const lastText = !last
    ? "No automatic check has run yet."
    : last.status === "failed"
      ? `The last automatic check${stamp ? ` (${stamp})` : ""} failed; the next one will try again.`
      : `Last automatic check${stamp ? ` (${stamp})` : ""}: ${plural(last.logs_checked, "log", "logs")}, ${plural(last.alerts_created, "new alert", "new alerts")}, ${plural(last.alerts_updated, "update", "updates")} to existing alerts.`;
  return {
    state: "Automatic checks are on.",
    detail: `Each ${automatic.window_minutes}-minute window of new logs is checked once the window after it is complete, or ${quiet} after logs stop arriving. ${lastText}`
  };
}

interface CoverageSweep {
  running: boolean;
  finished: boolean;
  checked: number;
  created: number;
  updated: number;
  batches: number;
  remaining: number;
  error: unknown;
}

const IDLE_SWEEP: CoverageSweep = { running: false, finished: false, checked: 0, created: 0, updated: 0, batches: 0, remaining: 0, error: null };

export function DemoControls() {
  const [limitText, setLimitText] = useState("1000");
  const [allLogs, setAllLogs] = useState(false);
  const [samplePath, setSamplePath] = useState("");
  const [useMl, setUseMl] = useState(false);
  const [queuedFile, setQueuedFile] = useState<File | null>(null);
  const [sweep, setSweep] = useState<CoverageSweep>(IDLE_SWEEP);
  const stopSweep = useRef(false);
  const queryClient = useQueryClient();
  const health = useHealth();
  const summary = useDashboardSummary();
  const ml = useMlReport();
  const demo = useDemoMutations();
  const queuedImport = useQueuedImportMutation();

  const parsedLimit = Number.parseInt(limitText.trim(), 10);
  const typedLimit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? parsedLimit : null;
  // 0 tells the server "no limit"; null falls back to the server default.
  const limit = allLogs ? 0 : typedLimit;
  const coverage = useDetectionCoverage(useDebouncedValue(allLogs ? null : typedLimit));
  const coverageData = coverage.data;
  const automatic = coverageData?.automatic ? automaticChecksText(coverageData.automatic) : null;
  const automaticOn = Boolean(coverageData?.automatic?.enabled && coverageData.automatic.worker_running);
  const liveFeed = coverageData?.live_feed ? liveFeedText(coverageData.live_feed, automaticOn) : null;
  const newestRange = !allLogs && typedLimit ? coverageData?.newest_log_id_range ?? null : null;
  const rangeText = newestRange ? ` (log IDs ${count(newestRange[0])} to ${count(newestRange[1])})` : "";
  const amount = allLogs ? "all" : typedLimit ? `the newest ${count(typedLimit)}` : "the newest 5,000 (server default)";
  const lines = allLogs ? "every line" : typedLimit ? `the first ${count(typedLimit)} lines` : "the first 5,000 lines (server default)";

  const cleanedSamplePath = samplePath.trim().replace(/^["']|["']$/g, "").trim();
  const samplePathPayload = cleanedSamplePath ? cleanedSamplePath : null;
  const samplePathHint = samplePathPayload ? "The file at this path is used for import and reset." : "Leave blank to use the built-in 2-line sample.";

  async function checkUncheckedLogs() {
    stopSweep.current = false;
    let totals = { ...IDLE_SWEEP, running: true, remaining: coverageData?.unchecked_logs ?? 0 };
    setSweep(totals);
    try {
      while (!stopSweep.current) {
        const batch = await api.demoCheckUncheckedBatch({ limit: coverageData?.unchecked_batch_size ?? 5000 });
        totals = {
          ...totals,
          checked: totals.checked + batch.evaluated,
          created: totals.created + batch.created_alerts,
          updated: totals.updated + batch.deduplicated_alert_updates,
          batches: totals.batches + 1,
          remaining: batch.remaining_unchecked
        };
        setSweep(totals);
        if (batch.remaining_unchecked === 0 || batch.evaluated === 0) break;
      }
      setSweep({ ...totals, running: false, finished: true });
    } catch (error) {
      setSweep({ ...totals, running: false, finished: true, error });
    } finally {
      void queryClient.invalidateQueries();
    }
  }

  const sweepTotal = sweep.checked + sweep.remaining;
  const sweepPercent = sweepTotal ? Math.round((sweep.checked / sweepTotal) * 100) : 0;

  const actionGroups = [
    {
      title: "Data setup",
      actions: [
        {
          label: "Import sample logs",
          description: "Load the built-in sample, or the file at the path below.",
          uses: `Reads ${lines} of ${samplePathPayload ? "the file at that path" : "the built-in 2-line sample"}.`,
          disabled: false,
          run: () => demo.importSample.mutate({ limit, sample_path: samplePathPayload })
        }
      ]
    },
    {
      title: "Detection",
      actions: [
        {
          label: "Run detection",
          description: "Re-check the newest logs with the rules.",
          uses: allLogs
            ? "Needs a number. To check every log, use Check all unchecked logs above."
            : `Checks ${amount} logs${rangeText}.`,
          disabled: allLogs,
          run: () => demo.runDetection.mutate({ limit, use_ml: useMl })
        }
      ]
    },
    {
      title: "AI / ML",
      actions: [
        {
          label: "Train ML model",
          description: "Train or refresh IsolationForest assistive anomaly scoring.",
          uses: `Learns what typical traffic looks like from ${amount} logs${rangeText}.`,
          disabled: false,
          run: () => demo.trainMl.mutate({ limit })
        },
        {
          label: "Apply ML scoring",
          description: "Refresh anomaly flags for the current dataset.",
          uses: allLogs
            ? `Scores all ${coverageData ? count(coverageData.total_logs) : ""} logs. This can take a few minutes.`
            : `Scores ${amount} logs${rangeText}.`,
          disabled: false,
          run: () => demo.applyMl.mutate({ limit })
        }
      ]
    },
    {
      title: "Evidence export",
      actions: [
        {
          label: "Export evidence bundle",
          description: "Create case-ready JSON/CSV/HTML/PDF evidence files.",
          uses: "Uses the top 10 alerts and the latest 50 audit entries.",
          disabled: false,
          run: () => demo.exportBundle.mutate({ top_alert_limit: 10, audit_limit: 50 })
        }
      ]
    }
  ];

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-danger">Data &amp; Detection</div>
        <h1 className="mt-2 text-3xl font-black">Import logs, run detection and refresh the models.</h1>
        <p className="mt-2 text-muted">Admin only.</p>
      </section>

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="API" value={health.data?.status ?? "review"} detail="Backend health" tone={health.data?.status === "ok" ? "success" : "danger"} />
        <MetricCard label="Logs" value={summary.data?.total_logs ?? "-"} detail="Loaded evidence rows" tone="teal" />
        <MetricCard label="Alerts" value={summary.data?.total_alerts ?? "-"} detail="Detection findings" tone="danger" />
        <MetricCard label="ML Artifact" value={ml.data?.model_status.artifact_exists ? "Ready" : "Missing"} detail="Assistive only" tone={ml.data?.model_status.artifact_exists ? "success" : "amber"} />
      </div>

      <section className="panel" data-testid="detection-coverage" aria-labelledby="detection-coverage-title">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="detection-coverage-title" className="text-sm font-extrabold uppercase tracking-wide text-muted">Detection coverage</h2>
            <p className="mt-1 text-lg font-bold text-text">
              {coverageData
                ? `${count(coverageData.checked_logs)} of ${count(coverageData.total_logs)} logs have been checked by detection.`
                : "Loading coverage..."}
            </p>
            {coverageData && coverageData.unchecked_logs > 0 ? (
              <p className="mt-1 text-sm text-muted">
                {count(coverageData.unchecked_logs)} logs have never been checked
                {coverageData.oldest_unchecked_log_id ? ` (oldest: log #${count(coverageData.oldest_unchecked_log_id)})` : ""}.
                This checks them oldest first in whole 5-minute windows of traffic (at least {count(coverageData.unchecked_batch_size)} logs per step), so every log is checked once with its full context. You can stop and continue later.
              </p>
            ) : null}
            {coverageData && coverageData.unchecked_logs === 0 && !sweep.running ? (
              <p className="mt-1 text-sm text-muted">
                {automaticOn
                  ? "Every log has been checked. New logs are checked automatically."
                  : "Every log has been checked. Newly imported logs will show up here until you check them."}
              </p>
            ) : null}
            {automatic ? (
              <p className="mt-2 text-sm text-muted" data-testid="automatic-detection">
                <span className="font-bold text-text">{automatic.state}</span> {automatic.detail}
              </p>
            ) : null}
            {liveFeed ? (
              <p className="mt-2 text-sm text-muted" data-testid="live-feed">
                <span className="font-bold text-text">{liveFeed.state}</span> {liveFeed.detail}
              </p>
            ) : null}
          </div>
          <div className="flex flex-wrap gap-2">
            {sweep.running ? (
              <button className="btn-secondary" type="button" onClick={() => { stopSweep.current = true; }}>
                Stop after this batch
              </button>
            ) : (
              <button
                className="btn-primary"
                type="button"
                disabled={!coverageData || coverageData.unchecked_logs === 0}
                onClick={() => void checkUncheckedLogs()}
              >
                Check all unchecked logs
              </button>
            )}
          </div>
        </div>
        {sweep.running || sweep.finished ? (
          <div className="mt-4 grid gap-2" data-testid="detection-sweep-progress">
            <div
              className="h-3 overflow-hidden rounded-full border border-line bg-panel2"
              role="progressbar"
              aria-label="Detection coverage progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={sweepPercent}
            >
              <div className="h-full bg-cyan transition-all" style={{ width: `${sweepPercent}%` }} />
            </div>
            <div className="text-sm text-text" aria-live="polite">
              {sweep.running ? "Checking: " : sweep.remaining === 0 ? "Done: " : "Stopped: "}
              {count(sweep.checked)} of {count(sweepTotal)} logs checked in {sweep.batches} {sweep.batches === 1 ? "batch" : "batches"},{" "}
              {count(sweep.created)} new {sweep.created === 1 ? "alert" : "alerts"}, {count(sweep.updated)}{" "}
              {sweep.updated === 1 ? "update" : "updates"} to existing alerts.
            </div>
            {sweep.error ? <ErrorBanner error={sweep.error} /> : null}
          </div>
        ) : null}
      </section>

      <section className="panel">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Workflow</div>
            <div className="mt-1 text-sm text-muted">Recommended order: import, detect, train/apply ML, export bundle.</div>
          </div>
          <Badge value="ready" />
        </div>
        <div className="grid gap-3 lg:grid-cols-[220px_1fr_220px]">
          <div className="grid gap-1">
            <label className="text-xs font-extrabold uppercase tracking-wide text-muted" htmlFor="demo-log-limit">Log limit</label>
            <div className="flex items-center gap-3">
              <input
                id="demo-log-limit"
                aria-label="Log import limit"
                className="input min-w-0 flex-1"
                inputMode="numeric"
                pattern="[0-9]*"
                placeholder="1000"
                value={limitText}
                disabled={allLogs}
                onChange={(event) => setLimitText(event.target.value.replace(/[^\d]/g, ""))}
              />
              <label className="flex shrink-0 items-center gap-2 text-sm text-muted">
                <input type="checkbox" checked={allLogs} onChange={(event) => setAllLogs(event.target.checked)} />
                All
              </label>
            </div>
          </div>
          <label className="grid gap-1">
            <span className="text-xs font-extrabold uppercase tracking-wide text-muted">Log file path (optional)</span>
            <input
              aria-label="Sample log file path"
              className="input"
              placeholder='Blank = the built-in sample. Example: D:\Logs\paloalto-firewall.log'
              value={samplePath}
              onChange={(event) => setSamplePath(event.target.value)}
            />
            <span className="text-xs text-muted">{samplePathHint}</span>
          </label>
          <label className="flex items-center gap-2 rounded-lg border border-line bg-panel2 px-3 py-2 text-sm text-muted">
            <input type="checkbox" checked={useMl} onChange={(event) => setUseMl(event.target.checked)} />
            Use ML during detection
          </label>
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs text-muted">
            Import reads the file above. The built-in sample has only 2 logs, so asking for 1,000 still imports 2.
          </div>
          <button
            className="btn-secondary"
            onClick={() => {
              if (window.confirm("Delete every log, alert and their history, then load the sample file? This cannot be undone.")) {
                demo.reset.mutate({ limit, use_ml: useMl, sample_path: samplePathPayload });
              }
            }}
          >
            Reset to sample data
          </button>
        </div>
        <div className="mt-4 flex flex-wrap items-end gap-3 rounded-lg border border-line bg-panel2 p-3" data-testid="durable-import-control">
          <label className="min-w-0 flex-1">
            <span className="text-xs font-extrabold uppercase tracking-wide text-muted">Durable file import</span>
            <input
              className="input mt-1 w-full"
              type="file"
              accept=".log,.txt,.csv,text/plain,text/csv"
              onChange={(event) => setQueuedFile(event.target.files?.[0] ?? null)}
            />
          </label>
          <button
            className="btn-secondary inline-flex items-center gap-2"
            type="button"
            disabled={!queuedFile || queuedImport.isPending}
            onClick={() => {
              if (!queuedFile) return;
              queuedImport.mutate({
                file: queuedFile,
                // The queue reads a missing limit as "the whole file".
                limit: allLogs ? null : typedLimit,
                job_type: "import_logs",
                source_type: "file_import",
                parser_profile: "palo_alto"
              });
            }}
          >
            <Upload size={16} />
            {queuedImport.isPending ? "Staging..." : "Queue import"}
          </button>
          <div className="w-full text-xs text-muted">
            Imports {allLogs || !typedLimit ? "every line" : `the first ${count(typedLimit)} lines`} of the chosen file (up to 1 GB, a whole MFU export) in the background worker, with checkpointed progress and safe resume. Check new logs afterwards with Check all unchecked logs.
          </div>
        </div>
        <div className="mt-4 grid gap-4 xl:grid-cols-4">
          {actionGroups.map((group) => (
            <div key={group.title} className="rounded-lg border border-line bg-panel2 p-3">
              <div className="mb-3 text-xs font-extrabold uppercase tracking-wide text-muted">{group.title}</div>
              <div className="grid gap-2">
                {group.actions.map((action) => (
                  <button
                    key={action.label}
                    className="rounded-lg border border-line bg-panel p-4 text-left transition hover:border-cyan/50 hover:bg-cyan/10 disabled:cursor-not-allowed disabled:opacity-60"
                    disabled={action.disabled}
                    onClick={action.run}
                  >
                    <div className="font-extrabold text-text">{action.label}</div>
                    <div className="mt-2 text-xs text-muted">{action.description}</div>
                    <div className="mt-2 text-xs font-bold text-text">{action.uses}</div>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <div className="grid gap-3 md:grid-cols-2">
        <ActionResultCard title="Import queued" kind="generic" result={queuedImport.data as unknown as Record<string, unknown> | undefined} />
        <ActionResultCard title="Reset complete" kind="reset" result={demo.reset.data as Record<string, unknown> | undefined} />
        <ActionResultCard title="Import complete" kind="import" result={demo.importSample.data as Record<string, unknown> | undefined} />
        <ActionResultCard title="Detection complete" kind="detection" result={demo.runDetection.data as Record<string, unknown> | undefined} />
        <ActionResultCard title="ML training complete" kind="ml-train" result={demo.trainMl.data as Record<string, unknown> | undefined} />
        <ActionResultCard title="ML scoring complete" kind="ml-score" result={demo.applyMl.data as Record<string, unknown> | undefined} />
        <ActionResultCard title="Evidence bundle exported" kind="export" result={demo.exportBundle.data as Record<string, unknown> | undefined} />
      </div>

      {[queuedImport, demo.reset, demo.importSample, demo.runDetection, demo.trainMl, demo.applyMl, demo.exportBundle].map((mutation, index) =>
        mutation.isError ? <ErrorBanner key={index} error={mutation.error} /> : null
      )}
    </div>
  );
}
