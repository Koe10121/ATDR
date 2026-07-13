import { useState } from "react";
import { Upload } from "lucide-react";
import { ActionResultCard } from "../components/ActionResultCard";
import { Badge } from "../components/Badge";
import { ErrorBanner } from "../components/ErrorBanner";
import { MetricCard } from "../components/MetricCard";
import { useDashboardSummary, useDemoMutations, useHealth, useMlReport, useQueuedImportMutation } from "../hooks/useApiQueries";

export function DemoControls() {
  const [limitText, setLimitText] = useState("1000");
  const [samplePath, setSamplePath] = useState("");
  const [useMl, setUseMl] = useState(false);
  const [queuedFile, setQueuedFile] = useState<File | null>(null);
  const health = useHealth();
  const summary = useDashboardSummary();
  const ml = useMlReport();
  const demo = useDemoMutations();
  const queuedImport = useQueuedImportMutation();

  const parsedLimit = Number.parseInt(limitText.trim(), 10);
  const limit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? parsedLimit : null;
  const cleanedSamplePath = samplePath.trim().replace(/^["']|["']$/g, "").trim();
  const samplePathPayload = cleanedSamplePath ? cleanedSamplePath : null;
  const samplePathHint = samplePathPayload ? "Custom sample path will be used for import/reset." : "Blank uses the safe 2-line demo sample.";

  const actionGroups = [
    {
      title: "Data setup",
      actions: [
        {
          label: "Import sample logs",
          description: "Load safe sample or the custom file path below.",
          run: () => demo.importSample.mutate({ limit, sample_path: samplePathPayload })
        }
      ]
    },
    {
      title: "Detection",
      actions: [
        {
          label: "Run detection",
          description: "Generate rule-first grouped alerts from parsed logs.",
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
          run: () => demo.trainMl.mutate({ limit })
        },
        {
          label: "Apply ML scoring",
          description: "Refresh anomaly flags for the current dataset.",
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
          run: () => demo.exportBundle.mutate({ top_alert_limit: 10, audit_limit: 50 })
        }
      ]
    }
  ];

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-danger">Demo Controls</div>
        <h1 className="mt-2 text-3xl font-black">Prepare safe demo data and evidence.</h1>
        <p className="mt-2 text-muted">Admin-only workflow with technical outputs collapsed.</p>
      </section>

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="API" value={health.data?.status ?? "review"} detail="Backend health" tone={health.data?.status === "ok" ? "success" : "danger"} />
        <MetricCard label="Logs" value={summary.data?.total_logs ?? "-"} detail="Loaded evidence rows" tone="teal" />
        <MetricCard label="Alerts" value={summary.data?.total_alerts ?? "-"} detail="Detection findings" tone="danger" />
        <MetricCard label="ML Artifact" value={ml.data?.model_status.artifact_exists ? "Ready" : "Missing"} detail="Assistive only" tone={ml.data?.model_status.artifact_exists ? "success" : "amber"} />
      </div>

      <section className="panel">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Guided Demo Workflow</div>
            <div className="mt-1 text-sm text-muted">Recommended order: import, detect, train/apply ML, export bundle.</div>
          </div>
          <Badge value="ready" />
        </div>
        <div className="grid gap-3 lg:grid-cols-[180px_1fr_220px]">
          <label className="grid gap-1">
            <span className="text-xs font-extrabold uppercase tracking-wide text-muted">Log limit</span>
            <input
              aria-label="Log import limit"
              className="input"
              inputMode="numeric"
              pattern="[0-9]*"
              placeholder="1000"
              value={limitText}
              onChange={(event) => setLimitText(event.target.value.replace(/[^\d]/g, ""))}
            />
          </label>
          <label className="grid gap-1">
            <span className="text-xs font-extrabold uppercase tracking-wide text-muted">Optional sample file path</span>
            <input
              aria-label="Sample log file path"
              className="input"
              placeholder='Blank = data/samples/paloalto-demo.txt. Example: C:\Users\User\Downloads\paloalto-firewall(1).log'
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
            Import sample logs reads from the selected file. The default safe sample has only 2 logs, so requesting 1000 still imports only 2.
          </div>
          <button
            className="btn-secondary"
            onClick={() => {
              if (window.confirm("Reset demo data? This is destructive for local demo data.")) {
                demo.reset.mutate({ limit, use_ml: useMl, sample_path: samplePathPayload });
              }
            }}
          >
            Reset demo data
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
                limit,
                job_type: "import_logs",
                source_type: "file_import",
                parser_profile: "palo_alto"
              });
            }}
          >
            <Upload size={16} />
            {queuedImport.isPending ? "Staging..." : "Queue import"}
          </button>
          <div className="w-full text-xs text-muted">Runs through the manual operation worker with checkpointed progress and safe resume.</div>
        </div>
        <div className="mt-4 grid gap-4 xl:grid-cols-4">
          {actionGroups.map((group) => (
            <div key={group.title} className="rounded-lg border border-line bg-panel2 p-3">
              <div className="mb-3 text-xs font-extrabold uppercase tracking-wide text-muted">{group.title}</div>
              <div className="grid gap-2">
                {group.actions.map((action) => (
                  <button
                    key={action.label}
                    className="rounded-lg border border-line bg-panel p-4 text-left transition hover:border-cyan/50 hover:bg-cyan/10"
                    onClick={action.run}
                  >
                    <div className="font-extrabold text-text">{action.label}</div>
                    <div className="mt-2 text-xs text-muted">{action.description}</div>
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
