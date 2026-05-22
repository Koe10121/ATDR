import { useState } from "react";
import { Badge } from "../components/Badge";
import { ErrorBanner } from "../components/ErrorBanner";
import { MetricCard } from "../components/MetricCard";
import { useDashboardSummary, useDemoMutations, useHealth, useMlReport } from "../hooks/useApiQueries";

function ResultCard({ title, result }: { title: string; result?: Record<string, unknown> }) {
  if (!result) return null;
  return (
    <div className="rounded-lg border border-success/30 bg-success/10 p-4 text-sm text-success">
      <div className="font-extrabold">{title}</div>
      <div className="mt-2 grid gap-1 text-xs">
        {Object.entries(result).slice(0, 8).map(([key, value]) => (
          <div key={key}>
            <span className="font-bold">{key}:</span> {typeof value === "object" ? JSON.stringify(value) : String(value)}
          </div>
        ))}
      </div>
    </div>
  );
}

export function DemoControls() {
  const [limit, setLimit] = useState(1000);
  const [useMl, setUseMl] = useState(false);
  const health = useHealth();
  const summary = useDashboardSummary();
  const ml = useMlReport();
  const demo = useDemoMutations();

  const actions = [
    {
      label: "Import sample logs",
      description: "Load the configured Palo Alto sample file.",
      run: () => demo.importSample.mutate({ limit })
    },
    {
      label: "Run detection",
      description: "Generate rule-first grouped alerts from parsed logs.",
      run: () => demo.runDetection.mutate({ limit, use_ml: useMl })
    },
    {
      label: "Train ML model",
      description: "Train or refresh IsolationForest assistive anomaly scoring.",
      run: () => demo.trainMl.mutate({ limit })
    },
    {
      label: "Apply ML scoring",
      description: "Refresh anomaly flags for the current dataset.",
      run: () => demo.applyMl.mutate({ limit })
    },
    {
      label: "Export evidence bundle",
      description: "Create supervisor-ready JSON/CSV/HTML/PDF evidence files.",
      run: () => demo.exportBundle.mutate({ top_alert_limit: 10, audit_limit: 50 })
    }
  ];

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Demo Controls</div>
        <h1 className="mt-2 text-3xl font-black">Prepare a safe supervisor or lab-pilot demo.</h1>
        <p className="mt-2 text-muted">Admin-only controls. All response actions remain simulated.</p>
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
        <div className="grid gap-3 md:grid-cols-3">
          <input className="input" type="number" min={1} value={limit} onChange={(event) => setLimit(Number(event.target.value))} />
          <label className="flex items-center gap-2 rounded-lg border border-line bg-panel2 px-3 py-2 text-sm text-muted">
            <input type="checkbox" checked={useMl} onChange={(event) => setUseMl(event.target.checked)} />
            Use ML during detection
          </label>
          <button
            className="btn-secondary"
            onClick={() => {
              if (window.confirm("Reset demo data? This is destructive for local demo data.")) {
                demo.reset.mutate({ limit, use_ml: useMl });
              }
            }}
          >
            Reset demo data
          </button>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          {actions.map((action) => (
            <button key={action.label} className="rounded-lg border border-line bg-panel2 p-4 text-left transition hover:border-cyan/50 hover:bg-cyan/10" onClick={action.run}>
              <div className="font-extrabold text-text">{action.label}</div>
              <div className="mt-2 text-xs text-muted">{action.description}</div>
            </button>
          ))}
        </div>
      </section>

      <div className="grid gap-3 md:grid-cols-2">
        <ResultCard title="Reset complete" result={demo.reset.data as Record<string, unknown> | undefined} />
        <ResultCard title="Import complete" result={demo.importSample.data as Record<string, unknown> | undefined} />
        <ResultCard title="Detection complete" result={demo.runDetection.data as Record<string, unknown> | undefined} />
        <ResultCard title="ML training complete" result={demo.trainMl.data as Record<string, unknown> | undefined} />
        <ResultCard title="ML scoring complete" result={demo.applyMl.data as Record<string, unknown> | undefined} />
        <ResultCard title="Evidence bundle exported" result={demo.exportBundle.data as Record<string, unknown> | undefined} />
      </div>

      {[demo.reset, demo.importSample, demo.runDetection, demo.trainMl, demo.applyMl, demo.exportBundle].map((mutation, index) =>
        mutation.isError ? <ErrorBanner key={index} error={mutation.error} /> : null
      )}
    </div>
  );
}
