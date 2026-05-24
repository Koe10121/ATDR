import { useState } from "react";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartCard } from "../components/ChartCard";
import { EmptyState } from "../components/EmptyState";
import { MetricCard } from "../components/MetricCard";
import { Badge } from "../components/Badge";
import { ErrorBanner } from "../components/ErrorBanner";
import { api } from "../lib/api";
import { useMlLabelMutations, useMlReport, useMlReviewQueue, useSupervisedReport } from "../hooks/useApiQueries";

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function MLGovernance() {
  const report = useMlReport();
  const supervised = useSupervisedReport();
  const reviewQueue = useMlReviewQueue({ limit: 25 });
  const labelMutations = useMlLabelMutations();
  const data = report.data;
  const supervisedData = supervised.data;
  const supervisedMetrics = supervisedData?.latest_run?.metrics ?? {};
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<string | null>(null);

  async function downloadExport(kind: "labels" | "queue" | "template" | "report" | "review_sample") {
    setDownloadError(null);
    try {
      const file =
        kind === "labels"
          ? await api.downloadMlLabels()
          : kind === "queue"
            ? await api.downloadMlReviewQueue({ limit: 1000 })
            : kind === "report"
              ? await api.downloadSupervisedReport()
              : kind === "review_sample"
                ? await api.downloadMlLabelReviewSample()
                : await api.downloadMlLabelTemplate();
      downloadBlob(file.blob, file.filename);
    } catch (error) {
      setDownloadError(error instanceof Error ? error.message : "Download failed.");
    }
  }

  function importLabels(file?: File) {
    if (!file) {
      return;
    }
    setImportResult(null);
    labelMutations.importCsv.mutate(file, {
      onSuccess: (result) =>
        setImportResult(
          `Reviewed import complete: ${result.created} created, ${result.updated} reviewed/updated, ${result.skipped ?? 0} skipped, ${result.protected_manual ?? 0} manual labels protected, ${result.failed} failed.`
        )
    });
  }

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">ML Governance</div>
        <h1 className="mt-2 text-3xl font-black">AI is assistive, explainable, and audited.</h1>
        <p className="mt-2 text-muted">
          IsolationForest highlights unusual traffic. Rule evidence and analyst review remain the authority for response decisions.
        </p>
      </section>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Model Artifact" value={data?.model_status.artifact_exists ? "Ready" : "Missing"} detail="Saved IsolationForest pipeline" tone="teal" />
        <MetricCard label="Scored Logs" value={data?.scored_log_count ?? "-"} detail="Latest scored population" tone="cyan" />
        <MetricCard label="Anomalies" value={data?.anomaly_count ?? "-"} detail="Current anomaly flags" tone="amber" />
        <MetricCard label="Anomaly Rate" value={`${data?.anomaly_rate ?? "-"}%`} detail="Assistive signal rate" tone="cyan" />
      </div>

      <section className="panel">
        <div className="mb-4 flex items-center justify-between gap-2">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">AI Model Evaluation</div>
            <h2 className="mt-1 text-xl font-black">Supervised label model</h2>
            <p className="mt-1 text-sm text-muted">Analyst-reviewed labels train a supervised classifier. Output remains decision support only.</p>
          </div>
          <Badge value={supervisedData?.artifact_exists ? "trained" : "needs labels"} />
        </div>
        <div className="grid gap-4 md:grid-cols-4">
          <MetricCard label="Label Rows" value={supervisedData?.label_count ?? "-"} detail="Reviewed ML labels" tone="teal" />
          <MetricCard label="Training Rows" value={supervisedData?.latest_run?.training_rows ?? "-"} detail="Latest supervised run" tone="cyan" />
          <MetricCard label="Test Rows" value={supervisedData?.latest_run?.test_rows ?? "-"} detail="Holdout evaluation" tone="amber" />
          <MetricCard label="F1 Score" value={String(supervisedMetrics.f1 ?? "-")} detail="Weighted test metric" tone="cyan" />
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <MetricCard label="Reviewed Labels" value={supervisedData?.reviewed_label_count ?? 0} detail="Human-reviewed/manual rows" tone="teal" />
          <MetricCard label="Assisted Pending Review" value={supervisedData?.unreviewed_assisted_label_count ?? 0} detail="Weak labels needing validation" tone="amber" />
          <MetricCard label="Label Sources" value={Object.keys(supervisedData?.label_source_distribution ?? {}).length} detail="Manual/rule/ML/hybrid provenance" tone="cyan" />
        </div>
        <div className="mt-4 grid gap-4 xl:grid-cols-2">
          <div className="rounded-lg border border-line bg-panel2 p-4">
            <div className="mb-2 text-xs font-extrabold uppercase tracking-wide text-muted">Metrics</div>
            <div className="grid gap-2 text-sm text-muted sm:grid-cols-2">
              {["accuracy", "precision", "recall", "f1"].map((name) => (
                <div key={name} className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                  <span className="capitalize">{name}</span>
                  <span className="font-bold text-text">{String(supervisedMetrics[name] ?? "-")}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-4">
            <div className="mb-2 text-xs font-extrabold uppercase tracking-wide text-muted">Label Distribution</div>
            <div className="space-y-2 text-sm text-muted">
              {Object.entries(supervisedData?.label_distribution ?? {}).length ? (
                Object.entries(supervisedData?.label_distribution ?? {}).map(([label, count]) => (
                  <div key={label} className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                    <span>{label}</span>
                    <span className="font-bold text-text">{count}</span>
                  </div>
                ))
              ) : (
                <EmptyState title="No labels yet" body="Create analyst-reviewed labels before training the supervised model." />
              )}
            </div>
          </div>
        </div>
        <div className="mt-4 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
          Assisted labels are weak labels. Review a representative sample before presenting supervised metrics as final model performance.
        </div>
      </section>

      <section className="panel">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Label Review Queue</div>
            <h2 className="mt-1 text-xl font-black">Prioritized analyst review worklist</h2>
            <p className="mt-1 text-sm text-muted">
              Prioritizes anomaly flags, high rule evidence, high hybrid risk, suspicious recent logs, and rule/ML disagreement.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("queue")}>Export Queue CSV</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("labels")}>Export Labels CSV</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("template")}>CSV Template</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("review_sample")}>Human Review Sample</button>
          </div>
        </div>
        <div className="mb-4 rounded-lg border border-line bg-panel2 p-3">
          <div className="flex flex-wrap items-center gap-3">
            <label className="btn-secondary cursor-pointer">
              Import Reviewed CSV
              <input className="hidden" type="file" accept=".csv,text/csv" onChange={(event) => importLabels(event.target.files?.[0])} />
            </label>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("report")}>Download Model Report</button>
            <span className="text-xs text-muted">
              Reviewed CSV import marks completed rows as reviewed, skips empty review rows, preserves assisted provenance, and protects manual labels.
            </span>
          </div>
          {importResult ? <div className="mt-3 rounded border border-success/30 bg-success/10 p-2 text-sm text-success">{importResult}</div> : null}
          {downloadError ? <div className="mt-3 text-sm text-danger">{downloadError}</div> : null}
          {labelMutations.importCsv.isError ? <div className="mt-3"><ErrorBanner error={labelMutations.importCsv.error} /></div> : null}
        </div>
        {reviewQueue.isLoading ? (
          <div className="text-sm text-muted">Loading review queue...</div>
        ) : reviewQueue.data?.length ? (
          <div className="overflow-auto">
            <table className="soc-table soc-table-compact">
              <thead>
                <tr>
                  <th>Priority</th>
                  <th>Log</th>
                  <th>Traffic</th>
                  <th>Evidence</th>
                  <th>AI Signals</th>
                  <th>Label</th>
                </tr>
              </thead>
              <tbody>
                {reviewQueue.data.map((item) => (
                  <tr key={item.log_id}>
                    <td>
                      <div className="font-black text-text">{item.priority_score}</div>
                      <div className="text-xs text-muted">Hybrid {item.hybrid_risk_score}</div>
                    </td>
                    <td>
                      <Link className="font-bold text-cyan underline" to={`/logs?log=${item.log_id}`}>Log {item.log_id}</Link>
                      <div className="text-xs text-muted">{item.generated_time ?? "-"}</div>
                    </td>
                    <td>
                      <div>{item.src_ip ?? "-"} {"->"} {item.dst_ip ?? "-"}</div>
                      <div className="text-xs text-muted">{item.app ?? "-"} / {item.action ?? "-"} / risk {item.app_risk ?? "-"}</div>
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {item.priority_reasons.map((reason) => <Badge key={reason} value={reason} />)}
                      </div>
                    </td>
                    <td>
                      <div className="text-sm">IF: {item.is_anomaly ? "anomaly" : "normal"}</div>
                      <div className="text-xs text-muted">Supervised: {item.supervised_prediction ?? "not trained"} ({item.malicious_probability})</div>
                    </td>
                    <td>{item.existing_label ? <Badge value={item.existing_label.label} /> : <Badge value="unlabeled" />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No review candidates" body="Run detection, score anomalies, or import suspicious logs to populate the label queue." />
        )}
      </section>

      <div className="grid gap-4 xl:grid-cols-[1fr_0.9fr]">
        <ChartCard title="Top Anomalous Apps">
          {data?.top_anomalous_apps?.length ? (
            <div className="h-80">
              <ResponsiveContainer>
                <BarChart data={data.top_anomalous_apps.slice(0, 8)} layout="vertical" margin={{ left: 100 }}>
                  <CartesianGrid stroke="#263445" strokeDasharray="3 3" />
                  <XAxis type="number" stroke="#93a4b7" />
                  <YAxis type="category" dataKey="name" stroke="#93a4b7" width={100} />
                  <Tooltip contentStyle={{ background: "#0f151d", border: "1px solid #263445", color: "#e5edf6" }} />
                  <Bar dataKey="count" fill="#22d3ee" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState title="No anomaly groups" body="Train and score the model to populate anomaly analysis." />
          )}
        </ChartCard>
        <section className="panel">
          <div className="mb-4 flex items-center justify-between gap-2">
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Drift Signals</div>
            <Badge value={data?.drift_signals?.length ? "review" : "ready"} />
          </div>
          <div className="space-y-3">
            {(data?.drift_signals ?? []).slice(0, 5).map((signal, index) => (
              <div key={index} className="rounded-lg border border-line bg-panel2 p-3 text-sm text-muted">
                <div className="font-bold text-text">{String(signal.metric ?? "drift_signal")}</div>
                <div className="mt-1">{String(signal.message ?? "")}</div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="mb-3 text-sm font-extrabold uppercase tracking-wide text-muted">Recommendations</div>
        <ul className="space-y-2 text-sm text-muted">
          {(data?.recommendations ?? []).map((item) => (
            <li key={item} className="rounded-lg border border-line bg-panel2 p-3">{item}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
