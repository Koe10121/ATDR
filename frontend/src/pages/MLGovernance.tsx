import { useState } from "react";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartCard } from "../components/ChartCard";
import { EmptyState } from "../components/EmptyState";
import { MetricCard } from "../components/MetricCard";
import { Badge } from "../components/Badge";
import { ErrorBanner } from "../components/ErrorBanner";
import { api } from "../lib/api";
import { useClassTemporalCoverage, useMlLabelMutations, useMlReport, useMlReviewQueue, useSupervisedReport } from "../hooks/useApiQueries";
import type { MLAttackType, MLLabelValue, MLReviewQueueItem } from "../types/api";

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
  const temporalCoverage = useClassTemporalCoverage();
  const reviewQueue = useMlReviewQueue({ limit: 25 });
  const labelMutations = useMlLabelMutations();
  const data = report.data;
  const supervisedData = supervised.data;
  const supervisedMetrics = supervisedData?.latest_run?.metrics ?? {};
  const threatPositive = (supervisedMetrics.threat_positive ?? {}) as Record<string, unknown>;
  const topFeatures = supervisedData?.latest_run?.top_features ?? [];
  const dataQuality = data?.data_quality;
  const validationWarnings = supervisedData?.validation_warnings ?? supervisedData?.latest_run?.validation_warnings ?? [];
  const reviewedTarget = supervisedData?.reviewed_label_target ?? 300;
  const reviewedCoverage = supervisedData?.reviewed_label_count ? Math.round((supervisedData.reviewed_label_count / reviewedTarget) * 100) : 0;
  const promotionGate = supervisedData?.latest_run?.promotion_gate ?? {};
  const featureGeneration = supervisedData?.latest_run?.feature_generation ?? {};
  const trainingDiagnostics = supervisedData?.latest_run?.training_dataset_diagnostics ?? {};
  const temporal = temporalCoverage.data;
  const readiness = supervisedData?.model_readiness_checklist ?? supervisedData?.latest_run?.model_readiness_checklist;
  const drift = data?.baseline_drift_report;
  const perClass = (supervisedMetrics.per_class ?? {}) as Record<string, Record<string, unknown>>;
  const suspiciousMetrics = perClass.suspicious ?? {};
  const maliciousMetrics = perClass.malicious ?? {};
  const suspiciousRecall = Number(suspiciousMetrics.recall ?? 0);
  const maliciousRecall = Number(maliciousMetrics.recall ?? 0);
  const productionPromoted = Boolean(promotionGate.production_promoted);
  const analystReviewEligible = Boolean(promotionGate.analyst_review_eligible);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<string | null>(null);
  const [quickReviewMessage, setQuickReviewMessage] = useState<string | null>(null);

  async function downloadExport(
    kind:
      | "labels"
      | "queue"
      | "template"
      | "report"
      | "review_sample"
      | "active_learning"
      | "active_learning_malicious"
      | "active_learning_boundary"
      | "active_learning_threat_boundary"
      | "training_window_threat"
      | "boundary_report"
      | "suspicious_recall_sample"
      | "suspicious_recall_report"
      | "label_quality"
      | "temporal_coverage"
  ) {
    setDownloadError(null);
    try {
      let file: { blob: Blob; filename: string };
      switch (kind) {
        case "labels":
          file = await api.downloadMlLabels();
          break;
        case "queue":
          file = await api.downloadMlReviewQueue({ limit: 1000 });
          break;
        case "report":
          file = await api.downloadSupervisedReport();
          break;
        case "review_sample":
          file = await api.downloadMlLabelReviewSample();
          break;
        case "active_learning":
          file = await api.downloadActiveLearningReviewSample({ limit: 100 });
          break;
        case "active_learning_malicious":
          file = await api.downloadActiveLearningReviewSample({ limit: 200, focus: "malicious,suspicious,needs_context" });
          break;
        case "active_learning_boundary":
          file = await api.downloadActiveLearningReviewSample({
            limit: 200,
            focus: "malicious,suspicious,needs_context",
            strategy: "boundary"
          });
          break;
        case "active_learning_threat_boundary":
          file = await api.downloadActiveLearningReviewSample({
            limit: 200,
            focus: "malicious,suspicious,needs_context",
            strategy: "threat_boundary"
          });
          break;
        case "training_window_threat":
          file = await api.downloadTrainingWindowThreatReviewSample({ limit: 150 });
          break;
        case "boundary_report":
          file = await api.downloadSuspiciousMaliciousBoundaryReport();
          break;
        case "suspicious_recall_sample":
          file = await api.downloadSuspiciousRecallReviewSample({ limit: 150 });
          break;
        case "suspicious_recall_report":
          file = await api.downloadSuspiciousRecallErrorReport();
          break;
        case "label_quality":
          file = await api.downloadLabelQualityIssues({ limit: 1000 });
          break;
        case "temporal_coverage":
          file = await api.downloadClassTemporalCoverage();
          break;
        case "template":
        default:
          file = await api.downloadMlLabelTemplate();
      }
      downloadBlob(file.blob, file.filename);
    } catch (error) {
      setDownloadError(error instanceof Error ? error.message : "Download failed.");
    }
  }

  function importLabels(file?: File, correctionMode = false) {
    if (!file) {
      return;
    }
    setImportResult(null);
    labelMutations.importCsv.mutate(
      correctionMode ? { file, params: { correction_mode: true, overwrite_reviewed: true } } : file,
      {
      onSuccess: (result) =>
        setImportResult(
          `Reviewed import complete: ${result.created} created, ${result.updated} reviewed/updated, ${result.changed_decisions ?? 0} decision changes, ${result.skipped ?? 0} skipped, ${result.protected_manual ?? 0} manual labels protected, ${result.protected_reviewed ?? 0} reviewed labels protected, ${result.failed} failed.`
        )
      }
    );
  }

  function attackTypeForQuickLabel(label: MLLabelValue): MLAttackType {
    if (label === "benign" || label === "benign_unusual") {
      return "normal";
    }
    if (label === "malicious") {
      return "unknown_anomaly";
    }
    if (label === "suspicious") {
      return "unknown_anomaly";
    }
    return "unknown_anomaly";
  }

  function quickReview(item: MLReviewQueueItem, label: MLLabelValue) {
    setQuickReviewMessage(null);
    if (item.existing_label?.label_source === "manual") {
      setQuickReviewMessage("Manual labels are protected. Open the log detail if you need an explicit override workflow.");
      return;
    }
    const payload = {
      log_id: item.log_id,
      label,
      attack_type: attackTypeForQuickLabel(label),
      confidence: label === "malicious" ? 4 : 3,
      review_note: `Quick review from ML Governance. Reason selected: ${item.priority_reasons.join("; ")}`,
      label_source: item.existing_label?.label_source ?? "manual",
      reviewed: true
    };
    if (item.existing_label?.id) {
      labelMutations.update.mutate(
        { id: item.existing_label.id, payload },
        {
          onSuccess: () => setQuickReviewMessage(`Marked log ${item.log_id} as ${label}.`),
          onError: (error) => setQuickReviewMessage(error instanceof Error ? error.message : "Quick review failed.")
        }
      );
      return;
    }
    labelMutations.create.mutate(
      payload,
      {
        onSuccess: () => setQuickReviewMessage(`Marked log ${item.log_id} as ${label}.`),
        onError: (error) => setQuickReviewMessage(error instanceof Error ? error.message : "Quick review failed.")
      }
    );
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
          <MetricCard label="Review Coverage" value={`${reviewedCoverage}%`} detail={`Target ${reviewedTarget} reviewed labels`} tone="cyan" />
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <MetricCard label="Threat-Positive Precision" value={String(threatPositive.precision ?? "-")} detail="Suspicious + malicious triage grouping" tone="amber" />
          <MetricCard label="Threat-Positive Recall" value={String(threatPositive.recall ?? "-")} detail="Combined SOC catch rate" tone="danger" />
          <MetricCard label="Threat-Positive F1" value={String(threatPositive.f1 ?? "-")} detail="Strong SOC triage signal; not production accuracy" tone="cyan" />
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <MetricCard
            label="Suspicious Recall"
            value={String(suspiciousMetrics.recall ?? "-")}
            detail={suspiciousRecall < 0.8 ? "Current model blocker: target >= 0.8" : "Meets current recall target"}
            tone={suspiciousRecall < 0.8 ? "amber" : "teal"}
          />
          <MetricCard
            label="Malicious Recall"
            value={String(maliciousMetrics.recall ?? "-")}
            detail={maliciousRecall > 0 ? "Boundary still needs review" : "No malicious recall in this split"}
            tone="danger"
          />
          <MetricCard
            label="Model Status"
            value={readiness?.status ?? "candidate_only"}
            detail="Do not promote until exact-class validation is stable"
            tone="cyan"
          />
        </div>
        {suspiciousRecall < 0.8 ? (
          <div className="mt-4 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
            Current blocker: suspicious recall is below the 0.8 target. Threat-positive triage can still be useful, but exact suspicious
            versus malicious separation needs more reviewed boundary labels before promotion.
          </div>
        ) : null}
        <div className="mt-4 rounded-lg border border-cyan/30 bg-cyan/10 p-3 text-sm text-cyan">
          {analystReviewEligible
            ? "Model is eligible for analyst review, not production promotion."
            : "Model remains candidate-only until analyst review criteria are met."}{" "}
          Threat-positive triage is strong, exact suspicious recall is still below target, and response actions remain analyst-approved.
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-4">
          <MetricCard label="Reviewed Malicious" value={temporal?.reviewed_malicious_count ?? 0} detail="Human-reviewed threat class" tone="danger" />
          <MetricCard label="Reviewed Suspicious" value={temporal?.reviewed_suspicious_count ?? 0} detail="Human-reviewed triage class" tone="amber" />
          <MetricCard
            label="Malicious Train/Test"
            value={`${temporal?.malicious_train_count ?? 0}/${temporal?.malicious_test_count ?? 0}`}
            detail={`Minimum ${temporal?.malicious_training_minimum ?? 20}, better ${temporal?.malicious_training_better_target ?? 50}`}
            tone="danger"
          />
          <MetricCard label="Suspicious Train/Test" value={`${temporal?.suspicious_train_count ?? 0}/${temporal?.suspicious_test_count ?? 0}`} detail="Time-split coverage" tone="amber" />
        </div>
        <div className="mt-4 rounded-lg border border-line bg-panel2 p-3 text-sm text-muted">
          <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Train/Test Row Accounting</div>
          <div className="mt-2 grid gap-2 md:grid-cols-3">
            <div>Total labels: <span className="font-bold text-text">{String(trainingDiagnostics.total_label_rows ?? supervisedData?.label_count ?? "-")}</span></div>
            <div>Latest trainable rows: <span className="font-bold text-text">{String(trainingDiagnostics.trainable_latest_rows ?? "-")}</span></div>
            <div>Excluded history rows: <span className="font-bold text-text">{String(trainingDiagnostics.excluded_from_training ?? "-")}</span></div>
          </div>
          <p className="mt-2 text-xs">
            {String(trainingDiagnostics.explanation ?? "Training uses the latest trainable label per log; older reviewed decisions remain as audit history.")}
          </p>
        </div>
        {temporal?.warnings?.length ? (
          <div className="mt-4 rounded-lg border border-amber/30 bg-amber/10 p-3">
            <div className="text-xs font-extrabold uppercase tracking-wide text-amber">Temporal Coverage Warnings</div>
            <ul className="mt-2 space-y-1 text-sm text-amber">
              {temporal.warnings.slice(0, 5).map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {readiness ? (
          <div className="mt-4 rounded-lg border border-line bg-panel2 p-4">
            <div className="mb-2 flex items-center justify-between gap-2">
              <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Model Readiness Checklist</div>
              <Badge value={`${readiness.passed}/${readiness.total} passed`} />
            </div>
            <div className="grid gap-2 md:grid-cols-2">
              {readiness.items.map((item) => (
                <div key={item.name} className="rounded border border-line bg-panel px-3 py-2 text-sm">
                  <div className={item.passed ? "font-bold text-success" : "font-bold text-amber"}>
                    {item.passed ? "Pass" : "Needs work"}: {item.name}
                  </div>
                  <div className="mt-1 text-muted">{item.detail}</div>
                  {item.target ? <div className="mt-1 text-xs text-muted">Target: {item.target}</div> : null}
                </div>
              ))}
            </div>
          </div>
        ) : null}
        <div className="mt-4 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
          Assisted labels are weak labels. Review a representative sample before presenting supervised metrics as final model performance.
        </div>
        {validationWarnings.length ? (
          <div className="mt-4 rounded-lg border border-danger/30 bg-danger/10 p-3">
            <div className="text-xs font-extrabold uppercase tracking-wide text-danger">Validation Warnings</div>
            <ul className="mt-2 space-y-1 text-sm text-danger">
              {validationWarnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </div>
        ) : null}
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
        <div className="mt-4 grid gap-4 xl:grid-cols-3">
          <div className="rounded-lg border border-line bg-panel2 p-4">
            <div className="mb-2 text-xs font-extrabold uppercase tracking-wide text-muted">Reviewed Coverage By Class</div>
            <div className="space-y-2 text-sm text-muted">
              {Object.entries(supervisedData?.reviewed_label_distribution ?? {}).length ? (
                Object.entries(supervisedData?.reviewed_label_distribution ?? {}).map(([label, count]) => (
                  <div key={label} className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                    <span>{label}</span>
                    <span className="font-bold text-text">{count}</span>
                  </div>
                ))
              ) : (
                <EmptyState title="No reviewed labels" body="Export an active-learning sample and import reviewed decisions to build validation coverage." />
              )}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-4">
            <div className="mb-2 text-xs font-extrabold uppercase tracking-wide text-muted">Weak Label Distribution</div>
            <div className="space-y-2 text-sm text-muted">
              {Object.entries(supervisedData?.weak_label_distribution ?? {}).length ? (
                Object.entries(supervisedData?.weak_label_distribution ?? {}).map(([label, count]) => (
                  <div key={label} className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                    <span>{label}</span>
                    <span className="font-bold text-text">{count}</span>
                  </div>
                ))
              ) : (
                <EmptyState title="No weak labels" body="Assisted labels will appear here until reviewed by an analyst." />
              )}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-4">
            <div className="mb-2 text-xs font-extrabold uppercase tracking-wide text-muted">Promotion Gate</div>
            <div className="space-y-2 text-sm text-muted">
              <div className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                <span>Decision</span>
                <span className="font-bold text-text">{String(promotionGate.decision ?? "candidate_only")}</span>
              </div>
              <div className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                <span>Analyst review</span>
                <span className="font-bold text-text">{String(analystReviewEligible)}</span>
              </div>
              <div className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                <span>Production promoted</span>
                <span className="font-bold text-text">{String(productionPromoted)}</span>
              </div>
              <div className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                <span>Auto response</span>
                <span className="font-bold text-text">{String(promotionGate.response_automation_allowed ?? false)}</span>
              </div>
              <div className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                <span>Split</span>
                <span className="font-bold text-text">{String(supervisedData?.latest_run?.split_strategy ?? "random")}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="mb-4 flex items-center justify-between gap-2">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Data Quality</div>
            <h2 className="mt-1 text-xl font-black">Can the AI learn from this dataset?</h2>
            <p className="mt-1 text-sm text-muted">Parsing completeness, missing fields, and unknown apps help explain model reliability.</p>
          </div>
          <Badge value={`${dataQuality?.parse_success_rate ?? 0}% parsed`} />
        </div>
        <div className="grid gap-4 md:grid-cols-4">
          <MetricCard label="Imported" value={dataQuality?.total_imported_logs ?? "-"} detail="Raw log lines" tone="teal" />
          <MetricCard label="Parsed" value={dataQuality?.parsed_successfully ?? "-"} detail="Normalized rows" tone="cyan" />
          <MetricCard label="Parse Errors" value={dataQuality?.parse_errors ?? "-"} detail="Preserved as raw evidence" tone="amber" />
          <MetricCard label="Unknown Apps" value={dataQuality?.unknown_app_count ?? "-"} detail="Needs context" tone="amber" />
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {[
            ["Missing timestamp", dataQuality?.missing_timestamp],
            ["Missing source IP", dataQuality?.missing_source_ip],
            ["Missing destination IP", dataQuality?.missing_destination_ip],
            ["Missing action", dataQuality?.missing_action],
            ["Duplicate raw groups", dataQuality?.duplicate_raw_line_groups],
            ["First event", dataQuality?.dataset_time_min],
            ["Last event", dataQuality?.dataset_time_max]
          ].map(([label, value]) => (
            <div key={String(label)} className="rounded-lg border border-line bg-panel2 p-3 text-sm">
              <div className="text-xs font-bold uppercase tracking-wide text-muted">{label}</div>
              <div className="mt-1 font-bold text-text">{String(value ?? "-")}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="mb-3 text-sm font-extrabold uppercase tracking-wide text-muted">Feature Importance</div>
        <div className="mb-4 rounded-lg border border-line bg-panel2 p-3 text-sm text-muted">
          Feature generation processed <span className="font-bold text-text">{String(featureGeneration.rows_processed ?? "-")}</span> rows in{" "}
          <span className="font-bold text-text">{String(featureGeneration.duration_seconds ?? "-")}</span> seconds.
          {featureGeneration.warning ? <div className="mt-1 text-amber">{String(featureGeneration.warning)}</div> : null}
        </div>
        {topFeatures.length ? (
          <div className="grid gap-2 md:grid-cols-2">
            {topFeatures.slice(0, 10).map((feature) => (
              <div key={String(feature.feature)} className="rounded-lg border border-line bg-panel2 p-3 text-sm">
                <div className="font-bold text-text">{String(feature.feature)}</div>
                <div className="text-muted">Importance {String(feature.importance)}</div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState title="No feature importance yet" body="Train the supervised model to populate feature importance." />
        )}
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
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("active_learning")}>General Active Learning Sample</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("active_learning_malicious")}>Malicious-Focused Sample</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("active_learning_boundary")}>Round 4 Boundary Cases</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("active_learning_threat_boundary")}>Round 5 Threat Boundary</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("training_window_threat")}>Training-Window Threat Sample</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("boundary_report")}>Boundary Report</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("suspicious_recall_sample")}>Suspicious Recall Sample</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("suspicious_recall_report")}>Suspicious Recall Report</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("label_quality")}>Label Quality Issues</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("temporal_coverage")}>Temporal Coverage Report</button>
          </div>
        </div>
        <div className="mb-4 rounded-lg border border-line bg-panel2 p-3">
          <div className="flex flex-wrap items-center gap-3">
            <label className="btn-secondary cursor-pointer">
              Import Reviewed CSV
              <input className="hidden" type="file" accept=".csv,text/csv" onChange={(event) => importLabels(event.target.files?.[0])} />
            </label>
            <label className="btn-secondary cursor-pointer">
              Import Correction CSV
              <input className="hidden" type="file" accept=".csv,text/csv" onChange={(event) => importLabels(event.target.files?.[0], true)} />
            </label>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("report")}>Download Model Report</button>
            <span className="text-xs text-muted">
              Reviewed CSV import marks completed rows as reviewed, skips empty review rows, preserves assisted provenance, and protects manual labels.
            </span>
          </div>
          {importResult ? <div className="mt-3 rounded border border-success/30 bg-success/10 p-2 text-sm text-success">{importResult}</div> : null}
          {downloadError ? <div className="mt-3 text-sm text-danger">{downloadError}</div> : null}
          {labelMutations.importCsv.isError ? <div className="mt-3"><ErrorBanner error={labelMutations.importCsv.error} /></div> : null}
          {quickReviewMessage ? <div className="mt-3 rounded border border-cyan/30 bg-cyan/10 p-2 text-sm text-cyan">{quickReviewMessage}</div> : null}
          <div className="mt-3 rounded border border-line bg-panel px-3 py-2 text-xs text-muted">
            For active-learning CSVs, fill at least `human_review_decision` with one of benign, benign_unusual, suspicious, malicious, or needs_context.
            Blank review rows are skipped safely.
          </div>
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
                  <th>Quick Review</th>
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
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {(["benign", "benign_unusual", "suspicious", "malicious", "needs_context"] as MLLabelValue[]).map((label) => (
                          <button
                            key={label}
                            className="rounded border border-line bg-panel2 px-2 py-1 text-xs font-bold text-muted hover:border-cyan hover:text-cyan"
                            type="button"
                            onClick={() => quickReview(item, label)}
                          >
                            {label}
                          </button>
                        ))}
                      </div>
                    </td>
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
        <div className="mb-4 flex items-center justify-between gap-2">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Baseline And Drift Snapshot</div>
            <h2 className="mt-1 text-xl font-black">Is current traffic changing?</h2>
            <p className="mt-1 text-sm text-muted">Distribution snapshot for apps, actions, source IPs, ports, unknown apps, denials, and anomaly rate.</p>
          </div>
          <Badge value={`${drift?.anomaly_rate ?? data?.anomaly_rate ?? 0}% anomaly`} />
        </div>
        <div className="grid gap-4 md:grid-cols-4">
          <MetricCard label="Unknown App Rate" value={`${drift?.unknown_app_rate ?? 0}%`} detail={`${drift?.unknown_app_count ?? 0} logs`} tone="amber" />
          <MetricCard label="Deny/Drop/Reset" value={`${drift?.deny_drop_reset_rate ?? 0}%`} detail={`${drift?.deny_drop_reset_count ?? 0} logs`} tone="danger" />
          <MetricCard label="Anomaly Rate" value={`${drift?.anomaly_rate ?? 0}%`} detail={`${drift?.anomaly_count ?? 0} logs`} tone="cyan" />
          <MetricCard label="Total Logs" value={drift?.total_logs ?? 0} detail="Current normalized population" tone="teal" />
        </div>
        <div className="mt-4 grid gap-4 xl:grid-cols-3">
          {[
            ["Top Apps", drift?.app_distribution],
            ["Top Actions", drift?.action_distribution],
            ["Top Destination Ports", drift?.top_destination_ports]
          ].map(([title, rows]) => (
            <div key={String(title)} className="rounded-lg border border-line bg-panel2 p-4">
              <div className="mb-2 text-xs font-extrabold uppercase tracking-wide text-muted">{String(title)}</div>
              <div className="space-y-2 text-sm">
                {(rows as Array<{ name: string; count: number }> | undefined)?.slice(0, 6).map((row) => (
                  <div key={`${title}-${row.name}`} className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                    <span className="text-muted">{row.name}</span>
                    <span className="font-bold text-text">{row.count}</span>
                  </div>
                )) ?? <EmptyState title="No distribution data" body="Import and normalize logs to populate this view." />}
              </div>
            </div>
          ))}
        </div>
        {drift?.interpretation ? <div className="mt-4 rounded border border-line bg-panel2 p-3 text-sm text-muted">{drift.interpretation}</div> : null}
      </section>

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
