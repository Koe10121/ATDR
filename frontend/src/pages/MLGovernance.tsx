import { useState } from "react";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartCard } from "../components/ChartCard";
import { EmptyState } from "../components/EmptyState";
import { MetricCard } from "../components/MetricCard";
import { Badge } from "../components/Badge";
import { ErrorBanner } from "../components/ErrorBanner";
import { api } from "../lib/api";
import {
  useClassTemporalCoverage,
  useDashboardValidationSummary,
  useMlLabelMutations,
  useMlReport,
  useMlReviewQueue,
  useSupervisedModels,
  useSupervisedReport
} from "../hooks/useApiQueries";
import type { ClassTemporalCoverageRow, MLAttackType, MLLabelValue, MLReviewQueueItem } from "../types/api";

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
  const validationSummary = useDashboardValidationSummary();
  const supervisedModels = useSupervisedModels();
  const temporalCoverage = useClassTemporalCoverage();
  const reviewQueue = useMlReviewQueue({ limit: 25 });
  const labelMutations = useMlLabelMutations();
  const data = report.data;
  const supervisedData = supervised.data;
  const supervisedMetrics = supervisedData?.latest_run?.metrics ?? {};
  const threatPositive = (supervisedMetrics.threat_positive ?? {}) as Record<string, unknown>;
  const socTriageMode = supervisedData?.soc_triage_mode;
  const socReviewProfiles = socTriageMode?.review_profiles ?? [];
  const topFeatures = supervisedData?.latest_run?.top_features ?? [];
  const dataQuality = data?.data_quality;
  const validationWarnings = supervisedData?.validation_warnings ?? supervisedData?.latest_run?.validation_warnings ?? [];
  const reviewedTarget = supervisedData?.reviewed_label_target ?? 300;
  const reviewedCoverage = supervisedData?.reviewed_label_count ? Math.round((supervisedData.reviewed_label_count / reviewedTarget) * 100) : 0;
  const reviewedDistribution = supervisedData?.reviewed_label_distribution ?? {};
  const promotionGate = supervisedData?.latest_run?.promotion_gate ?? {};
  const featureGeneration = supervisedData?.latest_run?.feature_generation ?? {};
  const trainingDiagnostics = supervisedData?.latest_run?.training_dataset_diagnostics ?? {};
  const temporal = temporalCoverage.data;
  const readiness = supervisedData?.model_readiness_checklist ?? supervisedData?.latest_run?.model_readiness_checklist;
  const benchmark = validationSummary.data?.benchmark;
  const v13Ai = validationSummary.data?.v13_ai;
  const v14Ai = validationSummary.data?.v14_ai;
  const v15Ai = validationSummary.data?.v15_ai;
  const v16Ai = validationSummary.data?.v16_ai;
  const v17Ai = validationSummary.data?.v17_ai;
  const v18Ai = validationSummary.data?.v18_ai;
  const v19Ai = validationSummary.data?.v19_ai;
  const v19bAi = validationSummary.data?.v19b_ai;
  const independentAi = v19bAi?.available ? v19bAi : v19Ai;
  const drift = data?.baseline_drift_report;
  const perClass = (supervisedMetrics.per_class ?? {}) as Record<string, Record<string, unknown>>;
  const benignMetrics = perClass.benign ?? {};
  const suspiciousMetrics = perClass.suspicious ?? {};
  const maliciousMetrics = perClass.malicious ?? {};
  const benignRecall = Number(benignMetrics.recall ?? 0);
  const suspiciousRecall = Number(suspiciousMetrics.recall ?? 0);
  const maliciousRecall = Number(maliciousMetrics.recall ?? 0);
  const threatPositiveRecall = Number(threatPositive.recall ?? 0);
  const productionPromoted = Boolean(promotionGate.production_promoted);
  const analystReviewEligible = Boolean(promotionGate.analyst_review_eligible);
  const reviewedBenign = Number(reviewedDistribution.benign ?? 0);
  const reviewedNeedsContext = Number(reviewedDistribution.needs_context ?? 0);
  const reviewedMalicious = Number(reviewedDistribution.malicious ?? temporal?.reviewed_malicious_count ?? 0);
  const reviewedSuspicious = Number(reviewedDistribution.suspicious ?? temporal?.reviewed_suspicious_count ?? 0);
  const classCoverage: Record<string, ClassTemporalCoverageRow> =
    temporal?.class_coverage ?? supervisedData?.class_temporal_coverage?.class_coverage ?? {};
  const unstableTimeSplit = Object.values(classCoverage).some((row) => {
    return Number(row.train_count ?? 0) === 0 || Number(row.test_count ?? 0) === 0;
  });
  const registry = supervisedModels.data;
  const activeRegistryModel = registry?.models.find((model) => model.is_active_path) ?? registry?.models[0];
  const activeArtifactMetadataUnknown =
    activeRegistryModel?.model_version === "active-unregistered" || activeRegistryModel?.model_type === "unknown";
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<string | null>(null);
  const [benchmarkImportResult, setBenchmarkImportResult] = useState<string | null>(null);
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
      | "stage1_threat_recall_sample"
      | "benign_final_gap_sample"
      | "final_small_gap_sample"
      | "soc_triage_final_report"
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
        case "stage1_threat_recall_sample":
          file = await api.downloadStage1ThreatRecallReviewSample({ limit: 300 });
          break;
        case "benign_final_gap_sample":
          file = await api.downloadBenignFinalGapReviewSample({ limit: 100 });
          break;
        case "final_small_gap_sample":
          file = await api.downloadFinalSmallLabelGapSample({ limit: 64 });
          break;
        case "soc_triage_final_report":
          file = await api.downloadSocTriageFinalRecommendation();
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
      onSuccess: (result) => {
        const errorSummary = Object.entries(result.error_summary ?? {})
          .map(([reason, count]) => `${reason}: ${count}`)
          .join(", ");
        setImportResult(
          `Reviewed import complete: ${result.created} created, ${result.updated} reviewed/updated, ${result.changed_decisions ?? 0} decision changes, ${result.skipped ?? 0} skipped, ${result.protected_manual ?? 0} manual labels protected, ${result.protected_reviewed ?? 0} reviewed labels protected, ${result.failed} failed.${errorSummary ? ` Failure reasons: ${errorSummary}.` : ""}`
        );
      }
      }
    );
  }

  function importBenchmarkReview(file?: File) {
    if (!file) {
      return;
    }
    setBenchmarkImportResult(null);
    labelMutations.importBenchmarkCsv.mutate(file, {
      onSuccess: (result) => {
        setBenchmarkImportResult(
          `Benchmark review import complete: ${result.imported} reviewed rows stored separately, ${result.skipped} skipped, ${result.failed} failed. Artifact: ${result.artifact_name ?? "created"}. No ml_labels rows were changed.`
        );
      }
    });
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

  function refreshGovernance() {
    void report.refetch();
    void supervised.refetch();
    void supervisedModels.refetch();
    void temporalCoverage.refetch();
    void reviewQueue.refetch();
  }

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">ML Governance</div>
            <h1 className="mt-2 text-3xl font-black">AI is assistive, explainable, and audited.</h1>
            <p className="mt-2 text-muted">
              IsolationForest highlights unusual traffic. Rule evidence and analyst review remain the authority for response decisions.
            </p>
            <p className="mt-2 text-xs text-muted">
              Summary data is cached briefly for dashboard responsiveness. Use refresh after training, scoring, or label import.
            </p>
          </div>
          <button className="btn-secondary" type="button" onClick={refreshGovernance}>
            Refresh ML Summary
          </button>
        </div>
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
        <div className="mt-4 rounded-lg border border-line bg-panel2 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Supervised Model Registry</div>
              <div className="mt-1 text-sm text-muted">
                Active and candidate artifacts are tracked for decision support. Automation stays disabled.
              </div>
            </div>
            <Badge value={registry?.active_artifact_exists ? "active artifact ready" : "no active artifact"} />
          </div>
          <div className="grid gap-3 md:grid-cols-4">
            <MetricCard label="Active Model Type" value={activeRegistryModel?.model_type ?? supervisedData?.latest_run?.model_type ?? "-"} detail="Current classifier family" tone="cyan" />
            <MetricCard label="Feature Set" value={activeRegistryModel?.feature_set_version ?? "-"} detail="Versioned feature pipeline" tone="teal" />
            <MetricCard label="Registry Entries" value={registry?.models.length ?? 0} detail="Recent train/activate/rollback runs" tone="amber" />
            <MetricCard label="Auto Response" value={String(registry?.response_automation_allowed ?? false)} detail="Must remain disabled" tone="danger" />
          </div>
          <details className="mt-3">
            <summary className="cursor-pointer text-sm font-bold text-text">View candidate model registry</summary>
            <div className="mt-3 overflow-auto">
              <table className="soc-table soc-table-compact">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Operation</th>
                    <th>Decision</th>
                    <th>F1</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {(registry?.models ?? []).slice(0, 8).map((model) => {
                    const metrics = model.metrics ?? {};
                    return (
                      <tr key={model.model_id}>
                        <td>{model.model_id}</td>
                        <td>{model.model_type ?? "-"}</td>
                        <td>{model.operation}</td>
                        <td>{model.readiness_decision ?? "candidate_only"}</td>
                        <td>{String(metrics.f1 ?? "-")}</td>
                        <td>{model.created_at}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </details>
        </div>
        <div className="mt-4 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
          <div className="font-bold">Analyst Review</div>
          <div className="mt-1">
            Supervised output is decision support. Automation is disabled.
            {activeArtifactMetadataUnknown ? " Active artifact metadata should be refreshed with a registered training run." : ""}
          </div>
        </div>
        <div className="mt-4 rounded-lg border border-cyan/30 bg-cyan/10 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-cyan">Recommended AI Mode</div>
              <div className="mt-1 text-lg font-black text-text">{socTriageMode?.recommended_ai_mode ?? "SOC triage decision support"}</div>
            </div>
            <Badge value="Decision Support" />
          </div>
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">SOC Triage Mode</div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">Analyst Review</div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">Manual Approval Required</div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">Automation Disabled</div>
          </div>
          <div className="mt-3 rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
            Benchmark:{" "}
            <span className="font-bold text-text">
              {independentAi?.available
                ? `${independentAi.independent_label_count ?? 0} independent rows | Threat F1 ${
                    independentAi.threat_positive_f1 ?? "-"
                  } | ${independentAi.readiness_decision ?? "analyst_review_eligible"}`
                : v18Ai?.available
                ? `${v18Ai.external_label_count ?? 0} reviewed benchmark rows | Threat F1 ${
                    v18Ai.threat_positive_f1 ?? "-"
                  } | ${v18Ai.readiness_decision ?? "candidate_only"}`
                : v17Ai?.available
                ? `${v17Ai.external_label_count ?? 0} unseen labels | Threat F1 ${
                    v17Ai.threat_positive_f1 ?? "-"
                  } | ${v17Ai.readiness_decision ?? "candidate_only"}`
                : v16Ai?.available
                ? `${v16Ai.external_label_count ?? 0} unseen labels | Threat F1 ${
                    v16Ai.threat_positive_f1 ?? "-"
                  } | ${v16Ai.readiness_decision ?? "candidate_only"}`
                : v15Ai?.available
                ? `${v15Ai.benchmark_label_count ?? 0} labels | Threat F1 ${
                    v15Ai.threat_positive_f1 ?? "-"
                  } | ${v15Ai.readiness_decision ?? "candidate_only"}`
                : benchmark?.available
                ? `${benchmark.detection_mode ?? "hybrid"} | Threat F1 ${benchmark.threat_positive_f1 ?? benchmark.f1 ?? "-"} | ${
                    benchmark.readiness_decision ?? "candidate_only"
                  }`
                : "not generated"}
            </span>
          </div>
          <div className="mt-2 rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
            Training data:{" "}
            <span className="font-bold text-text">
              {v13Ai?.available
                ? `${v13Ai.reviewed_label_count ?? 0} reviewed | minimum gaps ${v13Ai.minimum_label_gap ?? 0} | ${
                    v13Ai.readiness_decision ?? "candidate_only"
                  }`
                : "v1.3 audit not generated"}
            </span>
          </div>
          <div className="mt-2 grid gap-2 md:grid-cols-2">
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">Main blocker:</span>{" "}
              {v14Ai?.available ? v14Ai.current_blocker ?? "model validation" : "v1.4 evaluation pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">Calibration:</span>{" "}
              {independentAi?.available
                ? `${independentAi.calibration_status ?? "pending"} / ${independentAi.calibration_method ?? "none"}`
                : v18Ai?.available
                ? `${v18Ai.calibration_status ?? "pending"} / ${v18Ai.calibration_method ?? "none"}`
                : v17Ai?.calibration_status ?? v16Ai?.calibration_status ?? v15Ai?.calibration_status ?? v14Ai?.calibration_status ?? "pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">Confirmed noisy pattern:</span>{" "}
              {v14Ai?.confirmed_noisy_pattern ?? "analysis pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">False positives:</span>{" "}
              {v14Ai?.false_positives_improved ? "improved" : "validation pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">QUIC/443 mitigation:</span>{" "}
              {v14Ai?.quic_mitigation_status ?? "pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              Actionable review sample excludes protected manual labels
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              Model remains decision support only
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              Response automation disabled
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              Not production-promoted
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              {independentAi?.available
                ? `Independent readiness ${independentAi.readiness_version ?? "v7"} ${
                    independentAi.checks_passed ?? 0
                  }/${independentAi.checks_total ?? 0}`
                : v18Ai?.available
                ? `External readiness v6 ${v18Ai.checks_passed ?? 0}/${v18Ai.checks_total ?? 0}`
                : v17Ai?.available
                ? `External readiness checks ${v17Ai.checks_passed ?? 0}/${v17Ai.checks_total ?? 0}`
                : v16Ai?.available
                ? `External readiness checks ${v16Ai.checks_passed ?? 0}/${v16Ai.checks_total ?? 0}`
                : v15Ai?.available
                ? `Benchmark readiness checks ${v15Ai.checks_passed ?? 0}/${v15Ai.checks_total ?? 0}`
                : "Benchmark readiness pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">Generalization:</span>{" "}
              {independentAi?.available
                ? `${v19bAi?.available ? (v19bAi.fpr_blocker_resolved ? "FPR blocker resolved" : "FPR blocker active") : independentAi.generalization_status ?? "not evaluated"} | FPR ${
                    independentAi.benign_like_false_positive_rate ?? "-"
                  }`
                : v18Ai?.available
                ? `${v18Ai.overfitting_status ?? "not evaluated"} | FPR ${v18Ai.benign_like_false_positive_rate ?? "-"}`
                : v17Ai?.available
                ? `${v17Ai.overfitting_status ?? "not evaluated"} | FPR ${v17Ai.benign_like_false_positive_rate ?? "-"}`
                : v16Ai?.available
                ? `${v16Ai.overfitting_status ?? "not evaluated"} | F1 gap ${v16Ai.threat_f1_gap ?? "-"}`
                : "external holdout pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">External validation:</span>{" "}
              {independentAi?.available
                ? independentAi.external_benchmark_validated
                  ? "v1.8 external benchmark passed"
                  : "external benchmark not yet passed"
                : v18Ai?.available
                ? v18Ai.external_benchmark_validated
                  ? "external benchmark candidate passed"
                  : "not yet passed"
                : v17Ai?.available
                ? v17Ai.external_benchmark_validated
                  ? "passed"
                  : "not yet passed"
                : v16Ai?.external_benchmark_validated
                ? "passed"
                : "not yet passed"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">Current blockers:</span>{" "}
              {independentAi?.available
                ? (independentAi.failed_checks ?? []).filter(Boolean).join(", ") || "none"
                : v18Ai?.available
                ? (v18Ai.failed_checks ?? []).filter(Boolean).join(", ") || "none"
                : v17Ai?.available
                ? (v17Ai.failed_checks ?? []).filter(Boolean).join(", ") || "none"
                : "v1.7 profile comparison pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">Independent holdout:</span>{" "}
              {independentAi?.available
                ? `${independentAi.independent_label_count ?? 0} rows | ${
                    independentAi.independent_source_count ?? 0
                  } sources | ${independentAi.independent_holdout_validated ? "passed" : "review required"}`
                : v18Ai?.available
                ? `${v18Ai.recovered_false_negatives ?? 0} threat misses recovered; ${v18Ai.remaining_false_negatives ?? 0} remain`
                : v17Ai?.available
                ? `${v17Ai.review_sample_rows ?? 0} rows exported`
                : "pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">Validation profile:</span>{" "}
              {independentAi?.available
                ? independentAi.best_profile ?? "not selected"
                : v18Ai?.available
                ? v18Ai.best_profile ?? "not selected"
                : v17Ai?.best_profile ?? "pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">Independent metrics:</span>{" "}
              {independentAi?.available
                ? `F1 ${independentAi.threat_positive_f1 ?? "-"} | Recall ${
                    independentAi.threat_positive_recall ?? "-"
                  } | FPR ${independentAi.benign_like_false_positive_rate ?? "-"}`
                : v18Ai?.available
                ? `Threat ${v18Ai.threat_positive_recall ?? "-"} | Suspicious ${v18Ai.suspicious_recall ?? "-"}`
                : "v1.8 pending"}
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">Controlled source:</span>{" "}
              {independentAi?.available
                ? independentAi.controlled_real_source_validated
                  ? "validated in safe replay/source workflow"
                  : "validation pending or requires review"
                : "v1.9 pending"}
            </div>
            {v19bAi?.available ? (
              <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
                <span className="font-bold text-text">Review boundary:</span>{" "}
                {v19bAi.analyst_review_boundary_count ?? 0} ambiguous rows routed to analyst review;{" "}
                {v19bAi.false_positives_reduced ?? 0} false positives removed
              </div>
            ) : null}
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              Decision Support Only
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              Response Automation Disabled
            </div>
          </div>
          {socReviewProfiles.length ? (
            <details className="mt-3">
              <summary className="cursor-pointer text-sm font-bold text-text">SOC review profiles</summary>
              <div className="mt-3 overflow-auto">
                <table className="soc-table soc-table-compact">
                  <thead>
                    <tr>
                      <th>Profile</th>
                      <th>Precision</th>
                      <th>Recall</th>
                      <th>False Positives</th>
                      <th>False Negatives</th>
                      <th>Queue</th>
                      <th>Guidance</th>
                    </tr>
                  </thead>
                  <tbody>
                    {socReviewProfiles.map((profile) => (
                      <tr key={String(profile.profile)}>
                        <td>{String(profile.profile ?? "-")}</td>
                        <td>{String(profile.precision ?? "report")}</td>
                        <td>{String(profile.recall ?? "report")}</td>
                        <td>{String(profile.false_positives ?? "report")}</td>
                        <td>{String(profile.false_negatives ?? "report")}</td>
                        <td>{String(profile.estimated_review_queue_size ?? "report")}</td>
                        <td>{String(profile.guidance ?? "Diagnostic only; no auto activation.")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          ) : null}
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <MetricCard label="Reviewed Labels" value={supervisedData?.reviewed_label_count ?? 0} detail="Human-reviewed/manual rows" tone="teal" />
          <MetricCard label="Assisted Pending Review" value={supervisedData?.unreviewed_assisted_label_count ?? 0} detail="Weak labels needing validation" tone="amber" />
          <MetricCard label="Review Coverage" value={`${reviewedCoverage}%`} detail={`Target ${reviewedTarget} reviewed labels`} tone="cyan" />
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <MetricCard label="Threat-Positive Precision" value={String(threatPositive.precision ?? "-")} detail="Suspicious + malicious triage grouping" tone="amber" />
          <MetricCard label="Threat-Positive Recall" value={String(threatPositive.recall ?? "-")} detail="Combined SOC catch rate" tone="danger" />
          <MetricCard label="Threat-Positive F1" value={String(threatPositive.f1 ?? "-")} detail="SOC triage signal" tone="cyan" />
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-4">
          <MetricCard
            label="Benign Recall"
            value={String(benignMetrics.recall ?? "-")}
            detail={benignRecall <= 0 ? "Needs review" : "Calibration signal"}
            tone={benignRecall <= 0 ? "danger" : "teal"}
          />
          <MetricCard
            label="Suspicious Recall"
            value={String(suspiciousMetrics.recall ?? "-")}
            detail={suspiciousRecall < 0.8 ? "Still below target >= 0.8" : "Meets current recall target"}
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
            detail="Decision support"
            tone="cyan"
          />
        </div>
        {benignRecall <= 0 || suspiciousRecall < 0.8 ? (
          <div className="mt-4 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
            Review focus: benign and suspicious separation need more analyst-verified examples.
          </div>
        ) : null}
        <details className="mt-4 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
          <summary className="cursor-pointer font-bold">Technical Review Notes</summary>
          <ul className="mt-2 space-y-1">
            {reviewedMalicious >= 150 ? <li>Malicious reviewed target is met; do not prioritize malicious-heavy review unless evidence is strong.</li> : null}
            {reviewedSuspicious >= 300 ? <li>Suspicious reviewed target is met; continue only focused boundary cleanup.</li> : null}
            {reviewedBenign < 300 ? <li>Benign labels are under-reviewed.</li> : null}
            {reviewedNeedsContext < 50 ? <li>Needs_context labels are under-reviewed.</li> : null}
            {benignRecall <= 0 ? <li>Benign recall is the current blocker; many true benign rows are predicted as benign_unusual or suspicious.</li> : null}
            {threatPositiveRecall < 0.85 ? <li>Stage 1 threat-positive recall still needs calibration.</li> : null}
            <li>Stage 2 suspicious/malicious separation is promising, but Stage 1 must catch threat-positive rows first.</li>
            {unstableTimeSplit ? <li>Current time split has class imbalance; metrics are unstable.</li> : null}
            <li>Model remains decision support only.</li>
          </ul>
        </details>
        <div className="mt-4 rounded-lg border border-cyan/30 bg-cyan/10 p-3 text-sm text-cyan">
          {analystReviewEligible
            ? "Analyst Review Eligible."
            : "Analyst review criteria still need work."}{" "}
          Response actions remain analyst-approved.
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
          Weak labels require analyst review before model claims.
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
            <div className="mb-2 text-xs font-extrabold uppercase tracking-wide text-muted">Analyst Review Gate</div>
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
                <span>Deployment Mode</span>
                <span className="font-bold text-text">{productionPromoted ? "Promoted" : "Lab only"}</span>
              </div>
              <div className="flex justify-between rounded border border-line bg-panel px-3 py-2">
                <span>Automation</span>
                <span className="font-bold text-text">{promotionGate.response_automation_allowed ? "Enabled" : "Disabled"}</span>
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
            ["Latest ingestion", dataQuality?.latest_ingestion_time],
            ["First event", dataQuality?.dataset_time_min],
            ["Last event", dataQuality?.dataset_time_max]
          ].map(([label, value]) => (
            <div key={String(label)} className="rounded-lg border border-line bg-panel2 p-3 text-sm">
              <div className="text-xs font-bold uppercase tracking-wide text-muted">{label}</div>
              <div className="mt-1 font-bold text-text">{String(value ?? "-")}</div>
            </div>
          ))}
        </div>
        {dataQuality?.parser_error_examples?.length ? (
          <details className="mt-4">
            <summary className="cursor-pointer text-sm font-bold text-text">Parser error examples</summary>
            <div className="mt-3 space-y-2">
              {dataQuality.parser_error_examples.slice(0, 5).map((item, index) => (
                <div key={String(item.raw_log_id ?? index)} className="rounded-lg border border-line bg-shell p-3 text-xs text-muted">
                  <div className="font-bold text-text">Raw log {String(item.raw_log_id ?? "-")} | {String(item.imported_at ?? "-")}</div>
                  <div className="mt-1 break-all">{String(item.raw_line_excerpt ?? "-")}</div>
                </div>
              ))}
            </div>
          </details>
        ) : null}
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
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("stage1_threat_recall_sample")}>Stage 1 Recall Sample</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("benign_final_gap_sample")}>Benign Gap Sample</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("final_small_gap_sample")}>Final Small Gap Sample</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("soc_triage_final_report")}>SOC Triage Recommendation</button>
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
            <label className="btn-secondary cursor-pointer">
              Import Benchmark Review CSV
              <input className="hidden" type="file" accept=".csv,text/csv" onChange={(event) => importBenchmarkReview(event.target.files?.[0])} />
            </label>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("report")}>Download Model Report</button>
            <span className="text-xs text-muted">
              Reviewed CSV import marks completed rows as reviewed, skips empty review rows, preserves assisted provenance, and protects manual labels.
            </span>
          </div>
          {importResult ? <div className="mt-3 rounded border border-success/30 bg-success/10 p-2 text-sm text-success">{importResult}</div> : null}
          {benchmarkImportResult ? <div className="mt-3 rounded border border-cyan/30 bg-cyan/10 p-2 text-sm text-cyan">{benchmarkImportResult}</div> : null}
          {downloadError ? <div className="mt-3 text-sm text-danger">{downloadError}</div> : null}
          {labelMutations.importCsv.isError ? <div className="mt-3"><ErrorBanner error={labelMutations.importCsv.error} /></div> : null}
          {labelMutations.importBenchmarkCsv.isError ? <div className="mt-3"><ErrorBanner error={labelMutations.importBenchmarkCsv.error} /></div> : null}
          {quickReviewMessage ? <div className="mt-3 rounded border border-cyan/30 bg-cyan/10 p-2 text-sm text-cyan">{quickReviewMessage}</div> : null}
          <div className="mt-3 rounded border border-line bg-panel px-3 py-2 text-xs text-muted">
            For active-learning CSVs, fill at least `human_review_decision` with one of benign, benign_unusual, suspicious, malicious, or needs_context.
            Blank review rows are skipped safely. Files containing `benchmark_row_id` must use Benchmark Review Import and remain separate from database-backed labels.
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
