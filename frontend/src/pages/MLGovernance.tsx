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
  useDetectionMlProductization,
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

function firstMetric(...values: unknown[]) {
  return values.find((value) => value !== null && value !== undefined && value !== "");
}

function metricText(value: unknown) {
  return value === null || value === undefined || value === "" ? "-" : String(value);
}

export function MLGovernance() {
  const report = useMlReport();
  const supervised = useSupervisedReport();
  const validationSummary = useDashboardValidationSummary();
  const productization = useDetectionMlProductization();
  const supervisedModels = useSupervisedModels();
  const temporalCoverage = useClassTemporalCoverage();
  const reviewQueue = useMlReviewQueue({ limit: 25 });
  const labelMutations = useMlLabelMutations();
  const data = report.data;
  const supervisedData = supervised.data;
  const supervisedMetrics = supervisedData?.latest_run?.metrics ?? {};
  const threatPositive = (supervisedMetrics.threat_positive ?? {}) as Record<string, unknown>;
  const weightedAverage = (supervisedMetrics.weighted_average ?? {}) as Record<string, unknown>;
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
  const v20Ai = validationSummary.data?.v20_ai;
  const v330Quality = validationSummary.data?.v330_detection_ml_quality;
  const v355Queue = validationSummary.data?.v355_soc_queue;
  const v357Agreement = validationSummary.data?.v357_queue_evidence_agreement;
  const v359Policy = validationSummary.data?.v359_supervised_output_policy;
  const v30Readiness = validationSummary.data?.v30_production_readiness;
  const independentAi = v20Ai?.available ? v20Ai : v19bAi?.available ? v19bAi : v19Ai;
  const finalThreatPrecision = firstMetric(
    independentAi?.threat_positive_precision,
    v18Ai?.threat_positive_precision,
    v17Ai?.threat_positive_precision,
    v14Ai?.threat_positive_precision,
    benchmark?.precision,
    threatPositive.precision
  );
  const finalThreatRecall = firstMetric(
    independentAi?.threat_positive_recall,
    v18Ai?.threat_positive_recall,
    v17Ai?.threat_positive_recall,
    v16Ai?.threat_positive_recall,
    v15Ai?.threat_positive_recall,
    v14Ai?.threat_positive_recall,
    benchmark?.recall,
    threatPositive.recall
  );
  const finalThreatF1 = firstMetric(
    independentAi?.threat_positive_f1,
    v18Ai?.threat_positive_f1,
    v17Ai?.threat_positive_f1,
    v16Ai?.threat_positive_f1,
    v15Ai?.threat_positive_f1,
    v14Ai?.threat_positive_f1,
    benchmark?.threat_positive_f1,
    benchmark?.f1,
    threatPositive.f1
  );
  const finalBenignFpr = firstMetric(
    independentAi?.benign_like_false_positive_rate,
    v18Ai?.benign_like_false_positive_rate,
    v17Ai?.benign_like_false_positive_rate,
    v16Ai?.benign_like_false_positive_rate,
    v15Ai?.benign_like_false_positive_rate,
    v14Ai?.benign_like_false_positive_rate
  );
  const finalMacroF1 = firstMetric(independentAi?.macro_f1, v18Ai?.macro_f1, v17Ai?.macro_f1);
  const finalWeightedF1 = firstMetric(independentAi?.weighted_f1, v18Ai?.weighted_f1, weightedAverage.f1, supervisedMetrics.f1);
  const finalValidationRows = firstMetric(
    independentAi?.independent_label_count,
    v18Ai?.external_label_count,
    v17Ai?.external_label_count,
    v16Ai?.external_label_count,
    v15Ai?.benchmark_label_count,
    benchmark?.total_rows,
    supervisedData?.latest_run?.test_rows
  );
  const finalValidationDecision = String(
    firstMetric(independentAi?.readiness_decision, v18Ai?.readiness_decision, v17Ai?.readiness_decision, promotionGate.decision, "analyst_review_eligible")
  );
  const finalValidationSource = independentAi?.available
    ? v20Ai?.available
      ? "Fresh blind validation"
      : "Independent validation"
    : v18Ai?.available
    ? "External validation"
    : v17Ai?.available || v16Ai?.available
    ? "External holdout"
    : v15Ai?.available || benchmark?.available
    ? "Benchmark validation"
    : "Current supervised report";
  const v330BaselineFpr = Number(v330Quality?.baseline_benign_like_false_positive_rate ?? NaN);
  const v330SuspiciousRecall = Number(v330Quality?.baseline_suspicious_recall ?? NaN);
  const v330CalibrationStatus = String(v330Quality?.calibration_status ?? "not generated");
  const v330MainBlocker = !v330Quality?.available
    ? "Run v3.30 revalidation"
    : Number.isFinite(v330BaselineFpr) && v330BaselineFpr > 0.15
    ? "False-positive noise"
    : Number.isFinite(v330SuspiciousRecall) && v330SuspiciousRecall < 0.8
    ? "Suspicious recall"
    : v330CalibrationStatus !== "passed"
    ? "Confidence calibration"
    : "Monitor drift";
  const v330BestProfile = String(v330Quality?.best_profile ?? "not generated").replaceAll("_", " ");
  const v330SafetyLabel =
    v330Quality?.production_promoted || v330Quality?.model_activated || v330Quality?.response_automation_allowed
      ? "review safety"
      : "diagnostic only";
  const v355QueueLabel = v355Queue?.available
    ? `${v355Queue.passing_splits ?? 0}/${v355Queue.evaluated_splits ?? 0} splits`
    : "not generated";
  const v355QueueReadiness = String(v355Queue?.readiness_decision ?? "candidate_only").replaceAll("_", " ");
  const v355QueueSafetyLabel =
    v355Queue?.production_promoted || v355Queue?.model_activated || v355Queue?.response_automation_allowed || v355Queue?.labels_written
      ? "review safety"
      : "diagnostic only";
  const v357AgreementLabel = v357Agreement?.available
    ? `${v357Agreement.passing_splits ?? 0}/${v357Agreement.evaluated_splits ?? 0} splits`
    : "not generated";
  const v357Readiness = String(v357Agreement?.readiness_decision ?? "diagnostic_only").replaceAll("_", " ");
  const v357SafetyLabel =
    v357Agreement?.production_promoted ||
    v357Agreement?.model_activated ||
    v357Agreement?.response_automation_allowed ||
    v357Agreement?.labels_written ||
    v357Agreement?.raw_logs_included
      ? "review safety"
      : "diagnostic only";
  const v357CategoryCounts = v357Agreement?.category_counts ?? {};
  const v357EvidenceOnly = Number(v357CategoryCounts.evidence_only_review ?? 0);
  const v357QueueOnly = Number(v357CategoryCounts.queue_only_review ?? 0);
  const v359PolicyLabel = v359Policy?.available ? `${v359Policy.checks_passed ?? 0}/${v359Policy.checks_total ?? 0} checks` : "not generated";
  const v359Strategy = String(v359Policy?.recommended_supervised_strategy ?? "binary_soc_review_queue").replaceAll("_", " ");
  const v359ExactPolicy = String(v359Policy?.exact_classification_policy ?? "explanation_or_ranking_only").replaceAll("_", " ");
  const v359SafetyLabel =
    v359Policy?.production_promoted ||
    v359Policy?.model_activated ||
    v359Policy?.response_automation_allowed ||
    v359Policy?.real_firewall_blocking_enabled ||
    v359Policy?.labels_written
      ? "review safety"
      : "activation disabled";
  const v359AllowedStatuses = v359Policy?.allowed_output_statuses ?? {};
  const productizationData = productization.data;
  const productizationReadiness = String(productizationData?.readiness?.decision ?? "not evaluated").replaceAll("_", " ");
  const productizationReadinessDisplay = productizationData?.ok ? "Passed" : productizationData ? "Needs Review" : "Not Evaluated";
  const productizationChecks = productizationData?.readiness
    ? `${productizationData.readiness.required_checks_passed}/${productizationData.readiness.required_checks_total} required`
    : "not evaluated";
  const productizationRuleLabel = productizationData?.rule_contract?.ok ? "passed" : productizationData ? "needs review" : "not evaluated";
  const productizationScenarioLabel = productizationData?.scenario_quality?.included
    ? `${productizationData.scenario_quality.passed_count ?? 0}/${productizationData.scenario_quality.scenario_count ?? 0} scenarios`
    : "quick mode";
  const productizationSafetyLabel =
    productizationData?.safety?.current_database_mutated ||
    productizationData?.safety?.labels_written ||
    productizationData?.safety?.model_activated ||
    productizationData?.safety?.response_actions_created
      ? "review safety"
      : "read only";
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
    Boolean(registry?.active_artifact_metadata_unknown) ||
    Boolean(activeRegistryModel?.active_artifact_metadata_unknown) ||
    activeRegistryModel?.model_version === "active-unregistered" ||
    activeRegistryModel?.model_type === "unknown";
  const activeModelTypeDisplay = activeArtifactMetadataUnknown
    ? "Metadata unknown"
    : activeRegistryModel?.display_model_type ?? activeRegistryModel?.model_type ?? supervisedData?.latest_run?.model_type ?? "-";
  const activeFeatureSetDisplay = activeArtifactMetadataUnknown
    ? "Metadata unavailable"
    : activeRegistryModel?.display_feature_set ?? activeRegistryModel?.feature_set_version ?? "-";
  const registryBadge = activeArtifactMetadataUnknown
    ? "artifact metadata unknown"
    : registry?.active_artifact_exists
      ? "active artifact ready"
      : "no active artifact";
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
    void productization.refetch();
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
            <h1 className="mt-2 text-3xl font-black">Model status and review operations</h1>
            <div className="mt-3 flex flex-wrap gap-2">
              <Badge value="Decision Support Only" />
              <Badge value="Response Automation Disabled" />
              <Badge value="Not Production Promoted" />
              <Badge value="Manual Approval Required" />
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link className="btn-secondary" to={`/assistant?prompt=${encodeURIComponent("Explain current ML model status and why it is not production promoted.")}`}>
              Ask Assistant
            </Link>
            <button className="btn-secondary" type="button" onClick={refreshGovernance}>
              Refresh ML Summary
            </button>
          </div>
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
            <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Controlled Validation</div>
            <h2 className="mt-1 text-xl font-black">Current AI governance snapshot</h2>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge value={supervisedData?.artifact_exists ? "trained" : "needs labels"} />
            <Badge value={finalValidationDecision.replaceAll("_", " ")} />
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
          <MetricCard label="Threat Precision" value={metricText(finalThreatPrecision)} detail={finalValidationSource} tone="teal" />
          <MetricCard label="Threat Recall" value={metricText(finalThreatRecall)} detail="Threat-positive triage" tone="cyan" />
          <MetricCard label="Threat F1" value={metricText(finalThreatF1)} detail="Controlled validation" tone="cyan" />
          <MetricCard label="Benign FPR" value={metricText(finalBenignFpr)} detail="Noise control" tone="amber" />
          <MetricCard label="Macro F1" value={metricText(finalMacroF1)} detail="Class balance signal" tone="teal" />
          <MetricCard label="Weighted F1" value={metricText(finalWeightedF1)} detail={`${metricText(finalValidationRows)} validation rows`} tone="cyan" />
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <MetricCard label="Reviewed Labels" value={supervisedData?.reviewed_label_count ?? 0} detail="Analyst-reviewed rows" tone="teal" />
          <MetricCard label="Assisted Pending" value={supervisedData?.unreviewed_assisted_label_count ?? 0} detail="Awaiting review" tone="amber" />
          <MetricCard label="Review Coverage" value={`${reviewedCoverage}%`} detail={`Target ${reviewedTarget}`} tone="cyan" />
        </div>
        <div className="mt-4 rounded-lg border border-line bg-panel2 p-4" data-testid="detection-ml-productization-panel">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Detection / ML Productization</div>
              <div className="mt-1 text-sm text-muted">Read-only evaluator for rule coverage, supervised policy, training target, and safety invariants.</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge value={productizationData?.phase ?? "v3.72"} />
              <Badge value={productizationSafetyLabel} />
              <Badge value={productizationReadiness} />
            </div>
          </div>
          {productization.isError ? (
            <div className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
              Detection/ML productization status could not be loaded.
            </div>
          ) : (
            <>
              <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
                <MetricCard
                  label="Readiness"
                  value={productization.isLoading ? "Loading" : productizationReadinessDisplay}
                  detail={productizationChecks}
                  tone={productizationData?.ok ? "teal" : "amber"}
                />
                <MetricCard
                  label="Rule Contract"
                  value={productizationRuleLabel}
                  detail={`${metricText(productizationData?.rule_contract?.implemented_rule_count)} implemented rules`}
                  tone={productizationData?.rule_contract?.ok ? "teal" : "amber"}
                />
                <MetricCard
                  label="Scenario Check"
                  value={productizationScenarioLabel}
                  detail={productizationData?.scenario_quality?.included ? "Temporary-DB validation" : "Fast dashboard mode"}
                  tone={productizationData?.scenario_quality?.ok ? "teal" : "cyan"}
                />
                <MetricCard
                  label="Output Policy"
                  value={String(productizationData?.supervised_output_policy?.status ?? "not loaded").replaceAll("_", " ")}
                  detail={`${metricText(productizationData?.supervised_output_policy?.checks_passed)}/${metricText(productizationData?.supervised_output_policy?.checks_total)} checks`}
                  tone={productizationData?.supervised_output_policy?.available ? "teal" : "amber"}
                />
                <MetricCard
                  label="Training Target"
                  value={String(productizationData?.training_target_contract?.status ?? "not loaded").replaceAll("_", " ")}
                  detail={`${metricText(productizationData?.training_data?.trainable_log_count_estimate)} trainable logs`}
                  tone={productizationData?.training_target_contract?.available ? "teal" : "amber"}
                />
                <MetricCard
                  label="Response Actions"
                  value={productizationData?.safety?.response_actions_created ?? 0}
                  detail="Evaluator side effects"
                  tone={productizationData?.safety?.response_actions_created ? "danger" : "teal"}
                />
              </div>
              {productizationData ? (
                <details className="mt-3">
                  <summary className="cursor-pointer rounded border border-line bg-panel px-3 py-2 text-sm font-bold text-text">
                    View productization checks
                  </summary>
                  <div className="mt-3 grid gap-3 text-sm text-muted lg:grid-cols-2">
                    <div className="rounded border border-line bg-panel px-3 py-2">
                      Safety: database mutated{" "}
                      <span className="font-bold text-text">{String(productizationData.safety.current_database_mutated)}</span>, labels written{" "}
                      <span className="font-bold text-text">{String(productizationData.safety.labels_written)}</span>, model activated{" "}
                      <span className="font-bold text-text">{String(productizationData.safety.model_activated)}</span>, raw logs included{" "}
                      <span className="font-bold text-text">{String(productizationData.safety.raw_logs_included)}</span>.
                    </div>
                    <div className="rounded border border-line bg-panel px-3 py-2">
                      Training data: <span className="font-bold text-text">{metricText(productizationData.training_data.reviewed_label_rows)}</span> reviewed labels,{" "}
                      <span className="font-bold text-text">{metricText(productizationData.training_data.weak_or_unreviewed_label_rows)}</span> weak/unreviewed rows.
                    </div>
                  </div>
                  <div className="mt-3 overflow-auto rounded border border-line bg-panel px-3 py-2">
                    <table className="soc-table soc-table-compact">
                      <thead>
                        <tr>
                          <th>Check</th>
                          <th>Required</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {productizationData.checks.map((item) => (
                          <tr key={item.name}>
                            <td>{item.name}</td>
                            <td>{item.required ? "yes" : "no"}</td>
                            <td>{item.passed ? "passed" : "needs review"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              ) : null}
            </>
          )}
        </div>
        <div className="mt-4 rounded-lg border border-line bg-panel2 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Detection Quality Revalidation</div>
              <div className="mt-1 text-sm text-muted">Current labeled-data diagnostic. No model is activated from this panel.</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge value={v330Quality?.available ? "v3.30 generated" : "not generated"} />
              <Badge value={v330SafetyLabel} />
            </div>
          </div>
          <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
            <MetricCard label="Main Blocker" value={v330MainBlocker} detail={v330Quality?.split ? `${v330Quality.split} split` : "Run diagnostic script"} tone="amber" />
            <MetricCard label="Baseline FPR" value={metricText(v330Quality?.baseline_benign_like_false_positive_rate)} detail="Benign-like predicted threat" tone="amber" />
            <MetricCard label="Best Profile" value={v330BestProfile} detail={`FPR ${metricText(v330Quality?.best_benign_like_false_positive_rate)}`} tone="teal" />
            <MetricCard label="Threat F1" value={metricText(v330Quality?.best_threat_positive_f1)} detail="Best diagnostic profile" tone="cyan" />
            <MetricCard label="Calibration" value={v330CalibrationStatus} detail={`ECE ${metricText(v330Quality?.calibration_ece)}`} tone="amber" />
            <MetricCard label="Review Sample" value={v330Quality?.review_sample?.rows ?? "-"} detail="Rows for analyst review" tone="cyan" />
          </div>
          {v330Quality?.available ? (
            <details className="mt-3">
              <summary className="cursor-pointer rounded border border-line bg-panel px-3 py-2 text-sm font-bold text-text">
                View v3.30 diagnostic notes
              </summary>
              <div className="mt-3 grid gap-3 text-sm text-muted md:grid-cols-2">
                <div className="rounded border border-line bg-panel px-3 py-2">
                  Baseline: Threat F1 <span className="font-bold text-text">{metricText(v330Quality.baseline_threat_positive_f1)}</span>, suspicious recall{" "}
                  <span className="font-bold text-text">{metricText(v330Quality.baseline_suspicious_recall)}</span>, malicious recall{" "}
                  <span className="font-bold text-text">{metricText(v330Quality.baseline_malicious_recall)}</span>.
                </div>
                <div className="rounded border border-line bg-panel px-3 py-2">
                  Best profile: <span className="font-bold text-text">{v330BestProfile}</span>, estimated queue{" "}
                  <span className="font-bold text-text">{metricText(v330Quality.best_review_queue_size_estimate)}</span>, readiness{" "}
                  <span className="font-bold text-text">{String(v330Quality.readiness_decision ?? "candidate_only").replaceAll("_", " ")}</span>.
                </div>
                <div className="rounded border border-line bg-panel px-3 py-2">
                  Safety: production promoted <span className="font-bold text-text">{String(v330Quality.production_promoted ?? false)}</span>, model activated{" "}
                  <span className="font-bold text-text">{String(v330Quality.model_activated ?? false)}</span>, response automation{" "}
                  <span className="font-bold text-text">{String(v330Quality.response_automation_allowed ?? false)}</span>.
                </div>
                <div className="rounded border border-line bg-panel px-3 py-2">
                  Latest report: <span className="font-bold text-text">{v330Quality.latest_report_name ?? "generated local summary"}</span>.
                </div>
              </div>
              {v330Quality.top_patterns?.length ? (
                <div className="mt-3 overflow-auto rounded border border-line bg-panel px-3 py-2 text-sm">
                  <div className="mb-2 font-bold text-text">Top error patterns</div>
                  <table className="soc-table soc-table-compact">
                    <thead>
                      <tr>
                        <th>Pattern</th>
                        <th>Count</th>
                      </tr>
                    </thead>
                    <tbody>
                      {v330Quality.top_patterns.slice(0, 5).map((item) => (
                        <tr key={String(item[0])}>
                          <td>{String(item[0])}</td>
                          <td>{String(item[1])}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </details>
          ) : (
            <div className="mt-3 rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              Run <code>python -m atdr.scripts.run_v330_detection_ml_quality_revalidation --split time --test-size 0.3 --min-samples 6 --review-limit 200</code> to refresh this diagnostic.
            </div>
          )}
        </div>
        <div className="mt-4 rounded-lg border border-line bg-panel2 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Supervised Output Policy</div>
              <div className="mt-1 text-sm text-muted">Queue scoring is decision support. Exact labels stay explanation/ranking only.</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge value={v359PolicyLabel} />
              <Badge value={v359SafetyLabel} />
            </div>
          </div>
          {v359Policy?.available ? (
            <>
              <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
                <MetricCard label="Queue Output" value="Decision Support" detail={v359Strategy} tone="teal" />
                <MetricCard label="Exact Labels" value="Explanation Only" detail={v359ExactPolicy} tone="amber" />
                <MetricCard
                  label="Rule / Hybrid"
                  value={String(v359AllowedStatuses.rule_hybrid_evidence ?? "primary_detection_evidence").replaceAll("_", " ")}
                  detail="Primary detection evidence"
                  tone="cyan"
                />
                <MetricCard label="Runtime Activation" value={String(v359Policy.contract_ready_for_runtime_activation ?? false)} detail="Must remain false" tone="danger" />
                <MetricCard label="Automation" value={String(v359Policy.response_automation_allowed ?? false)} detail="Response disabled" tone="danger" />
                <MetricCard label="Guidance" value={String(v359Policy.contract_ready_for_dashboard_guidance ?? false)} detail={String(v359Policy.decision ?? "decision support")} tone="teal" />
              </div>
              <details className="mt-3">
                <summary className="cursor-pointer rounded border border-line bg-panel px-3 py-2 text-sm font-bold text-text">
                  View supervised output contract
                </summary>
                <div className="mt-3 grid gap-3 text-sm text-muted lg:grid-cols-2">
                  <div className="rounded border border-line bg-panel px-3 py-2">
                    Queue status: <span className="font-bold text-text">{String(v359Policy.queue_status ?? "unknown").replaceAll("_", " ")}</span>. Splits{" "}
                    <span className="font-bold text-text">
                      {v359Policy.queue_passing_splits ?? 0}/{v359Policy.queue_evaluated_splits ?? 0}
                    </span>
                    , F1 min <span className="font-bold text-text">{metricText(v359Policy.queue_f1_min)}</span>, FPR max{" "}
                    <span className="font-bold text-text">{metricText(v359Policy.queue_benign_like_false_positive_rate_max)}</span>.
                  </div>
                  <div className="rounded border border-line bg-panel px-3 py-2">
                    Queue/evidence agreement: <span className="font-bold text-text">{String(v359Policy.agreement_status ?? "unknown").replaceAll("_", " ")}</span>. Splits{" "}
                    <span className="font-bold text-text">
                      {v359Policy.agreement_passing_splits ?? 0}/{v359Policy.agreement_evaluated_splits ?? 0}
                    </span>
                    , agreement min <span className="font-bold text-text">{metricText(v359Policy.agreement_rate_min)}</span>.
                  </div>
                  <div className="rounded border border-line bg-panel px-3 py-2">
                    Exact severity: <span className="font-bold text-text">{String(v359Policy.exact_severity_status ?? "unstable").replaceAll("_", " ")}</span>. Stable policies{" "}
                    <span className="font-bold text-text">
                      {v359Policy.exact_stable_policy_count ?? 0}/{v359Policy.exact_evaluated_policy_count ?? 0}
                    </span>
                    .
                  </div>
                  <div className="rounded border border-line bg-panel px-3 py-2">
                    Safety: model activated <span className="font-bold text-text">{String(v359Policy.model_activated ?? false)}</span>, labels written{" "}
                    <span className="font-bold text-text">{String(v359Policy.labels_written ?? false)}</span>, raw logs included{" "}
                    <span className="font-bold text-text">{String(v359Policy.raw_logs_included ?? false)}</span>.
                  </div>
                </div>
                {v359Policy.blocked_uses?.length ? (
                  <div className="mt-3 rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
                    <div className="mb-2 font-bold text-text">Blocked uses</div>
                    <ul className="list-disc space-y-1 pl-5">
                      {v359Policy.blocked_uses.slice(0, 6).map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </details>
            </>
          ) : (
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              Run <code>python -m atdr.scripts.run_v359_supervised_output_policy_contract --pretty</code> to refresh this policy contract.
            </div>
          )}
        </div>
        <div className="mt-4 rounded-lg border border-line bg-panel2 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-muted">SOC Review Queue Diagnostic</div>
              <div className="mt-1 text-sm text-muted">Stable queue candidate for decision support. Exact severity remains explanation/ranking only.</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge value={v355QueueLabel} />
              <Badge value={v355QueueSafetyLabel} />
            </div>
          </div>
          {v355Queue?.available ? (
            <>
              <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
                <MetricCard label="Queue F1 Min" value={metricText(v355Queue.queue_f1_min)} detail="Across validation splits" tone="teal" />
                <MetricCard label="Queue Recall Min" value={metricText(v355Queue.queue_recall_min)} detail="Needs-review capture" tone="cyan" />
                <MetricCard label="Queue Precision Min" value={metricText(v355Queue.queue_precision_min)} detail="Low-noise queue" tone="cyan" />
                <MetricCard label="FPR Max" value={metricText(v355Queue.benign_like_false_positive_rate_max)} detail="Benign-like queued" tone="amber" />
                <MetricCard label="Calibration" value={v355Queue.calibration_status ?? "missing"} detail={`ECE ${metricText(v355Queue.calibration_ece)}`} tone="teal" />
                <MetricCard label="Readiness" value={v355QueueReadiness} detail={`${v355Queue.checks_passed ?? 0}/${v355Queue.checks_total ?? 0} checks`} tone="amber" />
              </div>
              <details className="mt-3">
                <summary className="cursor-pointer rounded border border-line bg-panel px-3 py-2 text-sm font-bold text-text">
                  View v3.55 queue diagnostic notes
                </summary>
                <div className="mt-3 grid gap-3 text-sm text-muted md:grid-cols-2">
                  <div className="rounded border border-line bg-panel px-3 py-2">
                    Best strategy: <span className="font-bold text-text">{v355Queue.best_strategy ?? "not available"}</span>.
                    Recommended use: <span className="font-bold text-text">{String(v355Queue.recommended_use ?? "diagnostic").replaceAll("_", " ")}</span>.
                  </div>
                  <div className="rounded border border-line bg-panel px-3 py-2">
                    Exact severity status:{" "}
                    <span className="font-bold text-text">{String(v355Queue.exact_severity_status ?? "not activated").replaceAll("_", " ")}</span>.
                  </div>
                  <div className="rounded border border-line bg-panel px-3 py-2">
                    Threshold selection:{" "}
                    <span className="font-bold text-text">{(v355Queue.threshold_selected_on ?? ["train_internal_calibration"]).join(", ")}</span>.
                  </div>
                  <div className="rounded border border-line bg-panel px-3 py-2">
                    Safety: production promoted <span className="font-bold text-text">{String(v355Queue.production_promoted ?? false)}</span>, model activated{" "}
                    <span className="font-bold text-text">{String(v355Queue.model_activated ?? false)}</span>, labels written{" "}
                    <span className="font-bold text-text">{String(v355Queue.labels_written ?? false)}</span>, response automation{" "}
                    <span className="font-bold text-text">{String(v355Queue.response_automation_allowed ?? false)}</span>.
                  </div>
                </div>
                {v355Queue.blockers?.length ? (
                  <div className="mt-3 rounded border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
                    Blockers: {v355Queue.blockers.join("; ")}
                  </div>
                ) : null}
              </details>
            </>
          ) : (
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              Run <code>python -m atdr.scripts.run_v355_severity_target_policy_reframing --test-size 0.3 --min-samples 6 --pretty</code> to refresh this diagnostic.
            </div>
          )}
        </div>
        <div className="mt-4 rounded-lg border border-line bg-panel2 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Queue / Evidence Agreement</div>
              <div className="mt-1 text-sm text-muted">Compares the SOC queue candidate with rule, anomaly, and hybrid evidence.</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge value={v357AgreementLabel} />
              <Badge value={v357SafetyLabel} />
            </div>
          </div>
          {v357Agreement?.available ? (
            <>
              <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
                <MetricCard label="Agreement Min" value={metricText(v357Agreement.agreement_rate_min)} detail="Queue and evidence" tone="teal" />
                <MetricCard label="Queue F1 Min" value={metricText(v357Agreement.queue_f1_min)} detail="SOC queue target" tone="cyan" />
                <MetricCard label="Queue FPR Max" value={metricText(v357Agreement.queue_false_positive_rate_max)} detail="Benign-like queued" tone="amber" />
                <MetricCard label="Evidence-Only" value={v357EvidenceOnly} detail="Rule/evidence flags only" tone="amber" />
                <MetricCard label="Queue-Only" value={v357QueueOnly} detail="ML queue flags only" tone="cyan" />
                <MetricCard label="Readiness" value={v357Readiness} detail={`${v357Agreement.checks_passed ?? 0}/${v357Agreement.checks_total ?? 0} checks`} tone="amber" />
              </div>
              <details className="mt-3">
                <summary className="cursor-pointer rounded border border-line bg-panel px-3 py-2 text-sm font-bold text-text">
                  View queue/evidence disagreement notes
                </summary>
                <div className="mt-3 grid gap-3 text-sm text-muted lg:grid-cols-2">
                  <div className="rounded border border-line bg-panel p-3">
                    <div className="mb-2 font-bold text-text">Top evidence-only review patterns</div>
                    {v357Agreement.top_evidence_only_patterns?.length ? (
                      <table className="soc-table soc-table-compact">
                        <thead>
                          <tr>
                            <th>Pattern</th>
                            <th>Count</th>
                          </tr>
                        </thead>
                        <tbody>
                          {v357Agreement.top_evidence_only_patterns.slice(0, 6).map((item) => (
                            <tr key={String(item[0])}>
                              <td>{String(item[0])}</td>
                              <td>{String(item[1])}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div>No evidence-only disagreement patterns reported.</div>
                    )}
                  </div>
                  <div className="rounded border border-line bg-panel p-3">
                    <div className="mb-2 font-bold text-text">Top queue-only review patterns</div>
                    {v357Agreement.top_queue_only_patterns?.length ? (
                      <table className="soc-table soc-table-compact">
                        <thead>
                          <tr>
                            <th>Pattern</th>
                            <th>Count</th>
                          </tr>
                        </thead>
                        <tbody>
                          {v357Agreement.top_queue_only_patterns.slice(0, 6).map((item) => (
                            <tr key={String(item[0])}>
                              <td>{String(item[0])}</td>
                              <td>{String(item[1])}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div>No queue-only disagreement patterns reported.</div>
                    )}
                  </div>
                  <div className="rounded border border-line bg-panel px-3 py-2">
                    Recommended use: <span className="font-bold text-text">{String(v357Agreement.recommended_use ?? "diagnostic").replaceAll("_", " ")}</span>.
                    Calibration ECE max: <span className="font-bold text-text">{metricText(v357Agreement.calibration_ece_max)}</span>.
                  </div>
                  <div className="rounded border border-line bg-panel px-3 py-2">
                    Safety: production promoted <span className="font-bold text-text">{String(v357Agreement.production_promoted ?? false)}</span>, model activated{" "}
                    <span className="font-bold text-text">{String(v357Agreement.model_activated ?? false)}</span>, labels written{" "}
                    <span className="font-bold text-text">{String(v357Agreement.labels_written ?? false)}</span>, raw logs included{" "}
                    <span className="font-bold text-text">{String(v357Agreement.raw_logs_included ?? false)}</span>.
                  </div>
                </div>
                {v357Agreement.blockers?.length || v357Agreement.aggregate_blockers?.length ? (
                  <div className="mt-3 rounded border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
                    Blockers: {[...(v357Agreement.blockers ?? []), ...(v357Agreement.aggregate_blockers ?? [])].join("; ")}
                  </div>
                ) : null}
              </details>
            </>
          ) : (
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              Run <code>python -m atdr.scripts.run_v357_queue_rule_hybrid_agreement --test-size 0.3 --min-samples 6 --pretty</code> to refresh this diagnostic.
            </div>
          )}
        </div>
        <div className="mt-4 rounded-lg border border-line bg-panel2 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Supervised Model Registry</div>
              <div className="mt-1 text-sm text-muted">
                Active and candidate artifacts are tracked for decision support. Automation stays disabled.
              </div>
            </div>
            <Badge value={registryBadge} />
          </div>
          <div className="grid gap-3 md:grid-cols-4">
            <MetricCard label="Active Artifact" value={activeModelTypeDisplay} detail={activeArtifactMetadataUnknown ? "Legacy or unregistered artifact" : "Current classifier family"} tone="cyan" />
            <MetricCard label="Feature Set" value={activeFeatureSetDisplay} detail="Versioned feature pipeline" tone="teal" />
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
                        <td>{model.active_artifact_metadata_unknown ? "metadata unknown" : model.display_model_type ?? model.model_type ?? "-"}</td>
                        <td>{model.operation}</td>
                        <td>
                          {model.active_artifact_metadata_unknown
                            ? "unregistered active artifact"
                            : model.readiness_decision ?? "candidate_only"}
                        </td>
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
        {activeArtifactMetadataUnknown ? (
          <details className="mt-4 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
            <summary className="cursor-pointer font-bold">Artifact Metadata</summary>
            <div className="mt-2">
              An active supervised artifact exists, but it is not linked to a registered training run. Treat it as a legacy
              decision-support artifact. Recent v3.31-v3.33 candidates remain diagnostic-only and are not activated.
            </div>
          </details>
        ) : null}
        <div className="mt-4 rounded-lg border border-cyan/30 bg-cyan/10 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-cyan">Recommended AI Mode</div>
              <div className="mt-1 text-lg font-black text-text">{socTriageMode?.recommended_ai_mode ?? "SOC triage decision support"}</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge value="Decision Support Only" />
              {v20Ai?.final_controlled_validation_passed ? <Badge value="Final Controlled Validation Candidate" /> : null}
            </div>
          </div>
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">SOC Triage Mode</div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">Analyst Review</div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">Manual Approval Required</div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">Response Automation Disabled</div>
          </div>
          <details className="mt-3">
            <summary className="cursor-pointer rounded border border-line bg-panel px-3 py-2 text-sm font-bold text-text">
              Operational readiness details
            </summary>
            <div className="mt-3 rounded border border-line bg-panel px-3 py-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Production Readiness Track</div>
                  <div className="mt-1 text-sm font-bold text-text">
                    {v30Readiness?.status ?? "final_controlled_validation_candidate"}
                  </div>
                </div>
                <Badge value="Not Production Ready" />
              </div>
              <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-2">
              <div>
                Real-source pilot:{" "}
                <span className="font-bold text-text">{v30Readiness?.real_source_pilot_validated ? "validated" : "pending"}</span>
              </div>
              <div>
                Simulated source:{" "}
                <span className="font-bold text-text">
                  {v30Readiness?.simulated_source_validated ? "validated" : v30Readiness?.simulated_source_pilot_status ?? "not run"}
                </span>
              </div>
              <div>
                Real device forwarding:{" "}
                <span className="font-bold text-text">
                  {v30Readiness?.real_device_forwarding_validated ? "validated" : "pending"}
                </span>
              </div>
              <div>
                PostgreSQL lab:{" "}
                <span className="font-bold text-text">
                  {v30Readiness?.postgres_lab_validated ? "validated" : v30Readiness?.postgres_lab_status ?? "pending"}
                </span>
              </div>
              <div>
                SQLite local workflow:{" "}
                <span className="font-bold text-text">{v30Readiness?.sqlite_local_workflow_valid ? "valid" : "not active"}</span>
              </div>
              <div>
                Backup/restore:{" "}
                <span className="font-bold text-text">
                  {v30Readiness?.backup_restore_validated ? "validated" : v30Readiness?.backup_restore_status ?? "planned"}
                </span>
              </div>
              <div>
                Doctor: <span className="font-bold text-text">{v30Readiness?.production_doctor_status ?? "not run"}</span>
              </div>
              <div>
                Safety: <span className="font-bold text-text">automation off, real blocking off</span>
              </div>
            </div>
            {v30Readiness?.production_doctor_blockers?.length ? (
              <details className="mt-3">
                <summary className="cursor-pointer text-xs font-bold text-amber">View readiness blockers</summary>
                <ul className="mt-2 space-y-1 text-xs text-muted">
                  {v30Readiness.production_doctor_blockers.slice(0, 4).map((blocker) => (
                    <li key={blocker}>{blocker}</li>
                  ))}
                </ul>
              </details>
            ) : null}
            </div>
          </details>
          <details className="mt-3">
            <summary className="cursor-pointer rounded border border-line bg-panel px-3 py-2 text-sm font-bold text-text">
              Technical validation details
            </summary>
            <div className="mt-3 space-y-2">
          <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
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
          <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
            Training data:{" "}
            <span className="font-bold text-text">
              {v13Ai?.available
                ? `${v13Ai.reviewed_label_count ?? 0} reviewed | minimum gaps ${v13Ai.minimum_label_gap ?? 0} | ${
                    v13Ai.readiness_decision ?? "candidate_only"
                  }`
                : "v1.3 audit not generated"}
            </span>
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              <span className="font-bold text-text">Main blocker:</span>{" "}
              {v20Ai?.available
                ? v20Ai.fresh_blind_revalidated
                  ? "No v2.0 metric blocker; real hardware validation remains future work"
                  : "Fresh blind validation requires review"
                : v14Ai?.available
                ? v14Ai.current_blocker ?? "model validation"
                : "v1.4 evaluation pending"}
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
              Not Production Promoted
            </div>
            <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
              {independentAi?.available
                ? `${v20Ai?.available ? "Fresh blind" : "Independent"} readiness ${
                    independentAi.readiness_version ?? "v7"
                  } ${
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
                ? `${v20Ai?.available ? (v20Ai.fresh_blind_revalidated ? "fresh blind passed" : "fresh blind review required") : v19bAi?.available ? (v19bAi.fpr_blocker_resolved ? "FPR blocker resolved" : "FPR blocker active") : independentAi.generalization_status ?? "not evaluated"} | FPR ${
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
              <span className="font-bold text-text">{v20Ai?.available ? "Fresh blind holdout:" : "Independent holdout:"}</span>{" "}
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
              <span className="font-bold text-text">{v20Ai?.available ? "Fresh blind metrics:" : "Independent metrics:"}</span>{" "}
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
            {v20Ai?.available ? (
              <div className="rounded border border-line bg-panel px-3 py-2 text-sm text-muted">
                <span className="font-bold text-text">Final controlled validation:</span>{" "}
                {v20Ai.final_controlled_validation_passed
                  ? "passed; candidate remains decision support only"
                  : "pending or requires review"}
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
          </details>
        </div>
        <details className="mt-4 rounded-lg border border-line bg-panel2 p-4">
          <summary className="cursor-pointer text-sm font-bold text-text">Model validation diagnostics</summary>
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <MetricCard label="Candidate Precision" value={String(supervisedMetrics.precision ?? "-")} detail="Latest training run" tone="amber" />
            <MetricCard label="Candidate Recall" value={String(supervisedMetrics.recall ?? "-")} detail="Latest training run" tone="danger" />
            <MetricCard label="Candidate F1" value={String(supervisedMetrics.f1 ?? "-")} detail="Latest training run" tone="cyan" />
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <MetricCard label="Threat-Positive Precision" value={String(threatPositive.precision ?? "-")} detail="Training report grouping" tone="amber" />
            <MetricCard label="Threat-Positive Recall" value={String(threatPositive.recall ?? "-")} detail="Training report grouping" tone="danger" />
            <MetricCard label="Threat-Positive F1" value={String(threatPositive.f1 ?? "-")} detail="Training report grouping" tone="cyan" />
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
        </details>
      </section>

      <section className="panel">
        <div className="mb-4 flex items-center justify-between gap-2">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Data Quality</div>
            <h2 className="mt-1 text-xl font-black">Dataset readiness</h2>
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
        <div className="presentation-technical mb-4 rounded-lg border border-line bg-panel2 p-3 text-sm text-muted">
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
            <h2 className="mt-1 text-xl font-black">Analyst review worklist</h2>
          </div>
          <div className="flex flex-wrap gap-2">
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("queue")}>Export Queue</button>
            <button className="btn-secondary" type="button" onClick={() => void downloadExport("labels")}>Export Labels</button>
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
          </div>
          <details className="mt-3 rounded border border-line bg-panel px-3 py-2">
            <summary className="cursor-pointer text-sm font-bold text-text">Review exports and technical reports</summary>
            <div className="mt-3 flex flex-wrap gap-2">
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
          </details>
          {importResult ? <div className="mt-3 rounded border border-success/30 bg-success/10 p-2 text-sm text-success">{importResult}</div> : null}
          {benchmarkImportResult ? <div className="mt-3 rounded border border-cyan/30 bg-cyan/10 p-2 text-sm text-cyan">{benchmarkImportResult}</div> : null}
          {downloadError ? <div className="mt-3 text-sm text-danger">{downloadError}</div> : null}
          {labelMutations.importCsv.isError ? <div className="mt-3"><ErrorBanner error={labelMutations.importCsv.error} /></div> : null}
          {labelMutations.importBenchmarkCsv.isError ? <div className="mt-3"><ErrorBanner error={labelMutations.importBenchmarkCsv.error} /></div> : null}
          {quickReviewMessage ? <div className="mt-3 rounded border border-cyan/30 bg-cyan/10 p-2 text-sm text-cyan">{quickReviewMessage}</div> : null}
          <details className="mt-3 rounded border border-line bg-panel px-3 py-2 text-xs text-muted">
            <summary className="cursor-pointer font-bold text-text">CSV import rules</summary>
            <div className="mt-2">
              Fill `human_review_decision` with benign, benign_unusual, suspicious, malicious, or needs_context. Blank rows are skipped safely and the import preserves assisted provenance.
              Files containing `benchmark_row_id` must use Benchmark Review Import and remain separate from database-backed labels.
            </div>
          </details>
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
            <h2 className="mt-1 text-xl font-black">Traffic distribution</h2>
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
