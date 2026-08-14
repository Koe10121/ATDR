import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { ChartCard } from "../components/ChartCard";
import { EmptyState } from "../components/EmptyState";
import { MetricCard } from "../components/MetricCard";
import { MLEvidenceSnapshotPanel } from "../components/MLEvidenceSnapshotPanel";
import { MLGovernancePolicyPanel } from "../components/MLGovernancePolicyPanel";
import { Badge } from "../components/Badge";
import { ErrorBanner } from "../components/ErrorBanner";
import { SocPageHeader } from "../components/SocPageHeader";
import { api } from "../lib/api";
import {
  useClassTemporalCoverage,
  useDetectionMlProductization,
  useMlLabelMutations,
  useMlEvidenceSnapshot,
  useMlReport,
  useMlReviewQueue,
  useParserProfileOperationalDiagnostics,
  useShadowMonitoringDiagnostics,
  useShadowOperationalAcceptance,
  useShadowObservationSummary,
  useSources,
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

function metricText(value: unknown) {
  return value === null || value === undefined || value === "" ? "-" : String(value);
}

function rateText(value: unknown) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${(numeric * 100).toFixed(1)}%` : "-";
}

export function MLGovernance() {
  const report = useMlReport();
  const evidenceSnapshot = useMlEvidenceSnapshot();
  const supervised = useSupervisedReport();
  const productization = useDetectionMlProductization();
  const supervisedModels = useSupervisedModels();
  const longitudinalShadow = useShadowObservationSummary();
  const shadowOperations = useShadowOperationalAcceptance();
  const shadowDiagnostics = useShadowMonitoringDiagnostics();
  const parserProfileDiagnostics =
    useParserProfileOperationalDiagnostics();
  const runtimeSources = useSources({ limit: 100 });
  const temporalCoverage = useClassTemporalCoverage();
  const reviewQueue = useMlReviewQueue({ limit: 25 });
  const labelMutations = useMlLabelMutations();
  const data = report.data;
  const supervisedData = supervised.data;
  const supervisedMetrics = supervisedData?.latest_run?.metrics ?? {};
  const threatPositive = (supervisedMetrics.threat_positive ?? {}) as Record<string, unknown>;
  const socTriageMode = supervisedData?.soc_triage_mode;
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
  const governedLifecycle = registry?.governed_lifecycle;
  const governedShadowRuntime = governedLifecycle?.governed_shadow_runtime;
  const governedShadowTelemetry = governedShadowRuntime?.telemetry;
  const governedShadowDrift =
    governedShadowTelemetry?.drift?.status ?? "Insufficient Evidence";
  const longitudinal = longitudinalShadow.data;
  const operational = shadowOperations.data;
  const diagnostics = shadowDiagnostics.data;
  const parserDiagnostics = parserProfileDiagnostics.data;
  const runtimeParserAlertCount = (runtimeSources.data ?? []).reduce(
    (total, source) => total + (source.health.operational_alerts?.length ?? 0),
    0
  );
  const runtimeContractSourceCount = (runtimeSources.data ?? []).filter(
    (source) => source.health.parser_contract_state === "current_contract"
  ).length;
  const legacyContractSourceCount = (runtimeSources.data ?? []).filter(
    (source) =>
      source.health.parser_contract_state === "legacy_contract" ||
      source.health.parser_contract_state === "mixed_contract"
  ).length;
  const longitudinalTrend = (longitudinal?.trend ?? []).map(
    (observation, index) => ({
      name: observation.created_at
        ? new Date(observation.created_at).toLocaleDateString()
        : `Run ${index + 1}`,
      queueRate: Number(observation.queue_rate ?? 0) * 100,
      disagreementRate:
        Number(observation.disagreement_rate ?? 0) * 100
    })
  );
  const lifecycleState = governedLifecycle?.lifecycle_state ?? "inactive";
  const reliabilityValidation = governedLifecycle?.reliability_validation;
  const durableTelemetry = governedLifecycle?.durable_telemetry;
  const shadowTelemetry = (durableTelemetry?.available
    ? durableTelemetry.telemetry
    : governedLifecycle?.telemetry) ?? {};
  const shadowLatency = (shadowTelemetry.latency_ms ?? {}) as Record<string, unknown>;
  const shadowScores = (shadowTelemetry.queue_score_distribution ?? {}) as Record<string, unknown>;
  const layeredAfter = (reliabilityValidation?.layered_after ?? {}) as Record<string, unknown>;
  const reliabilityBlockers = reliabilityValidation?.blockers ?? [];
  const v55Blockers = reliabilityValidation?.v55_blockers ?? [];
  const v56Blockers = reliabilityValidation?.v56_blockers ?? [];
  const v57Blockers = reliabilityValidation?.v57_blockers ?? [];
  const temporalFpr = Number(reliabilityValidation?.temporal_fpr ?? 0);
  const temporalOodRate = Number(reliabilityValidation?.ood_rate ?? 0);
  const abstentionMaximum = reliabilityValidation?.abstention_rate_range?.max;
  const rollingTemporal = reliabilityValidation?.rolling_temporal;
  const shadowDriftStatus = reliabilityValidation?.shadow_drift_status ?? "Insufficient Evidence";
  const shadowDriftTone =
    shadowDriftStatus === "OOD Warning"
      ? "danger"
      : shadowDriftStatus === "Drift Warning" || shadowDriftStatus === "Insufficient Evidence"
        ? "amber"
        : "teal";
  const activeArtifactExists = Boolean(registry?.active_artifact_exists);
  const activeRegistryModel = registry?.models.find((model) => model.is_active_path);
  const activeArtifactMetadataUnknown =
    activeArtifactExists &&
    (Boolean(registry?.active_artifact_metadata_unknown) ||
      Boolean(activeRegistryModel?.active_artifact_metadata_unknown) ||
      !activeRegistryModel ||
      activeRegistryModel.model_version === "active-unregistered" ||
      activeRegistryModel.model_type === "unknown");
  const activeModelTypeDisplay = !activeArtifactExists
    ? "None"
    : activeArtifactMetadataUnknown
      ? "Metadata unknown"
      : activeRegistryModel?.display_model_type ?? activeRegistryModel?.model_type ?? "-";
  const activeFeatureSetDisplay = !activeArtifactExists
    ? "-"
    : activeArtifactMetadataUnknown
      ? "Metadata unavailable"
      : activeRegistryModel?.display_feature_set ?? activeRegistryModel?.feature_set_version ?? "-";
  const registryBadge = lifecycleState === "shadow_observation"
    ? "shadow active"
    : lifecycleState === "decision_support"
      ? "decision support active"
      : activeArtifactMetadataUnknown
        ? "active metadata unavailable"
        : "supervised inactive";
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
    void evidenceSnapshot.refetch();
    void supervised.refetch();
    void productization.refetch();
    void supervisedModels.refetch();
    void longitudinalShadow.refetch();
    void shadowOperations.refetch();
    void temporalCoverage.refetch();
    void reviewQueue.refetch();
  }

  return (
    <div className="space-y-5">
      <SocPageHeader
        eyebrow="ML Governance"
        eyebrowTone="cyan"
        title="Model status and review operations"
        badges={[
          "Decision Support Only",
          "Response Automation Disabled",
          "Not Production Promoted",
          "Manual Approval Required"
        ]}
        badgePlacement="under-title"
        actions={
          <>
            <Link className="btn-secondary" to={`/assistant?prompt=${encodeURIComponent("Explain current ML model status and why it is not production promoted.")}`}>
              Ask Assistant
            </Link>
            <button className="btn-secondary" type="button" onClick={refreshGovernance}>
              Refresh ML Summary
            </button>
          </>
        }
      />

      {report.isError || supervised.isError ? (
        <ErrorBanner
          error={report.error ?? supervised.error}
          fallback="AI Governance data is temporarily unavailable. No model state changed."
        />
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="IsolationForest" value={data?.model_status.artifact_exists ? "Ready" : "Missing"} detail="Assistive anomaly pipeline" tone="teal" />
        <MetricCard label="Scored Logs" value={data?.scored_log_count ?? "-"} detail="Latest scored population" tone="cyan" />
        <MetricCard label="Anomalies" value={data?.anomaly_count ?? "-"} detail="Current anomaly flags" tone="amber" />
        <MetricCard label="Anomaly Rate" value={`${data?.anomaly_rate ?? "-"}%`} detail="Assistive signal rate" tone="cyan" />
      </div>

      <MLEvidenceSnapshotPanel snapshot={evidenceSnapshot.data} loading={evidenceSnapshot.isLoading} error={evidenceSnapshot.isError} />

      <section className="panel">
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
        <div className="mt-4 rounded-lg border border-line bg-panel2 p-4" data-testid="supervised-model-registry">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Supervised Model Registry</div>
              <div className="mt-1 text-sm text-muted">
                Active and candidate artifacts are tracked for decision support. Automation stays disabled.
              </div>
            </div>
            <Badge value={registryBadge} />
          </div>
          <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
            <MetricCard
              label="Lifecycle"
              value={lifecycleState.replaceAll("_", " ")}
              detail={governedLifecycle?.status_message ?? "Rules remain authoritative"}
              tone="cyan"
            />
            <MetricCard
              label="Model"
              value={activeModelTypeDisplay}
              detail={governedLifecycle?.model_version ?? (!activeArtifactExists ? "No governed artifact" : "Registered artifact")}
              tone="teal"
            />
            <MetricCard label="Feature Set" value={activeFeatureSetDisplay} detail="Leakage-controlled causal features" tone="teal" />
            <MetricCard
              label="Calibration"
              value={(governedLifecycle?.calibration_status ?? "not active").replaceAll("_", " ")}
              detail={governedLifecycle?.calibration_method ?? "No active calibration"}
              tone={governedLifecycle?.calibration_status === "passed_all_splits" ? "teal" : "amber"}
            />
            <MetricCard
              label="Validation"
              value={(governedLifecycle?.validation_status ?? "not active").replaceAll("_", " ")}
              detail={governedLifecycle?.decision_support_eligible ? "Strict gates passed" : "Shadow evidence only"}
              tone={governedLifecycle?.decision_support_eligible ? "teal" : "amber"}
            />
            <MetricCard label="Response Automation" value="Disabled" detail="No model may execute containment" tone="danger" />
          </div>
          <div className="mt-4 border-t border-line pt-4" data-testid="shadow-reliability-summary">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Shadow Reliability</div>
                <div className="mt-1 text-sm text-muted">
                  Aggregate monitoring and diagnostic validation. Rule detection remains alert-authoritative.
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Badge value="rules authoritative" />
                <Badge value="diagnostic only" />
              </div>
            </div>
            <div className="grid gap-3 md:grid-cols-3">
              <MetricCard
                label="Split Stability"
                value={reliabilityValidation?.available
                  ? `${reliabilityValidation.strict_passing_splits ?? 0}/${reliabilityValidation.required_splits ?? 0}`
                  : "Not evaluated"}
                detail={reliabilityValidation?.available
                  ? `${reliabilityValidation.evaluated_splits ?? 0} evaluated; ${reliabilityValidation.failed_closed_splits?.length ?? 0} failed closed`
                  : "Run the current reliability evaluation"}
                tone="amber"
              />
              <MetricCard
                label="Layered Validation"
                value={reliabilityValidation?.available
                  ? `${metricText(layeredAfter.passed_count)}/${metricText(layeredAfter.mode_run_count)}`
                  : "Not loaded"}
                detail={reliabilityValidation?.available
                  ? `${metricText(layeredAfter.false_positive_count)} FP / ${metricText(layeredAfter.false_negative_count)} FN`
                  : "Controlled rules, anomaly, supervised, hybrid matrix"}
                tone={Number(layeredAfter.failed_count ?? 1) === 0 ? "teal" : "amber"}
              />
              <MetricCard
                label="Shadow Inferences"
                value={metricText(shadowTelemetry.inference_count)}
                detail={durableTelemetry?.available ? "Latest durable aggregate snapshot" : "Current backend process"}
                tone="cyan"
              />
              <MetricCard
                label="Queue Rate"
                value={rateText(shadowTelemetry.queue_rate)}
                detail="Shadow review recommendations"
                tone="cyan"
              />
              <MetricCard
                label="P95 Latency"
                value={shadowLatency.p95 === undefined ? "-" : `${metricText(shadowLatency.p95)} ms`}
                detail="Per-row shadow inference"
                tone="teal"
              />
              <MetricCard
                label="Drift Warnings"
                value={(durableTelemetry?.drift_warnings?.length ?? 0) + (reliabilityValidation?.drift_warning_splits ?? 0)}
                detail={`${reliabilityValidation?.drift_warning_splits ?? 0} validation splits`}
                tone={(durableTelemetry?.drift_warnings?.length ?? 0) + (reliabilityValidation?.drift_warning_splits ?? 0) ? "amber" : "teal"}
              />
              <MetricCard
                label="Inference Failures"
                value={metricText(shadowTelemetry.failure_count)}
                detail="Rule processing continues on failure"
                tone={Number(shadowTelemetry.failure_count ?? 0) ? "danger" : "teal"}
              />
              <MetricCard
                label="Missing Features"
                value={rateText(shadowTelemetry.missing_feature_rate)}
                detail="Aggregate feature completeness"
                tone={Number(shadowTelemetry.missing_feature_rate ?? 0) > 0.05 ? "amber" : "teal"}
              />
              <MetricCard
                label="Queue Score P95"
                value={metricText(shadowScores.p95)}
                detail={`${metricText(shadowScores.count)} aggregate observations`}
                tone="cyan"
              />
              <MetricCard
                label="Temporal FPR"
                value={reliabilityValidation?.temporal_fpr === undefined ? "-" : rateText(temporalFpr)}
                detail="Frozen future holdout"
                tone={temporalFpr > 0.10 ? "danger" : "teal"}
              />
              <MetricCard
                label="OOD Rate"
                value={reliabilityValidation?.ood_rate === undefined ? "-" : rateText(temporalOodRate)}
                detail="Insufficient-distribution evidence"
                tone={temporalOodRate > 0.10 ? "amber" : "teal"}
              />
              <MetricCard
                label="Abstention Maximum"
                value={abstentionMaximum === undefined || abstentionMaximum === null ? "-" : rateText(abstentionMaximum)}
                detail={`${rollingTemporal?.evaluated ?? 0}/${rollingTemporal?.required ?? 0} rolling windows evaluated`}
                tone={Number(abstentionMaximum ?? 0) > 0.20 ? "amber" : "cyan"}
              />
              <MetricCard
                label="Evidence Drift"
                value={shadowDriftStatus}
                detail={`Lock: ${reliabilityValidation?.evidence_lock_status ?? "not run"}`}
                tone={shadowDriftTone}
              />
              <MetricCard
                label="Development Evidence"
                value={metricText(reliabilityValidation?.development_evidence_rows)}
                detail={`${metricText(reliabilityValidation?.excluded_evidence_rows)} locked or quarantined`}
                tone="cyan"
              />
            </div>
            <div
              className="mt-3 rounded border border-line bg-surface px-3 py-3"
              data-testid="governed-shadow-runtime"
            >
              <div className="flex flex-wrap gap-2">
                <Badge value="Frozen Diagnostic Candidate" />
                <Badge
                  value={
                    governedShadowRuntime?.enabled
                      ? "Shadow Scoring Enabled"
                      : "Shadow Scoring Disabled"
                  }
                />
                <Badge
                  value={
                    governedShadowRuntime?.candidate_contract_matched
                      ? "Candidate Contract Matched"
                      : "Candidate Contract Mismatched"
                  }
                />
                <Badge
                  value={
                    governedShadowRuntime?.independent_evidence?.qualified
                      ? "Independent Evidence Available"
                      : "Independent Evidence Pending"
                  }
                />
                <Badge value="Rules Authoritative" />
                <Badge value="Response Automation Disabled" />
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-4">
                <MetricCard
                  label="Shadow Rows"
                  value={metricText(governedShadowTelemetry?.rows_evaluated)}
                  detail={(governedShadowRuntime?.status ?? "not evaluated").replaceAll("_", " ")}
                  tone="cyan"
                />
                <MetricCard
                  label="Shadow Queue Rate"
                  value={rateText(governedShadowTelemetry?.queue_rate)}
                  detail="Advisory review queue only"
                  tone="cyan"
                />
                <MetricCard
                  label="Runtime Drift"
                  value={governedShadowDrift}
                  detail="Aggregate application, schema, and missingness"
                  tone={
                    governedShadowDrift === "Stable"
                      ? "teal"
                      : governedShadowDrift === "OOD Warning"
                        ? "danger"
                        : "amber"
                  }
                />
                <MetricCard
                  label="Rule / Shadow Disagreement"
                  value={rateText(
                    governedShadowTelemetry?.rule_shadow_agreement
                      ?.disagreement_rate
                  )}
                  detail="Rules remain authoritative"
                  tone="amber"
                />
              </div>
            </div>
            <div
              className="mt-3 rounded border border-line bg-surface px-3 py-3"
              data-testid="longitudinal-shadow-observation"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="text-xs font-extrabold uppercase tracking-wide text-muted">
                    Longitudinal Shadow Observation
                  </div>
                  <div className="mt-1 text-sm text-muted">
                    Aggregate advisory telemetry only
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Badge value="Rules Authoritative" />
                  <Badge value="Shadow Observation" />
                  <Badge value="No Model Activation" />
                  <Badge value="Response Automation Disabled" />
                  <Badge value="Raw Evidence Excluded" />
                </div>
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
                <MetricCard
                  label="Observations"
                  value={metricText(operational?.observation_count ?? longitudinal?.observation_count)}
                  detail={
                    longitudinal?.observation_enabled
                      ? "Collection enabled"
                      : "Collection disabled"
                  }
                  tone="cyan"
                />
                <MetricCard
                  label="Observed Scopes"
                  value={
                    operational
                      ? `${operational.source_scope_count} / ${operational.time_scope_count}`
                      : "-"
                  }
                  detail="Source / time scopes"
                  tone="cyan"
                />
                <MetricCard
                  label="Latest Observation"
                  value={
                    operational?.latest_observation_at
                      ? new Date(operational.latest_observation_at).toLocaleDateString()
                      : "None"
                  }
                  detail="Aggregate telemetry only"
                  tone="teal"
                />
                <MetricCard
                  label="Current Drift"
                  value={operational?.drift.current_state ?? longitudinal?.latest?.drift_status ?? "No observations"}
                  detail="Aggregate distribution status"
                  tone={
                    (operational?.drift.current_state ?? longitudinal?.latest?.drift_status) === "Stable"
                      ? "teal"
                      : (operational?.drift.current_state ?? longitudinal?.latest?.drift_status) === "OOD Warning"
                        ? "danger"
                        : "amber"
                  }
                />
                <MetricCard
                  label="Mean Queue Rate"
                  value={rateText(longitudinal?.queue_rate.mean)}
                  detail="Advisory review queue"
                  tone="cyan"
                />
                <MetricCard
                  label="Mean Rule Disagreement"
                  value={rateText(
                    longitudinal?.rule_disagreement_rate.mean
                  )}
                  detail="Rules remain authoritative"
                  tone="amber"
                />
                <MetricCard
                  label="Failed / Insufficient"
                  value={
                    operational
                      ? `${operational.failed_observation_count} / ${operational.insufficient_evidence_count}`
                      : "-"
                  }
                  detail="Operational observations"
                  tone={
                    Number(operational?.failed_observation_count ?? 0) > 0
                      ? "danger"
                      : Number(operational?.insufficient_evidence_count ?? 0) > 0
                        ? "amber"
                        : "teal"
                  }
                />
              </div>
              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded border border-line bg-panel px-3 py-2 text-sm">
                <div className="text-muted">
                  Operational gates{" "}
                  <span className="font-bold text-text">
                    {operational ? `${operational.gates_passed}/${operational.gates_total}` : "not evaluated"}
                  </span>
                  . These gates measure monitoring reliability, not model accuracy.
                </div>
                <Badge
                  value={
                    operational?.operational_acceptance_passed
                      ? "Operational Monitoring Accepted"
                      : operational?.observation_count
                        ? "Operational Warning"
                        : "Insufficient Evidence"
                  }
                />
              </div>
              {shadowOperations.isError ? (
                <div className="mt-3 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
                  Operational observation status could not be loaded.
                </div>
              ) : operational?.warnings.length ? (
                <details className="mt-3 rounded border border-line bg-panel px-3 py-2 text-sm">
                  <summary className="cursor-pointer font-bold text-text">
                    View operational warnings ({operational.warnings.length})
                  </summary>
                  <ul className="mt-2 space-y-1 text-muted">
                    {operational.warnings.map((warning) => (
                      <li key={warning}>{warning}</li>
                    ))}
                  </ul>
                </details>
              ) : null}
              <details
                className="mt-3 rounded border border-line bg-panel px-3 py-2 text-sm"
                data-testid="parser-profile-diagnostics"
              >
                <summary className="cursor-pointer font-bold text-text">
                  Parser profile baseline ({parserDiagnostics?.observation_count ?? 0})
                </summary>
                {parserProfileDiagnostics.isError ? (
                  <div className="mt-3 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-danger">
                    Parser profile diagnostics could not be loaded.
                  </div>
                ) : parserDiagnostics?.rows.length ? (
                  <>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Badge value={parserDiagnostics.current_state} />
                      <Badge value={parserDiagnostics.parser_contract_version} />
                      <Badge
                        value={`${parserDiagnostics.baseline_scope_counts.parser_profile_source_type ?? 0} Profile Baselines`}
                      />
                      <Badge
                        value={`${parserDiagnostics.baseline_scope_counts.global_fallback ?? 0} Global Fallbacks`}
                      />
                      <Badge value="No Accuracy Metrics" />
                      <Badge value={`${runtimeContractSourceCount} Runtime Contract Sources`} />
                      <Badge value={`${legacyContractSourceCount} Legacy/Mixed Sources`} />
                      <Badge value={`${runtimeParserAlertCount} Runtime Parser Alerts`} />
                    </div>
                    <div className="mt-2 text-xs text-muted">
                      Unresolved application values are tracked as data quality, not parser failures.
                      {" "}
                      {parserDiagnostics.legacy_warning_windows_reclassified} legacy warning window(s)
                      reclassified.
                    </div>
                    <div className="mt-2 text-xs text-muted">
                      Future ingestion uses the v5.13 runtime contract. Historical rows remain unchanged and are shown as legacy or mixed coverage.
                    </div>
                    <div className="mt-3 max-w-full overflow-x-auto">
                      <table className="w-full min-w-[860px] border-collapse text-left text-xs">
                        <thead>
                          <tr className="border-b border-line text-muted">
                            <th className="px-2 py-2">Scope</th>
                            <th className="px-2 py-2">Profile</th>
                            <th className="px-2 py-2">Baseline</th>
                            <th className="px-2 py-2">Parser Errors</th>
                            <th className="px-2 py-2">Structural Warnings</th>
                            <th className="px-2 py-2">Unresolved App</th>
                            <th className="px-2 py-2">Drift</th>
                          </tr>
                        </thead>
                        <tbody>
                          {parserDiagnostics.rows.slice(-12).map((row) => (
                            <tr
                              className="border-b border-line/70 align-top last:border-b-0"
                              key={`${row.source_scope}-${row.time_scope}`}
                            >
                              <td className="px-2 py-2 font-bold text-text">
                                {row.source_scope}
                                <div className="font-normal text-muted">{row.time_scope}</div>
                              </td>
                              <td className="px-2 py-2 text-text">
                                {row.baseline_selection.parser_profile}
                                <div className="text-muted">{row.baseline_selection.source_type}</div>
                              </td>
                              <td className="px-2 py-2 text-muted">
                                {row.baseline_selection.scope.replaceAll("_", " ")}
                                <div>{row.baseline_selection.support_rows.toLocaleString()} rows</div>
                              </td>
                              <td className="px-2 py-2 text-text">
                                {rateText(row.quality.parser_error_rate)}
                              </td>
                              <td className="px-2 py-2 text-text">
                                {rateText(row.quality.parser_structural_warning_per_row)}
                              </td>
                              <td className="px-2 py-2 text-text">
                                {rateText(row.quality.unresolved_application_rate)}
                              </td>
                              <td className="px-2 py-2">
                                <Badge value={row.drift_state} />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="mt-3 text-xs text-muted">
                      Baselines use governed development-fit aggregates only. Labels, accuracy,
                      source identity, raw logs, and locked final evidence are excluded.
                    </div>
                  </>
                ) : (
                  <div className="mt-3 rounded border border-dashed border-line px-3 py-4 text-muted">
                    No comparable parser-profile observations are available.
                  </div>
                )}
              </details>
              <details
                className="mt-3 rounded border border-line bg-panel px-3 py-2 text-sm"
                data-testid="shadow-monitoring-diagnostics"
              >
                <summary className="cursor-pointer font-bold text-text">
                  Operational drift diagnostics ({diagnostics?.observation_count ?? 0})
                </summary>
                {shadowDiagnostics.isError ? (
                  <div className="mt-3 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-danger">
                    Aggregate drift diagnostics could not be loaded.
                  </div>
                ) : diagnostics?.rows.length ? (
                  <>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Badge value={diagnostics.current_state} />
                      <Badge
                        value={
                          diagnostics.cadence.enabled
                            ? `Monitoring Every ${diagnostics.cadence.cadence_minutes} Minutes`
                            : "Monitoring Cadence Disabled"
                        }
                      />
                      <Badge value="No Accuracy Metrics" />
                    </div>
                    <div className="mt-3 max-w-full overflow-x-auto">
                      <table className="w-full min-w-[920px] border-collapse text-left text-xs">
                        <thead>
                          <tr className="border-b border-line text-muted">
                            <th className="px-2 py-2">Scope</th>
                            <th className="px-2 py-2">Observed</th>
                            <th className="px-2 py-2">Drift</th>
                            <th className="px-2 py-2">Queue</th>
                            <th className="px-2 py-2">Disagreement</th>
                            <th className="px-2 py-2">Anomaly</th>
                            <th className="px-2 py-2">Quality</th>
                            <th className="px-2 py-2">Runtime</th>
                          </tr>
                        </thead>
                        <tbody>
                          {diagnostics.rows.map((row) => (
                            <tr
                              className="border-b border-line/70 align-top last:border-b-0"
                              key={`${row.source_scope}-${row.time_scope}`}
                            >
                              <td className="px-2 py-2 font-bold text-text">
                                {row.source_scope}
                                <div className="font-normal text-muted">{row.time_scope}</div>
                              </td>
                              <td className="px-2 py-2 text-muted">
                                {new Date(row.observation_time).toLocaleString()}
                                <div>{row.rows_evaluated} rows</div>
                              </td>
                              <td className="px-2 py-2">
                                <Badge value={row.drift_state} />
                              </td>
                              <td className="px-2 py-2 text-text">{rateText(row.queue_rate)}</td>
                              <td className="px-2 py-2 text-text">{rateText(row.disagreement_rate)}</td>
                              <td className="px-2 py-2 text-text">{rateText(row.isolation_anomaly_rate)}</td>
                              <td className="max-w-[300px] px-2 py-2 text-muted">
                                <div className="break-words">{row.quality_warning}</div>
                                <div className="mt-1 break-words text-[11px]">
                                  {row.root_cause_codes
                                    .map((value) => value.replaceAll("_", " "))
                                    .join(", ")}
                                </div>
                              </td>
                              <td className="px-2 py-2 text-text">
                                {row.runtime_seconds === null
                                  ? "-"
                                  : `${row.runtime_seconds.toFixed(2)} s`}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="mt-3 text-xs text-muted">
                      Thresholds use aggregate distributions only. Hysteresis requires repeated
                      evidence before warning recovery; insufficient windows never clear an
                      existing warning.
                    </div>
                  </>
                ) : (
                  <div className="mt-3 rounded border border-dashed border-line px-3 py-4 text-muted">
                    No aggregate operational diagnostics are available.
                  </div>
                )}
              </details>
              {longitudinalTrend.length > 1 ? (
                <div className="mt-3 h-56 min-w-0 rounded border border-line bg-panel p-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart
                      data={longitudinalTrend}
                      margin={{ top: 8, right: 12, left: 0, bottom: 4 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" minTickGap={24} />
                      <YAxis domain={[0, 100]} unit="%" width={46} />
                      <Tooltip formatter={(value) => `${Number(value).toFixed(1)}%`} />
                      <Legend />
                      <Line
                        type="monotone"
                        dataKey="queueRate"
                        name="Queue rate"
                        stroke="#2563eb"
                        strokeWidth={2}
                        dot={false}
                      />
                      <Line
                        type="monotone"
                        dataKey="disagreementRate"
                        name="Rule disagreement"
                        stroke="#b45309"
                        strokeWidth={2}
                        dot={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="mt-3 rounded border border-dashed border-line px-3 py-4 text-sm text-muted">
                  At least two bounded observations are required for a trend.
                </div>
              )}
              <div className="mt-3 text-xs text-muted">
                Independent evidence:{" "}
                <span className="font-bold text-text">
                  {longitudinal?.independent_evidence.qualified
                    ? "available"
                    : "still required"}
                </span>
                . Retention is explicit and aggregate-only.
              </div>
            </div>
            {reliabilityValidation?.available ? (
              <details className="mt-3 rounded border border-line bg-panel px-3 py-2 text-sm">
                <summary className="cursor-pointer font-bold text-text">View reliability blockers</summary>
                <div className="mt-2 space-y-2 text-muted">
                  <div>
                    Leading comparator: <span className="font-bold text-text">{reliabilityValidation.selected_diagnostic_strategy ?? "none"}</span>.
                    No supervised candidate was selected or made eligible for activation.
                  </div>
                  {reliabilityValidation.v55_available ? (
                    <div>
                      v5.5 development leader: <span className="font-bold text-text">{reliabilityValidation.v55_development_leader ?? "none"}</span>.
                      Locked regression F1 {metricText(reliabilityValidation.v55_locked_queue_f1)}, benign FPR{" "}
                      {rateText(reliabilityValidation.v55_locked_benign_fpr)}, calibration{" "}
                      {reliabilityValidation.v55_locked_calibration_status ?? "not evaluated"}. Lifecycle remains shadow observation.
                    </div>
                  ) : null}
                  {reliabilityValidation.v55_available ? (
                    <div>
                      IsolationForest development benign FPR {rateText(reliabilityValidation.v55_isolation_benign_fpr)} and threat capture{" "}
                      {rateText(reliabilityValidation.v55_isolation_threat_detection_rate)}. This layer remains advisory.
                    </div>
                  ) : null}
                  {reliabilityValidation.v56_available ? (
                    <div>
                      v5.6 private chronology: {metricText(reliabilityValidation.v56_private_rows_processed)} rows, drift{" "}
                      <span className="font-bold text-text">{reliabilityValidation.v56_drift_status ?? "not evaluated"}</span>.
                      Diagnostic candidate{" "}
                      <span className="font-bold text-text">{reliabilityValidation.v56_diagnostic_candidate ?? "none"}</span>;
                      untouched-future F1 {metricText(reliabilityValidation.v56_future_queue_f1)} and benign FPR{" "}
                      {rateText(reliabilityValidation.v56_future_benign_fpr)}. Assisted evidence is non-human and the lifecycle remains shadow observation.
                    </div>
                  ) : null}
                  {reliabilityValidation.v57_available ? (
                    <div className="rounded border border-line bg-surface px-3 py-2">
                      <div className="mb-2 flex flex-wrap gap-2">
                        <Badge value="Frozen Diagnostic Candidate" />
                        <Badge
                          value={
                            reliabilityValidation.v57_evidence_qualified
                              ? "Independent Evidence Available"
                              : "Independent Evidence Pending"
                          }
                        />
                        <Badge value="Shadow Observation" />
                        <Badge value="Rules Authoritative" />
                        <Badge value="Response Automation Disabled" />
                      </div>
                      <div>
                        Candidate <span className="font-bold text-text">
                          {reliabilityValidation.v57_frozen_candidate ?? "not frozen"}
                        </span>
                        ; blind validation{" "}
                        <span className="font-bold text-text">
                          {(reliabilityValidation.v57_blind_validation_status ?? "pending").replaceAll("_", " ")}
                        </span>.
                        {reliabilityValidation.v57_blind_queue_f1 === undefined ||
                        reliabilityValidation.v57_blind_queue_f1 === null
                          ? " No independent metrics are shown until predictions are frozen and approved labels are revealed."
                          : ` Blind F1 ${metricText(reliabilityValidation.v57_blind_queue_f1)}, benign FPR ${rateText(
                              reliabilityValidation.v57_blind_benign_fpr
                            )}.`}
                      </div>
                    </div>
                  ) : null}
                  {reliabilityBlockers.length ? reliabilityBlockers.map((blocker) => <div key={blocker}>{blocker}</div>) : <div>No recorded blockers.</div>}
                  {v55Blockers.map((blocker) => <div key={`v55-${blocker}`}>v5.5: {blocker}.</div>)}
                  {v56Blockers.map((blocker) => <div key={`v56-${blocker}`}>v5.6: {blocker}.</div>)}
                  {v57Blockers.map((blocker) => <div key={`v57-${blocker}`}>v5.7: {blocker}.</div>)}
                  {(reliabilityValidation.temporal_root_causes ?? []).map((cause) => <div key={cause}>Temporal drift: {cause}.</div>)}
                  {(reliabilityValidation.shadow_drift_findings ?? []).map((finding) => <div key={finding}>Shadow evidence: {finding}.</div>)}
                  {reliabilityValidation.source_holdout_limitation ? <div>{reliabilityValidation.source_holdout_limitation}</div> : null}
                </div>
              </details>
            ) : null}
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
                            : model.lifecycle_state && model.lifecycle_state !== "inactive"
                              ? model.lifecycle_state.replaceAll("_", " ")
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
              decision-support artifact with unknown classifier and feature metadata. The v4.9 reliability-lock candidates are
              diagnostic only, remain candidate-only, and are not activated.
            </div>
          </details>
        ) : null}
        <MLGovernancePolicyPanel mode={socTriageMode} />
        <details className="mt-4 rounded-lg border border-line bg-panel2 p-4">
          <summary className="cursor-pointer text-sm font-bold text-text">Latest registered training run</summary>
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <MetricCard label="Latest Run Precision" value={String(supervisedMetrics.precision ?? "-")} detail="Separate from canonical validation" tone="amber" />
            <MetricCard label="Latest Run Recall" value={String(supervisedMetrics.recall ?? "-")} detail="Separate from canonical validation" tone="danger" />
            <MetricCard label="Latest Run F1" value={String(supervisedMetrics.f1 ?? "-")} detail="Separate from canonical validation" tone="cyan" />
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
