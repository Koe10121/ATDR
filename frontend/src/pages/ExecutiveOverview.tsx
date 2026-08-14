import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Play, RotateCcw, X } from "lucide-react";
import { ChartCard } from "../components/ChartCard";
import { DetailDrawer } from "../components/DetailDrawer";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { MetaGrid } from "../components/MetaGrid";
import { MetricCard } from "../components/MetricCard";
import { Badge } from "../components/Badge";
import { SocPageHeader } from "../components/SocPageHeader";
import {
  useAlerts,
  useAuditPage,
  useCancelJobMutation,
  useDashboardSummary,
  useDashboardValidationSummary,
  useDetectionRuns,
  useHealth,
  useIngestionRuns,
  useJobs,
  useJobsSummary,
  useMlReport,
  useMlEvidenceSnapshot,
  useResumeJobMutation,
  useRetryJobMutation,
  useSource,
  useSources,
  useSupervisedReport
} from "../hooks/useApiQueries";
import { inferAttackTypeFromAlertType } from "../lib/attackMapping";
import { api } from "../lib/api";
import { useAuth } from "../hooks/useAuth";
import type { HistoricalReparseImpactPreview } from "../types/api";

const chartColors = ["#ef4444", "#f97316", "#f59e0b", "#22c55e", "#22d3ee", "#94a3b8"];

function numericJobDetail(details: Record<string, unknown> | undefined, key: string): number | null {
  const value = details?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function parserQualityDetail(details: Record<string, unknown> | undefined) {
  const value = details?.parser_quality;
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
}

export function ExecutiveOverview() {
  const { isAdmin } = useAuth();
  const [searchParams] = useSearchParams();
  const summary = useDashboardSummary();
  const validationSummary = useDashboardValidationSummary();
  const health = useHealth();
  const mlReport = useMlReport();
  const evidenceSnapshot = useMlEvidenceSnapshot();
  const supervised = useSupervisedReport();
  const latestDetectionAudit = useAuditPage({ action: "run_detection", limit: 1 });
  const latestAudit = useAuditPage({ limit: 1 });
  const ingestionRuns = useIngestionRuns({ limit: 5 });
  const detectionRuns = useDetectionRuns({ limit: 5 });
  const jobs = useJobs({ limit: 5 });
  const jobsSummary = useJobsSummary();
  const cancelJob = useCancelJobMutation();
  const retryJob = useRetryJobMutation();
  const resumeJob = useResumeJobMutation();
  const sources = useSources({ limit: 5 });
  const [selectedSourceId, setSelectedSourceId] = useState<number | null>(null);
  const [validationReportsOpen, setValidationReportsOpen] = useState(false);
  const sourceParam = Number(searchParams.get("source"));
  const sourceParamId = Number.isFinite(sourceParam) && sourceParam > 0 ? sourceParam : null;
  const sourceDetail = useSource(selectedSourceId);
  const [reparsePreview, setReparsePreview] = useState<HistoricalReparseImpactPreview | null>(null);
  const [reparsePreviewLoading, setReparsePreviewLoading] = useState(false);
  const [reparsePreviewError, setReparsePreviewError] = useState<string | null>(null);
  const critical = useAlerts({ severity: "Critical", status: "open", limit: 5 });
  const data = summary.data;
  const severityRows = data ? Object.entries(data.severity_counts).map(([name, count]) => ({ name, count })) : [];
  const highCritical = (data?.critical_open_alerts ?? 0) + (data?.high_open_alerts ?? 0);
  const attackRows =
    data?.top_alert_types.map((item) => ({ name: inferAttackTypeFromAlertType(item.name).replaceAll("_", " "), count: item.count })) ?? [];
  const detectionBreakdown = [
    { name: "Rule alerts", count: data?.total_alerts ?? 0 },
    { name: "Anomaly logs", count: data?.ml_anomaly_logs ?? 0 },
    { name: "Supervised labels", count: supervised.data?.label_count ?? 0 }
  ];
  const databaseStatus = health.data?.checks.database?.status ?? "unknown";
  const responseMode = health.data?.checks.response_mode?.status ?? "unknown";
  const mlStatus = health.data?.checks.ml_model?.status ?? (mlReport.data?.model_status.artifact_exists ? "ready" : "missing");
  const latestIngestion = mlReport.data?.data_quality?.latest_ingestion_time ?? "-";
  const latestDetection = latestDetectionAudit.data?.items?.[0]?.created_at ?? "-";
  const auditCount = latestAudit.data?.totalCount ?? "-";
  const ingestion = data?.ingestion_stats;
  const quality = data?.data_quality;
  const latestIngestionRun = data?.latest_ingestion_run ?? ingestionRuns.data?.[0] ?? null;
  const latestDetectionRun = data?.latest_detection_run ?? detectionRuns.data?.[0] ?? null;
  const latestJob = jobs.data?.[0] ?? null;
  const latestRawImported = numericJobDetail(latestJob?.details, "raw_logs_imported");
  const latestParsed = numericJobDetail(latestJob?.details, "parsed_successfully");
  const latestParseFailures = numericJobDetail(latestJob?.details, "parse_failures");
  const latestDuplicates = numericJobDetail(latestJob?.details, "duplicate_raw_logs");
  const staleJobCount = jobsSummary.data?.stale_count ?? 0;
  const latestFailedJob = jobsSummary.data?.latest_failed_job ?? null;
  const queue = jobsSummary.data?.queue;
  const worker = jobsSummary.data?.worker;
  const staging = jobsSummary.data?.staging;
  const operationWarnings = jobsSummary.data?.warnings ?? [];
  const parserOperationalAlerts = (sources.data ?? []).flatMap((source) =>
    (source.health.operational_alerts ?? []).map((alert) => ({
      ...alert,
      sourceId: source.source_id
    }))
  );
  const latestScenarioRun =
    (ingestionRuns.data ?? []).find(
      (run) =>
        String(run.details?.actor ?? "").includes("source_scenario") ||
        String(run.input_name ?? "").includes("_traffic") ||
        String(run.input_name ?? "").includes("syslog")
    ) ?? null;
  const demoSource = (sources.data ?? []).find((source) => source.name.startsWith("scenario-")) ?? (sources.data ?? [])[0] ?? null;
  const validation = validationSummary.data;
  const canonicalEvidence = evidenceSnapshot.data?.canonical_evidence;
  const detectionOperations = data?.detection_operations;
  const dispositionRows = Object.entries(detectionOperations?.analyst_dispositions ?? {})
    .map(([name, count]) => ({ name, count }))
    .sort((left, right) => right.count - left.count);

  useEffect(() => {
    if (sourceParamId) {
      setSelectedSourceId(sourceParamId);
    }
  }, [sourceParamId]);

  useEffect(() => {
    setReparsePreview(null);
    setReparsePreviewError(null);
  }, [selectedSourceId]);

  async function loadReparseImpactPreview() {
    if (!selectedSourceId || reparsePreviewLoading) return;
    setReparsePreviewLoading(true);
    setReparsePreviewError(null);
    try {
      setReparsePreview(await api.sourceReparseImpactPreview(selectedSourceId));
    } catch (error) {
      setReparsePreviewError(error instanceof Error ? error.message : "Historical contract preview failed.");
    } finally {
      setReparsePreviewLoading(false);
    }
  }

  return (
    <div className="space-y-5">
      <SocPageHeader eyebrow="Overview" title="ATDR lab SOC status." />

      {summary.isError || health.isError ? (
        <ErrorBanner
          error={summary.error ?? health.error}
          fallback="Overview data is temporarily unavailable. Check system health and retry."
        />
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Logs Ingested" value={data?.total_logs ?? "-"} detail="Normalized firewall events" tone="teal" />
        <MetricCard label="High/Critical Open" value={highCritical} detail="Priority SOC queue" tone="danger" />
        <MetricCard label="Top Source IPs" value={data?.top_suspicious_source_ips?.length ?? "-"} detail="Ranked suspicious sources" tone="amber" />
        <MetricCard label="ML Anomaly Rate" value={`${data?.anomaly_rate ?? "-"}%`} detail="Assistive anomaly signal" tone="cyan" />
      </div>

      <section className="panel">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">System Health</div>
          </div>
          <Badge value={health.data?.status === "ok" ? "ready" : "review"} />
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {[
            ["API", health.data?.status ?? "unknown"],
            ["Database", databaseStatus],
            ["Response Mode", responseMode],
            ["ML Model", mlStatus],
            ["Latest Ingestion", latestIngestion],
            ["Latest Detection", latestDetection],
            ["Alert Count", data?.total_alerts ?? "-"],
            ["Audit Count", auditCount],
          ].map(([label, value]) => (
            <div key={String(label)} className="rounded-lg border border-line bg-panel2 p-3 text-sm">
              <div className="text-xs font-bold uppercase tracking-wide text-muted">{label}</div>
              <div className="mt-1 break-words font-bold text-text">{String(value ?? "-")}</div>
            </div>
          ))}
        </div>
        <div className="mt-3 rounded-lg border border-cyan/30 bg-cyan/10 p-3 text-sm text-cyan">
          Config: local lab profile. Replace demo secrets before shared lab use.
        </div>
        <details className="mt-3">
          <summary className="cursor-pointer text-sm font-extrabold uppercase tracking-wide text-muted">Ingestion Quality Details</summary>
          <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {[
              ["Raw Imports", ingestion?.import_count ?? data?.total_raw_logs ?? "-"],
              ["Parse Failures", ingestion?.parse_failure_count ?? "-"],
              ["Duplicate Raw Groups", ingestion?.duplicate_raw_line_groups ?? "-"],
              ["Dedup Alert Updates", ingestion?.deduplicated_alert_updates ?? "-"],
              ["Missing Source IP", quality?.missing_source_ip ?? "-"],
              ["Missing Destination IP", quality?.missing_destination_ip ?? "-"],
              ["Unknown Apps", quality?.unknown_app_count ?? "-"],
              ["Alert Occurrences", ingestion?.alert_occurrence_count ?? "-"],
            ].map(([label, value]) => (
              <div key={String(label)} className="rounded-lg border border-line bg-shell p-3 text-sm">
                <div className="text-xs font-bold uppercase tracking-wide text-muted">{label}</div>
                <div className="mt-1 font-black text-text">{String(value ?? "-")}</div>
              </div>
            ))}
          </div>
        </details>
      </section>

      <section className="panel" data-testid="detection-operations-panel">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Detection Operations</div>
            <p className="mt-1 text-sm text-muted">Current alert workload, evidence grouping, and source context.</p>
          </div>
          <Badge value="Insufficient Evidence" />
        </div>

        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {[
            ["Unique Alerts", detectionOperations?.deduplication.unique_alerts ?? data?.total_alerts ?? "-"],
            ["Alert Occurrences", detectionOperations?.deduplication.total_occurrences ?? ingestion?.alert_occurrence_count ?? "-"],
            ["Dedup Updates", detectionOperations?.deduplication.deduplicated_updates ?? ingestion?.deduplicated_alert_updates ?? "-"],
            ["Occurrences / Alert", detectionOperations?.deduplication.occurrences_per_alert ?? "-"],
          ].map(([label, value]) => (
            <div key={String(label)} className="rounded-lg border border-line bg-panel2 p-3 text-sm">
              <div className="text-xs font-bold uppercase tracking-wide text-muted">{label}</div>
              <div className="mt-1 font-black text-text">{String(value)}</div>
            </div>
          ))}
        </div>

        <div className="mt-4 grid gap-4 lg:grid-cols-3">
          <div data-testid="detection-rule-volume">
            <div className="mb-2 text-xs font-extrabold uppercase tracking-wide text-muted">Primary Rule Volume</div>
            <div className="space-y-2">
              {(detectionOperations?.primary_rule_alert_volume ?? data?.top_alert_types ?? []).slice(0, 5).map((item) => (
                <div key={item.name} className="flex min-w-0 items-center justify-between gap-3 border-b border-line py-2 text-sm last:border-b-0">
                  <span className="min-w-0 truncate capitalize text-text" title={item.name.replaceAll("_", " ")}>{item.name.replaceAll("_", " ")}</span>
                  <span className="shrink-0 font-black text-text">{item.count}</span>
                </div>
              ))}
              {!(detectionOperations?.primary_rule_alert_volume ?? data?.top_alert_types ?? []).length ? (
                <div className="py-3 text-sm text-muted">No governed rule alerts recorded.</div>
              ) : null}
            </div>
          </div>

          <div data-testid="detection-source-volume">
            <div className="mb-2 text-xs font-extrabold uppercase tracking-wide text-muted">Source-Scoped Alert Volume</div>
            <div className="space-y-2">
              {(detectionOperations?.source_alert_volume ?? []).slice(0, 5).map((item) => (
                <Link
                  key={item.source_id}
                  className="flex min-w-0 items-center justify-between gap-3 border-b border-line py-2 text-sm text-text transition hover:text-cyan last:border-b-0"
                  to={`/overview?source=${item.source_id}`}
                  title={`Open source ${item.name}`}
                >
                  <span className="min-w-0 truncate">{item.name}</span>
                  <span className="shrink-0 font-black">{item.count}</span>
                </Link>
              ))}
              {!detectionOperations?.source_alert_volume.length ? (
                <div className="py-3 text-sm text-muted">No source-linked alerts recorded.</div>
              ) : null}
            </div>
          </div>

          <div data-testid="detection-dispositions">
            <div className="mb-2 text-xs font-extrabold uppercase tracking-wide text-muted">Analyst Dispositions</div>
            <div className="space-y-2">
              {dispositionRows.slice(0, 5).map((item) => (
                <div key={item.name} className="flex min-w-0 items-center justify-between gap-3 border-b border-line py-2 text-sm last:border-b-0">
                  <Badge value={item.name} />
                  <span className="shrink-0 font-black text-text">{item.count}</span>
                </div>
              ))}
              {!dispositionRows.length ? <div className="py-3 text-sm text-muted">No analyst dispositions recorded.</div> : null}
            </div>
          </div>
        </div>

        <div className="mt-4 grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
          <div className="rounded-lg border border-line bg-panel2 p-3" data-testid="detection-parser-context">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Parser Context</div>
              <Badge value={detectionOperations?.parser_warning_context.status ?? "unavailable"} />
            </div>
            <p className="mt-2 text-sm text-muted">
              {detectionOperations?.parser_warning_context.message ?? "Parser context is unavailable."}
            </p>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3" data-testid="detection-accuracy-state">
            <div className="text-xs font-extrabold uppercase tracking-wide text-muted">Accuracy Evidence</div>
            <p className="mt-2 text-sm text-muted">
              {detectionOperations?.accuracy_evidence.message ??
                "Operational alert volume is not an accuracy metric. Independent labeled validation is required."}
            </p>
          </div>
        </div>

        <details className="mt-4" data-testid="detection-run-trend">
          <summary className="cursor-pointer text-sm font-extrabold uppercase tracking-wide text-muted">Recent Detection Trend</summary>
          <div className="mt-3 overflow-x-auto">
            <table className="min-w-[620px] text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs uppercase tracking-wide text-muted">
                  <th className="px-2 py-2">Run</th>
                  <th className="px-2 py-2">Status</th>
                  <th className="px-2 py-2">Evaluated</th>
                  <th className="px-2 py-2">Created</th>
                  <th className="px-2 py-2">Deduplicated</th>
                  <th className="px-2 py-2">Suppressed</th>
                </tr>
              </thead>
              <tbody>
                {(detectionRuns.data ?? []).slice(0, 5).map((run) => (
                  <tr key={run.run_id} className="border-b border-line/70 text-text last:border-b-0">
                    <td className="px-2 py-2 font-bold">#{run.run_id}</td>
                    <td className="px-2 py-2"><Badge value={run.status} /></td>
                    <td className="px-2 py-2">{run.logs_evaluated}</td>
                    <td className="px-2 py-2">{run.alerts_created}</td>
                    <td className="px-2 py-2">{run.alerts_deduplicated}</td>
                    <td className="px-2 py-2">{run.alerts_suppressed}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!(detectionRuns.data ?? []).length ? <div className="py-3 text-sm text-muted">No detection runs recorded.</div> : null}
          </div>
        </details>
      </section>

      <section className="panel">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Controlled Validation</div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge value="Lab-Scale Validation" />
            <Badge value={validation?.available ? (validation.ok ? "Validation Passing" : "Validation Review") : "Run Validation Suite"} />
            <Badge value="Manual Approval Required" />
          </div>
        </div>
        <div className="mt-3">
          <button
            type="button"
            className="inline-flex w-full items-center justify-between rounded-lg border border-line bg-panel2 px-3 py-2 text-left text-sm font-extrabold uppercase tracking-wide text-muted transition hover:border-cyan/50 hover:text-text"
            aria-expanded={validationReportsOpen}
            onClick={() => setValidationReportsOpen((open) => !open)}
          >
            <span>Validation reports</span>
            <span aria-hidden="true">{validationReportsOpen ? "Hide" : "Show"}</span>
          </button>
        {validationReportsOpen ? <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Validation Suite</div>
            <div className="mt-1 font-bold text-text">
              {validation?.available ? `${validation.passed_count ?? 0}/${validation.scenario_count ?? 0} passed` : "No report yet"}
            </div>
            <div className="mt-1 text-xs text-muted">
              {validation?.available ? `Generated ${validation.generated_at ?? "-"}` : validation?.message ?? "Run detection validation to publish a report."}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Generalization</div>
            <div className="mt-1 font-bold text-text">
              {validation?.generalization?.available
                ? `${validation.generalization.passed_count ?? 0}/${validation.generalization.variant_count ?? 0} variants`
                : "No variant run yet"}
            </div>
            <div className="mt-1 text-xs text-muted">
              {validation?.generalization?.available
                ? `FP ${validation.generalization.false_positive_count ?? 0} | FN ${validation.generalization.false_negative_count ?? 0}`
                : validation?.generalization?.message ?? "Run detection generalization to publish a report."}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Layered Modes</div>
            <div className="mt-1 font-bold text-text">
              {validation?.layered?.available
                ? `${validation.layered.passed_count ?? 0}/${validation.layered.mode_run_count ?? 0} mode runs`
                : "No layered run yet"}
            </div>
            <div className="mt-1 text-xs text-muted">
              {validation?.layered?.available
                ? `FP ${validation.layered.false_positive_count ?? 0} | FN ${validation.layered.false_negative_count ?? 0}`
                : validation?.layered?.message ?? "Run layered detection validation to publish a report."}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">E2E Workflow</div>
            <div className="mt-1 font-bold text-text">
              {validation?.e2e_workflow?.available
                ? `${validation.e2e_workflow.passed_count ?? 0}/${validation.e2e_workflow.scenario_count ?? 0} passed`
                : "No e2e run yet"}
            </div>
            <div className="mt-1 text-xs text-muted">
              {validation?.e2e_workflow?.available
                ? `${validation.e2e_workflow.alert_count ?? 0} alerts | ${validation.e2e_workflow.case_count ?? 0} cases`
                : validation?.e2e_workflow?.message ?? "Run e2e workflow validation to publish a report."}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Reliability</div>
            <div className="mt-1 font-bold text-text">
              {validation?.reliability?.available
                ? `${validation.reliability.scenario_passed_count ?? 0}/${validation.reliability.scenario_count ?? 0} scenarios`
                : "No v1.1 baseline yet"}
            </div>
            <div className="mt-1 text-xs text-muted">
              {validation?.reliability?.available
                ? `FP ${validation.reliability.false_positive_count ?? 0} | FN ${validation.reliability.false_negative_count ?? 0}`
                : validation?.reliability?.message ?? "Run detection reliability baseline."}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Canonical ML Evidence</div>
            <div className="mt-1 font-bold text-text">
              {canonicalEvidence?.available
                ? `${canonicalEvidence.evaluated_splits ?? 0} development splits | Snapshot ${canonicalEvidence.snapshot_id}`
                : "Canonical evidence unavailable"}
            </div>
            <div className="mt-1 text-xs text-muted">
              {canonicalEvidence?.available
                ? `${(canonicalEvidence.readiness_decision ?? "candidate_only").replaceAll("_", " ")} | ${(
                    canonicalEvidence.evidence_type ?? "controlled_validation"
                  ).replaceAll("_", " ")}`
                : canonicalEvidence?.reason ?? "No historical ML metric fallback is used."}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Drift</div>
            <div className="mt-1 font-bold text-text">
              {validation?.drift?.available ? `${validation.drift.warning_count ?? 0} warnings` : "No drift report yet"}
            </div>
            <div className="mt-1 text-xs text-muted">
              {validation?.drift?.available
                ? `Alert rate ${validation.drift.alert_rate ?? "-"}`
                : validation?.drift?.message ?? "Run detection drift monitor."}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Demo Source</div>
            <div className="mt-1 break-words font-bold text-text">{demoSource?.name ?? "No source yet"}</div>
            <div className="mt-1 text-xs text-muted">
              {demoSource ? `${demoSource.source_type} / ${demoSource.parser_profile}` : "Run a source scenario or replay first."}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Source Health</div>
            <div className="mt-1 font-bold text-text">{demoSource?.health.status ?? "-"}</div>
            <div className="mt-1 text-xs text-muted">Last log {demoSource?.last_log_received_at ?? "-"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Latest Scenario Run</div>
            <div className="mt-1 break-words font-bold text-text">{latestScenarioRun?.input_name ?? latestIngestionRun?.input_name ?? "-"}</div>
            <div className="mt-1 text-xs text-muted">
              Parsed {latestScenarioRun?.parsed_successfully ?? latestIngestionRun?.parsed_successfully ?? "-"} | failed{" "}
              {latestScenarioRun?.parse_failures ?? latestIngestionRun?.parse_failures ?? "-"}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Risk Calibration</div>
            <div className="mt-1 break-words font-bold text-text">{validation?.latest_risk_calibration_name ?? "Not generated"}</div>
            <div className="mt-1 text-xs text-muted">
              Latest report {validation?.latest_report_name ?? "-"}
            </div>
          </div>
        </div> : null}
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-lg border border-cyan/30 bg-cyan/10 p-3 text-sm text-cyan">Decision Support Only</div>
          <div className="rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">Response Automation Disabled</div>
          <div className="rounded-lg border border-line bg-panel2 p-3 text-sm text-muted">Not Production Promoted</div>
          <div className="rounded-lg border border-success/30 bg-success/10 p-3 text-sm text-success">
            {canonicalEvidence?.available ? "Canonical Evidence Available" : "Canonical Evidence Pending"}
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Log Sources</div>
            <p className="mt-1 text-sm text-muted">Lab sensors and ingestion sources tracked without requiring source selection for normal imports.</p>
          </div>
          <Badge value={`${sources.data?.length ?? 0} sources`} />
        </div>
        {sources.data?.length ? (
          <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
            {sources.data.slice(0, 6).map((source) => (
              <button
                key={source.source_id}
                type="button"
                className="rounded-lg border border-line bg-panel2 p-4 text-left transition hover:border-cyan/50"
                onClick={() => setSelectedSourceId(source.source_id)}
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="font-bold text-text">{source.name}</div>
                    <div className="text-xs text-muted">
                      {source.source_type} {source.host ? `| ${source.host}${source.port ? `:${source.port}` : ""}` : ""}
                    </div>
                  </div>
                  <Badge value={source.health.status} />
                </div>
                <div className="mt-3 grid gap-2 text-sm text-muted sm:grid-cols-2">
                  <div>Logs: <span className="font-bold text-text">{source.logs_received_count}</span></div>
                  <div>Parsed: <span className="font-bold text-text">{source.parse_success_count}</span></div>
                  <div>Fallback / Failed: <span className="font-bold text-text">{source.parse_failure_count}</span></div>
                  <div>Stored Parse Success: <span className="font-bold text-text">{source.health.parse_success_rate}%</span></div>
                  <div>Contract: <span className="font-bold text-text">{(source.health.parser_contract_state ?? "legacy_contract").replaceAll("_", " ")}</span></div>
                  <div>Quality: <span className="font-bold text-text">{(source.health.parser_quality_state ?? "legacy").replaceAll("_", " ")}</span></div>
                  <div className="sm:col-span-2">Last log: <span className="font-bold text-text">{source.last_log_received_at ?? "-"}</span></div>
                </div>
                {source.latest_error ? <div className="mt-2 text-xs text-amber">{source.latest_error}</div> : null}
              </button>
            ))}
          </div>
        ) : (
          <EmptyState title="No sources recorded yet" body="Import, replay, or receive syslog lines to create the default local source automatically." />
        )}
      </section>

      <div className="grid gap-4 xl:grid-cols-3">
        <ChartCard title="Severity Mix">
          {severityRows.length ? (
            <div className="h-72">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={severityRows} dataKey="count" nameKey="name" innerRadius={72} outerRadius={108} paddingAngle={3}>
                    {severityRows.map((_, index) => (
                      <Cell key={index} fill={chartColors[index % chartColors.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#0f151d", border: "1px solid #263445", color: "#e5edf6" }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState title="No severity data" body="Import logs and run detection to populate the posture chart." />
          )}
        </ChartCard>

        <ChartCard title="Detection Breakdown">
          <div className="h-72">
            <ResponsiveContainer>
              <BarChart data={detectionBreakdown} layout="vertical" margin={{ left: 110 }}>
                <XAxis type="number" stroke="#93a4b7" />
                <YAxis type="category" dataKey="name" stroke="#93a4b7" width={110} />
                <Tooltip contentStyle={{ background: "#0f151d", border: "1px solid #263445", color: "#e5edf6" }} />
                <Bar dataKey="count" fill="#22d3ee" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>

        <section className="panel">
          <div className="mb-4 text-sm font-extrabold uppercase tracking-wide text-muted">Top Sources And Attack Types</div>
          <div className="space-y-3">
            {(data?.top_suspicious_source_ips ?? []).slice(0, 4).map((item) => (
              <div key={item.name} className="flex justify-between rounded-lg border border-line bg-panel2 px-3 py-2 text-sm">
                <span className="font-bold text-text">{item.name}</span>
                <span className="text-muted">{item.count}</span>
              </div>
            ))}
            {attackRows.slice(0, 4).map((item) => (
              <div key={item.name} className="flex justify-between rounded-lg border border-line bg-panel2 px-3 py-2 text-sm">
                <span className="capitalize text-muted">{item.name}</span>
                <span className="font-bold text-text">{item.count}</span>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Operations Health</div>
            <p className="mt-1 text-sm text-muted">Latest ingestion and detection runs for lab SOC visibility.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge value={jobsSummary.data?.health_status ?? "healthy"} />
            <Badge value={latestDetectionRun?.status ?? latestIngestionRun?.status ?? "no runs"} />
            <Link className="btn-secondary text-xs" to={`/assistant?prompt=${encodeURIComponent("Summarize recent detection runs and failed jobs.")}`}>
              Ask Assistant
            </Link>
          </div>
        </div>
        {operationWarnings.length ? (
          <div
            data-testid="operational-warnings"
            className="mb-3 rounded-lg border border-amber/40 bg-amber/10 px-4 py-3"
            role="status"
          >
            <div className="text-xs font-extrabold uppercase tracking-wide text-amber">Operational Warnings</div>
            <div className="mt-2 grid gap-1 text-sm text-text lg:grid-cols-2">
              {operationWarnings.slice(0, 4).map((warning) => (
                <div key={warning.code} className="break-words">
                  <span className="font-bold capitalize">{warning.code.replaceAll("_", " ")}:</span> {warning.message}
                </div>
              ))}
            </div>
          </div>
        ) : null}
        {parserOperationalAlerts.length ? (
          <div
            data-testid="parser-operational-alerts"
            className="mb-3 rounded-lg border border-amber/40 bg-amber/10 px-4 py-3"
            role="status"
          >
            <div className="text-xs font-extrabold uppercase tracking-wide text-amber">Parser Quality Alerts</div>
            <div className="mt-2 grid gap-1 text-sm text-text lg:grid-cols-2">
              {parserOperationalAlerts.slice(0, 6).map((alert, index) => (
                <button
                  type="button"
                  className="break-words text-left"
                  key={`${alert.sourceId}-${alert.code}-${index}`}
                  onClick={() => setSelectedSourceId(alert.sourceId)}
                >
                  <span className="font-bold capitalize">{alert.code.replaceAll("_", " ")}:</span> {alert.message}
                </button>
              ))}
            </div>
          </div>
        ) : null}
        <div className="grid gap-3 lg:grid-cols-2">
          <div className="rounded-lg border border-line bg-panel2 p-4">
            <div className="flex items-center justify-between gap-2">
              <div className="font-bold text-text">Latest Ingestion Run</div>
              <Badge value={latestIngestionRun?.status ?? "none"} />
            </div>
            <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-2">
              <div>Run: {latestIngestionRun?.run_id ?? "-"}</div>
              <div>Source: {latestIngestionRun?.source_type ?? "-"}</div>
              <div>Input: {latestIngestionRun?.input_name ?? "-"}</div>
              <div>Runtime: {latestIngestionRun?.runtime_seconds ?? "-"}s</div>
              <div>Parsed: {latestIngestionRun?.parsed_successfully ?? "-"}</div>
              <div>Failures: {latestIngestionRun?.parse_failures ?? "-"}</div>
              <div>Duplicates: {latestIngestionRun?.duplicate_raw_logs ?? "-"}</div>
              <div>Dedup alerts: {latestIngestionRun?.alerts_deduplicated ?? "-"}</div>
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-4">
            <div className="flex items-center justify-between gap-2">
              <div className="font-bold text-text">Latest Detection Run</div>
              <Badge value={latestDetectionRun?.status ?? "none"} />
            </div>
            <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-2">
              <div>Run: {latestDetectionRun?.run_id ?? "-"}</div>
              <div>Type: {latestDetectionRun?.detection_type ?? "-"}</div>
              <div>Runtime: {latestDetectionRun?.runtime_seconds ?? "-"}s</div>
              <div>Evaluated: {latestDetectionRun?.logs_evaluated ?? "-"}</div>
              <div>Created: {latestDetectionRun?.alerts_created ?? "-"}</div>
              <div>Deduped: {latestDetectionRun?.alerts_deduplicated ?? "-"}</div>
              <div>Suppressed: {latestDetectionRun?.alerts_suppressed ?? "-"}</div>
              <div>Run top attack type: {latestDetectionRun?.top_attack_types?.[0]?.name ?? "-"}</div>
            </div>
          </div>
        </div>
        <div className="mt-3 rounded-lg border border-line bg-panel2 p-4">
          <div className="flex items-center justify-between gap-2">
            <div className="font-bold text-text">Latest Operation Job</div>
            <Badge value={latestJob?.status ?? "none"} />
          </div>
          <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-4">
            <div>Job: {latestJob?.job_id ?? "-"}</div>
            <div>Type: {latestJob?.job_type?.replaceAll("_", " ") ?? "-"}</div>
            <div>Actor: {latestJob?.requested_by ?? "-"}</div>
            <div>
              Progress: {latestJob ? `${latestJob.progress_current}/${latestJob.progress_total || latestJob.progress_current}` : "-"}
            </div>
          </div>
          {latestJob ? (
            <div className="mt-3" data-testid="latest-job-progress">
              <div className="h-2 overflow-hidden rounded-full bg-shell" aria-label={`Operation progress ${latestJob.progress_percentage ?? 0}%`}>
                <div
                  className="h-full rounded-full bg-cyan transition-[width] duration-300"
                  style={{ width: `${Math.max(0, Math.min(100, latestJob.progress_percentage ?? 0))}%` }}
                />
              </div>
              <div className="mt-1 flex flex-wrap justify-between gap-2 text-xs text-muted">
                <span>{latestJob.progress_current} of {latestJob.progress_total || "unknown"} lines committed</span>
                <span>{latestJob.chunk_commits ?? 0} chunk commits</span>
              </div>
              {latestRawImported !== null ? (
                <div data-testid="latest-job-counters" className="mt-3 grid gap-2 text-xs text-muted sm:grid-cols-4">
                  <span>Raw imported: <strong className="text-text">{latestRawImported}</strong></span>
                  <span>Parsed: <strong className="text-text">{latestParsed ?? 0}</strong></span>
                  <span>Failed: <strong className="text-text">{latestParseFailures ?? 0}</strong></span>
                  <span>Duplicates: <strong className="text-text">{latestDuplicates ?? 0}</strong></span>
                </div>
              ) : null}
            </div>
          ) : null}
          {latestJob?.error_summary ? <div className="mt-2 text-sm text-amber">{latestJob.error_summary}</div> : null}
        </div>
        <div data-testid="operation-queue-panel" className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-6">
          <div className="rounded-lg border border-line bg-panel2 p-3 text-sm">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Active Jobs</div>
            <div className="mt-1 font-black text-text">{jobsSummary.data?.active_count ?? "-"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3 text-sm">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Import Staging</div>
            <div className="mt-1 flex items-center gap-2">
              <Badge value={staging?.state ?? "unknown"} />
              <span className="text-muted">{staging?.pressure ? "imports paused" : "available"}</span>
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3 text-sm">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Queue</div>
            <div className="mt-1 font-black text-text">{queue?.queued ?? 0} queued / {queue?.running ?? 0} running</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3 text-sm">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Worker</div>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <Badge value={worker?.status ?? "not seen"} />
              <span className="text-muted">{worker?.enabled ? "enabled" : "manual"}</span>
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3 text-sm">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Stale Jobs</div>
            <div className={staleJobCount ? "mt-1 font-black text-amber" : "mt-1 font-black text-text"}>{staleJobCount}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3 text-sm">
            <div className="text-xs font-bold uppercase tracking-wide text-muted">Latest Failed Job</div>
            <div className="mt-1 break-words font-bold text-text">
              {latestFailedJob ? `#${latestFailedJob.job_id} ${latestFailedJob.job_type.replaceAll("_", " ")}` : "-"}
            </div>
          </div>
        </div>
        <details className="mt-4">
          <summary className="cursor-pointer text-sm font-extrabold uppercase tracking-wide text-muted">Recent Run History</summary>
          <div className="mt-3 grid gap-3 lg:grid-cols-2">
            <div className="space-y-2">
              {(ingestionRuns.data ?? []).slice(0, 5).map((run) => (
                <div key={run.run_id} className="rounded border border-line bg-shell p-3 text-sm text-muted">
                  <div className="font-bold text-text">Ingestion #{run.run_id} | {run.status}</div>
                  <div>{run.source_type} | parsed {run.parsed_successfully} | failed {run.parse_failures} | {run.runtime_seconds ?? "-"}s</div>
                </div>
              ))}
            </div>
            <div className="space-y-2">
              {(detectionRuns.data ?? []).slice(0, 5).map((run) => (
                <div key={run.run_id} className="rounded border border-line bg-shell p-3 text-sm text-muted">
                  <div className="font-bold text-text">Detection #{run.run_id} | {run.status}</div>
                  <div>{run.detection_type} | evaluated {run.logs_evaluated} | created {run.alerts_created} | dedup {run.alerts_deduplicated}</div>
                </div>
              ))}
            </div>
          </div>
          <div className="mt-3 space-y-2">
            {(jobs.data ?? []).slice(0, 5).map((job) => (
              <div key={job.job_id} className="rounded border border-line bg-shell p-3 text-sm text-muted">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-bold text-text">
                    Job #{job.job_id} | {job.job_type.replaceAll("_", " ")} | {job.status}
                  </div>
                  <div className="flex items-center gap-1">
                    {job.can_resume && isAdmin ? (
                      <button
                        type="button"
                        className="grid h-8 w-8 place-items-center rounded-md border border-line bg-panel2 text-muted transition hover:border-cyan/50 hover:text-text disabled:cursor-not-allowed disabled:opacity-50"
                        title="Resume from the last committed checkpoint"
                        aria-label={`Resume operation job ${job.job_id}`}
                        disabled={resumeJob.isPending}
                        onClick={() => resumeJob.mutate(job.job_id)}
                      >
                        <Play size={15} />
                      </button>
                    ) : null}
                    {job.can_retry ? (
                      <button
                        type="button"
                        className="grid h-8 w-8 place-items-center rounded-md border border-line bg-panel2 text-muted transition hover:border-cyan/50 hover:text-text disabled:cursor-not-allowed disabled:opacity-50"
                        title="Retry failed operation"
                        aria-label={`Retry operation job ${job.job_id}`}
                        disabled={retryJob.isPending}
                        onClick={() => retryJob.mutate(job.job_id)}
                      >
                        <RotateCcw size={15} />
                      </button>
                    ) : null}
                    {job.can_cancel ? (
                      <button
                        type="button"
                        className="grid h-8 w-8 place-items-center rounded-md border border-line bg-panel2 text-muted transition hover:border-danger/50 hover:text-danger disabled:cursor-not-allowed disabled:opacity-50"
                        title={job.status === "running" ? "Request cancellation at the next committed chunk" : "Cancel queued operation"}
                        aria-label={`Cancel operation job ${job.job_id}`}
                        disabled={cancelJob.isPending}
                        onClick={() => {
                          if (window.confirm("Request safe cancellation for this operation? Committed evidence will be retained.")) {
                            cancelJob.mutate(job.job_id);
                          }
                        }}
                      >
                        <X size={16} />
                      </button>
                    ) : null}
                  </div>
                </div>
                <div>
                  Requested by {job.requested_by} | attempt {job.attempt_count ?? 0}/{job.max_attempts ?? 1} | progress {job.progress_current}/{job.progress_total || job.progress_current}
                </div>
                <div className="mt-2 h-2 overflow-hidden rounded-full bg-panel2" aria-label={`Job ${job.job_id} progress`}>
                  <div
                    className="h-full rounded-full bg-cyan transition-[width] duration-300"
                    style={{ width: `${Math.max(0, Math.min(100, job.progress_percentage ?? 0))}%` }}
                  />
                </div>
                {job.error_summary ? <div className="mt-1 break-words text-amber">{job.error_summary}</div> : null}
                {job.resume_ineligible_reason && ["import_logs", "replay_logs"].includes(job.job_type) && ["failed", "cancelled"].includes(job.status) ? (
                  <div className="mt-1 break-words text-xs text-muted">Resume unavailable: {job.resume_ineligible_reason}</div>
                ) : null}
                {(job.checkpoint_line ?? 0) > 0 ? (
                  <details className="mt-2 text-xs">
                    <summary className="cursor-pointer font-bold text-muted">Technical details</summary>
                    <div className="mt-1 break-words text-muted">
                      Checkpoint line {job.checkpoint_line} | bytes {job.checkpoint_bytes ?? 0} | chunks {job.chunk_commits ?? 0}
                      {job.resume_of_job_id ? ` | resumed from job #${job.resume_of_job_id}` : ""}
                    </div>
                  </details>
                ) : null}
              </div>
            ))}
          </div>
        </details>
      </section>

      <div className="grid gap-4 xl:grid-cols-[0.8fr_1.2fr]">
        <section className="panel">
          <div className="mb-4 text-sm font-extrabold uppercase tracking-wide text-muted">Recent Severe Alerts</div>
          <div className="space-y-3">
            {(critical.data ?? []).map((alert) => (
              <div key={alert.id} className="rounded-lg border border-line bg-panel2 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-bold text-text">{alert.title}</div>
                  <Badge value={alert.severity} kind="severity" />
                </div>
                <div className="mt-2 text-sm text-muted">
                  Score {alert.threat_score} | {alert.src_ip ?? "unknown source"} to {alert.dst_ip ?? "multiple destinations"} | SLA{" "}
                  {alert.sla?.label ?? "-"}
                </div>
              </div>
            ))}
            {!critical.isLoading && !(critical.data ?? []).length ? (
              <EmptyState title="No critical open alerts" body="The critical queue is empty for the current filters." />
            ) : null}
          </div>
        </section>
      </div>

      <DetailDrawer title={`Source ${sourceDetail.data?.name ?? ""}`} open={Boolean(selectedSourceId)} onClose={() => setSelectedSourceId(null)}>
        {sourceDetail.data ? (
          <div className="space-y-5">
            <div className="flex flex-wrap gap-2">
              <Badge value={sourceDetail.data.health.status} />
              <Badge value={sourceDetail.data.source_type} />
              <Badge value={sourceDetail.data.parser_profile} />
              <Link
                className="btn-secondary text-xs"
                to={`/assistant?source=${sourceDetail.data.source_id}&prompt=${encodeURIComponent(`Summarize source ${sourceDetail.data.source_id} health and what an analyst should check next.`)}`}
              >
                Ask Assistant
              </Link>
            </div>
            <MetaGrid
              rows={[
                { label: "Name", value: sourceDetail.data.name },
                { label: "Type", value: sourceDetail.data.source_type },
                { label: "Parser Profile", value: sourceDetail.data.parser_profile },
                { label: "Host / Port", value: `${sourceDetail.data.host ?? "-"}:${sourceDetail.data.port ?? "-"}` },
                { label: "Enabled", value: sourceDetail.data.enabled ? "yes" : "no" },
                { label: "Last Seen", value: sourceDetail.data.last_seen },
                { label: "Last Log", value: sourceDetail.data.last_log_received_at },
                { label: "Logs Received", value: sourceDetail.data.logs_received_count },
                { label: "Parsed", value: sourceDetail.data.parse_success_count },
                { label: "Fallback / Failed Rows", value: sourceDetail.data.parse_failure_count },
                { label: "Contract State", value: (sourceDetail.data.health.parser_contract_state ?? "legacy_contract").replaceAll("_", " ") },
                { label: "Parser Quality", value: (sourceDetail.data.health.parser_quality_state ?? "legacy").replaceAll("_", " ") },
                { label: "Runtime Parser Errors", value: sourceDetail.data.quality?.parser_error_count ?? 0 },
                { label: "Structural Warnings", value: sourceDetail.data.quality?.structural_warning_count ?? 0 },
                { label: "Compatible / Extended", value: `${sourceDetail.data.quality?.compatible_layout_count ?? 0} / ${sourceDetail.data.quality?.extended_layout_count ?? 0}` },
                { label: "Partial / Unsupported", value: `${sourceDetail.data.quality?.partial_layout_count ?? 0} / ${sourceDetail.data.quality?.unsupported_layout_count ?? 0}` },
                { label: "Unresolved App Rate", value: `${sourceDetail.data.quality?.unresolved_application_rate ?? 0}%` },
                { label: "Absent / N/A Apps", value: `${sourceDetail.data.quality?.absent_application_count ?? 0} / ${sourceDetail.data.quality?.not_applicable_application_count ?? 0}` },
                { label: "Generic / Raw Fallback", value: `${sourceDetail.data.quality?.generic_syslog_count ?? 0} / ${sourceDetail.data.quality?.raw_fallback_count ?? 0}` },
                { label: "Legacy Contract Rows", value: sourceDetail.data.quality?.legacy_contract_rows ?? 0 },
                { label: "Alert Count", value: sourceDetail.data.quality?.alert_count ?? 0 }
              ]}
            />
            {(sourceDetail.data.quality?.operational_alerts ?? []).length ? (
              <section className="rounded-lg border border-amber/30 bg-amber/10 p-4" data-testid="source-parser-alerts">
                <div className="text-sm font-extrabold uppercase tracking-wide text-amber">Parser Quality Alerts</div>
                <div className="mt-2 space-y-2 text-sm text-text">
                  {(sourceDetail.data.quality?.operational_alerts ?? []).map((alert) => (
                    <div className="break-words" key={alert.code}>
                      <span className="font-bold capitalize">{alert.code.replaceAll("_", " ")}:</span> {alert.message}
                    </div>
                  ))}
                </div>
              </section>
            ) : null}
            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Troubleshooting Hints</div>
              <div className="mt-2 space-y-2 text-sm text-muted">
                {!sourceDetail.data.enabled ? (
                  <div className="rounded border border-cyan/30 bg-cyan/10 p-2 text-cyan">
                    Disabled sources keep all historical raw logs, normalized rows, alerts, labels, and audit evidence. Re-enable only when the lab sender should be monitored again.
                  </div>
                ) : null}
                <div>{sourceDetail.data.health.recommendation}</div>
                <div>
                  Parser profile behavior: <span className="font-bold text-text">{sourceDetail.data.parser_profile}</span>. Palo Alto extracts firewall CSV
                  fields, generic syslog preserves minimal wrapper data, and raw fallback preserves raw evidence while structured fields may be limited.
                </div>
                {(sourceDetail.data.health.warnings ?? []).map((warning) => (
                  <div key={warning} className="rounded border border-amber/30 bg-amber/10 p-2 text-amber">{warning}</div>
                ))}
                {(sourceDetail.data.quality?.warnings ?? []).map((warning) => (
                  <div key={warning} className="rounded border border-amber/30 bg-amber/10 p-2 text-amber">{warning}</div>
                ))}
              </div>
            </section>
            <section className="rounded-lg border border-line bg-panel2 p-4" data-testid="historical-contract-preview">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Historical Contract Coverage</div>
                  <div className="mt-1 text-xs text-muted">Read-only metadata preview. No log is reparsed or changed.</div>
                </div>
                <button
                  type="button"
                  className="btn-secondary text-xs"
                  disabled={reparsePreviewLoading}
                  onClick={() => void loadReparseImpactPreview()}
                >
                  {reparsePreviewLoading ? "Loading..." : "Preview impact"}
                </button>
              </div>
              {reparsePreviewError ? <div className="mt-3 text-sm text-danger">{reparsePreviewError}</div> : null}
              {reparsePreview ? (
                <div className="mt-3 grid gap-2 text-sm text-muted sm:grid-cols-2">
                  <div>Rows scanned: <span className="font-bold text-text">{reparsePreview.rows_scanned}</span></div>
                  <div>Total rows: <span className="font-bold text-text">{reparsePreview.total_rows}</span></div>
                  <div>Current metadata: <span className="font-bold text-text">{reparsePreview.current_contract_metadata_rows}</span></div>
                  <div>Legacy metadata: <span className="font-bold text-text">{reparsePreview.legacy_contract_rows_scanned}</span></div>
                  <div className="sm:col-span-2 text-xs">
                    {reparsePreview.coverage_complete ? "Complete metadata coverage." : "Bounded sample only."} Database mutated: no.
                  </div>
                </div>
              ) : null}
            </section>
            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Recent Ingestion Runs</div>
              <div className="mt-3 space-y-2">
                {(sourceDetail.data.recent_ingestion_runs ?? []).map((run) => (
                  <div key={run.run_id} className="rounded border border-line bg-shell p-3 text-sm text-muted">
                    <div className="font-bold text-text">Run #{run.run_id} | {run.status}</div>
                    <div>{run.source_type} | parsed {run.parsed_successfully} | failed {run.parse_failures} | {run.runtime_seconds ?? "-"}s</div>
                    {parserQualityDetail(run.details) ? (
                      <div className="mt-1 text-xs">
                        Contract rows {String(parserQualityDetail(run.details)?.observed_rows ?? 0)} | structural warnings{" "}
                        {String(parserQualityDetail(run.details)?.structural_warning_rows ?? 0)} | unresolved apps{" "}
                        {String(
                          (parserQualityDetail(run.details)?.application_resolution_statuses as Record<string, number> | undefined)?.unresolved ?? 0
                        )}
                      </div>
                    ) : (
                      <div className="mt-1 text-xs">Legacy run: parser-quality contract was not recorded.</div>
                    )}
                  </div>
                ))}
                {!(sourceDetail.data.recent_ingestion_runs ?? []).length ? <EmptyState title="No linked runs" body="Future direct replay or imports from this source will appear here." /> : null}
              </div>
            </section>
            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Recent Detection Runs</div>
              <div className="mt-3 space-y-2">
                {(sourceDetail.data.recent_detection_runs ?? []).map((run) => (
                  <div key={run.run_id} className="rounded border border-line bg-shell p-3 text-sm text-muted">
                    <div className="font-bold text-text">Run #{run.run_id} | {run.status}</div>
                    <div>
                      {run.detection_type} | evaluated {run.logs_evaluated} | created {run.alerts_created} | dedup {run.alerts_deduplicated} |{" "}
                      {run.runtime_seconds ?? "-"}s
                    </div>
                    <div>Run attack types: {run.top_attack_types?.map((item) => `${item.name} (${item.count})`).join(", ") || "none"}</div>
                  </div>
                ))}
                {!(sourceDetail.data.recent_detection_runs ?? []).length ? (
                  <EmptyState title="No linked detection runs" body="Run detection after source-specific replay to populate source-linked detection history." />
                ) : null}
              </div>
            </section>
            {sourceDetail.data.latest_error || sourceDetail.data.quality?.parse_failure_examples?.length ? (
              <section className="rounded-lg border border-line bg-panel2 p-4">
                <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Latest Errors</div>
                {sourceDetail.data.latest_error ? <div className="mt-2 text-sm text-amber">{sourceDetail.data.latest_error}</div> : null}
                <pre className="mt-3 max-h-60 overflow-auto rounded-lg border border-line bg-shell p-3 text-xs text-muted">
                  {JSON.stringify(sourceDetail.data.quality?.parse_failure_examples ?? [], null, 2)}
                </pre>
              </section>
            ) : null}
          </div>
        ) : null}
      </DetailDrawer>
    </div>
  );
}
