import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useState } from "react";
import { ChartCard } from "../components/ChartCard";
import { DetailDrawer } from "../components/DetailDrawer";
import { EmptyState } from "../components/EmptyState";
import { MetaGrid } from "../components/MetaGrid";
import { MetricCard } from "../components/MetricCard";
import { Badge } from "../components/Badge";
import {
  useAlerts,
  useAuditPage,
  useDashboardSummary,
  useDashboardValidationSummary,
  useDetectionRuns,
  useHealth,
  useIngestionRuns,
  useMlReport,
  useSource,
  useSources,
  useSupervisedReport
} from "../hooks/useApiQueries";
import { inferAttackTypeFromAlertType } from "../lib/attackMapping";

const chartColors = ["#ef4444", "#f97316", "#f59e0b", "#22c55e", "#22d3ee", "#94a3b8"];

export function ExecutiveOverview() {
  const summary = useDashboardSummary();
  const validationSummary = useDashboardValidationSummary();
  const health = useHealth();
  const mlReport = useMlReport();
  const supervised = useSupervisedReport();
  const latestDetectionAudit = useAuditPage({ action: "run_detection", limit: 1 });
  const latestAudit = useAuditPage({ limit: 1 });
  const ingestionRuns = useIngestionRuns({ limit: 5 });
  const detectionRuns = useDetectionRuns({ limit: 5 });
  const sources = useSources({ limit: 5 });
  const [selectedSourceId, setSelectedSourceId] = useState<number | null>(null);
  const sourceDetail = useSource(selectedSourceId);
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
  const latestScenarioRun =
    (ingestionRuns.data ?? []).find(
      (run) =>
        String(run.details?.actor ?? "").includes("source_scenario") ||
        String(run.input_name ?? "").includes("_traffic") ||
        String(run.input_name ?? "").includes("syslog")
    ) ?? null;
  const demoSource = (sources.data ?? []).find((source) => source.name.startsWith("scenario-")) ?? (sources.data ?? [])[0] ?? null;
  const validation = validationSummary.data;

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Executive Overview</div>
        <h1 className="mt-2 text-3xl font-black">Operational posture for MFU firewall monitoring.</h1>
        <p className="mt-2 max-w-4xl text-muted">
          Rule-first detection, ML-assisted scoring, evidence retention, simulated response, and audit trails in one SOC triage console.
        </p>
      </section>

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
            <p className="mt-1 text-sm text-muted">Compact readiness view for local lab acceptance checks.</p>
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
          <summary className="cursor-pointer text-sm font-extrabold uppercase tracking-wide text-muted">Ingestion Quality Snapshot</summary>
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

      <section className="panel">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Controlled Validation</div>
            <p className="mt-1 text-sm text-muted">
              Small-subnet scenario validation with replayed logs. Real device validation remains future work.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge value="Lab-Scale Validation" />
            <Badge value={validation?.available ? (validation.ok ? "Validation Passing" : "Validation Review") : "Run Validation Suite"} />
            <Badge value="Manual Approval Required" />
          </div>
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-6">
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
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <div className="rounded-lg border border-success/30 bg-success/10 p-3 text-sm text-success">Simulated Response</div>
          <div className="rounded-lg border border-cyan/30 bg-cyan/10 p-3 text-sm text-cyan">Decision Support Only</div>
          <div className="rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">Hardware Validation Pending</div>
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
                  <div>Failures: <span className="font-bold text-text">{source.parse_failure_count}</span></div>
                  <div>Success: <span className="font-bold text-text">{source.health.parse_success_rate}%</span></div>
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
          <Badge value={latestDetectionRun?.status ?? latestIngestionRun?.status ?? "no runs"} />
        </div>
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
              <div>Top: {latestDetectionRun?.top_attack_types?.[0]?.name ?? "-"}</div>
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
                { label: "Parse Failures", value: sourceDetail.data.parse_failure_count },
                { label: "Unknown App Rate", value: `${sourceDetail.data.quality?.unknown_app_rate ?? 0}%` },
                { label: "Alert Count", value: sourceDetail.data.quality?.alert_count ?? 0 }
              ]}
            />
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
            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Recent Ingestion Runs</div>
              <div className="mt-3 space-y-2">
                {(sourceDetail.data.recent_ingestion_runs ?? []).map((run) => (
                  <div key={run.run_id} className="rounded border border-line bg-shell p-3 text-sm text-muted">
                    <div className="font-bold text-text">Run #{run.run_id} | {run.status}</div>
                    <div>{run.source_type} | parsed {run.parsed_successfully} | failed {run.parse_failures} | {run.runtime_seconds ?? "-"}s</div>
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
