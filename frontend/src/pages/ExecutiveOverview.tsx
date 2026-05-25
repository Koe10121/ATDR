import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartCard } from "../components/ChartCard";
import { EmptyState } from "../components/EmptyState";
import { MetricCard } from "../components/MetricCard";
import { Badge } from "../components/Badge";
import { useAlerts, useAuditPage, useDashboardSummary, useHealth, useMlReport, useSupervisedReport } from "../hooks/useApiQueries";
import { inferAttackTypeFromAlertType } from "../lib/attackMapping";

const chartColors = ["#ef4444", "#f97316", "#f59e0b", "#22c55e", "#22d3ee", "#94a3b8"];

export function ExecutiveOverview() {
  const summary = useDashboardSummary();
  const health = useHealth();
  const mlReport = useMlReport();
  const supervised = useSupervisedReport();
  const latestDetectionAudit = useAuditPage({ action: "run_detection", limit: 1 });
  const latestAudit = useAuditPage({ limit: 1 });
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

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Executive Overview</div>
        <h1 className="mt-2 text-3xl font-black">Operational posture for MFU firewall monitoring.</h1>
        <p className="mt-2 max-w-4xl text-muted">
          Rule-first detection, ML-assisted scoring, evidence retention, simulated response, and audit trails in one production migration console.
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
        <div className="mt-3 rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
          Config warnings are checked by Config Doctor. In local demo mode, the default JWT-secret warning is expected; replace it before shared lab use.
        </div>
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
    </div>
  );
}
