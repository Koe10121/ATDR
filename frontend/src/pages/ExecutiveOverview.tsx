import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { ChartCard } from "../components/ChartCard";
import { EmptyState } from "../components/EmptyState";
import { MetricCard } from "../components/MetricCard";
import { Badge } from "../components/Badge";
import { useAlerts, useDashboardSummary } from "../hooks/useApiQueries";

const chartColors = ["#ef4444", "#f97316", "#f59e0b", "#22c55e", "#22d3ee", "#94a3b8"];

export function ExecutiveOverview() {
  const summary = useDashboardSummary();
  const critical = useAlerts({ severity: "Critical", status: "open", limit: 5 });
  const data = summary.data;
  const severityRows = data ? Object.entries(data.severity_counts).map(([name, count]) => ({ name, count })) : [];

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
        <MetricCard label="Active Alerts" value={data?.active_alerts ?? "-"} detail="Grouped findings requiring review" tone="danger" />
        <MetricCard label="Critical Open" value={data?.critical_open_alerts ?? "-"} detail="Immediate triage queue" tone="danger" />
        <MetricCard label="ML Anomaly Rate" value={`${data?.anomaly_rate ?? "-"}%`} detail="Assistive anomaly signal" tone="cyan" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[0.8fr_1.2fr]">
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

        <section className="panel">
          <div className="mb-4 text-sm font-extrabold uppercase tracking-wide text-muted">Critical Open Queue</div>
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
