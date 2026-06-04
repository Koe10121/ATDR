import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartCard } from "../components/ChartCard";
import { EmptyState } from "../components/EmptyState";
import { MetricCard } from "../components/MetricCard";
import { Badge } from "../components/Badge";
import { useDetectionTuning } from "../hooks/useApiQueries";

export function DetectionTuning() {
  const tuning = useDetectionTuning();
  const data = tuning.data;

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Detection Tuning</div>
        <h1 className="mt-2 text-3xl font-black">Convert SOC feedback into lower-noise detections.</h1>
        <p className="mt-2 text-muted">Alert pressure, false-positive learning, suppression candidates, ML baseline health, and ownership gaps.</p>
      </section>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Alert Pressure" value={data?.summary.alerts_per_1000_logs ?? "-"} detail="Alerts per 1,000 logs" tone="amber" />
        <MetricCard label="High/Critical" value={data?.summary.high_critical_open ?? "-"} detail="Active priority queue" tone="danger" />
        <MetricCard label="Unassigned Priority" value={data?.summary.high_critical_unassigned ?? "-"} detail="Needs owner" tone="amber" />
        <MetricCard label="ML Anomaly Rate" value={`${data?.ml.current_anomaly_rate ?? "-"}%`} detail="Assistive signal" tone="cyan" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_0.9fr]">
        <ChartCard title="Top Alert Types">
          {data?.alert_type_pressure?.length ? (
            <div className="h-80">
              <ResponsiveContainer>
                <BarChart data={data.alert_type_pressure.slice(0, 8)} layout="vertical" margin={{ left: 110 }}>
                  <CartesianGrid stroke="#263445" strokeDasharray="3 3" />
                  <XAxis type="number" stroke="#93a4b7" />
                  <YAxis type="category" dataKey="alert_type" stroke="#93a4b7" width={110} />
                  <Tooltip contentStyle={{ background: "#0f151d", border: "1px solid #263445", color: "#e5edf6" }} />
                  <Bar dataKey="count" fill="#ef4444" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState title="No tuning data" body="Run detection to populate alert pressure." />
          )}
        </ChartCard>
        <section className="panel">
          <div className="mb-4 text-sm font-extrabold uppercase tracking-wide text-muted">Operational Readiness</div>
          <div className="space-y-3">
            {(data?.production_readiness ?? []).map((item) => (
              <div key={item.name} className="rounded-lg border border-line bg-panel2 p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="font-bold">{item.name}</div>
                  <Badge value={item.status} />
                </div>
                <div className="mt-2 text-sm text-muted">{item.detail}</div>
                {item.recommendation ? <div className="mt-2 text-xs text-amber">{item.recommendation}</div> : null}
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="mb-4 text-sm font-extrabold uppercase tracking-wide text-muted">False Positive Learning</div>
        {data?.false_positive_learning.suppression_recommendations.length ? (
          <div className="grid gap-3 lg:grid-cols-3">
            {data.false_positive_learning.suppression_recommendations.slice(0, 3).map((item, index) => (
              <div key={index} className="rounded-lg border border-amber/30 bg-amber/10 p-4">
                <div className="text-sm font-bold text-amber">Candidate suppression</div>
                <pre className="mt-2 whitespace-pre-wrap text-xs text-muted">{JSON.stringify(item, null, 2)}</pre>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState title="Learning needs analyst feedback" body={data?.false_positive_learning.message ?? "Mark reviewed alerts as false positives to unlock recommendations."} />
        )}
      </section>
    </div>
  );
}
