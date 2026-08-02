import { Badge } from "./Badge";
import { MetricCard } from "./MetricCard";
import type { MLEvidenceMetricRange, MLEvidenceSnapshot } from "../types/api";

interface MLEvidenceSnapshotPanelProps {
  snapshot?: MLEvidenceSnapshot;
  loading: boolean;
  error: boolean;
}

function rangeText(range?: MLEvidenceMetricRange) {
  if (!range || range.min == null || range.max == null) return "-";
  return `${range.min.toFixed(4)}-${range.max.toFixed(4)}`;
}

function displayDate(value?: string) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function MLEvidenceSnapshotPanel({ snapshot, loading, error }: MLEvidenceSnapshotPanelProps) {
  const evidence = snapshot?.canonical_evidence;
  const ranges = evidence?.metric_ranges;
  const isolation = snapshot?.operational_models.isolation_forest;
  const supervised = snapshot?.operational_models.active_supervised_artifact;
  const candidates = snapshot?.operational_models.diagnostic_candidates;
  const abstention = snapshot?.schema_aware_abstention;
  const abstentionRuntime = abstention?.runtime;

  return (
    <section className="panel" data-testid="ml-evidence-snapshot">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Canonical ML Evidence</div>
          <h2 className="mt-1 text-xl font-black">Controlled validation snapshot</h2>
          <div className="mt-1 text-sm text-muted">
            One versioned evidence source. Historical runs are not merged into these metrics.
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge value={evidence?.readiness_decision?.replaceAll("_", " ") ?? "not available"} />
          <Badge value="Decision Support Only" />
        </div>
      </div>

      {loading ? <div className="rounded border border-line bg-panel2 p-4 text-sm text-muted">Loading canonical evidence...</div> : null}
      {error ? (
        <div className="rounded border border-danger/30 bg-danger/10 p-4 text-sm text-danger">
          Canonical ML evidence could not be loaded. No historical metric fallback was used.
        </div>
      ) : null}
      {!loading && !error && evidence && !evidence.available ? (
        <div className="rounded border border-amber/30 bg-amber/10 p-4 text-sm text-amber">
          <div className="font-bold">Canonical evidence unavailable</div>
          <div className="mt-1">{evidence.reason}</div>
        </div>
      ) : null}

      {evidence?.available ? (
        <>
          <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
            <MetricCard label="Queue Precision" value={rangeText(ranges?.queue_precision)} detail="Range across evaluated splits" tone="teal" />
            <MetricCard label="Queue Recall" value={rangeText(ranges?.queue_recall)} detail="Range across evaluated splits" tone="cyan" />
            <MetricCard label="Queue F1" value={rangeText(ranges?.queue_f1)} detail="SOC review queue" tone="cyan" />
            <MetricCard label="Benign FPR" value={rangeText(ranges?.benign_like_false_positive_rate)} detail="Lower is better" tone="amber" />
            <MetricCard label="Suspicious Recall" value={rangeText(ranges?.suspicious_recall)} detail="Development evidence" tone="teal" />
            <MetricCard label="Malicious Recall" value={rangeText(ranges?.malicious_recall)} detail="Development evidence" tone="teal" />
          </div>

          <div className="mt-4 grid gap-3 lg:grid-cols-3">
            <div className="rounded border border-line bg-panel2 p-4 text-sm">
              <div className="font-extrabold uppercase text-muted">Evidence Provenance</div>
              <div className="mt-2 font-bold text-text">{evidence.dataset?.title ?? "Dataset not recorded"}</div>
              <div className="mt-1 text-muted">{evidence.dataset?.publisher}</div>
              <div className="mt-2 text-muted">Snapshot {evidence.snapshot_id} | {displayDate(evidence.generated_at)}</div>
            </div>
            <div className="rounded border border-line bg-panel2 p-4 text-sm">
              <div className="font-extrabold uppercase text-muted">Selected Diagnostic</div>
              <div className="mt-2 break-words font-bold text-text">{evidence.selected_strategy?.replaceAll("_", " ")}</div>
              <div className="mt-1 text-muted">{evidence.evaluated_splits ?? 0} development splits | not active</div>
              <div className="mt-2 text-muted">Worst split: {evidence.worst_split?.split_mode?.replaceAll("_", " ") ?? "not recorded"}</div>
            </div>
            <div className="rounded border border-amber/30 bg-amber/10 p-4 text-sm">
              <div className="font-extrabold uppercase text-amber">Calibration</div>
              <div className="mt-2 font-bold text-text">{evidence.calibration?.status ?? "unknown"}</div>
              <div className="mt-1 text-muted">ECE {evidence.calibration?.expected_calibration_error ?? "-"} | max gap {evidence.calibration?.max_confidence_accuracy_gap ?? "-"}</div>
              <div className="mt-2 text-muted">{evidence.calibration?.passed ? "Calibration gate passed." : "Calibration gate remains open."}</div>
            </div>
          </div>
        </>
      ) : null}

      <div className="mt-4 border-t border-line pt-4">
        <div className="mb-3 text-xs font-extrabold uppercase text-muted">Operational Model States</div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="IsolationForest"
            value={isolation?.artifact_exists ? "Assistive signal active" : "Artifact missing"}
            detail={`${isolation?.anomaly_rate_percent ?? "-"}% current anomaly rate`}
            tone="teal"
          />
          <MetricCard
            label="Supervised Artifact"
            value={supervised?.metadata_unknown ? "Metadata unknown" : supervised?.model_type ?? "Not available"}
            detail={supervised?.metadata_unknown ? "Legacy or unregistered artifact" : "Active artifact metadata"}
            tone="amber"
          />
          <MetricCard
            label="Diagnostic Candidate"
            value={evidence?.selected_strategy?.replaceAll("_", " ") ?? candidates?.latest_candidate?.model_type ?? "Not available"}
            detail="Not activated or production promoted"
            tone="cyan"
          />
          <div data-testid="schema-aware-abstention">
            <MetricCard
              label="Schema Gate"
              value={abstention?.fail_closed ? "Fail closed" : "Not available"}
              detail={`${abstentionRuntime?.abstained_count ?? 0} of ${abstentionRuntime?.rows_checked ?? 0} runtime rows abstained`}
              tone={Number(abstentionRuntime?.abstained_count ?? 0) ? "amber" : "teal"}
            />
          </div>
        </div>
      </div>

      {abstention ? (
        <details className="mt-4 rounded border border-line bg-panel2 p-3 text-sm">
          <summary className="cursor-pointer font-bold text-text">Schema compatibility policy</summary>
          <div className="mt-3 grid gap-2 text-muted md:grid-cols-2">
            <div>Expected evidence: {abstention.expected_schema_id.replaceAll("_", " ")}</div>
            <div>Incompatible evidence scored: {abstention.incompatible_evidence_scored ? "yes" : "no"}</div>
            <div>Required fields: {abstention.required_features.join(", ")}</div>
            <div>Rules remain authoritative: {abstention.rules_remain_authoritative ? "yes" : "no"}</div>
          </div>
        </details>
      ) : null}

      {evidence?.limitations?.length || supervised?.message ? (
        <details className="mt-4 rounded border border-line bg-panel2 p-3 text-sm">
          <summary className="cursor-pointer font-bold text-text">Provenance and limitations</summary>
          <div className="mt-3 space-y-2 text-muted">
            {supervised?.message ? <div>{supervised.message}</div> : null}
            {evidence?.limitations?.map((item) => <div key={item}>{item}</div>)}
          </div>
        </details>
      ) : null}
    </section>
  );
}
