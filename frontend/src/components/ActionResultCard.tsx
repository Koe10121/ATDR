import { useMemo, useState } from "react";

type Tone = "success" | "amber" | "danger" | "cyan";

interface ActionResultCardProps {
  title: string;
  result?: Record<string, unknown>;
  kind?: "import" | "detection" | "ml-train" | "ml-score" | "export" | "reset" | "generic";
}

function valueAt(payload: Record<string, unknown>, keys: string[]): unknown {
  for (const key of keys) {
    const parts = key.split(".");
    let current: unknown = payload;
    for (const part of parts) {
      if (current && typeof current === "object" && part in current) {
        current = (current as Record<string, unknown>)[part];
      } else {
        current = undefined;
        break;
      }
    }
    if (current !== undefined && current !== null && current !== "") {
      return current;
    }
  }
  return undefined;
}

function shortValue(value: unknown): string {
  if (value === undefined || value === null || value === "") return "-";
  if (typeof value === "string") {
    const normalized = value.replace(/\\/g, "/");
    if (normalized.length > 72) {
      const parts = normalized.split("/");
      return parts.length > 1 ? `.../${parts.slice(-2).join("/")}` : `${normalized.slice(0, 68)}...`;
    }
    return value;
  }
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function numberValue(value: unknown): number | null {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function buildSummary(result: Record<string, unknown>, kind: ActionResultCardProps["kind"]) {
  if (kind === "reset") {
    const nestedImport = valueAt(result, ["import"]);
    const nestedDetection = valueAt(result, ["detection"]);
    return [
      ["Reset status", "completed"],
      ["Raw logs imported", valueAt((nestedImport as Record<string, unknown>) ?? {}, ["raw_logs_imported", "imported"])],
      ["Parsed successfully", valueAt((nestedImport as Record<string, unknown>) ?? {}, ["parsed_successfully", "parsed"])],
      ["Alerts created", valueAt((nestedDetection as Record<string, unknown>) ?? {}, ["created_alerts", "alerts_created"])],
      ["Alerts deduplicated", valueAt((nestedDetection as Record<string, unknown>) ?? {}, ["deduplicated_alert_updates", "alerts_deduplicated"])],
      ["Users", valueAt(result, ["users.created", "users.status"])]
    ];
  }
  if (kind === "import") {
    return [
      ["Requested limit", valueAt(result, ["requested_limit", "limit"])],
      ["Available lines", valueAt(result, ["available_lines"])],
      ["Raw logs imported", valueAt(result, ["raw_logs_imported", "imported"])],
      ["Normalized logs", valueAt(result, ["normalized_logs_created", "parsed_successfully", "parsed"])],
      ["Parse failures", valueAt(result, ["parse_failures", "failed"])],
      ["Duplicate raw logs", valueAt(result, ["duplicate_raw_logs"])],
      ["Alerts created", valueAt(result, ["alerts_created"])],
      ["Alerts deduplicated", valueAt(result, ["alerts_deduplicated"])],
      ["Source", valueAt(result, ["source_label", "sample_file", "source"])]
    ];
  }
  if (kind === "detection") {
    return [
      ["Logs evaluated", valueAt(result, ["evaluated_logs", "logs_evaluated", "processed_logs"])],
      ["Alerts created", valueAt(result, ["created_alerts", "alerts_created"])],
      ["Alerts deduplicated", valueAt(result, ["deduplicated_alert_updates", "alerts_deduplicated"])],
      ["Alerts suppressed", valueAt(result, ["suppressed_alerts", "alerts_suppressed"])],
      ["Detection run", valueAt(result, ["detection_run_id", "run_id"])]
    ];
  }
  if (kind === "ml-train") {
    return [
      ["Status", valueAt(result, ["status", "trained"])],
      ["Trained", valueAt(result, ["trained"])],
      ["Training logs", valueAt(result, ["training_log_count", "training_rows", "scored_log_count"])],
      ["Contamination", valueAt(result, ["contamination"])],
      ["Model type", valueAt(result, ["model_type", "model_name", "algorithm"])],
      ["Model path", valueAt(result, ["model_path", "path"])],
      ["Feature count", Array.isArray(result.feature_columns) ? result.feature_columns.length : valueAt(result, ["feature_count"])]
    ];
  }
  if (kind === "ml-score") {
    return [
      ["Scored logs", valueAt(result, ["scored", "scored_log_count"])],
      ["Anomalies", valueAt(result, ["anomalies", "anomaly_count"])],
      ["Anomaly rate", valueAt(result, ["anomaly_rate"])],
      ["Model path", valueAt(result, ["model_path", "path"])]
    ];
  }
  if (kind === "export") {
    const files = valueAt(result, ["files"]);
    return [
      ["Export status", "completed"],
      ["Export directory", valueAt(result, ["export_dir"])],
      ["Files", files && typeof files === "object" ? Object.keys(files).length : valueAt(result, ["file_count"])],
      ["Total logs", valueAt(result, ["counts.total_logs"])],
      ["Total alerts", valueAt(result, ["counts.total_alerts"])]
    ];
  }
  return Object.entries(result)
    .filter(([, value]) => typeof value !== "object")
    .slice(0, 6)
    .map(([key, value]) => [key, value]);
}

function inferTone(result: Record<string, unknown>): Tone {
  const failed = numberValue(valueAt(result, ["failed", "parse_failures"]));
  const status = String(valueAt(result, ["status"]) ?? "").toLowerCase();
  if (status.includes("failed") || (failed ?? 0) > 0) return "amber";
  return "success";
}

export function ActionResultCard({ title, result, kind = "generic" }: ActionResultCardProps) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const detailText = useMemo(() => JSON.stringify(result ?? {}, null, 2), [result]);
  if (!result) return null;

  const tone = inferTone(result);
  const summary = buildSummary(result, kind).filter(([, value]) => value !== undefined && value !== null && value !== "");
  const safeSampleNote = shortValue(valueAt(result, ["safe_sample_note", "import.safe_sample_note"]));
  const hasSafeSampleNote = safeSampleNote !== "-";

  return (
    <article className={`action-result-card action-result-card-${tone}`} data-testid={`action-result-${kind}`}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="text-xs font-extrabold uppercase tracking-wide opacity-80">Action Result</div>
          <h3 className="mt-1 text-base font-black text-text">{title}</h3>
        </div>
        <span className="rounded-full border border-current px-2 py-1 text-[11px] font-black uppercase tracking-wide">
          {tone === "success" ? "complete" : "review"}
        </span>
      </div>

      {hasSafeSampleNote ? <div className="mt-3 rounded border border-amber/30 bg-amber/10 p-2 text-xs text-amber">{safeSampleNote}</div> : null}

      <div className="mt-3 grid gap-2 sm:grid-cols-2">
        {summary.map(([label, value]) => (
          <div key={String(label)} className="min-w-0 rounded border border-line/80 bg-shell/50 px-3 py-2">
            <div className="text-[11px] font-bold uppercase tracking-wide text-muted">{String(label)}</div>
            <div className="mt-1 break-words text-sm font-bold text-text">{shortValue(value)}</div>
          </div>
        ))}
      </div>

      <button className="mt-3 text-xs font-bold text-cyan underline" type="button" onClick={() => setDetailsOpen((value) => !value)}>
        {detailsOpen ? "Hide technical details" : "View technical details"}
      </button>
      {detailsOpen ? (
        <pre className="technical-json mt-3" data-testid="technical-details">
          {detailText}
        </pre>
      ) : null}
    </article>
  );
}
