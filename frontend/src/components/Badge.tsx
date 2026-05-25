import clsx from "clsx";

const severityClass: Record<string, string> = {
  Low: "border-success/30 bg-success/10 text-success",
  Medium: "border-amber/30 bg-amber/10 text-amber",
  High: "border-orange-400/30 bg-orange-400/10 text-orange-300",
  Critical: "border-danger/40 bg-danger/10 text-danger"
};

const statusClass: Record<string, string> = {
  open: "border-danger/40 bg-danger/10 text-danger",
  investigating: "border-amber/30 bg-amber/10 text-amber",
  contained: "border-cyan/30 bg-cyan/10 text-cyan",
  resolved: "border-success/30 bg-success/10 text-success",
  false_positive: "border-slate-400/30 bg-slate-400/10 text-slate-300",
  needs_more_context: "border-purple-300/30 bg-purple-300/10 text-purple-200",
  needs_owner: "border-amber/30 bg-amber/10 text-amber",
  ready: "border-success/30 bg-success/10 text-success",
  review: "border-amber/30 bg-amber/10 text-amber",
  available: "border-cyan/30 bg-cyan/10 text-cyan",
  blocked: "border-danger/40 bg-danger/10 text-danger"
};

export function Badge({ value, kind = "status" }: { value?: string | null; kind?: "severity" | "status" }) {
  const label = value || "unknown";
  const classes = kind === "severity" ? severityClass[label] : statusClass[label];
  const displayLabel = label === "open" ? "New" : label.replaceAll("_", " ");
  return (
    <span className={clsx("inline-flex rounded-full border px-2.5 py-1 text-xs font-bold uppercase tracking-wide", classes ?? "border-line bg-panel2 text-muted")}>
      {displayLabel}
    </span>
  );
}
