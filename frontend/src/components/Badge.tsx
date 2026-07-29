import clsx from "clsx";

const severityClass: Record<string, string> = {
  Low: "border-success/30 bg-success/10 text-success",
  Medium: "border-amber/30 bg-amber/10 text-amber",
  High: "border-orange-500/30 bg-orange-500/10 text-orange-700",
  Critical: "border-danger/40 bg-danger/10 text-danger"
};

const statusClass: Record<string, string> = {
  open: "border-danger/40 bg-danger/10 text-danger",
  investigating: "border-amber/30 bg-amber/10 text-amber",
  contained: "border-cyan/30 bg-cyan/10 text-cyan",
  resolved: "border-success/30 bg-success/10 text-success",
  false_positive: "border-slate-400/30 bg-slate-400/10 text-slate-600",
  needs_more_context: "border-purple-500/30 bg-purple-500/10 text-purple-700",
  needs_owner: "border-amber/30 bg-amber/10 text-amber",
  ready: "border-success/30 bg-success/10 text-success",
  review: "border-amber/30 bg-amber/10 text-amber",
  available: "border-cyan/30 bg-cyan/10 text-cyan",
  blocked: "border-danger/40 bg-danger/10 text-danger",
  local: "border-slate-400/30 bg-slate-400/10 text-slate-600",
  external: "border-cyan/30 bg-cyan/10 text-cyan",
  "Local login only": "border-slate-400/30 bg-slate-400/10 text-slate-600",
  "OIDC Ready": "border-cyan/30 bg-cyan/10 text-cyan",
  "Decision Support Only": "border-cyan/30 bg-cyan/10 text-cyan",
  "Response Automation Disabled": "border-amber/30 bg-amber/10 text-amber",
  "Not Production Promoted": "border-slate-400/30 bg-slate-400/10 text-slate-600",
  "Simulation Mode": "border-success/30 bg-success/10 text-success",
  "Manual Approval Required": "border-amber/30 bg-amber/10 text-amber",
  "Email Verified": "border-success/30 bg-success/10 text-success",
  "Email Unverified": "border-amber/30 bg-amber/10 text-amber",
  "No Email": "border-slate-400/30 bg-slate-400/10 text-slate-600",
  "analyst review eligible": "border-success/30 bg-success/10 text-success",
  "final controlled validation candidate": "border-success/30 bg-success/10 text-success",
  "Final Controlled Validation Candidate": "border-success/30 bg-success/10 text-success",
  "Not Production Ready": "border-slate-400/30 bg-slate-400/10 text-slate-600",
  trained: "border-success/30 bg-success/10 text-success",
  "needs labels": "border-amber/30 bg-amber/10 text-amber",
  "active artifact ready": "border-success/30 bg-success/10 text-success",
  "active decision-support artifact": "border-cyan/30 bg-cyan/10 text-cyan",
  "active metadata unavailable": "border-amber/30 bg-amber/10 text-amber",
  "no active artifact": "border-amber/30 bg-amber/10 text-amber",
  "Frozen Diagnostic Candidate": "border-cyan/30 bg-cyan/10 text-cyan",
  "Independent Evidence Available": "border-success/30 bg-success/10 text-success",
  "Independent Evidence Pending": "border-amber/30 bg-amber/10 text-amber",
  "Shadow Observation": "border-slate-400/30 bg-slate-400/10 text-slate-600",
  "Rules Authoritative": "border-cyan/30 bg-cyan/10 text-cyan",
  "Shadow Scoring Enabled": "border-success/30 bg-success/10 text-success",
  "Shadow Scoring Disabled": "border-slate-400/30 bg-slate-400/10 text-slate-600",
  "Candidate Contract Matched": "border-success/30 bg-success/10 text-success",
  "Candidate Contract Mismatched": "border-danger/40 bg-danger/10 text-danger"
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
