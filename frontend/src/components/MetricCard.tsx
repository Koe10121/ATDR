import clsx from "clsx";

const toneClass: Record<string, string> = {
  teal: "border-l-teal",
  cyan: "border-l-cyan",
  amber: "border-l-amber",
  danger: "border-l-danger",
  success: "border-l-success",
  slate: "border-l-slate-400"
};

export function MetricCard({
  label,
  value,
  detail,
  tone = "teal"
}: {
  label: string;
  value: string | number;
  detail?: string;
  tone?: keyof typeof toneClass;
}) {
  return (
    <div className={clsx("panel min-h-28 border-l-4", toneClass[tone])}>
      <div className="text-xs font-extrabold uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-3 text-3xl font-black text-text">{value}</div>
      {detail ? <div className="mt-2 text-sm text-muted">{detail}</div> : null}
    </div>
  );
}
