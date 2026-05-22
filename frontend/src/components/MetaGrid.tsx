export function MetaGrid({ rows }: { rows: Array<{ label: string; value: unknown }> }) {
  return (
    <div className="grid gap-2 md:grid-cols-2">
      {rows.map((row) => (
        <div key={row.label} className="rounded-lg border border-line bg-panel2 p-3">
          <div className="text-xs font-extrabold uppercase tracking-wide text-muted">{row.label}</div>
          <div className="mt-1 break-words text-sm font-bold text-text">{row.value === null || row.value === undefined || row.value === "" ? "-" : String(row.value)}</div>
        </div>
      ))}
    </div>
  );
}
