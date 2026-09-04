export function LoadingPanel({ label = "Loading data..." }: { label?: string }) {
  return (
    <div className="panel animate-pulse" role="status" aria-live="polite" aria-busy="true">
      <div aria-hidden="true">
        <div className="h-3 w-32 rounded bg-line" />
        <div className="mt-4 h-8 w-2/3 rounded bg-line/70" />
        <div className="mt-3 h-3 w-full rounded bg-line/50" />
        <div className="mt-2 h-3 w-5/6 rounded bg-line/50" />
      </div>
      <span className="sr-only">{label}</span>
    </div>
  );
}
