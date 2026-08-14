import { ApiError } from "../lib/api";

export function ErrorBanner({ error, fallback = "Unable to load this data." }: { error: unknown; fallback?: string }) {
  const detail = error instanceof ApiError ? String(error.detail) : error instanceof Error ? error.message : fallback;
  return (
    <div role="alert" className="rounded-lg border border-danger/40 bg-danger/10 p-4 text-sm text-danger">
      <div className="font-extrabold">Request failed</div>
      <div className="mt-1 opacity-90">{detail || fallback}</div>
    </div>
  );
}
