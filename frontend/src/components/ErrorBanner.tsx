import { ApiError } from "../lib/api";

interface ValidationErrorItem {
  loc?: unknown;
  msg?: unknown;
}

function isValidationErrorList(detail: unknown): detail is ValidationErrorItem[] {
  return (
    Array.isArray(detail) &&
    detail.length > 0 &&
    detail.every((item) => typeof item === "object" && item !== null && "msg" in item)
  );
}

// FastAPI/Pydantic 422 responses send `detail` as an array of
// {loc, msg, type} objects rather than a string. String(detail) on that
// shape renders as "[object Object],[object Object]" -- format it into
// readable text instead.
function formatDetail(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (isValidationErrorList(detail)) {
    return detail
      .map((item) => {
        const loc = Array.isArray(item.loc) ? item.loc.filter((part) => part !== "body").join(".") : "";
        const msg = String(item.msg ?? "Invalid value");
        return loc ? `${loc}: ${msg}` : msg;
      })
      .join("; ");
  }
  return String(detail);
}

export function ErrorBanner({ error, fallback = "Unable to load this data." }: { error: unknown; fallback?: string }) {
  const detail = error instanceof ApiError ? formatDetail(error.detail) : error instanceof Error ? error.message : fallback;
  return (
    <div role="alert" className="rounded-lg border border-danger/40 bg-danger/10 p-4 text-sm text-danger">
      <div className="font-extrabold">Request failed</div>
      <div className="mt-1 opacity-90">{detail || fallback}</div>
    </div>
  );
}
