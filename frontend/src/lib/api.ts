import type {
  Alert,
  AlertNote,
  AlertReport,
  AlertStatus,
  AlertTimelineEvent,
  AuditLog,
  BlockedIP,
  DashboardSummary,
  DemoActionResult,
  DetectionTuningReport,
  HealthResponse,
  MLEvaluationReport,
  MLLabel,
  MLLabelImportResult,
  MLLabelPayload,
  MLReviewQueueItem,
  NormalizedLog,
  ResponseAction,
  SupervisedModelReport,
  Suppression,
  TokenResponse,
  User,
  WatchlistItem
} from "../types/api";
import { clearSession, loadSession } from "./session";

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(status: number, detail: unknown) {
    super(typeof detail === "string" ? detail : `API request failed with status ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

export type Params = Record<string, string | number | boolean | null | undefined>;
export interface PaginatedResult<T> {
  items: T[];
  totalCount: number;
}

function buildUrl(path: string, params?: Params): string {
  const url = new URL(`${API_BASE_URL}${path}`);
  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  });
  return url.toString();
}

export async function apiRequest<T>(path: string, options: RequestInit & { params?: Params } = {}): Promise<T> {
  const session = loadSession();
  const headers = new Headers(options.headers);
  if (!headers.has("Content-Type") && options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (session?.token) {
    headers.set("Authorization", `Bearer ${session.token}`);
  }

  const response = await fetch(buildUrl(path, options.params), { ...options, headers });
  if (response.status === 401) {
    clearSession();
    window.dispatchEvent(new Event("atdr:session-expired"));
  }
  if (!response.ok) {
    let detail: unknown = response.statusText;
    try {
      const payload = (await response.json()) as { detail?: unknown };
      detail = payload.detail ?? payload;
    } catch {
      detail = await response.text();
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export async function apiListRequest<T>(path: string, options: RequestInit & { params?: Params } = {}): Promise<PaginatedResult<T>> {
  const session = loadSession();
  const headers = new Headers(options.headers);
  if (session?.token) {
    headers.set("Authorization", `Bearer ${session.token}`);
  }
  const response = await fetch(buildUrl(path, options.params), { ...options, headers });
  if (response.status === 401) {
    clearSession();
    window.dispatchEvent(new Event("atdr:session-expired"));
  }
  if (!response.ok) {
    let detail: unknown = response.statusText;
    try {
      const payload = (await response.json()) as { detail?: unknown };
      detail = payload.detail ?? payload;
    } catch {
      detail = await response.text();
    }
    throw new ApiError(response.status, detail);
  }
  const items = (await response.json()) as T[];
  const totalCount = Number(response.headers.get("X-Total-Count") ?? items.length);
  return { items, totalCount: Number.isFinite(totalCount) ? totalCount : items.length };
}

export async function apiDownload(path: string, params?: Params): Promise<{ blob: Blob; filename: string }> {
  const session = loadSession();
  const headers = new Headers();
  if (session?.token) {
    headers.set("Authorization", `Bearer ${session.token}`);
  }
  const response = await fetch(buildUrl(path, params), { headers });
  if (response.status === 401) {
    clearSession();
    window.dispatchEvent(new Event("atdr:session-expired"));
  }
  if (!response.ok) {
    throw new ApiError(response.status, await response.text());
  }
  const disposition = response.headers.get("content-disposition") ?? "";
  const match = disposition.match(/filename="?(?<filename>[^";]+)"?/);
  return { blob: await response.blob(), filename: match?.groups?.filename ?? "atdr-export" };
}

export const api = {
  health: () => apiRequest<HealthResponse>("/health"),
  login: (username: string, password: string) =>
    apiRequest<TokenResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    }),
  me: () => apiRequest<User>("/api/auth/me"),
  dashboardSummary: () => apiRequest<DashboardSummary>("/api/dashboard/summary"),
  alerts: (params: Params = {}) => apiRequest<Alert[]>("/api/alerts", { params }),
  alertsPage: (params: Params = {}) => apiListRequest<Alert>("/api/alerts", { params }),
  alert: (id: number) => apiRequest<Alert>(`/api/alerts/${id}`),
  assignAlertToMe: (id: number) => apiRequest<Alert>(`/api/alerts/${id}/assign/me`, { method: "POST" }),
  addAlertNote: (id: number, note: string) =>
    apiRequest<AlertNote>(`/api/alerts/${id}/notes`, { method: "POST", body: JSON.stringify({ note }) }),
  alertNotes: (id: number) => apiRequest<AlertNote[]>(`/api/alerts/${id}/notes`),
  alertTimeline: (id: number) => apiRequest<AlertTimelineEvent[]>(`/api/alerts/${id}/timeline`),
  alertReport: (id: number) => apiRequest<AlertReport>(`/api/alerts/${id}/report`),
  downloadAlertReport: (id: number, format: "csv" | "html" | "pdf") => apiDownload(`/api/alerts/${id}/report`, { format }),
  updateAlertStatus: (id: number, status: AlertStatus) =>
    apiRequest<{ id: number; status: string; updated_at: string }>(`/api/alerts/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status })
    }),
  logs: (params: Params = {}) => apiRequest<NormalizedLog[]>("/api/logs", { params }),
  logsPage: (params: Params = {}) => apiListRequest<NormalizedLog>("/api/logs", { params }),
  log: (id: number) => apiRequest<NormalizedLog>(`/api/logs/${id}`),
  audit: (params: Params = {}) => apiRequest<AuditLog[]>("/api/audit", { params }),
  auditPage: (params: Params = {}) => apiListRequest<AuditLog>("/api/audit", { params }),
  detectionTuning: () => apiRequest<DetectionTuningReport>("/api/detection/tuning"),
  mlReport: () => apiRequest<MLEvaluationReport>("/api/ml/report"),
  supervisedReport: () => apiRequest<SupervisedModelReport>("/api/ml/supervised/report"),
  downloadSupervisedReport: () => apiDownload("/api/ml/supervised/report/export"),
  mlLabels: (params: Params = {}) => apiRequest<MLLabel[]>("/api/ml/labels", { params }),
  createMlLabel: (payload: MLLabelPayload) => apiRequest<MLLabel>("/api/ml/labels", { method: "POST", body: JSON.stringify(payload) }),
  updateMlLabel: (id: number, payload: Partial<MLLabelPayload>) =>
    apiRequest<MLLabel>(`/api/ml/labels/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
  mlReviewQueue: (params: Params = {}) => apiRequest<MLReviewQueueItem[]>("/api/ml/review-queue", { params }),
  downloadMlLabels: () => apiDownload("/api/ml/labels/export"),
  downloadMlLabelTemplate: () => apiDownload("/api/ml/labels/template"),
  downloadMlLabelReviewSample: () => apiDownload("/api/ml/labels/review-sample/export"),
  downloadMlReviewQueue: (params: Params = {}) => apiDownload("/api/ml/review-queue/export", params),
  importMlLabels: (file: File, params: Params = {}) => {
    const form = new FormData();
    form.append("upload", file);
    return apiRequest<MLLabelImportResult>("/api/ml/labels/import", { method: "POST", body: form, params });
  },
  suppressions: (params: Params = {}) => apiRequest<Suppression[]>("/api/suppressions", { params }),
  createSuppression: (payload: { src_ip?: string; app?: string; alert_type?: string; reason: string }) =>
    apiRequest<Suppression>("/api/suppressions", { method: "POST", body: JSON.stringify(payload) }),
  disableSuppression: (id: number) => apiRequest<Suppression>(`/api/suppressions/${id}/disable`, { method: "POST" }),
  reviewSuppression: (id: number, review_status: string, review_notes?: string) =>
    apiRequest<Suppression>(`/api/suppressions/${id}/review`, {
      method: "POST",
      body: JSON.stringify({ review_status, review_notes })
    }),
  watchlists: (params: Params = {}) => apiRequest<WatchlistItem[]>("/api/watchlists", { params }),
  createWatchlist: (payload: { indicator_type: string; indicator_value: string; description: string; severity_boost: number }) =>
    apiRequest<WatchlistItem>("/api/watchlists", { method: "POST", body: JSON.stringify(payload) }),
  disableWatchlist: (id: number) => apiRequest<WatchlistItem>(`/api/watchlists/${id}/disable`, { method: "POST" }),
  blockedIps: () => apiRequest<BlockedIP[]>("/api/response/blocked-ips"),
  blockIp: (targetIp: string, reason: string, alertId?: number | null) =>
    apiRequest<ResponseAction>("/api/response/block-ip", {
      method: "POST",
      body: JSON.stringify({ target_ip: targetIp, reason, alert_id: alertId ?? null })
    }),
  unblockIp: (targetIp: string, reason: string) =>
    apiRequest<ResponseAction>("/api/response/unblock-ip", {
      method: "POST",
      body: JSON.stringify({ target_ip: targetIp, reason })
    }),
  users: () => apiRequest<User[]>("/api/users"),
  createUser: (payload: { username: string; password: string; role: string; full_name?: string }) =>
    apiRequest<User>("/api/users", { method: "POST", body: JSON.stringify(payload) }),
  disableUser: (id: number) => apiRequest<User>(`/api/users/${id}/disable`, { method: "POST" }),
  resetPassword: (id: number, new_password: string) =>
    apiRequest<User>(`/api/users/${id}/reset-password`, { method: "POST", body: JSON.stringify({ new_password }) }),
  changeUserRole: (id: number, role: string) =>
    apiRequest<User>(`/api/users/${id}/role`, { method: "POST", body: JSON.stringify({ role }) }),
  demoReset: (payload: { limit?: number | null; use_ml?: boolean; sample_path?: string | null }) =>
    apiRequest<DemoActionResult>("/api/demo/reset", { method: "POST", body: JSON.stringify(payload) }),
  demoImportSample: (payload: { limit?: number | null; sample_path?: string | null }) =>
    apiRequest<DemoActionResult>("/api/demo/import-sample", { method: "POST", body: JSON.stringify(payload) }),
  demoRunDetection: (payload: { limit?: number | null; use_ml?: boolean }) =>
    apiRequest<DemoActionResult>("/api/demo/run-detection", { method: "POST", body: JSON.stringify(payload) }),
  demoTrainMl: (payload: { limit?: number | null }) =>
    apiRequest<DemoActionResult>("/api/demo/train-ml", { method: "POST", body: JSON.stringify(payload) }),
  demoApplyMl: (payload: { limit?: number | null }) =>
    apiRequest<DemoActionResult>("/api/demo/apply-ml", { method: "POST", body: JSON.stringify(payload) }),
  demoExportBundle: (payload: { alert_id?: number | null; top_alert_limit?: number; audit_limit?: number }) =>
    apiRequest<DemoActionResult>("/api/demo/export-bundle", { method: "POST", body: JSON.stringify(payload) })
};
