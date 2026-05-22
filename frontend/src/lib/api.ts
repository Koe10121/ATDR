import type {
  Alert,
  AlertStatus,
  BlockedIP,
  DashboardSummary,
  DetectionTuningReport,
  HealthResponse,
  MLEvaluationReport,
  ResponseAction,
  TokenResponse,
  User
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
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (session?.token) {
    headers.set("Authorization", `Bearer ${session.token}`);
  }

  const response = await fetch(buildUrl(path, options.params), { ...options, headers });
  if (response.status === 401) {
    clearSession();
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
  alert: (id: number) => apiRequest<Alert>(`/api/alerts/${id}`),
  updateAlertStatus: (id: number, status: AlertStatus) =>
    apiRequest<{ id: number; status: string; updated_at: string }>(`/api/alerts/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status })
    }),
  detectionTuning: () => apiRequest<DetectionTuningReport>("/api/detection/tuning"),
  mlReport: () => apiRequest<MLEvaluationReport>("/api/ml/report"),
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
    })
};
