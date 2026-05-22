export type Role = "admin" | "analyst";
export type Severity = "Low" | "Medium" | "High" | "Critical";
export type AlertStatus = "open" | "investigating" | "contained" | "resolved" | "false_positive";

export interface User {
  id: number;
  username: string;
  full_name?: string | null;
  role: Role;
  is_active: boolean;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
  username: string;
  role: Role;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
  checks: {
    database?: { status?: string; [key: string]: unknown };
    ml_model?: { status?: string; path?: string };
    response_mode?: { status?: string };
  };
}

export interface CountRow {
  name: string;
  count: number;
}

export interface AlertSla {
  label?: string;
  state?: string;
  due_at?: string;
  age_minutes?: number;
  minutes_remaining?: number;
  target_minutes?: number;
}

export interface Alert {
  id: number;
  title: string;
  alert_type: string;
  src_ip?: string | null;
  dst_ip?: string | null;
  threat_score: number;
  severity: Severity | string;
  status: AlertStatus | string;
  assigned_to?: string | null;
  priority_owner?: string | null;
  escalation_reason?: string | null;
  ticket_reference?: string | null;
  explanation: string;
  matched_rules_json: Array<Record<string, unknown>>;
  recommended_response: string;
  created_at: string;
  updated_at: string;
  evidence_count: number;
  evidence_log_ids: number[];
  sla: AlertSla;
}

export interface DashboardSummary {
  total_logs: number;
  total_alerts: number;
  active_alerts: number;
  critical_open_alerts: number;
  high_open_alerts: number;
  unassigned_active_alerts: number;
  false_positive_alerts: number;
  ml_anomaly_logs: number;
  anomaly_rate: number;
  active_suppressions: number;
  suppressed_hits: number;
  active_watchlist_items: number;
  watchlist_hits: number;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  top_alert_types: CountRow[];
  top_suspicious_source_ips: CountRow[];
  top_destination_countries: CountRow[];
  action_distribution: CountRow[];
  protocol_distribution: CountRow[];
  app_risk_distribution: CountRow[];
  recent_alerts: Alert[];
}

export interface TuningReadinessItem {
  name: string;
  status: string;
  detail: string;
  recommendation?: string | null;
}

export interface AlertTypePressure {
  alert_type: string;
  count: number;
  share_pct: number;
  high_or_critical_count: number;
  high_or_critical_rate: number;
  severity_counts: Record<string, number>;
  tuning_priority: string;
}

export interface FalsePositiveLearning {
  false_positive_count: number;
  top_false_positive_types: Array<Record<string, unknown>>;
  suppression_recommendations: Array<Record<string, unknown>>;
  learning_state: string;
  message: string;
}

export interface DetectionTuningReport {
  summary: {
    total_logs: number;
    total_alerts: number;
    active_alerts: number;
    alerts_per_1000_logs: number;
    high_critical_open: number;
    high_critical_unassigned: number;
    unassigned_active: number;
    false_positive_alerts: number;
    active_suppressions: number;
    active_watchlists: number;
  };
  alert_type_pressure: AlertTypePressure[];
  suppression_candidates: Array<Record<string, unknown>>;
  false_positive_learning: FalsePositiveLearning;
  severity_distribution: CountRow[];
  status_distribution: CountRow[];
  ml: {
    artifact_exists: boolean;
    latest_training_log_count?: number | null;
    latest_scored_log_count?: number | null;
    current_anomaly_rate: number;
    expected_contamination_rate: number;
    baseline_candidate_count?: number | null;
    high_risk_rate?: number | null;
    unknown_app_rate?: number | null;
    latest_runs: Array<Record<string, unknown>>;
  };
  production_readiness: TuningReadinessItem[];
  recommendations: string[];
}

export interface MLEvaluationReport {
  model_status: {
    artifact_exists: boolean;
    model_path: string;
    contamination: number;
    latest_training?: Record<string, unknown> | null;
    latest_scoring?: Record<string, unknown> | null;
    total_logs: number;
    current_anomaly_logs: number;
    current_anomaly_rate: number;
  };
  dataset_profile: {
    total_logs: number;
    baseline_candidate_count: number;
    high_risk_rate: number;
    unknown_app_rate: number;
    recommendations: string[];
  };
  scored_log_count: number;
  anomaly_count: number;
  anomaly_rate: number;
  recommendations: string[];
  drift_signals: Array<Record<string, unknown>>;
  top_anomalous_src_ips: CountRow[];
  top_anomalous_apps: CountRow[];
  top_anomalous_dst_ports: CountRow[];
}

export interface BlockedIP {
  id: number;
  ip_address: string;
  reason?: string | null;
  created_at: string;
  created_by: string;
  active: boolean;
}

export interface ResponseAction {
  id: number;
  alert_id?: number | null;
  action_type: string;
  target_ip: string;
  status: string;
  result_message: string;
  executed_by: string;
  executed_at: string;
}
