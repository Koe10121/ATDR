export type Role = "admin" | "analyst";
export type Severity = "Low" | "Medium" | "High" | "Critical";
export type AlertStatus = "open" | "investigating" | "contained" | "resolved" | "false_positive" | "needs_more_context";

export interface User {
  id: number;
  username: string;
  email?: string | null;
  full_name?: string | null;
  role: Role;
  is_active: boolean;
  email_verified?: boolean;
  auth_provider?: "local" | "external" | string;
  external_subject?: string | null;
  last_login_at?: string | null;
  invited_at?: string | null;
  disabled_at?: string | null;
  created_at?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
  username: string;
  role: Role;
}

export interface OidcStatus {
  enabled: boolean;
  provider_name?: string | null;
  issuer_configured: boolean;
  client_configured: boolean;
  allowed_domains: string[];
  default_role: Role | string;
  mode: "local_login_only" | "external_oidc" | string;
  school_email_domains: string[];
  require_school_email: boolean;
  local_email_login_enabled: boolean;
  smtp_enabled: boolean;
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
  source_ids?: number[];
  source_names?: string[];
  sla: AlertSla;
  detection_summary?: DetectionSummary;
}

export interface AlertCase {
  case_id: string;
  title: string;
  related_alert_count: number;
  total_related_logs?: number;
  source_ips: string[];
  destination_ips: string[];
  attack_types: string[];
  severity: Severity | string;
  status: AlertStatus | string;
  assigned_analyst?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  top_destination_ports?: CountRow[];
  top_actions?: CountRow[];
  recommended_analyst_focus?: string | null;
  notes: string[];
}

export interface AttackMapping {
  attack_type: string;
  tactic: string;
  technique: string;
  technique_id: string;
  description: string;
}

export interface DetectionSummary {
  detection_source: string[];
  attack_type: string;
  attack_mapping: AttackMapping;
  matched_rule_names: string[];
  anomaly: Record<string, unknown>;
  supervised: Record<string, unknown>;
  hybrid_risk: Record<string, unknown>;
  behavior_window: Record<string, unknown>;
  top_evidence_points: string[];
  why_flagged: string;
}

export interface NormalizedLog {
  id: number;
  raw_log_id: number;
  source_id?: number | null;
  source_name?: string | null;
  source_type?: string | null;
  parser_profile?: string | null;
  receive_time?: string | null;
  generated_time?: string | null;
  log_type?: string | null;
  subtype?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  app?: string | null;
  src_zone?: string | null;
  dst_zone?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  action?: string | null;
  bytes?: number | null;
  packets?: number | null;
  src_country?: string | null;
  dst_country?: string | null;
  app_risk?: number | null;
  app_characteristic?: string | null;
  is_anomaly: boolean;
  anomaly_score?: number | null;
  parsed_json: Record<string, unknown>;
  raw_line?: string | null;
  alert_ids?: number[];
}

export interface SourceHealth {
  source_id: number;
  status: "healthy" | "idle" | "warning" | "error" | "disabled" | string;
  enabled: boolean;
  logs_received_count: number;
  parse_success_count: number;
  parse_failure_count: number;
  parse_success_rate: number;
  last_seen?: string | null;
  last_log_received_at?: string | null;
  latest_error?: string | null;
  recommendation: string;
  warnings?: string[];
}

export interface SourceQuality {
  raw_logs: number;
  normalized_logs: number;
  unknown_app_count: number;
  unknown_app_rate: number;
  alert_count: number;
  parse_failure_examples: Array<Record<string, unknown>>;
  warnings?: string[];
}

export interface LogSource {
  source_id: number;
  name: string;
  source_type: string;
  parser_profile: string;
  host?: string | null;
  port?: number | null;
  enabled: boolean;
  last_seen?: string | null;
  last_log_received_at?: string | null;
  logs_received_count: number;
  parse_success_count: number;
  parse_failure_count: number;
  latest_error?: string | null;
  created_at: string;
  updated_at: string;
  health: SourceHealth;
  quality?: SourceQuality | null;
  recent_ingestion_runs?: IngestionRun[];
  recent_detection_runs?: DetectionRun[];
}

export type MLLabelValue = "benign" | "benign_unusual" | "suspicious" | "malicious" | "needs_context";
export type MLAttackType =
  | "normal"
  | "port_scan"
  | "brute_force"
  | "dos_ddos"
  | "malware_c2"
  | "policy_violation"
  | "data_exfiltration_suspicion"
  | "unknown_anomaly";

export interface MLLabel {
  id: number;
  log_id: number;
  label: MLLabelValue | string;
  attack_type: MLAttackType | string;
  confidence: number;
  reviewer: string;
  label_source?: string;
  reviewed?: boolean;
  review_note?: string | null;
  created_at: string;
}

export interface MLLabelPayload {
  log_id: number;
  label: MLLabelValue;
  attack_type: MLAttackType;
  confidence: number;
  review_note?: string | null;
  label_source?: string;
  reviewed?: boolean;
}

export interface MLLabelImportResult {
  created: number;
  updated: number;
  skipped?: number;
  protected_manual?: number;
  protected_reviewed?: number;
  changed_decisions?: number;
  failed: number;
  error_summary?: Record<string, number>;
  errors: Array<Record<string, unknown>>;
}

export interface MLReviewQueueItem {
  log_id: number;
  generated_time?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  app?: string | null;
  action?: string | null;
  protocol?: string | null;
  src_zone?: string | null;
  dst_zone?: string | null;
  app_risk?: number | null;
  is_anomaly: boolean;
  anomaly_score?: number | null;
  rule_score: number;
  supervised_prediction?: string | null;
  malicious_probability: number;
  hybrid_risk_score: number;
  priority_score: number;
  priority_reasons: string[];
  existing_label?: MLLabel | null;
  alert_ids: number[];
}

export interface AuditLog {
  id: number;
  actor: string;
  action: string;
  target_type: string;
  target_value: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface Suppression {
  id: number;
  src_ip?: string | null;
  app?: string | null;
  alert_type?: string | null;
  reason: string;
  active: boolean;
  suppressed_count: number;
  last_matched_at?: string | null;
  created_by: string;
  created_at: string;
  review_status: string;
  review_notes?: string | null;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  disabled_by?: string | null;
  disabled_at?: string | null;
}

export interface WatchlistItem {
  id: number;
  indicator_type: "src_ip" | "dst_ip" | "app" | string;
  indicator_value: string;
  description: string;
  severity_boost: number;
  active: boolean;
  match_count: number;
  last_matched_at?: string | null;
  created_by: string;
  created_at: string;
  disabled_by?: string | null;
  disabled_at?: string | null;
}

export interface AlertNote {
  id: number;
  alert_id: number;
  author: string;
  note: string;
  created_at: string;
}

export interface AlertTimelineEvent {
  event_time: string;
  event_type: string;
  actor: string;
  summary: string;
  details: Record<string, unknown>;
}

export interface AlertReport {
  alert: Record<string, unknown>;
  matched_rules: Array<Record<string, unknown>>;
  detection_summary?: DetectionSummary;
  evidence_logs: Array<Record<string, unknown>>;
  timeline: AlertTimelineEvent[];
  notes: AlertNote[];
  response_actions: Array<Record<string, unknown>>;
  generated_by?: string;
  executive_summary?: string;
  risk_assessment?: string;
  recommended_next_steps?: string[];
  sla?: Record<string, unknown>;
}

export interface DemoActionResult {
  [key: string]: unknown;
}

export interface DashboardSummary {
  total_logs: number;
  total_raw_logs?: number;
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
  ingestion_stats?: {
    latest_raw_log_time?: string | null;
    latest_normalized_log_time?: string | null;
    latest_detection_run_time?: string | null;
    import_count: number;
    parse_success_count: number;
    parse_failure_count: number;
    duplicate_raw_line_groups: number;
    deduplicated_alert_updates: number;
    alert_occurrence_count: number;
  };
  data_quality?: {
    missing_timestamp: number;
    missing_source_ip: number;
    missing_destination_ip: number;
    missing_action: number;
    unknown_app_count: number;
    parser_error_examples: Array<Record<string, unknown>>;
  };
  latest_ingestion_run?: IngestionRun | null;
  latest_detection_run?: DetectionRun | null;
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
  data_quality?: {
    total_imported_logs: number;
    parsed_successfully: number;
    parse_errors: number;
    parse_success_rate: number;
    missing_timestamp: number;
    missing_source_ip: number;
    missing_destination_ip: number;
    missing_action: number;
    unknown_app_count: number;
    duplicate_raw_line_groups: number;
    dataset_time_min?: string | null;
    dataset_time_max?: string | null;
    latest_ingestion_time?: string | null;
    parser_error_examples?: Array<Record<string, unknown>>;
  };
  scored_log_count: number;
  anomaly_count: number;
  anomaly_rate: number;
  recommendations: string[];
  drift_signals: Array<Record<string, unknown>>;
  baseline_drift_report?: {
    total_logs: number;
    unknown_app_count: number;
    unknown_app_rate: number;
    deny_drop_reset_count: number;
    deny_drop_reset_rate: number;
    anomaly_count: number;
    anomaly_rate: number;
    app_distribution: CountRow[];
    action_distribution: CountRow[];
    top_source_ips: CountRow[];
    top_destination_ports: CountRow[];
    top_destination_ips: CountRow[];
    run_comparison?: Record<string, unknown>;
    interpretation?: string;
  };
  top_anomalous_src_ips: CountRow[];
  top_anomalous_apps: CountRow[];
  top_anomalous_dst_ports: CountRow[];
}

export interface SupervisedModelReport {
  model_name: string;
  model_path: string;
  artifact_exists: boolean;
  artifact_sha256?: string | null;
  latest_run?: {
    id: number;
    model_version?: string | null;
    model_type?: string | null;
    status: string;
    actor: string;
    training_rows?: number | null;
    test_rows: number;
    metrics: Record<string, unknown>;
    evaluation?: Record<string, unknown>;
    label_distribution: Record<string, number>;
    label_source_distribution?: Record<string, number>;
    reviewed_label_distribution?: Record<string, number>;
    weak_label_distribution?: Record<string, number>;
    validation_warnings?: string[];
    promotion_gate?: Record<string, unknown>;
    model_readiness_checklist?: ModelReadinessChecklist;
    class_temporal_coverage?: ClassTemporalCoverageReport;
    split_strategy?: string;
    split_warnings?: string[];
    label_quality?: string;
    feature_generation?: Record<string, unknown>;
    training_dataset_diagnostics?: Record<string, unknown>;
    feature_set_metadata?: Record<string, unknown>;
    dataset_snapshot_id?: string | null;
    top_features: Array<Record<string, unknown>>;
    report_path?: string | null;
    created_at: string;
    message: string;
  } | null;
  label_count: number;
  label_distribution: Record<string, number>;
  label_source_distribution?: Record<string, number>;
  reviewed_label_distribution?: Record<string, number>;
  weak_label_distribution?: Record<string, number>;
  reviewed_label_count?: number;
  reviewed_label_target?: number;
  unreviewed_assisted_label_count?: number;
  validation_warnings?: string[];
  class_temporal_coverage?: ClassTemporalCoverageReport;
  model_readiness_checklist?: ModelReadinessChecklist;
  soc_triage_mode?: {
    recommended_ai_mode: string;
    primary_signal: string;
    flat_5_class_status: string;
    response_automation_allowed: boolean;
    production_promoted: boolean;
    limitations: string[];
    review_profiles: Array<Record<string, unknown>>;
  };
  decision_support_only: boolean;
}

export interface SupervisedModelRegistryItem {
  model_id: number;
  model_name: string;
  model_version?: string | null;
  model_type?: string | null;
  operation: string;
  status: string;
  created_at?: string | null;
  actor: string;
  model_path: string;
  artifact_sha256?: string | null;
  artifact_exists: boolean;
  is_active_path: boolean;
  feature_set_version?: string | null;
  dataset_snapshot_id?: string | null;
  split_strategy?: string | null;
  metrics?: Record<string, unknown>;
  readiness_decision?: string | null;
  analyst_review_eligible: boolean;
  production_promoted: boolean;
  response_automation_allowed: boolean;
  report_path?: string | null;
  message?: string | null;
}

export interface SupervisedModelRegistry {
  ok: boolean;
  active_model_path: string;
  active_artifact_exists: boolean;
  active_artifact_sha256?: string | null;
  models: SupervisedModelRegistryItem[];
  production_promoted: boolean;
  response_automation_allowed: boolean;
  decision_support_only: boolean;
}

export interface ModelReadinessItem {
  name: string;
  passed: boolean;
  detail: string;
  target?: string | null;
}

export interface ModelReadinessChecklist {
  status: string;
  passed: number;
  total: number;
  items: ModelReadinessItem[];
  message: string;
}

export interface ClassTemporalCoverageRow {
  label: string;
  total: number;
  reviewed_total: number;
  train_count: number;
  test_count: number;
  reviewed_train_count: number;
  reviewed_test_count: number;
  exists_in_train: boolean;
  exists_in_test: boolean;
  earliest_timestamp?: string | null;
  latest_timestamp?: string | null;
}

export interface ClassTemporalCoverageReport {
  test_size: number;
  total_labels: number;
  training_rows: number;
  test_rows: number;
  first_test_timestamp?: string | null;
  reviewed_label_target: number;
  malicious_training_minimum: number;
  malicious_training_better_target: number;
  reviewed_label_count: number;
  reviewed_malicious_count: number;
  reviewed_suspicious_count: number;
  malicious_train_count: number;
  malicious_test_count: number;
  suspicious_train_count: number;
  suspicious_test_count: number;
  class_coverage: Record<string, ClassTemporalCoverageRow>;
  warnings: string[];
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

export interface IngestionRun {
  run_id: number;
  started_at: string;
  finished_at?: string | null;
  source_type: string;
  input_name?: string | null;
  status: string;
  total_lines_received: number;
  raw_logs_created: number;
  parsed_successfully: number;
  parse_failures: number;
  duplicate_raw_logs: number;
  alerts_created: number;
  alerts_deduplicated: number;
  alerts_suppressed: number;
  runtime_seconds?: number | null;
  error_summary?: string | null;
  details: Record<string, unknown>;
}

export interface DetectionRun {
  run_id: number;
  started_at: string;
  finished_at?: string | null;
  detection_type: string;
  status: string;
  logs_evaluated: number;
  alerts_created: number;
  alerts_deduplicated: number;
  alerts_suppressed: number;
  top_attack_types: CountRow[];
  runtime_seconds?: number | null;
  error_summary?: string | null;
  details: Record<string, unknown>;
}
