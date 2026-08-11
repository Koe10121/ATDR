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

export interface MfuIamStatus {
  auth_mode: "template_shell" | "local_recovery" | string;
  local_login_enabled: boolean;
  template_shell_required: boolean;
  enabled: boolean;
  base_url_configured: boolean;
  client_id_configured: boolean;
  client_secret_configured: boolean;
  audience_configured: boolean;
  scope_configured: boolean;
  timeout_ms: number;
  token_path_configured: boolean;
  introspect_path_configured: boolean;
  profile_path_configured: boolean;
  admin_base_path_configured: boolean;
  admin_client_configured: boolean;
  admin_secret_configured: boolean;
  admin_audience_configured: boolean;
  admin_scope_configured: boolean;
  compat_profile_configured: boolean;
  allowed_domains: string[];
  domain_hints: string[];
  default_role: Role | string;
  mock_enabled: boolean;
  template_shell_enabled: boolean;
  template_shell_base_url_configured: boolean;
  template_shell_me_path: string;
  template_shell_header: string;
  template_shell_ready: boolean;
  handoff_enabled: boolean;
  handoff_secret_configured: boolean;
  handoff_exchange_path_configured: boolean;
  handoff_frontend_url_configured: boolean;
  handoff_allowed_origins_configured: boolean;
  handoff_allowed_return_paths: string[];
  handoff_cookie_secure: boolean;
  handoff_ready: boolean;
  template_shell_launch_url_configured: boolean;
  admin_group_mapping_configured: boolean;
  admin_email_mapping_configured: boolean;
  google_sso_enabled: boolean;
  google_client_id_configured: boolean;
  permission_source?: string | null;
  permission_bootstrap_mode?: string | null;
  permission_root_configured: boolean;
  permission_paths_count: number;
  project_account_email_configured: boolean;
  auth_require_2fa: boolean;
  audit_retention_days: number;
  managed_client_configured: boolean;
  managed_client_endpoint_configured: boolean;
  managed_client_owner_configured: boolean;
  managed_client_scopes_configured: boolean;
  managed_client_audiences_configured: boolean;
  init_admin_emails_configured: boolean;
  seed_admin_email_configured: boolean;
  b2b_ready: boolean;
  admin_api_ready: boolean;
  permission_bootstrap_ready: boolean;
  mode: "local_login_only" | "mfu_iam_mock" | "template_shell_secure_handoff" | "template_shell_handoff_incomplete" | "mfu_iam_b2b_token" | "mfu_iam_incomplete" | string;
  last_safe_validation_status: "not_run" | "passed" | "failed" | string;
  last_safe_validation_at: string | null;
  last_safe_validation_reason: string | null;
  secrets_exposed: boolean;
}

export interface MfuIamPublicStatus {
  auth_mode: "template_shell" | "local_recovery" | string;
  local_login_enabled: boolean;
  template_shell_required: boolean;
  enabled: boolean;
  b2b_ready: boolean;
  mock_enabled: boolean;
  template_shell_enabled: boolean;
  template_shell_ready: boolean;
  handoff_enabled: boolean;
  handoff_ready: boolean;
  template_shell_launch_url?: string | null;
  google_sso_enabled: boolean;
  google_client_id_configured: boolean;
  allowed_domains: string[];
  domain_hints: string[];
  default_role: Role | string;
  auth_require_2fa: boolean;
  mode: "local_login_only" | "mfu_iam_configured" | string;
  secrets_exposed: boolean;
}

export interface EmailVerificationStatus {
  notifications_enabled: boolean;
  verification_enabled: boolean;
  delivery_mode: "disabled" | "log_only" | "dev_outbox" | "smtp" | string;
  smtp_configured: boolean;
  smtp_enabled_legacy: boolean;
  from_email_configured: boolean;
  dev_outbox_available: boolean;
  code_ttl_minutes: number;
  code_length: number;
  verification_required_for_login: boolean;
  verification_required_for_admin_actions: boolean;
  school_email_domains: string[];
  require_school_email: boolean;
  local_email_login_enabled: boolean;
  secrets_exposed: boolean;
}

export interface EmailVerificationRequestResult {
  created: boolean;
  status: string;
  message: string;
  user_id?: number | null;
  email?: string | null;
  expires_at?: string | null;
  delivery_mode: string;
  delivery_status: string;
  outbox_id?: number | null;
}

export interface DevEmailOutboxItem {
  id: number;
  user_id?: number | null;
  recipient_email: string;
  subject: string;
  body_preview: string;
  purpose: string;
  delivery_mode: string;
  delivery_status: string;
  created_by?: string | null;
  created_at: string;
  sent_at?: string | null;
  error_summary?: string | null;
}

export interface AssistantChatRequest {
  question: string;
  alert_id?: number | null;
  log_id?: number | null;
  source_id?: number | null;
  case_id?: string | null;
  include_recent_context?: boolean;
  conversation_id?: string | null;
  reset_context?: boolean;
}

export interface AssistantActiveContext {
  alert_id?: number | null;
  log_id?: number | null;
  source_id?: number | null;
  case_id?: string | null;
  primary?: "alert" | "log" | "source" | "case" | null;
}

export interface AssistantCitation {
  label: string;
  source: string;
  reference_id?: string | null;
}

export type AssistantResponseMode =
  | "direct_fact"
  | "alert_explanation"
  | "safe_next_step"
  | "related_logs"
  | "source_health"
  | "list_summary"
  | "case_handoff"
  | "investigation_brief"
  | "how_to"
  | "governance";

export interface AssistantChatResponse {
  answer: string;
  mode: string;
  response_mode: AssistantResponseMode;
  external_provider_used: boolean;
  safety: string[];
  context_used: string[];
  citations: AssistantCitation[];
  redaction_applied: boolean;
  raw_log_context_included: boolean;
  suggested_followups: string[];
  details: Record<string, unknown>;
  conversation_id: string;
  active_context: AssistantActiveContext;
}

export type AssistantFeedbackRating = "helpful" | "not_helpful" | "unsafe" | "incorrect" | "unclear";

export interface AssistantFeedbackRequest {
  question: string;
  rating: AssistantFeedbackRating;
  answer?: string | null;
  feedback_note?: string | null;
  context_type?: string | null;
  context_reference?: string | null;
  external_provider_used?: boolean;
  raw_log_context_included?: boolean;
  action_requested?: boolean | null;
  assistant_audit_id?: number | null;
}

export interface AssistantFeedbackItem {
  feedback_id: number;
  created_at: string;
  actor_user_id?: number | null;
  actor_username: string;
  question: string;
  answer_summary?: string | null;
  answer_hash: string;
  context_type?: string | null;
  context_reference?: string | null;
  rating: string;
  feedback_note?: string | null;
  external_provider_used: boolean;
  raw_log_context_included: boolean;
  action_requested: boolean;
  action_executed: boolean;
  assistant_audit_id?: number | null;
  review_recommended?: boolean;
  review_reason?: string | null;
}

export interface AssistantFeedbackSummary {
  total_count: number;
  rating_counts: Record<string, number>;
  unsafe_or_incorrect_count: number;
  needs_review_count: number;
  external_provider_used_count: number;
  raw_log_context_included_count: number;
  action_requested_count: number;
  action_executed_count: number;
  latest_unsafe_or_incorrect: AssistantFeedbackItem[];
  recent: AssistantFeedbackItem[];
  scope: string;
  filtered_rating?: string | null;
  filtered_context_type?: string | null;
  filtered_since_days?: number | null;
  review_warning: boolean;
  secrets_exposed: boolean;
}

export interface AssistantHistoryItem {
  id: number;
  actor: string;
  question: string;
  created_at: string;
  context_used: string[];
  external_provider_used: boolean;
  conversation_id?: string | null;
  question_category?: string | null;
}

export interface AssistantStatusResponse {
  available: boolean;
  mode: string;
  external_provider_configured: boolean;
  external_provider_used_by_default: boolean;
  provider: string;
  model_configured: boolean;
  llm_enabled: boolean;
  llm_provider_configured: boolean;
  llm_provider_name: string;
  llm_ready: boolean;
  llm_model_configured: boolean;
  llm_secret_configured: boolean;
  llm_base_url_configured: boolean;
  llm_timeout_seconds: number;
  llm_max_retries: number;
  llm_max_prompt_chars: number;
  llm_max_output_tokens: number;
  llm_max_visible_chars: number;
  llm_circuit_breaker_failures: number;
  llm_circuit_breaker_cooldown_seconds: number;
  llm_operational: {
    status?: string;
    calls_attempted?: number;
    calls_succeeded?: number;
    calls_failed?: number;
    fallbacks?: number;
    guarded_fallbacks?: number;
    circuit_open?: boolean;
    circuit_open_count?: number;
    cooldown_remaining_seconds?: number;
    average_latency_ms?: number;
    token_usage?: { input_tokens?: number; output_tokens?: number; total_tokens?: number };
    estimated_cost_usd?: number;
    cost_rates_configured?: boolean;
    last_outcome?: string;
    secrets_exposed?: boolean;
  };
  conversation_history_turns: number;
  rate_limit_requests: number;
  rate_limit_window_seconds: number;
  llm_secrets_exposed: boolean;
  redaction_enabled: boolean;
  raw_log_context_allowed: boolean;
  max_context_rows: number;
  safety: string[];
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
  evidence_log_ids_truncated?: boolean;
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
  what_happened?: string;
  detection_source: string[];
  attack_type: string;
  attack_mapping: AttackMapping;
  normalized_fields_used?: Record<string, unknown>;
  rule_evidence?: string[];
  alert_authority?: {
    layer?: string;
    authoritative_rule_count?: number;
    authoritative_rule_names?: string[];
    anomaly_advisory_only?: boolean;
    supervised_decision_support_only?: boolean;
    hybrid_diagnostic_only?: boolean;
  };
  anomaly_evidence?: Record<string, unknown>;
  ml_evidence?: Record<string, unknown>;
  matched_rule_names: string[];
  anomaly: Record<string, unknown>;
  supervised: Record<string, unknown>;
  hybrid_risk: Record<string, unknown>;
  observed_evidence?: string[];
  rule_inferences?: string[];
  diagnostic_evidence?: string[];
  missing_context?: string[];
  evidence_confidence?: string;
  behavior_window: Record<string, unknown>;
  top_evidence_points: string[];
  why_flagged: string;
  why_suspicious?: string;
  analyst_next_steps?: string[];
  decision_support_only?: boolean;
  response_automation_allowed?: boolean;
  safety_note?: string;
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
  triage_explanation?: {
    status: "flagged" | "not_flagged" | string;
    summary: string;
    reasons: string[];
    why_flagged?: string | null;
    why_not_flagged?: string | null;
    normalized_fields_used?: Record<string, unknown>;
    normalized_signals: string[];
    rule_evidence?: string[];
    anomaly_evidence?: Record<string, unknown>;
    ml_evidence?: Record<string, unknown>;
    risk_score?: number | null;
    severity?: string | null;
    attack_mapping?: AttackMapping | null;
    evidence_strength?: string;
    missing_context?: string[];
    parser_warnings: string[];
    alert_ids: number[];
    decision_support_only: boolean;
    response_automation_allowed: boolean;
    safety_note?: string;
    analyst_next_steps: string[];
  };
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
  parser_quality_state: string;
  parser_contract_state: string;
  runtime_parser_error_count: number;
  runtime_parser_error_rate: number;
  structural_warning_count: number;
  unresolved_application_count: number;
  unresolved_application_rate: number;
  generic_syslog_count: number;
  raw_fallback_count: number;
  operational_alerts: ParserOperationalAlert[];
}

export interface ParserOperationalAlert {
  code: string;
  severity: "info" | "warning" | "error" | string;
  message: string;
}

export interface SourceQuality {
  raw_logs: number;
  normalized_logs: number;
  unknown_app_count: number;
  unknown_app_rate: number;
  alert_count: number;
  parse_failure_examples: Array<Record<string, unknown>>;
  warnings?: string[];
  parser_quality: Record<string, unknown>;
  parser_quality_state: string;
  parser_contract_state: string;
  runtime_observed_rows: number;
  legacy_contract_rows: number;
  parser_error_count: number;
  parser_error_rate: number;
  structural_warning_count: number;
  compatible_layout_count: number;
  extended_layout_count: number;
  partial_layout_count: number;
  unsupported_layout_count: number;
  unresolved_application_count: number;
  unresolved_application_rate: number;
  absent_application_count: number;
  not_applicable_application_count: number;
  generic_syslog_count: number;
  raw_fallback_count: number;
  operational_alerts: ParserOperationalAlert[];
}

export interface HistoricalReparseImpactPreview {
  version: string;
  status: "preview_complete" | "preview_sampled" | string;
  scope: "selected_source";
  preview_only: true;
  reparse_performed: false;
  database_mutated: false;
  total_rows: number;
  rows_scanned: number;
  coverage_complete: boolean;
  current_contract_metadata_rows: number;
  legacy_contract_rows_scanned: number;
  parser_profiles: Record<string, number>;
  parser_contract_versions: Record<string, number>;
  compatibility_statuses: Record<string, number>;
  application_resolution_statuses: Record<string, number>;
  raw_evidence_accessed: false;
  raw_logs_returned: false;
  private_paths_included: false;
  ip_addresses_included: false;
  source_identity_included: false;
  labels_accessed: false;
  alerts_created: 0;
  response_actions_created: 0;
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

export interface BenchmarkReviewImportResult {
  ok: boolean;
  status: string;
  benchmark_kind: string;
  input_name: string;
  imported: number;
  skipped: number;
  failed: number;
  decision_distribution: Record<string, number>;
  attack_type_distribution: Record<string, number>;
  artifact_name?: string | null;
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
  detection_operations?: {
    primary_rule_alert_volume: CountRow[];
    source_alert_volume: Array<CountRow & { source_id: number }>;
    analyst_dispositions: Record<string, number>;
    deduplication: {
      unique_alerts: number;
      total_occurrences: number;
      deduplicated_updates: number;
      occurrences_per_alert: number;
    };
    parser_warning_context: {
      status: "clear" | "limited_fields" | "warning";
      parse_failure_count: number;
      unknown_application_rows: number;
      message: string;
    };
    accuracy_evidence: {
      status: "insufficient_evidence";
      value: null;
      message: string;
    };
  };
}

export interface DashboardValidationSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  scenario_count?: number;
  passed_count?: number;
  failed_count?: number;
  failed_scenarios?: string[];
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  latest_risk_calibration_name?: string | null;
  validation_scope?: string | null;
  response_mode?: string | null;
  production_readiness_claim?: boolean;
  message?: string;
  generalization?: DashboardGeneralizationSummary;
  layered?: DashboardLayeredValidationSummary;
  e2e_workflow?: DashboardE2EWorkflowSummary;
  reliability?: DashboardReliabilitySummary;
  benchmark?: DashboardBenchmarkSummary;
  drift?: DashboardDriftSummary;
  v13_ai?: DashboardV13AiSummary;
  v14_ai?: DashboardV14AiSummary;
  v15_ai?: DashboardV15AiSummary;
  v16_ai?: DashboardV16AiSummary;
  v17_ai?: DashboardV17AiSummary;
  v18_ai?: DashboardV18AiSummary;
  v19_ai?: DashboardV19AiSummary;
  v19b_ai?: DashboardV19BAiSummary;
  v20_ai?: DashboardV20AiSummary;
  v330_detection_ml_quality?: DashboardV330DetectionMlQualitySummary;
  v355_soc_queue?: DashboardV355SocQueueSummary;
  v357_queue_evidence_agreement?: DashboardV357QueueEvidenceAgreementSummary;
  v359_supervised_output_policy?: DashboardV359SupervisedOutputPolicySummary;
  v30_production_readiness?: DashboardV30ProductionReadinessSummary;
}

export interface DetectionMlProductizationCheck {
  name: string;
  required: boolean;
  passed: boolean;
  value?: unknown;
}

export interface DetectionMlProductizationEvaluation {
  ok: boolean;
  phase: string;
  status: string;
  generated_at: string;
  read_only: boolean;
  readiness: {
    decision: string;
    required_checks_passed: number;
    required_checks_total: number;
    advisory_checks_passed: number;
    advisory_checks_total: number;
    blockers: string[];
    advisories: string[];
    production_ready: boolean;
    model_activation_allowed: boolean;
    response_automation_allowed: boolean;
  };
  checks: DetectionMlProductizationCheck[];
  rule_contract: {
    ok?: boolean;
    implemented_rule_count?: number;
    documented_rule_count?: number;
    scenario_count?: number;
    registered_scenario_count?: number;
    issues?: string[];
    [key: string]: unknown;
  };
  scenario_quality: {
    included?: boolean;
    status?: string;
    ok?: boolean;
    scenario_count?: number;
    passed_count?: number;
    false_positive_scenario_count?: number;
    false_negative_scenario_count?: number;
    response_actions_created?: number;
    recommendation?: string;
    [key: string]: unknown;
  };
  supervised_output_policy: {
    available?: boolean;
    status?: string;
    checks_passed?: number;
    checks_total?: number;
    recommended_supervised_strategy?: string | null;
    exact_classification_policy?: string | null;
    dashboard_guidance_ready?: boolean;
    runtime_activation_allowed?: boolean;
    response_automation_allowed?: boolean;
    blocked_uses?: string[];
    safety?: Record<string, unknown>;
    [key: string]: unknown;
  };
  training_target_contract: {
    available?: boolean;
    status?: string;
    checks_passed?: number;
    checks_total?: number;
    recommended_training_target?: string | null;
    exact_label_policy?: string | null;
    runtime_activation_allowed?: boolean;
    production_promotion_allowed?: boolean;
    response_automation_allowed?: boolean;
    quality_warnings?: string[];
    safety?: Record<string, unknown>;
    [key: string]: unknown;
  };
  training_data: {
    available?: boolean;
    mode?: string;
    total_label_rows?: number;
    trainable_label_rows?: number;
    trainable_log_count_estimate?: number;
    reviewed_label_rows?: number;
    weak_or_unreviewed_label_rows?: number;
    feature_generation_ran?: boolean;
    note?: string;
  };
  safety: {
    current_database_mutated: boolean;
    counts_before: Record<string, number>;
    counts_after: Record<string, number>;
    production_promoted: boolean;
    model_activated: boolean;
    model_artifact_written: boolean;
    labels_written: boolean;
    response_actions_created: number;
    response_automation_allowed: boolean;
    real_firewall_blocking_enabled: boolean;
    raw_logs_included: boolean;
  };
}

export interface DashboardGeneralizationSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  scenario_count?: number;
  variant_count?: number;
  passed_count?: number;
  failed_count?: number;
  false_positive_count?: number;
  false_negative_count?: number;
  failed_families?: string[];
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  validation_scope?: string | null;
  use_temp_db?: boolean;
  response_mode?: string | null;
  production_readiness_claim?: boolean;
  synthetic_variants_only?: boolean;
  message?: string;
}

export interface DashboardLayeredValidationModeSummary {
  mode: string;
  tests: number;
  passed_count: number;
  failed_count: number;
  false_positive_count: number;
  false_negative_count: number;
  rule_contribution_count: number;
  anomaly_contribution_count: number;
  supervised_contribution_count: number;
  hybrid_contribution_count: number;
}

export interface DashboardLayeredValidationSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  scenario_count?: number;
  variant_count?: number;
  mode_count?: number;
  mode_run_count?: number;
  passed_count?: number;
  failed_count?: number;
  false_positive_count?: number;
  false_negative_count?: number;
  mode_summary?: DashboardLayeredValidationModeSummary[];
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  validation_scope?: string | null;
  use_temp_db?: boolean;
  response_mode?: string | null;
  production_readiness_claim?: boolean;
  message?: string;
}

export interface DashboardE2EWorkflowSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  scenario_count?: number;
  passed_count?: number;
  failed_count?: number;
  simulate_response?: boolean;
  response_actions_created?: number;
  alert_count?: number;
  case_count?: number;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  validation_scope?: string | null;
  use_temp_db?: boolean;
  response_mode?: string | null;
  production_readiness_claim?: boolean;
  message?: string;
}

export interface DashboardReliabilitySummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  scenario_count?: number;
  scenario_passed_count?: number;
  variant_count?: number;
  variant_passed_count?: number;
  mode_run_count?: number;
  mode_passed_count?: number;
  e2e_scenario_count?: number;
  e2e_passed_count?: number;
  false_positive_count?: number;
  false_negative_count?: number;
  alert_volume?: number;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  validation_scope?: string | null;
  production_readiness_claim?: boolean;
  message?: string;
}

export interface DashboardBenchmarkSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  total_rows?: number;
  rows_mapped?: number;
  dataset_name?: string | null;
  snapshot_id?: string | null;
  detection_mode?: string | null;
  precision?: number | string | null;
  recall?: number | string | null;
  f1?: number | string | null;
  threat_positive_f1?: number | string | null;
  false_positive_count?: number;
  false_negative_count?: number;
  alert_volume?: number;
  readiness_decision?: string | null;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  validation_scope?: string | null;
  production_readiness_claim?: boolean;
  message?: string;
}

export interface DashboardV13AiSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  reviewed_label_count?: number;
  weak_label_count?: number;
  minimum_target_classes_met?: number;
  minimum_target_class_count?: number;
  minimum_label_gap?: number;
  best_candidate?: string | null;
  threat_positive_f1?: number | null;
  suspicious_recall?: number | null;
  malicious_recall?: number | null;
  readiness_decision?: string | null;
  production_status?: string | null;
  response_automation_allowed?: boolean;
  latest_audit_report_name?: string | null;
  latest_candidate_report_name?: string | null;
  message?: string;
}

export interface DashboardV14AiSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  best_strategy?: string | null;
  best_profile?: string | null;
  threat_positive_precision?: number | null;
  threat_positive_recall?: number | null;
  threat_positive_f1?: number | null;
  benign_like_false_positive_rate?: number | null;
  suspicious_recall?: number | null;
  malicious_recall?: number | null;
  calibration_status?: string | null;
  readiness_decision?: string | null;
  production_promoted?: boolean;
  response_automation_allowed?: boolean;
  false_positives_improved?: boolean;
  current_blocker?: string | null;
  quic_mitigation_status?: string | null;
  confirmed_noisy_pattern?: string | null;
  quic_false_positive_count?: number | null;
  actionable_review_rows?: number | null;
  actionable_review_excludes_manual?: boolean | null;
  malicious_recovery_review_rows?: number | null;
  latest_mitigation_report_name?: string | null;
  latest_recovery_report_name?: string | null;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  message?: string;
}

export interface DashboardV15AiSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  benchmark_label_count?: number;
  benchmark_target_met?: boolean;
  best_candidate?: string | null;
  best_profile?: string | null;
  threat_positive_f1?: number | null;
  threat_positive_recall?: number | null;
  benign_like_false_positive_rate?: number | null;
  suspicious_recall?: number | null;
  malicious_recall?: number | null;
  calibration_status?: string | null;
  readiness_decision?: string | null;
  checks_passed?: number;
  checks_total?: number;
  production_promoted?: boolean;
  model_activated?: boolean;
  response_automation_allowed?: boolean;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  message?: string;
}

export interface DashboardV16AiSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  external_label_count?: number;
  preferred_target_met?: boolean;
  source_count?: number;
  scenario_count?: number;
  candidate_name?: string | null;
  threat_positive_f1?: number | null;
  threat_positive_recall?: number | null;
  benign_like_false_positive_rate?: number | null;
  suspicious_recall?: number | null;
  malicious_recall?: number | null;
  calibration_status?: string | null;
  overfitting_status?: string | null;
  overfitting_warning?: boolean;
  threat_f1_gap?: number | null;
  readiness_decision?: string | null;
  checks_passed?: number;
  checks_total?: number;
  external_benchmark_validated?: boolean;
  production_promoted?: boolean;
  model_activated?: boolean;
  response_automation_allowed?: boolean;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  message?: string;
}

export interface DashboardV17AiSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  external_label_count?: number;
  best_profile?: string | null;
  threat_positive_precision?: number | null;
  threat_positive_recall?: number | null;
  threat_positive_f1?: number | null;
  benign_like_false_positive_rate?: number | null;
  suspicious_recall?: number | null;
  malicious_recall?: number | null;
  macro_f1?: number | null;
  calibration_status?: string | null;
  calibration_ece?: number | null;
  calibration_brier?: number | null;
  calibration_max_gap?: number | null;
  queue_size?: number;
  cost_sensitive_total?: number | null;
  overfitting_status?: string | null;
  overfitting_warning?: boolean;
  readiness_decision?: string | null;
  checks_passed?: number;
  checks_total?: number;
  external_benchmark_validated?: boolean;
  failed_checks?: Array<string | null | undefined>;
  review_sample_rows?: number;
  production_promoted?: boolean;
  model_activated?: boolean;
  response_automation_allowed?: boolean;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  message?: string;
}

export interface DashboardV18AiSummary extends DashboardV17AiSummary {
  weighted_f1?: number | null;
  calibration_method?: string | null;
  readiness_version?: string | null;
  baseline_false_negatives?: number;
  remaining_false_negatives?: number;
  recovered_false_negatives?: number;
  independent_revalidation_recommended?: boolean;
}

export interface DashboardV19AiSummary extends DashboardV18AiSummary {
  independent_label_count?: number;
  independent_source_count?: number;
  independent_scenario_count?: number;
  exact_overlap_rows?: number;
  generalization_status?: string | null;
  controlled_real_source_available?: boolean;
  controlled_real_source_validated?: boolean;
  independent_holdout_validated?: boolean;
  real_firewall_blocking_enabled?: boolean;
}

export interface DashboardV19BAiSummary extends DashboardV19AiSummary {
  fpr_blocker_resolved?: boolean;
  false_positives_reduced?: number;
  analyst_review_boundary_count?: number;
  minimum_false_positive_reduction_needed?: number;
}

export interface DashboardV20AiSummary extends DashboardV19BAiSummary {
  near_overlap_rows?: number;
  candidate_hash?: string | null;
  fresh_blind_revalidated?: boolean;
  final_controlled_validation_passed?: boolean;
  threshold_tuning_performed?: boolean;
}

export interface DashboardV330DetectionMlQualitySummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  split?: string | null;
  model_type?: string | null;
  class_weight?: string | null;
  training_rows?: number | null;
  test_rows?: number | null;
  baseline_profile?: string | null;
  baseline_threat_positive_precision?: number | null;
  baseline_threat_positive_recall?: number | null;
  baseline_threat_positive_f1?: number | null;
  baseline_benign_like_false_positive_rate?: number | null;
  baseline_suspicious_recall?: number | null;
  baseline_malicious_recall?: number | null;
  baseline_macro_f1?: number | null;
  baseline_weighted_f1?: number | null;
  best_profile?: string | null;
  best_threat_positive_precision?: number | null;
  best_threat_positive_recall?: number | null;
  best_threat_positive_f1?: number | null;
  best_benign_like_false_positive_rate?: number | null;
  best_suspicious_recall?: number | null;
  best_malicious_recall?: number | null;
  best_review_queue_size_estimate?: number | null;
  calibration_status?: string | null;
  calibration_ece?: number | null;
  calibration_brier?: number | null;
  calibration_max_gap?: number | null;
  error_buckets?: Record<string, number>;
  top_patterns?: Array<[string, number]>;
  signal_counts?: Record<string, number>;
  review_sample?: {
    generated?: boolean;
    rows?: number;
    path?: string;
  };
  readiness_decision?: string | null;
  checks_passed?: number;
  checks_total?: number;
  blockers?: string[];
  production_promoted?: boolean;
  model_activated?: boolean;
  response_automation_allowed?: boolean;
  real_firewall_blocking_enabled?: boolean;
  diagnostic_only?: boolean;
  latest_report_name?: string | null;
  message?: string;
}

export interface DashboardV355SocQueueSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  phase?: string | null;
  best_strategy?: string | null;
  policy_name?: string | null;
  policy_description?: string | null;
  recommended_use?: string | null;
  exact_severity_status?: string | null;
  evaluated_splits?: number;
  passing_splits?: number;
  split_stability_passed?: boolean;
  queue_f1_min?: number | null;
  queue_f1_max?: number | null;
  queue_recall_min?: number | null;
  queue_precision_min?: number | null;
  benign_like_false_positive_rate_max?: number | null;
  critical_recall_min?: number | null;
  macro_f1_min?: number | null;
  weighted_f1_min?: number | null;
  calibration_status?: string | null;
  calibration_ece?: number | null;
  calibration_brier?: number | null;
  calibration_max_gap?: number | null;
  threshold_selected_on?: string[];
  readiness_decision?: string | null;
  checks_passed?: number;
  checks_total?: number;
  blockers?: string[];
  production_promoted?: boolean;
  model_activated?: boolean;
  model_artifact_written?: boolean;
  labels_written?: boolean;
  response_automation_allowed?: boolean;
  diagnostic_only?: boolean;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  message?: string;
}

export interface DashboardV357QueueEvidenceAgreementSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  phase?: string | null;
  policy_name?: string | null;
  recommended_use?: string | null;
  evaluated_splits?: number;
  passing_splits?: number;
  queue_f1_min?: number | null;
  queue_recall_min?: number | null;
  queue_precision_min?: number | null;
  queue_false_positive_rate_max?: number | null;
  agreement_rate_min?: number | null;
  agreement_rate_max?: number | null;
  calibration_ece_max?: number | null;
  category_counts?: Record<string, number>;
  top_queue_only_patterns?: Array<[string, number]>;
  top_evidence_only_patterns?: Array<[string, number]>;
  aggregate_blockers?: string[];
  readiness_decision?: string | null;
  checks_passed?: number;
  checks_total?: number;
  blockers?: string[];
  production_promoted?: boolean;
  model_activated?: boolean;
  model_artifact_written?: boolean;
  labels_written?: boolean;
  raw_logs_included?: boolean;
  response_automation_allowed?: boolean;
  diagnostic_only?: boolean;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  message?: string;
}

export interface DashboardV359SupervisedOutputPolicySummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  phase?: string | null;
  decision?: string | null;
  contract_ready_for_runtime_activation?: boolean;
  contract_ready_for_dashboard_guidance?: boolean;
  recommended_supervised_strategy?: string | null;
  exact_classification_policy?: string | null;
  checks_passed?: number;
  checks_total?: number;
  blockers?: string[];
  queue_status?: string | null;
  queue_readiness_decision?: string | null;
  queue_evaluated_splits?: number;
  queue_passing_splits?: number;
  queue_f1_min?: number | null;
  queue_recall_min?: number | null;
  queue_precision_min?: number | null;
  queue_benign_like_false_positive_rate_max?: number | null;
  queue_calibration_status?: string | null;
  queue_calibration_ece?: number | null;
  agreement_status?: string | null;
  agreement_readiness_decision?: string | null;
  agreement_evaluated_splits?: number;
  agreement_passing_splits?: number;
  agreement_rate_min?: number | null;
  agreement_fpr_max?: number | null;
  exact_severity_status?: string | null;
  exact_stable_policy_count?: number;
  exact_evaluated_policy_count?: number;
  allowed_output_statuses?: Record<string, string | null | undefined>;
  blocked_uses?: string[];
  safety_statement?: string | null;
  production_promoted?: boolean;
  model_activated?: boolean;
  model_artifact_written?: boolean;
  labels_written?: boolean;
  raw_logs_included?: boolean;
  response_automation_allowed?: boolean;
  real_firewall_blocking_enabled?: boolean;
  diagnostic_only?: boolean;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  message?: string;
}

export interface DashboardV30ProductionReadinessSummary {
  available: boolean;
  status?: string;
  version?: string;
  checks_passed?: number;
  checks_total?: number;
  production_ready?: boolean;
  production_readiness_claim?: boolean;
  production_promoted?: boolean;
  model_activated?: boolean;
  response_automation_allowed?: boolean;
  real_firewall_blocking_enabled?: boolean;
  real_source_pilot_validated?: boolean;
  real_device_forwarding_validated?: boolean;
  simulated_source_pilot_status?: string;
  simulated_source_validated?: boolean;
  simulated_source?: {
    status?: string;
    simulated_source_validated?: boolean;
    real_device_forwarding_validated?: boolean;
    source_name?: string;
    source_health?: string;
    raw_logs?: number;
    normalized_logs?: number;
    parse_success_count?: number;
    parse_failure_count?: number;
    detection_runs?: number;
    message?: string;
  };
  postgres_lab_validated?: boolean;
  postgres_lab_status?: string;
  database_kind?: string;
  sqlite_local_workflow_valid?: boolean;
  backup_restore_validated?: boolean;
  backup_restore_status?: string;
  production_doctor_status?: string;
  production_doctor_blockers?: string[];
  production_doctor_warnings?: string[];
  docs?: Record<string, boolean>;
  message?: string;
}

export interface DashboardDriftSummary {
  available: boolean;
  ok?: boolean;
  generated_at?: string | null;
  recent_rows?: number;
  baseline_rows?: number;
  unknown_app_rate?: number | null;
  parse_failure_rate?: number | null;
  alert_rate?: number | null;
  warning_count?: number;
  latest_report_name?: string | null;
  latest_markdown_name?: string | null;
  validation_scope?: string | null;
  production_readiness_claim?: boolean;
  message?: string;
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
  active_artifact_metadata_status?: string | null;
  active_artifact_metadata_unknown?: boolean;
  display_model_type?: string | null;
  display_feature_set?: string | null;
  feature_set_version?: string | null;
  dataset_snapshot_id?: string | null;
  split_strategy?: string | null;
  metrics?: Record<string, unknown>;
  readiness_decision?: string | null;
  lifecycle_state?: string | null;
  target_mode?: string | null;
  calibration_method?: string | null;
  shadow_safety_passed?: boolean;
  decision_support_eligible?: boolean;
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
  active_artifact_metadata_status?: string | null;
  active_artifact_metadata_unknown?: boolean;
  lifecycle_state?: string;
  governed_lifecycle?: {
    lifecycle_state: string;
    configured_lifecycle_state?: string;
    model_run_id?: number | null;
    lifecycle_run_id?: number | null;
    model_version?: string | null;
    model_type?: string | null;
    target_mode?: string | null;
    feature_set_version?: string | null;
    dataset_fingerprint?: string | null;
    calibration_method?: string | null;
    calibration_status?: string;
    validation_status?: string;
    decision_support_eligible?: boolean;
    shadow_safety_passed?: boolean;
    threshold?: number | null;
    status_message?: string;
    telemetry?: Record<string, unknown>;
    durable_telemetry?: {
      available: boolean;
      snapshot_id?: number;
      recorded_at?: string;
      model_version?: string | null;
      telemetry?: Record<string, unknown>;
      drift_warnings?: string[];
      raw_logs_included?: boolean;
      private_identifiers_included?: boolean;
      response_actions_created?: number;
    };
    reliability_validation?: {
      available: boolean;
      version?: string;
      generated_at?: string;
      lifecycle_decision?: string;
      checks_passed?: number;
      checks_total?: number;
      blockers?: string[];
      selected_diagnostic_strategy?: string | null;
      selection_role?: string;
      candidate_selected?: boolean;
      governance_outcome?: string;
      eligible_for_activation?: boolean;
      strict_passing_splits?: number;
      required_splits?: number;
      evaluated_splits?: number;
      failed_closed_splits?: string[];
      calibration_ranges?: Record<string, { min?: number | null; max?: number | null; mean?: number | null }>;
      threshold_stability?: { minimum?: number | null; maximum?: number | null; range?: number | null };
      drift_warning_splits?: number;
      temporal_root_causes?: string[];
      temporal_fpr?: number | null;
      temporal_queue_rate?: number | null;
      threshold_window_queue_prevalence?: number | null;
      final_window_queue_prevalence?: number | null;
      ood_rate?: number | null;
      confidence_instability_rate?: number | null;
      abstention_rate_range?: { min?: number | null; max?: number | null; mean?: number | null; range?: number | null };
      coverage_rate_range?: { min?: number | null; max?: number | null; mean?: number | null; range?: number | null };
      missingness?: { fit_rate?: number | null; final_rate?: number | null };
      rolling_temporal?: { evaluated?: number; required?: number; failed_closed?: string[] };
      source_holdout_limitation?: string;
      layered_before?: Record<string, unknown>;
      layered_after?: Record<string, unknown>;
      external_benchmark_passed?: boolean;
      evidence_lock_status?: string;
      shadow_drift_status?: "Stable" | "Drift Warning" | "OOD Warning" | "Insufficient Evidence" | string;
      shadow_drift_findings?: string[];
      development_evidence_rows?: number;
      excluded_evidence_rows?: number;
      locked_temporal_final_rows?: number;
      quarantined_evidence_rows?: number;
      independent_labeled_evidence_sufficient?: boolean;
      v55_available?: boolean;
      v55_status?: string;
      v55_generated_at?: string;
      v55_lifecycle_state?: string;
      v55_development_leader?: string | null;
      v55_development_gates_passed?: boolean;
      v55_candidate_selected?: boolean;
      v55_model_activated?: boolean;
      v55_locked_queue_f1?: number | null;
      v55_locked_benign_fpr?: number | null;
      v55_locked_suspicious_recall?: number | null;
      v55_locked_malicious_recall?: number | null;
      v55_locked_calibration_status?: string | null;
      v55_isolation_benign_fpr?: number | null;
      v55_isolation_threat_detection_rate?: number | null;
      v55_blockers?: string[];
      v56_available?: boolean;
      v56_status?: string;
      v56_generated_at?: string;
      v56_lifecycle_state?: string;
      v56_private_rows_processed?: number | null;
      v56_overlap_rows_excluded?: number | null;
      v56_drift_status?: string | null;
      v56_assisted_training_rows?: number | null;
      v56_assisted_human_reviewed_rows?: number | null;
      v56_diagnostic_candidate?: string | null;
      v56_future_queue_f1?: number | null;
      v56_future_benign_fpr?: number | null;
      v56_future_suspicious_recall?: number | null;
      v56_future_malicious_recall?: number | null;
      v56_future_calibration_status?: string | null;
      v56_future_calibration_ece?: number | null;
      v56_isolation_future_fpr?: number | null;
      v56_isolation_future_threat_capture?: number | null;
      v56_candidate_activated?: boolean;
      v56_response_automation_allowed?: boolean;
      v56_independent_validation_claimed?: boolean;
      v56_blockers?: string[];
      v57_available?: boolean;
      v57_status?: string;
      v57_generated_at?: string;
      v57_lifecycle_state?: string;
      v57_frozen_candidate?: string | null;
      v57_candidate_model_type?: string | null;
      v57_candidate_calibration?: string | null;
      v57_candidate_threshold?: number | null;
      v57_evidence_status?: string;
      v57_evidence_qualified?: boolean;
      v57_source_device_count?: number | null;
      v57_independent_time_windows?: number | null;
      v57_prediction_freeze_status?: string;
      v57_blind_validation_status?: string;
      v57_blind_queue_f1?: number | null;
      v57_blind_benign_fpr?: number | null;
      v57_blind_suspicious_recall?: number | null;
      v57_blind_malicious_recall?: number | null;
      v57_blind_calibration_ece?: number | null;
      v57_blind_max_calibration_gap?: number | null;
      v57_isolation_status?: string;
      v57_isolation_benign_fpr?: number | null;
      v57_isolation_threat_capture?: number | null;
      v57_candidate_activated?: boolean;
      v57_rules_alert_authoritative?: boolean;
      v57_response_automation_allowed?: boolean;
      v57_blockers?: string[];
      rules_alert_authoritative?: boolean;
      production_promoted?: boolean;
      response_automation_allowed?: boolean;
    };
    governed_shadow_runtime?: {
      ok: boolean;
      version?: string;
      status: string;
      enabled: boolean;
      lifecycle_state: string;
      candidate_contract_matched: boolean;
      candidate_contract?: {
        status?: string;
        matched?: boolean;
        candidate_name?: string | null;
        model_type?: string | null;
        calibration_method?: string | null;
        threshold?: number | null;
        feature_count?: number | null;
        active?: boolean;
        production_promoted?: boolean;
        response_automation_allowed?: boolean;
        rules_alert_authoritative?: boolean;
        fallback_model_used?: boolean;
      };
      independent_evidence?: {
        status?: string;
        qualified?: boolean;
        source_device_count?: number | null;
        independent_time_window_count?: number | null;
        blind_validation_status?: string;
        blind_metrics_available?: boolean;
      };
      telemetry?: {
        rows_evaluated?: number;
        queue_count?: number;
        queue_rate?: number;
        score_summary?: Record<string, number | null>;
        confidence_summary?: Record<string, number | null>;
        drift?: {
          status?: string;
          rows_evaluated?: number;
          application_total_variation?: number | null;
          schema_total_variation?: number | null;
        };
        source_stability?: Record<string, number | boolean | null>;
        time_window_stability?: Record<string, number | boolean | null>;
        rule_shadow_agreement?: {
          both_queue?: number;
          rule_only?: number;
          shadow_only?: number;
          neither?: number;
          disagreement_count?: number;
          disagreement_rate?: number;
          rules_alert_authoritative?: boolean;
        };
        isolation_forest?: {
          advisory_only?: boolean;
          persisted_anomaly_count?: number;
          persisted_anomaly_rate?: number;
          new_isolation_scoring_performed?: boolean;
          alert_authority?: boolean;
        };
        accuracy_metrics_calculated?: boolean;
        labels_accessed?: boolean;
      };
      safety?: {
        configured_database_unchanged?: boolean;
        active_model_artifacts_unchanged?: boolean;
        frozen_candidate_artifact_unchanged?: boolean;
        alerts_created?: number;
        labels_created?: number;
        model_runs_created?: number;
        detection_runs_created?: number;
        response_actions_created?: number;
      };
      rules_alert_authoritative: boolean;
      model_activated: boolean;
      production_promoted: boolean;
      response_automation_allowed: boolean;
      fallback_model_used: boolean;
    };
    production_promoted: boolean;
    response_automation_allowed: boolean;
    rule_detection_authoritative: boolean;
  };
  legacy_artifact_exists?: boolean;
  legacy_artifact_selected?: boolean;
  models: SupervisedModelRegistryItem[];
  production_promoted: boolean;
  response_automation_allowed: boolean;
  decision_support_only: boolean;
}

export interface MLEvidenceMetricRange {
  min: number | null;
  max: number | null;
}

export interface ShadowObservation {
  observation_id: number;
  candidate_name: string;
  candidate_version: string;
  status: string;
  contract_matched: boolean;
  window_start: string | null;
  window_end: string | null;
  observed_start: string | null;
  observed_end: string | null;
  requested_limit: number;
  rows_evaluated: number;
  queue_count: number;
  queue_rate: number;
  score_mean: number | null;
  score_p95: number | null;
  confidence_mean: number | null;
  confidence_p95: number | null;
  drift_status: string;
  application_total_variation: number | null;
  schema_total_variation: number | null;
  disagreement_count: number;
  disagreement_rate: number;
  isolation_anomaly_count: number;
  isolation_anomaly_rate: number;
  runtime_seconds: number | null;
  failure_code: string | null;
  created_at: string;
  raw_logs_included: false;
  ip_addresses_included: false;
  private_paths_included: false;
  fingerprints_included: false;
  source_identifiers_included: false;
  secrets_exposed: false;
}

export interface ShadowObservationSummary {
  ok: boolean;
  version: string;
  status: string;
  observation_enabled: boolean;
  shadow_scoring_enabled: boolean;
  observation_count: number;
  source_filter_applied: boolean;
  since_filter_applied: boolean;
  latest: ShadowObservation | null;
  trend: ShadowObservation[];
  trend_count: number;
  drift_status_counts: Record<string, number>;
  runtime_status_counts: Record<string, number>;
  queue_rate: {
    minimum: number | null;
    mean: number | null;
    maximum: number | null;
  };
  rule_disagreement_rate: {
    minimum: number | null;
    mean: number | null;
    maximum: number | null;
  };
  independent_evidence: {
    status: string;
    qualified: boolean;
    source_device_count: number | null;
    independent_time_window_count: number | null;
    blind_metrics_available: boolean;
  };
  retention: {
    retention_days: number;
    automatic_cleanup_enabled: false;
    append_only_between_explicit_retention_runs: true;
  };
  lifecycle_state: "shadow_observation";
  rules_alert_authoritative: true;
  model_activated: false;
  production_promoted: false;
  response_automation_allowed: false;
  real_firewall_blocking_enabled: false;
  raw_logs_included: false;
  private_paths_included: false;
  fingerprints_included: false;
  secrets_exposed: false;
}

export interface ShadowOperationalMetricRange {
  minimum: number | null;
  mean: number | null;
  maximum: number | null;
  range: number | null;
}

export interface ShadowOperationalGate {
  name: string;
  required: true;
  passed: boolean;
  evidence: string;
}

export interface ShadowOperationalAcceptance {
  ok: boolean;
  version: string;
  status:
    | "operational_shadow_acceptance_passed"
    | "operational_shadow_acceptance_passed_with_warnings"
    | "operational_shadow_acceptance_warning"
    | "insufficient_operational_evidence";
  evidence_role: "reused_development_operational_evidence_only";
  independent_validation: false;
  observation_count: number;
  source_scope_count: number;
  time_scope_count: number;
  latest_observation_at: string | null;
  queue_rate: ShadowOperationalMetricRange;
  rule_shadow_disagreement_rate: ShadowOperationalMetricRange;
  isolation_forest_anomaly_rate: ShadowOperationalMetricRange;
  runtime_seconds: ShadowOperationalMetricRange;
  quality: Record<string, ShadowOperationalMetricRange>;
  drift: {
    current_state: string;
    status_counts: Record<string, number>;
  };
  failed_observation_count: number;
  insufficient_evidence_count: number;
  contract_mismatch_count: number;
  warnings: string[];
  gates: ShadowOperationalGate[];
  gates_passed: number;
  gates_total: number;
  operational_acceptance_passed: boolean;
  accuracy_metrics_calculated: false;
  lifecycle_state: "shadow_observation";
  rules_alert_authoritative: true;
  isolation_forest_advisory_only: true;
  model_activated: false;
  production_promoted: false;
  response_automation_allowed: false;
  real_firewall_blocking_enabled: false;
  source_identifiers_included: false;
  raw_logs_included: false;
  ip_addresses_included: false;
  private_paths_included: false;
  fingerprints_included: false;
  labels_accessed: false;
  secrets_exposed: false;
}

export interface ShadowMonitoringDiagnosticRow {
  source_scope: string;
  time_scope: string;
  observation_time: string;
  rows_evaluated: number;
  raw_drift_state: string;
  drift_state: string;
  queue_rate: number;
  disagreement_rate: number;
  isolation_anomaly_rate: number;
  score_mean: number | null;
  score_p95: number | null;
  application_total_variation: number | null;
  schema_total_variation: number | null;
  unknown_app_rate: number;
  parser_warning_per_row: number;
  runtime_seconds: number | null;
  root_cause_codes: string[];
  quality_warning: string;
  accuracy_metrics_calculated: false;
}

export interface ShadowMonitoringDiagnostics {
  ok: boolean;
  version: string;
  status: string;
  observation_count: number;
  source_scope_count: number;
  current_state: string;
  rows: ShadowMonitoringDiagnosticRow[];
  root_cause_counts: Record<string, number>;
  operational_metrics: {
    queue_rate: ShadowOperationalMetricRange;
    rule_shadow_disagreement_rate: ShadowOperationalMetricRange;
    isolation_forest_anomaly_rate: ShadowOperationalMetricRange;
  };
  thresholds: Record<string, number>;
  hysteresis: Record<string, number | boolean>;
  cadence: {
    enabled: boolean;
    dependencies_ready: boolean;
    scheduler_mode: "external_due_check_only";
    always_on_scheduler_enabled: false;
    cadence_minutes: number;
    active_job: boolean;
    latest_status: string;
    last_completed_at: string | null;
    next_due_at: string | null;
    due: boolean;
    bounded_source_count: number;
    bounded_windows_per_source: number;
    duplicate_suppression: true;
    idempotent_retry: true;
    cooperative_cancellation: true;
  };
  accuracy_metrics_calculated: false;
  lifecycle_state: "shadow_observation";
  rules_alert_authoritative: true;
  isolation_forest_advisory_only: true;
  model_activated: false;
  production_promoted: false;
  response_automation_allowed: false;
  real_firewall_blocking_enabled: false;
  source_identifiers_included: false;
  raw_logs_included: false;
  ip_addresses_included: false;
  private_paths_included: false;
  fingerprints_included: false;
  labels_accessed: false;
  secrets_exposed: false;
}

export interface ParserProfileDiagnosticRow {
  source_scope: string;
  time_scope: string;
  rows_evaluated: number;
  old_drift_state: string;
  raw_repaired_state: string;
  drift_state: string;
  queue_rate: number;
  disagreement_rate: number;
  isolation_anomaly_rate: number;
  baseline_selection: {
    status: string;
    scope: string;
    comparable: boolean;
    parser_profile: string;
    source_type: string;
    support_rows: number;
  };
  application_total_variation: number | null;
  schema_total_variation: number | null;
  quality: {
    rows: number;
    parser_error_rate: number;
    parser_structural_warning_per_row: number;
    required_missing_per_row: number;
    unresolved_application_rate: number;
  };
  quality_absolute_delta: Record<string, number>;
  compatibility_status_counts: Record<string, number>;
  application_resolution_counts: Record<string, number>;
  root_cause_codes: string[];
  accuracy_metrics_calculated: false;
}

export interface ParserProfileOperationalDiagnostics {
  ok: boolean;
  version: string;
  status: string;
  parser_contract_version: string;
  observation_count: number;
  source_scope_count: number;
  current_state: string;
  old_state_counts: Record<string, number>;
  repaired_state_counts: Record<string, number>;
  baseline_scope_counts: Record<string, number>;
  legacy_warning_windows_reclassified: number;
  baseline_catalog: {
    status: string;
    available: boolean;
    minimum_support: number;
    parser_contract_version: string;
    provenance: {
      evidence_role: string;
      selection_labels_used: false;
      accuracy_metrics_used: false;
      source_identity_used: false;
      locked_final_evidence_used: false;
      baseline_report_committed: false;
    };
  };
  rows: ParserProfileDiagnosticRow[];
  lifecycle_state: "shadow_observation";
  rules_alert_authoritative: true;
  isolation_forest_advisory_only: true;
  model_activated: false;
  production_promoted: false;
  response_automation_allowed: false;
  real_firewall_blocking_enabled: false;
  source_identifiers_included: false;
  raw_logs_included: false;
  ip_addresses_included: false;
  private_paths_included: false;
  labels_accessed: false;
  accuracy_metrics_calculated: false;
  secrets_exposed: false;
}

export interface MLEvidenceSnapshot {
  schema_version: string;
  schema_aware_abstention?: {
    contract_version: string;
    expected_schema_id: string;
    required_features: string[];
    compatible_status: string;
    fail_closed: boolean;
    incompatible_evidence_scored: boolean;
    rules_remain_authoritative: boolean;
    decision_support_only: boolean;
    production_promoted: boolean;
    response_automation_allowed: boolean;
    runtime?: {
      rows_checked: number;
      abstained_count: number;
      abstention_rate: number;
      reason_counts: Record<string, number>;
    };
  };
  canonical_evidence: {
    available: boolean;
    status: string;
    reason?: string;
    expected_report_name?: string;
    snapshot_id?: string;
    generated_at?: string;
    version?: string;
    evidence_type?: string;
    readiness_decision?: string;
    selected_strategy?: string;
    selection_scope?: string;
    evaluated_splits?: number;
    calibration_passed_splits?: number;
    dataset?: {
      dataset_id?: string;
      title?: string;
      publisher?: string;
      role?: string;
      accepted_rows?: number;
      sample_sha256?: string;
      provider_ground_truth?: boolean;
      human_reviewed?: boolean;
    };
    provenance?: {
      report_name?: string;
      development_manifest_hash?: string;
      source_file_count?: number;
    };
    metric_ranges?: Record<string, MLEvidenceMetricRange>;
    worst_split?: {
      split_mode?: string;
      metrics?: Record<string, number | null>;
    };
    calibration?: {
      status: string;
      passed: boolean;
      brier_score?: number | null;
      expected_calibration_error?: number | null;
      max_confidence_accuracy_gap?: number | null;
    };
    safety?: {
      development_only: boolean;
      model_activated: boolean;
      model_artifact_written: boolean;
      production_promoted: boolean;
      response_automation_allowed: boolean;
      real_firewall_blocking_enabled: boolean;
      database_counts_unchanged: boolean;
    };
    limitations?: string[];
  };
  operational_models: {
    isolation_forest: {
      role: string;
      artifact_exists: boolean;
      model_type: string;
      last_trained_at?: string | null;
      last_scored_at?: string | null;
      scored_log_count?: number | null;
      anomaly_count?: number | null;
      anomaly_rate_percent?: number | null;
      decision_support_only: boolean;
    };
    active_supervised_artifact: {
      artifact_exists: boolean;
      metadata_status?: string;
      metadata_unknown: boolean;
      model_type?: string | null;
      feature_set?: string | null;
      message: string;
      production_promoted: boolean;
      response_automation_allowed: boolean;
    };
    diagnostic_candidates: {
      registry_entry_count: number;
      latest_candidate?: {
        model_id: number;
        model_type?: string | null;
        created_at?: string | null;
        readiness_decision?: string | null;
        is_active: boolean;
      } | null;
      canonical_candidate_is_active: boolean;
    };
  };
  safety: {
    decision_support_only: boolean;
    production_promoted: boolean;
    response_automation_allowed: boolean;
    real_firewall_blocking_enabled: boolean;
    secrets_exposed: boolean;
    local_paths_exposed: boolean;
  };
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

export interface OperationJob {
  job_id: number;
  job_type: string;
  status: string;
  requested_by: string;
  started_at?: string | null;
  finished_at?: string | null;
  progress_current: number;
  progress_total: number;
  progress_percentage?: number;
  progress_status?: string;
  checkpoint_line?: number;
  checkpoint_bytes?: number;
  checkpoint_at?: string | null;
  chunk_commits?: number;
  input_size_bytes?: number | null;
  cancellation_requested?: boolean;
  cancellation_requested_at?: string | null;
  resume_eligible?: boolean;
  resume_ineligible_reason?: string | null;
  resume_of_job_id?: number | null;
  original_job_id?: number | null;
  resume_expires_at?: string | null;
  latest_heartbeat_at?: string | null;
  result_summary: Record<string, unknown>;
  error_summary?: string | null;
  related_ingestion_run_id?: number | null;
  related_detection_run_id?: number | null;
  related_ml_model_run_id?: number | null;
  attempt_count?: number;
  max_attempts?: number;
  next_attempt_at?: string | null;
  lease_expires_at?: string | null;
  can_cancel?: boolean;
  can_request_cancel?: boolean;
  can_retry?: boolean;
  can_resume?: boolean;
  details: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface OperationJobSummary {
  counts: Record<string, number>;
  active_count: number;
  failed_count: number;
  stale_count: number;
  stale_job_ids: number[];
  latest_failed_job?: OperationJob | null;
  latest_successful_job?: OperationJob | null;
  retention_policy: Record<string, unknown>;
  worker?: {
    enabled?: boolean;
    status?: string;
    worker_id?: string | null;
    last_seen_at?: string | null;
    current_job_id?: number | null;
  };
  staging?: {
    state?: string;
    pressure?: boolean;
    used_bytes?: number;
    max_total_bytes?: number;
    free_bytes?: number;
    min_free_bytes?: number;
  };
  queue?: {
    queued?: number;
    retry_wait?: number;
    running?: number;
    failed?: number;
    backlog_warning_threshold?: number;
  };
  health_status?: "healthy" | "warning" | "critical" | string;
  warnings?: Array<{
    code: string;
    severity: "warning" | "critical" | string;
    message: string;
  }>;
  warning_count?: number;
  recent_failure_count?: number;
}

export interface OperationJobSubmit {
  job_type: string;
  payload?: Record<string, unknown>;
  idempotency_key?: string;
  max_attempts?: number;
}

export interface OperationImportSubmit {
  file: File;
  job_type?: "import_logs" | "replay_logs";
  source_type?: string;
  parser_profile?: string;
  limit?: number | null;
  source_id?: number | null;
  idempotency_key?: string | null;
}
