import { expect, test } from "@playwright/test";
import type { Page, Route } from "@playwright/test";

async function seedSession(page: Page) {
  await page.goto("/login");
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/overview/);
}

const source = {
  source_id: 1,
  name: "e2e-validation-source-port_scan_like_traffic",
  source_type: "firewall",
  parser_profile: "palo_alto",
  enabled: true,
  last_seen: "2026-06-05T02:00:00Z",
  last_log_received_at: "2026-06-05T02:00:00Z",
  logs_received_count: 10,
  parse_success_count: 10,
  parse_failure_count: 0,
  latest_error: null,
  created_at: "2026-06-05T02:00:00Z",
  updated_at: "2026-06-05T02:00:00Z",
  health: {
    source_id: 1,
    status: "healthy",
    enabled: true,
    logs_received_count: 10,
    parse_success_count: 10,
    parse_failure_count: 0,
    parse_success_rate: 100,
    last_seen: "2026-06-05T02:00:00Z",
    last_log_received_at: "2026-06-05T02:00:00Z",
    latest_error: null,
    recommendation: "Healthy: logs recently received and parsed successfully.",
    warnings: []
  },
  quality: {
    raw_logs: 10,
    normalized_logs: 10,
    unknown_app_count: 10,
    unknown_app_rate: 100,
    alert_count: 1,
    parse_failure_examples: [],
    warnings: ["Unknown/incomplete app rate is high at 100%."]
  },
  recent_ingestion_runs: [],
  recent_detection_runs: []
};

const alert = {
  id: 1,
  title: "Critical: Possible port scanning behavior from 203.0.113.44 (10 events)",
  alert_type: "possible_port_scan",
  src_ip: "203.0.113.44",
  dst_ip: "10.20.30.44",
  threat_score: 100,
  severity: "Critical",
  status: "open",
  assigned_to: null,
  explanation: "Grouped 10 matching log events.",
  matched_rules_json: [
    { code: "possible_port_scan", title: "Possible port scanning behavior", explanation: "Source touched 10 distinct destination ports." },
    { code: "group_metadata", occurrence_count: 10, related_log_count: 10 }
  ],
  recommended_response: "Review related logs before containment.",
  created_at: "2026-06-05T02:00:00Z",
  updated_at: "2026-06-05T02:00:00Z",
  evidence_count: 10,
  evidence_log_ids: [1],
  source_ids: [1],
  source_names: [source.name],
  sla: { label: "Immediate", state: "needs_owner" },
  detection_summary: {
    detection_source: ["rule", "supervised", "hybrid"],
    attack_type: "port_scan",
    attack_mapping: {
      attack_type: "port_scan",
      tactic: "Discovery",
      technique: "Network Service Discovery",
      technique_id: "T1046",
      description: "Scanning-like behavior can indicate discovery of exposed services."
    },
    anomaly: { present: false, count: 0, min_score: null, max_score: null },
    supervised: { predicted_label: "suspicious", malicious_probability: 0.74, confidence: 0.86, decision_support_only: true },
    hybrid_risk: { final_risk_score: 100 },
    behavior_window: { src_ip_5min_unique_dst_ports: 10, scanning_like_behavior_score: 85 },
    top_evidence_points: ["Possible port scanning behavior: Source touched 10 distinct destination ports."],
    why_flagged: "Flagged because the source touched 10 distinct destination ports and rule evidence matched scanning-like behavior."
  }
};

const log = {
  id: 1,
  raw_log_id: 1,
  source_id: 1,
  source_name: source.name,
  source_type: "firewall",
  parser_profile: "palo_alto",
  generated_time: "2026-06-05T02:00:00Z",
  src_ip: "203.0.113.44",
  dst_ip: "10.20.30.44",
  app: "incomplete",
  action: "deny",
  protocol: "tcp",
  src_zone: "outside",
  dst_zone: "inside",
  dst_port: 20000,
  bytes: 80,
  packets: 1,
  app_risk: 4,
  is_anomaly: false,
  anomaly_score: null,
  parsed_json: {},
  raw_line: "safe synthetic palo alto log line",
  alert_ids: [1]
};

async function fulfill(route: Route, json: unknown, headers: Record<string, string> = {}) {
  await route.fulfill({ json, headers });
}

async function mockWorkflowApi(page: Page) {
  await page.route("**/health", (route) =>
    fulfill(route, {
      status: "ok",
      checks: {
        api: { status: "ok" },
        database: { status: "ok" },
        response_mode: { status: "simulation" }
      }
    })
  );
  await page.route("**/api/auth/oidc/status", (route) =>
    fulfill(route, {
      enabled: false,
      provider_name: null,
      issuer_configured: false,
      allowed_domains: [],
      default_role: "analyst",
      mode: "local_login_only",
      school_email_domains: [],
      require_school_email: false,
      local_email_login_enabled: true,
      smtp_enabled: false
    })
  );
  await page.route("**/api/auth/email/status", (route) =>
    fulfill(route, {
      notifications_enabled: false,
      verification_enabled: false,
      delivery_mode: "disabled",
      smtp_enabled_legacy: false,
      smtp_configured: false,
      dev_outbox_available: false,
      code_ttl_minutes: 15,
      school_email_domains: [],
      require_school_email: false,
      local_email_login_enabled: true,
      verification_required_for_login: false,
      verification_required_for_admin_actions: false
    })
  );
  await page.route("**/api/auth/login", (route) =>
    fulfill(route, {
      access_token: "e2e-workflow-token",
      token_type: "bearer",
      username: "admin",
      role: "admin",
      expires_in_minutes: 60
    })
  );
  await page.route("**/api/auth/me", (route) =>
    fulfill(route, { id: 1, username: "admin", full_name: "E2E Admin", role: "admin", is_active: true, created_at: "2026-06-05T02:00:00Z" })
  );
  await page.route("**/api/users/me", (route) =>
    fulfill(route, { id: 1, username: "admin", full_name: "E2E Admin", role: "admin", is_active: true, created_at: "2026-06-05T02:00:00Z" })
  );
  await page.route("**/api/dashboard/summary", (route) =>
    fulfill(route, {
      total_logs: 10,
      total_alerts: 1,
      active_alerts: 1,
      critical_open_alerts: 1,
      high_open_alerts: 0,
      unassigned_active_alerts: 1,
      false_positive_alerts: 0,
      ml_anomaly_logs: 0,
      anomaly_rate: 0,
      active_suppressions: 0,
      suppressed_hits: 0,
      active_watchlist_items: 0,
      watchlist_hits: 0,
      severity_counts: { Critical: 1 },
      status_counts: { open: 1 },
      top_alert_types: [{ name: "possible_port_scan", count: 1 }],
      top_suspicious_source_ips: [{ name: "203.0.113.44", count: 10 }],
      top_destination_countries: [],
      action_distribution: [{ name: "deny", count: 10 }],
      protocol_distribution: [{ name: "tcp", count: 10 }],
      app_risk_distribution: [{ name: "4", count: 10 }],
      recent_alerts: [alert],
      latest_ingestion_run: null,
      latest_detection_run: null
    })
  );
  await page.route("**/api/dashboard/validation-summary**", (route) =>
    fulfill(route, {
      available: true,
      ok: true,
      scenario_count: 14,
      passed_count: 14,
      generalization: { available: true, ok: true, variant_count: 70, passed_count: 70, false_positive_count: 0, false_negative_count: 0 },
      layered: { available: true, ok: true, mode_run_count: 168, passed_count: 168, false_positive_count: 0, false_negative_count: 0 },
      e2e_workflow: { available: true, ok: true, scenario_count: 1, passed_count: 1, alert_count: 1, case_count: 1, response_actions_created: 3 }
    })
  );
  await page.route("**/api/sources**", (route) => fulfill(route, [source]));
  await page.route("**/api/ingestion/runs**", (route) => fulfill(route, []));
  await page.route("**/api/detection/runs**", (route) => fulfill(route, []));
  await page.route("**/api/jobs**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/summary")) {
      return fulfill(route, { stale_count: 0, running_count: 0, failed_count: 0, latest_failed_job: null });
    }
    return fulfill(route, []);
  });
  await page.route("**/api/alerts**", (route) => fulfill(route, [alert], { "X-Total-Count": "1" }));
  await page.route("**/api/alerts/cases**", (route) =>
    fulfill(route, [
      {
        case_id: "e2e-case",
        title: "Critical port_scan case from 203.0.113.44",
        related_alert_count: 1,
        source_ips: ["203.0.113.44"],
        destination_ips: ["10.20.30.44"],
        attack_types: ["port_scan"],
        severity: "Critical",
        status: "open",
        first_seen: "2026-06-05T02:00:00Z",
        last_seen: "2026-06-05T02:00:00Z",
        total_related_logs: 10,
        top_destination_ports: [{ name: "20000", count: 1 }],
        top_actions: [{ name: "deny", count: 10 }],
        recommended_analyst_focus: "Review repeated destination-port/service patterns."
      }
    ])
  );
  await page.route("**/api/alerts/1**", (route) => fulfill(route, alert));
  await page.route("**/api/alerts/1/timeline**", (route) => fulfill(route, []));
  await page.route("**/api/alerts/1/notes**", (route) => fulfill(route, []));
  await page.route("**/api/alerts/1/report**", (route) => fulfill(route, { report_id: "e2e-report" }));
  await page.route("**/api/logs**", (route) => fulfill(route, [log], { "X-Total-Count": "1" }));
  await page.route("**/api/logs/1**", (route) => fulfill(route, log));
  await page.route("**/api/ml/report", (route) => fulfill(route, { model_status: "Decision Support", response_automation_allowed: false }));
  await page.route("**/api/ml/supervised/report", (route) =>
    fulfill(route, {
      current_model_status: "candidate_improved",
      analyst_review_eligible: true,
      production_promoted: false,
      response_automation_allowed: false,
      threat_positive: { precision: 0.87, recall: 0.91, f1: 0.89 }
    })
  );
  await page.route("**/api/ml/labels**", (route) => fulfill(route, []));
  await page.route("**/api/response/blocked-ips**", (route) => fulfill(route, []));
  await page.route("**/api/audit**", (route) =>
    fulfill(route, [
      {
        id: 1,
        actor: "e2e_workflow_validation",
        action: "block_ip",
        target_type: "ip_address",
        target_value: "203.0.113.44",
        details: { simulation: true, status: "simulated" },
        created_at: "2026-06-05T02:00:00Z"
      }
    ], { "X-Total-Count": "1" })
  );
  await page.route("**/api/users**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/me")) {
      return fulfill(route, { id: 1, username: "admin", full_name: "E2E Admin", role: "admin", is_active: true, created_at: "2026-06-05T02:00:00Z" });
    }
    return fulfill(route, []);
  });
}

test("dashboard supports the end-to-end validation workflow with safe fixtures", async ({ page }) => {
  await mockWorkflowApi(page);
  await seedSession(page);

  await page.goto("/overview");
  await page.getByRole("button", { name: /validation reports/i }).click();
  await expect(page.getByText("E2E Workflow", { exact: true })).toBeVisible();
  await expect(page.getByText("1/1 passed")).toBeVisible();
  await expect(page.getByText(source.name).first()).toBeVisible();

  await page.goto("/alerts?alert=1");
  await expect(page.getByText("Prioritize, investigate, contain, and document alerts.")).toBeVisible();
  await expect(page.getByText("Why flagged?")).toBeVisible();
  await expect(page.getByText(/Possible port scanning behavior/i).first()).toBeVisible();

  await page.goto("/logs");
  await expect(page.getByText("Search raw evidence and normalized firewall events.")).toBeVisible();
  await expect(page.getByText("Advanced filters and sorting")).toBeVisible();

  await page.goto("/response");
  await expect(page.getByText("Containment actions stay simulated by default.")).toBeVisible();
  await expect(page.getByText("Simulated Response Approval")).toBeVisible();
  await expect(page.getByText(/justification note is required/i)).toBeVisible();

  await page.goto("/audit");
  await expect(page.getByText("Audit Log").first()).toBeVisible();
  await expect(page.getByText("e2e_workflow_validation")).toBeVisible();

  await page.goto("/users");
  await expect(page.getByText("External IAM")).toBeVisible();
  await expect(page.getByText("Local login only").first()).toBeVisible();

  const hasHorizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth
  );
  expect(hasHorizontalOverflow).toBe(false);
});
