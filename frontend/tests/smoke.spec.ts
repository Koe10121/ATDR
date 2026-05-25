import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

async function seedSession(page: Page, role: "admin" | "analyst" = "admin") {
  await page.addInitScript((userRole) => {
    window.localStorage.setItem(
      "atdr.session.v1",
      JSON.stringify({ token: "smoke-token", username: userRole === "admin" ? "admin" : "analyst", role: userRole, expiresAt: Date.now() + 3600000 })
    );
  }, role);
}

async function mockApi(page: Page, role: "admin" | "analyst" = "admin") {
  let deniedResponseAttempt = false;
  const smokeAlert = {
    id: 1,
    title: "Critical: Smoke alert",
    alert_type: "policy_deny",
    src_ip: "203.0.113.10",
    dst_ip: "10.0.0.5",
    threat_score: 88,
    severity: "Critical",
    status: "open",
    assigned_to: null,
    explanation: "Smoke alert for route testing.",
    matched_rules_json: [{ code: "policy_deny", title: "Policy deny", explanation: "Denied traffic." }],
    recommended_response: "Investigate source IP.",
    created_at: "2026-05-22T00:00:00Z",
    updated_at: "2026-05-22T00:00:00Z",
    evidence_count: 1,
    evidence_log_ids: [1],
    sla: { label: "Immediate", state: "needs_owner" },
    detection_summary: {
      detection_source: ["rule", "anomaly", "hybrid"],
      attack_type: "port_scan",
      attack_mapping: {
        attack_type: "port_scan",
        tactic: "Discovery",
        technique: "Network Service Discovery",
        technique_id: "T1046",
        description: "Scanning-like behavior can indicate discovery of exposed services."
      },
      matched_rule_names: ["Policy deny"],
      anomaly: { present: true, count: 1, min_score: -0.2, max_score: -0.2 },
      supervised: { predicted_label: "suspicious", malicious_probability: 0.82, confidence: 0.9, decision_support_only: true },
      hybrid_risk: { final_risk_score: 88 },
      behavior_window: { src_ip_5min_unique_dst_ports: 32, scanning_like_behavior_score: 80 },
      top_evidence_points: ["Policy deny: Denied traffic.", "Source touched 32 unique destination ports in 5 minutes."],
      why_flagged: "Flagged as suspicious because action=deny and source touched 32 unique destination ports in 5 minutes."
    }
  };
  const smokeLog = {
    id: 1,
    raw_log_id: 1,
    generated_time: "2026-05-22T00:00:00Z",
    src_ip: "203.0.113.10",
    dst_ip: "10.0.0.5",
    app: "ssl",
    action: "deny",
    protocol: "tcp",
    src_zone: "outside",
    dst_zone: "inside",
    bytes: 120,
    packets: 2,
    app_risk: 4,
    is_anomaly: false,
    parsed_json: {},
    raw_line: "smoke raw log",
    alert_ids: [1]
  };
  await page.route("**/health", async (route) =>
    route.fulfill({
      json: {
        status: "ok",
        service: "MFU ATDR",
        version: "0.1.0",
        environment: "test",
        checks: { database: { status: "ok" }, ml_model: { status: "ready" }, response_mode: { status: "simulation" } }
      }
    })
  );
  await page.route("**/api/auth/me", async (route) =>
    route.fulfill({ json: { id: 1, username: role, full_name: "Smoke User", role, is_active: true, created_at: "2026-05-22T00:00:00Z" } })
  );
  await page.route("**/api/dashboard/summary", async (route) =>
    route.fulfill({
      json: {
        total_logs: 1200,
        total_alerts: 12,
        active_alerts: 4,
        critical_open_alerts: 1,
        high_open_alerts: 2,
        unassigned_active_alerts: 1,
        false_positive_alerts: 0,
        ml_anomaly_logs: 8,
        anomaly_rate: 0.67,
        active_suppressions: 1,
        suppressed_hits: 10,
        active_watchlist_items: 1,
        watchlist_hits: 2,
        severity_counts: { Critical: 1, High: 2, Medium: 6, Low: 3 },
        status_counts: { open: 4, resolved: 8 },
        top_alert_types: [{ name: "policy_deny", count: 4 }],
        top_suspicious_source_ips: [{ name: "203.0.113.10", count: 3 }],
        top_destination_countries: [],
        action_distribution: [],
        protocol_distribution: [],
        app_risk_distribution: [],
        recent_alerts: []
      }
    })
  );
  await page.route("**/api/alerts**", async (route) => {
    const url = route.request().url();
    if (url.includes("/cases")) {
      return route.fulfill({
        json: [
          {
            case_id: "smoke-case",
            title: "Critical port_scan case from 203.0.113.10",
            related_alert_count: 1,
            source_ips: ["203.0.113.10"],
            destination_ips: ["10.0.0.5"],
            attack_types: ["port_scan"],
            severity: "Critical",
            status: "open",
            assigned_analyst: null,
            first_seen: "2026-05-22T00:00:00Z",
            last_seen: "2026-05-22T00:00:00Z",
            notes: []
          }
        ]
      });
    }
    if (url.includes("/notes")) return route.fulfill({ json: [] });
    if (url.includes("/timeline")) return route.fulfill({ json: [] });
    if (url.includes("/report")) return route.fulfill({ json: { evidence_logs: [], matched_rules: [], timeline: [], notes: [], response_actions: [] } });
    if (url.match(/\/api\/alerts\/1(\?|$)/)) return route.fulfill({ json: smokeAlert });
    return route.fulfill({ json: [smokeAlert] });
  });
  await page.route("**/api/logs**", async (route) =>
    route.fulfill({ json: route.request().url().match(/\/api\/logs\/1(\?|$)/) ? smokeLog : [smokeLog] })
  );
  await page.route("**/api/audit**", async (route) =>
    route.fulfill({
      json: deniedResponseAttempt
        ? [
            {
              id: 2,
              actor: "admin",
              action: "block_ip_denied",
              target_type: "ip_address",
              target_value: "10.0.0.10",
              details: { status: "denied" },
              created_at: "2026-05-22T00:01:00Z"
            }
          ]
        : [{ id: 1, actor: "admin", action: "login", target_type: "user", target_value: "admin", details: {}, created_at: "2026-05-22T00:00:00Z" }]
    })
  );
  await page.route("**/api/detection/tuning", async (route) =>
    route.fulfill({ json: { summary: {}, alert_type_pressure: [], suppression_candidates: [], false_positive_learning: {}, severity_distribution: [], status_distribution: [], ml: {}, production_readiness: [], recommendations: [] } })
  );
  await page.route("**/api/ml/report", async (route) =>
    route.fulfill({ json: { model_status: { artifact_exists: true }, dataset_profile: { recommendations: [] }, scored_log_count: 0, anomaly_count: 0, anomaly_rate: 0, recommendations: [], drift_signals: [], top_anomalous_src_ips: [], top_anomalous_apps: [], top_anomalous_dst_ports: [] } })
  );
  await page.route("**/api/ml/supervised/report", async (route) =>
    route.fulfill({
      json: {
        model_name: "supervised_random_forest",
        model_path: "models/supervised_classifier.joblib",
        artifact_exists: false,
        latest_run: {
          metrics: {
            f1: 0.72,
            threat_positive: { precision: 0.87, recall: 0.95, f1: 0.91 },
            per_class: {
              suspicious: { recall: 0.71 },
              malicious: { recall: 0.54 }
            }
          },
          promotion_gate: {
            decision: "eligible_for_analyst_review",
            analyst_review_eligible: true,
            production_promoted: false,
            response_automation_allowed: false
          },
          model_readiness_checklist: { status: "candidate_improved", passed: 6, total: 7, items: [], message: "candidate" },
          split_strategy: "time"
        },
        label_count: 0,
        label_distribution: {},
        label_source_distribution: {},
        reviewed_label_distribution: {},
        weak_label_distribution: {},
        reviewed_label_count: 0,
        reviewed_label_target: 300,
        unreviewed_assisted_label_count: 0,
        validation_warnings: ["Reviewed-label sample is too small for reliable model validation."],
        class_temporal_coverage: {
          reviewed_label_count: 0,
          reviewed_label_target: 300,
          reviewed_malicious_count: 0,
          reviewed_suspicious_count: 0,
          malicious_train_count: 0,
          malicious_test_count: 0,
          suspicious_train_count: 0,
          suspicious_test_count: 0,
          malicious_training_minimum: 20,
          malicious_training_better_target: 50,
          class_coverage: {},
          warnings: []
        },
        model_readiness_checklist: { status: "candidate_improved", passed: 6, total: 7, items: [], message: "candidate" },
        decision_support_only: true
      }
    })
  );
  await page.route("**/api/ml/review-queue**", async (route) => route.fulfill({ json: [] }));
  await page.route("**/api/ml/active-learning/review-sample/export**", async (route) =>
    route.fulfill({
      body: "label_id,log_id,reason_selected_for_review,human_review_decision,human_review_note\n,1,low-confidence model prediction,,\n",
      headers: { "content-type": "text/csv", "content-disposition": 'attachment; filename="active-learning-review-sample.csv"' }
    })
  );
  await page.route("**/api/ml/training-window-threat-review/export**", async (route) =>
    route.fulfill({
      body: "label_id,log_id,split_window,current_label,human_review_decision,human_review_note\n,1,training_window,suspicious,,\n",
      headers: { "content-type": "text/csv", "content-disposition": 'attachment; filename="training-window-threat-review-sample.csv"' }
    })
  );
  await page.route("**/api/ml/boundary-report/export**", async (route) =>
    route.fulfill({
      body: "# Suspicious / Malicious Boundary Report\n",
      headers: { "content-type": "text/markdown", "content-disposition": 'attachment; filename="suspicious-malicious-boundary-report.md"' }
    })
  );
  await page.route("**/api/ml/suspicious-recall-review/export**", async (route) =>
    route.fulfill({
      body: "label_id,log_id,timestamp,split_window,current_label,current_attack_type,reviewed_status,model_prediction,model_confidence,threat_positive_score,rule_evidence,anomaly_evidence,hybrid_risk,reason_selected,evidence_summary,human_review_decision,human_review_attack_type,human_review_confidence,human_review_note\n1,1,2026-05-20T00:00:00Z,test_window,suspicious,unknown_anomaly,true,malicious,0.7,0.9,rule_score=50,is_anomaly=false,70,boundary,test,,unknown_anomaly,3,\n",
      headers: { "content-type": "text/csv", "content-disposition": 'attachment; filename="suspicious-recall-review-sample.csv"' }
    })
  );
  await page.route("**/api/ml/suspicious-recall-report/export**", async (route) =>
    route.fulfill({
      body: "# Suspicious Recall Error Report\n",
      headers: { "content-type": "text/markdown", "content-disposition": 'attachment; filename="suspicious-recall-error-report.md"' }
    })
  );
  await page.route("**/api/ml/labels/quality-issues/export**", async (route) =>
    route.fulfill({
      body: "label_id,log_id,current_label,current_attack_type,issue_type,human_review_decision,human_review_note\n,1,suspicious,unknown_anomaly,test,,\n",
      headers: { "content-type": "text/csv", "content-disposition": 'attachment; filename="label-quality-issues.csv"' }
    })
  );
  await page.route("**/api/ml/class-temporal-coverage**", async (route) =>
    route.fulfill({
      json: {
        reviewed_label_count: 0,
        reviewed_label_target: 300,
        reviewed_malicious_count: 0,
        reviewed_suspicious_count: 0,
        malicious_train_count: 0,
        malicious_test_count: 0,
        suspicious_train_count: 0,
        suspicious_test_count: 0,
        malicious_training_minimum: 20,
        malicious_training_better_target: 50,
        class_coverage: {},
        warnings: []
      }
    })
  );
  await page.route("**/api/ml/labels**", async (route) => route.fulfill({ json: [] }));
  await page.route("**/api/response/blocked-ips", async (route) => route.fulfill({ json: [] }));
  await page.route("**/api/response/block-ip", async (route) => {
    deniedResponseAttempt = true;
    await route.fulfill({
      json: {
        id: 10,
        alert_id: null,
        action_type: "block_ip",
        target_ip: "10.0.0.10",
        status: "denied",
        result_message: "Denied: Target IP is in the protected internal/management allowlist.",
        executed_by: "admin",
        executed_at: "2026-05-22T00:01:00Z"
      }
    });
  });
  await page.route("**/api/suppressions**", async (route) => route.fulfill({ json: [] }));
  await page.route("**/api/watchlists**", async (route) => route.fulfill({ json: [] }));
  await page.route("**/api/users", async (route) => route.fulfill({ json: [{ id: 1, username: "admin", full_name: "Admin", role: "admin", is_active: true, created_at: "2026-05-22T00:00:00Z" }] }));
}

async function chooseSafeSelect(page: Page, ariaLabel: string, optionName: string) {
  await page.getByRole("button", { name: ariaLabel }).click();
  await expect(page.locator('[data-atdr-dropdown-open="true"]')).toHaveCount(1);
  await page.getByRole("option", { name: optionName, exact: true }).click();
  await expect(page.locator('[data-atdr-dropdown-open="true"]')).toHaveCount(0);
}

test("login page loads", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByText("MFU ATDR SOC Console")).toBeVisible();
  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
});

test("core analyst routes render with mocked API", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  for (const path of ["/overview", "/alerts", "/logs", "/response", "/controls", "/audit", "/tuning", "/ml"]) {
    await page.goto(path);
    await expect(page.getByText("SOC Command Center")).toBeVisible();
    await expect(page.getByText("API health check failed")).not.toBeVisible();
  }
});

test("overview system health panel and ML governance wording render", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);

  await page.goto("/overview");
  await expect(page.getByText("System Health")).toBeVisible();
  await expect(page.getByText("Response Mode")).toBeVisible();
  await expect(page.getByText("Config warnings are checked by Config Doctor")).toBeVisible();

  await page.goto("/ml");
  await expect(page.getByText("Model is eligible for analyst review, not production promotion.")).toBeVisible();
  await expect(page.getByText("Analyst Review Gate")).toBeVisible();
  await expect(page.getByText("Assisted labels are weak labels.")).toBeVisible();
});

test("deep-linked alert and log drawers render", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/alerts?alert=1");
  await expect(page.getByRole("heading", { name: "Critical: Smoke alert" })).toBeVisible();
  await expect(page.getByText("Why flagged?")).toBeVisible();
  await expect(page.getByText("Discovery / Network Service Discovery (T1046)")).toBeVisible();
  await page.goto("/logs?log=1");
  await expect(page.getByText("Analyst ML Label")).toBeVisible();
  await expect(page.getByText("Raw Evidence", { exact: true })).toBeVisible();
});

test("analyst cannot access admin routes", async ({ page }) => {
  await mockApi(page, "analyst");
  await seedSession(page, "analyst");
  await page.goto("/users");
  await expect(page.getByText("Access denied")).toBeVisible();
});

test("simulated response confirmation and denied audit are visible", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/response");

  await page.getByPlaceholder("IP address").fill("10.0.0.10");
  await page.locator("textarea").fill("Acceptance test protected IP block attempt.");
  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toContain("No real firewall device will be changed");
    await dialog.accept();
  });
  await page.getByRole("button", { name: "Record simulated block" }).click();
  await expect(page.getByText("Denied: Target IP is in the protected internal/management allowlist.")).toBeVisible();

  await page.goto("/audit");
  await expect(page.getByText("block_ip_denied")).toBeVisible();
  await expect(page.getByText("10.0.0.10")).toBeVisible();
});

test("sort and saved-view dropdowns tolerate malformed persisted table state", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await mockApi(page);
  await page.addInitScript(() => {
    window.localStorage.setItem(
      "atdr.session.v1",
      JSON.stringify({ token: "smoke-token", username: "admin", role: "admin", expiresAt: Date.now() + 3600000 })
    );
    window.localStorage.setItem("atdr.log.filters.v1", JSON.stringify(null));
    window.localStorage.setItem("atdr.alert.filters.v1", JSON.stringify({ sort_by: "not-a-real-sort", status: null }));
    window.localStorage.setItem("atdr.log.views.v1", JSON.stringify([{ name: "legacy-log-view", value: { sort_by: "src_ip" } }]));
    window.localStorage.setItem("atdr.alert.views.v1", JSON.stringify([{ name: "legacy-alert-view", value: null }]));
  });

  await page.goto("/logs");
  await expect(page.getByRole("heading", { name: "Search raw evidence and normalized firewall events." })).toBeVisible();
  await chooseSafeSelect(page, "Apply saved view", "legacy-log-view");
  await page.getByText("Advanced filters and sorting").click();
  await chooseSafeSelect(page, "Log sort", "Sort by destination IP");
  await page.getByPlaceholder("Source IP", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Search raw evidence and normalized firewall events." })).toBeVisible();

  await page.goto("/alerts");
  await expect(page.getByRole("heading", { name: "Prioritize, investigate, contain, and document alerts." })).toBeVisible();
  await chooseSafeSelect(page, "Apply saved view", "legacy-alert-view");
  await chooseSafeSelect(page, "Alert sort", "Sort by severity");
  await page.getByPlaceholder("Source IP", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Prioritize, investigate, contain, and document alerts." })).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test("dashboard dropdowns close and do not block follow-up clicks", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await page.goto("/logs");
  await page.getByText("Advanced filters and sorting").click();
  await chooseSafeSelect(page, "Log sort", "Sort by source IP");
  await page.getByPlaceholder("Search IP, app, rule, action, protocol, or zone").click();
  await chooseSafeSelect(page, "Table density", "Compact");
  await page.getByRole("button", { name: "Save view" }).click();

  await page.goto("/alerts");
  await chooseSafeSelect(page, "Alert severity filter", "High");
  await page.getByPlaceholder("Source IP", { exact: true }).click();
  await chooseSafeSelect(page, "Alert status filter", "Investigating");
  await page.getByPlaceholder("Destination IP", { exact: true }).click();
  await chooseSafeSelect(page, "Alert sort", "Sort by updated");
  await page.getByPlaceholder("Alert type", { exact: true }).click();

  await page.goto("/audit");
  await chooseSafeSelect(page, "Table density", "Compact");
  await page.getByPlaceholder("Actor").click();

  await page.goto("/controls");
  await page.getByRole("button", { name: "Watchlists" }).click();
  await chooseSafeSelect(page, "Watchlist indicator type", "Destination IP");
  await page.getByPlaceholder("Indicator value").click();

  await page.goto("/ml");
  await expect(page.getByRole("heading", { name: "AI is assistive, explainable, and audited." })).toBeVisible();
  await expect(page.getByText("AI Model Evaluation")).toBeVisible();
  await expect(page.getByRole("button", { name: "General Active Learning Sample" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Malicious-Focused Sample" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Round 5 Threat Boundary" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Training-Window Threat Sample" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Suspicious Recall Sample" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Suspicious Recall Report" })).toBeVisible();
  await page.getByRole("button", { name: "Human Review Sample" }).click();
  await page.getByRole("button", { name: "General Active Learning Sample" }).click();
  await page.getByRole("button", { name: "Malicious-Focused Sample" }).click();
  await page.getByRole("button", { name: "Suspicious Recall Sample" }).click();
  await page.getByRole("button", { name: "Suspicious Recall Report" }).click();
  await page.getByRole("button", { name: "Round 5 Threat Boundary" }).click();
  await page.getByRole("button", { name: "Training-Window Threat Sample" }).click();
  await page.getByRole("button", { name: "Boundary Report" }).click();
  await page.getByRole("button", { name: "Download Model Report" }).click();
  await expect(page.locator('[data-atdr-dropdown-open="true"]')).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});
