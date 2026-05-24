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
    sla: { label: "Immediate", state: "needs_owner" }
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
    route.fulfill({ json: [{ id: 1, actor: "admin", action: "login", target_type: "user", target_value: "admin", details: {}, created_at: "2026-05-22T00:00:00Z" }] })
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
        latest_run: null,
        label_count: 0,
        label_distribution: {},
        decision_support_only: true
      }
    })
  );
  await page.route("**/api/ml/review-queue**", async (route) => route.fulfill({ json: [] }));
  await page.route("**/api/ml/labels**", async (route) => route.fulfill({ json: [] }));
  await page.route("**/api/response/blocked-ips", async (route) => route.fulfill({ json: [] }));
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

test("deep-linked alert and log drawers render", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/alerts?alert=1");
  await expect(page.getByRole("heading", { name: "Critical: Smoke alert" })).toBeVisible();
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
  await page.getByRole("button", { name: "Human Review Sample" }).click();
  await page.getByRole("button", { name: "Download Model Report" }).click();
  await expect(page.locator('[data-atdr-dropdown-open="true"]')).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});
