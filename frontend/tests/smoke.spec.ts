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
    matched_rules_json: [
      { code: "policy_deny", title: "Policy deny", explanation: "Denied traffic." },
      { code: "group_metadata", occurrence_count: 12, related_log_count: 12, deduplicated: true }
    ],
    recommended_response: "Investigate source IP.",
    created_at: "2026-05-22T00:00:00Z",
    updated_at: "2026-05-22T00:00:00Z",
    evidence_count: 1,
    evidence_log_ids: [1],
    source_ids: [1],
    source_names: ["local_import"],
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
    source_id: 1,
    source_name: "local_import",
    source_type: "file_import",
    parser_profile: "palo_alto",
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
    alert_ids: [1],
    triage_explanation: {
      status: "flagged",
      summary: "Linked alert evidence exists for this normalized log.",
      reasons: ["Alert #1 uses this log as evidence.", "Denied traffic is a normalized signal."],
      normalized_signals: ["action=deny", "app=ssl", "app_risk=4"],
      parser_warnings: [],
      alert_ids: [1],
      decision_support_only: true,
      response_automation_allowed: false,
      analyst_next_steps: ["Open linked alert evidence before taking action."]
    }
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
  await page.route("**/api/auth/oidc/status", async (route) =>
    route.fulfill({
      json: {
        enabled: false,
        provider_name: null,
        issuer_configured: false,
        client_configured: false,
        allowed_domains: [],
        default_role: "analyst",
        mode: "local_login_only",
        school_email_domains: [],
        require_school_email: false,
        local_email_login_enabled: true,
        smtp_enabled: false
      }
    })
  );
  await page.route("**/api/auth/mfu-iam/public-status", async (route) =>
    route.fulfill({
      json: {
        enabled: false,
        b2b_ready: false,
        mock_enabled: false,
        google_sso_enabled: false,
        google_client_id_configured: false,
        allowed_domains: [],
        domain_hints: [],
        default_role: "analyst",
        auth_require_2fa: false,
        mode: "local_login_only",
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/auth/mfu-iam/status", async (route) =>
    route.fulfill({
      json: {
        enabled: false,
        base_url_configured: false,
        client_id_configured: false,
        client_secret_configured: false,
        audience_configured: false,
        scope_configured: false,
        timeout_ms: 5000,
        token_path_configured: true,
        introspect_path_configured: true,
        profile_path_configured: true,
        admin_base_path_configured: true,
        admin_client_configured: false,
        admin_secret_configured: false,
        admin_audience_configured: false,
        admin_scope_configured: false,
        compat_profile_configured: false,
        allowed_domains: [],
        domain_hints: [],
        default_role: "analyst",
        mock_enabled: false,
        admin_email_mapping_configured: false,
        google_sso_enabled: false,
        google_client_id_configured: false,
        permission_source: null,
        permission_bootstrap_mode: null,
        permission_root_configured: false,
        permission_paths_count: 0,
        project_account_email_configured: false,
        auth_require_2fa: false,
        audit_retention_days: 90,
        managed_client_configured: false,
        managed_client_endpoint_configured: false,
        managed_client_owner_configured: false,
        managed_client_scopes_configured: false,
        managed_client_audiences_configured: false,
        init_admin_emails_configured: false,
        seed_admin_email_configured: false,
        b2b_ready: false,
        admin_api_ready: false,
        permission_bootstrap_ready: false,
        mode: "local_login_only",
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/auth/email/status", async (route) =>
    route.fulfill({
      json: {
        notifications_enabled: false,
        verification_enabled: false,
        delivery_mode: "disabled",
        smtp_configured: false,
        smtp_enabled_legacy: false,
        from_email_configured: false,
        dev_outbox_available: false,
        code_ttl_minutes: 15,
        code_length: 6,
        verification_required_for_login: false,
        verification_required_for_admin_actions: false,
        school_email_domains: [],
        require_school_email: false,
        local_email_login_enabled: true,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/assistant/status", async (route) =>
    route.fulfill({
      json: {
        available: true,
        mode: "deterministic_local",
        external_provider_configured: false,
        external_provider_used_by_default: false,
        provider: "disabled",
        model_configured: false,
        llm_enabled: false,
        llm_provider_configured: false,
        llm_provider_name: "",
        llm_ready: false,
        llm_model_configured: false,
        llm_secret_configured: false,
        llm_base_url_configured: false,
        llm_timeout_seconds: 15,
        llm_max_retries: 2,
        llm_max_prompt_chars: 12000,
        conversation_history_turns: 4,
        rate_limit_requests: 30,
        rate_limit_window_seconds: 60,
        llm_secrets_exposed: false,
        redaction_enabled: true,
        raw_log_context_allowed: false,
        max_context_rows: 20,
        safety: ["Read Only", "Decision Support Only", "Response Automation Disabled", "Simulation Mode"]
      }
    })
  );
  await page.route("**/api/assistant/history**", async (route) =>
    route.fulfill({
      json: [
        {
          id: 11,
          actor: "admin",
          question: "Summarize failed jobs.",
          created_at: "2026-05-22T00:03:00Z",
          context_used: ["operation_jobs", "failed_jobs"],
          external_provider_used: false
        }
      ]
    })
  );
  await page.route("**/api/assistant/feedback/summary**", async (route) =>
    route.fulfill({
      json: {
        total_count: 2,
        rating_counts: { helpful: 1, not_helpful: 0, incorrect: 1, unsafe: 0, unclear: 0 },
        unsafe_or_incorrect_count: 1,
        needs_review_count: 1,
        external_provider_used_count: 0,
        raw_log_context_included_count: 0,
        action_requested_count: 0,
        action_executed_count: 0,
        latest_unsafe_or_incorrect: [
          {
            feedback_id: 23,
            actor_user_id: 1,
            actor_username: "admin",
            question: "This answer looked incorrect.",
            answer_summary: "Possibly incorrect answer summary.",
            answer_hash: "ghi789",
            context_type: "alert",
            context_reference: "1",
            rating: "incorrect",
            feedback_note: "Review the evidence wording.",
            external_provider_used: false,
            raw_log_context_included: false,
            action_requested: false,
            action_executed: false,
            assistant_audit_id: 11,
            review_recommended: true,
            review_reason: "Review recommended for unsafe/incorrect assistant feedback.",
            created_at: "2026-05-22T00:06:00Z"
          }
        ],
        recent: [],
        scope: "all",
        filtered_rating: null,
        filtered_context_type: null,
        filtered_since_days: 30,
        review_warning: true,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/assistant/feedback/recent**", async (route) =>
    route.fulfill({
      json: [
        {
          feedback_id: 21,
          actor_user_id: 1,
          actor_username: "admin",
          question: "Why was alert 1 flagged?",
          answer_summary: "Alert explanation summary.",
          answer_hash: "abc123",
          context_type: "alert",
          context_reference: "1",
          rating: "helpful",
          feedback_note: "Clear",
          external_provider_used: false,
          raw_log_context_included: false,
          action_requested: false,
          action_executed: false,
          assistant_audit_id: 11,
          review_recommended: false,
          review_reason: null,
          created_at: "2026-05-22T00:04:00Z"
        }
      ]
    })
  );
  await page.route("**/api/assistant/feedback", async (route) =>
    route.fulfill({
      json: {
        feedback_id: 22,
        actor_user_id: 1,
        actor_username: "admin",
        question: "Why was alert 1 flagged?",
        answer_summary: "Assistant answer summary.",
        answer_hash: "def456",
        context_type: "alert",
        context_reference: "1",
        rating: "helpful",
        feedback_note: "Clear enough",
        external_provider_used: false,
        raw_log_context_included: false,
        action_requested: false,
        action_executed: false,
        assistant_audit_id: 12,
        review_recommended: false,
        review_reason: null,
        created_at: "2026-05-22T00:05:00Z"
      }
    })
  );
  await page.route("**/api/assistant/chat", async (route) =>
    route.fulfill({
      json: {
        answer:
          "Summary\n- Alert #1: Critical policy_deny with risk score 88.\n\nEvidence / why flagged\nFlagged as suspicious because action=deny and source touched 32 unique destination ports in 5 minutes.\n\nRisk interpretation\n- Evidence strength: moderate confidence.\n- False-positive/noise review recommended when parser data is incomplete.\n\nWhat to check next\n- Review related logs before containment.\n- Use simulated response only after confirmation.\n\nSafety note\n- The assistant is read-only.\n- Response automation is disabled.\n- No raw log context was included.",
        mode: "deterministic_local",
        external_provider_used: false,
        safety: ["Read Only", "Decision Support Only", "Response Automation Disabled", "Simulation Mode"],
        context_used: ["alert_detail", "why_flagged"],
        citations: [
          { label: "Alert detail", source: "/api/alerts/{alert_id}", reference_id: "1" },
          { label: "Log detail", source: "/api/logs/{log_id}", reference_id: "1" },
          { label: "Source", source: "/api/sources/{source_id}", reference_id: "1" },
          { label: "Detection run", source: "/api/detection/runs/{run_id}", reference_id: "8" },
          { label: "Operation job", source: "/api/jobs/{job_id}", reference_id: "3" },
          { label: "ML report API", source: "/api/ml/report", reference_id: null },
          { label: "Detection rule catalog", source: "docs/DETECTION_RULE_CATALOG.md", reference_id: null }
        ],
        redaction_applied: true,
        raw_log_context_included: false,
        suggested_followups: ["Summarize source health.", "Explain current ML model status."],
        details: {
          assistant_audit_id: 12,
          llm: {
            used: false,
            provider: "disabled",
            model_configured: false,
            fallback_reason: null,
            raw_log_context_included: false,
            secrets_exposed: false,
            prompt_contract: "soc_evidence_grounded_structured_v2",
            provider_called: false,
            answer_used: false,
            answer_guard_reason: null
          },
          alert: { id: 1, severity: "Critical" },
          answer_sections: {
            summary: ["Alert #1: Critical policy_deny with risk score 88.", "Detection source: rule, anomaly, hybrid."],
            what_happened: ["Alert #1 was generated from denied traffic and scanning-like behavior."],
            why_flagged_or_not: ["Flagged as suspicious because action=deny and source touched 32 unique destination ports."],
            evidence: ["Flagged as suspicious because action=deny.", "Policy deny: Denied traffic.", "ATT&CK mapping: Discovery / Network Service Discovery / T1046."],
            risk_interpretation: ["Evidence strength: moderate confidence.", "False-positive/noise review recommended when parser data is incomplete."],
            related_context: ["Brief context type: alert.", "Alert detail: /api/alerts/{alert_id} #1"],
            what_to_check_next: ["Review related logs before containment.", "Use simulated response only after confirmation."],
            safe_next_steps: ["Review related logs before containment.", "Use simulated response only after confirmation."],
            limitations: ["Decision support only; analyst judgment is required.", "Response automation is disabled."],
            safety_note: ["The assistant is read-only.", "Response automation is disabled."],
            safety_limitation: ["The assistant is read-only.", "Response automation is disabled."],
            citations: ["Alert detail: /api/alerts/{alert_id} #1", "Detection rule catalog: docs/DETECTION_RULE_CATALOG.md"]
          }
        },
        conversation_id: "smoke-assistant-conversation",
        active_context: { alert_id: 1, log_id: 1, source_id: 1, case_id: null, primary: "alert" }
      }
    })
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
        recent_alerts: [],
        latest_ingestion_run: {
          run_id: 7,
          started_at: "2026-05-22T00:00:00Z",
          finished_at: "2026-05-22T00:00:01Z",
          source_type: "replay_direct",
          input_name: "paloalto-demo.txt",
          status: "completed",
          total_lines_received: 2,
          raw_logs_created: 2,
          parsed_successfully: 2,
          parse_failures: 0,
          duplicate_raw_logs: 0,
          alerts_created: 1,
          alerts_deduplicated: 1,
          alerts_suppressed: 0,
          runtime_seconds: 1,
          details: {}
        },
        latest_detection_run: {
          run_id: 8,
          started_at: "2026-05-22T00:00:02Z",
          finished_at: "2026-05-22T00:00:03Z",
          detection_type: "hybrid",
          status: "completed",
          logs_evaluated: 2,
          alerts_created: 1,
          alerts_deduplicated: 1,
          alerts_suppressed: 0,
          top_attack_types: [{ name: "port_scan", count: 1 }],
          runtime_seconds: 1,
          details: {}
        }
      }
    })
  );
  await page.route("**/api/ingestion/runs**", async (route) =>
    route.fulfill({
      json: [
        {
          run_id: 7,
          started_at: "2026-05-22T00:00:00Z",
          finished_at: "2026-05-22T00:00:01Z",
          source_type: "replay_direct",
          input_name: "paloalto-demo.txt",
          status: "completed",
          total_lines_received: 2,
          raw_logs_created: 2,
          parsed_successfully: 2,
          parse_failures: 0,
          duplicate_raw_logs: 0,
          alerts_created: 1,
          alerts_deduplicated: 1,
          alerts_suppressed: 0,
          runtime_seconds: 1,
          details: {}
        }
      ]
    })
  );
  await page.route("**/api/detection/runs**", async (route) =>
    route.fulfill({
      json: [
        {
          run_id: 8,
          started_at: "2026-05-22T00:00:02Z",
          finished_at: "2026-05-22T00:00:03Z",
          detection_type: "hybrid",
          status: "completed",
          logs_evaluated: 2,
          alerts_created: 1,
          alerts_deduplicated: 1,
          alerts_suppressed: 0,
          top_attack_types: [{ name: "port_scan", count: 1 }],
          runtime_seconds: 1,
          details: {}
        }
      ]
    })
  );
  await page.route("**/api/jobs**", async (route) => {
    const job = {
      job_id: 3,
      job_type: "run_detection",
      status: "completed",
      requested_by: "admin",
      started_at: "2026-05-22T00:00:02Z",
      finished_at: "2026-05-22T00:00:03Z",
      progress_current: 1,
      progress_total: 1,
      result_summary: { logs_evaluated: 2, alerts_created: 1, alerts_deduplicated: 1 },
      error_summary: null,
      related_ingestion_run_id: null,
      related_detection_run_id: 8,
      related_ml_model_run_id: null,
      attempt_count: 1,
      max_attempts: 1,
      next_attempt_at: null,
      lease_expires_at: null,
      can_cancel: false,
      can_retry: false,
      details: { limit: 10 },
      created_at: "2026-05-22T00:00:02Z",
      updated_at: "2026-05-22T00:00:03Z"
    };
    if (route.request().url().includes("/api/jobs/summary")) {
      return route.fulfill({
        json: {
          counts: { cancelled: 0, completed: 1, failed: 0, queued: 0, retry_wait: 0, running: 0 },
          active_count: 0,
          failed_count: 0,
          stale_count: 0,
          stale_job_ids: [],
          latest_failed_job: null,
          latest_successful_job: job,
          queue: { queued: 0, retry_wait: 0, running: 0, failed: 0 },
          worker: { enabled: false, status: "idle", worker_id: "test-worker", last_seen_at: "2026-05-22T00:00:03Z", current_job_id: null },
          health_status: "warning",
          warning_count: 1,
          recent_failure_count: 0,
          warnings: [{ code: "migration_drift", severity: "warning", message: "Database migration revision is not at Alembic head." }],
          retention_policy: {
            job_stale_after_minutes: 60,
            job_retention_days: 30,
            run_history_retention_days: 90,
            automatic_cleanup_enabled: false,
            raw_evidence_cleanup_enabled: false
          }
        }
      });
    }
    return route.fulfill({ json: [job] });
  });
  await page.route("**/api/sources**", async (route) => {
    const source = {
      source_id: 1,
      name: "local_import",
      source_type: "file_import",
      parser_profile: "palo_alto",
      host: null,
      port: null,
      enabled: true,
      last_seen: "2026-05-22T00:00:01Z",
      last_log_received_at: "2026-05-22T00:00:01Z",
      logs_received_count: 2,
      parse_success_count: 2,
      parse_failure_count: 0,
      latest_error: null,
      created_at: "2026-05-22T00:00:00Z",
      updated_at: "2026-05-22T00:00:01Z",
      health: {
        source_id: 1,
        status: "healthy",
        enabled: true,
        logs_received_count: 2,
        parse_success_count: 2,
        parse_failure_count: 0,
        parse_success_rate: 100,
        last_seen: "2026-05-22T00:00:01Z",
        last_log_received_at: "2026-05-22T00:00:01Z",
        latest_error: null,
        recommendation: "Healthy: logs recently received and parsed successfully.",
        warnings: []
      },
      quality: {
        raw_logs: 2,
        normalized_logs: 2,
        unknown_app_count: 0,
        unknown_app_rate: 0,
        alert_count: 1,
        parse_failure_examples: [],
        warnings: []
      },
      recent_ingestion_runs: [
        {
          run_id: 7,
          started_at: "2026-05-22T00:00:00Z",
          finished_at: "2026-05-22T00:00:01Z",
          source_type: "replay_direct",
          input_name: "paloalto-demo.txt",
          status: "completed",
          total_lines_received: 2,
          raw_logs_created: 2,
          parsed_successfully: 2,
          parse_failures: 0,
          duplicate_raw_logs: 0,
          alerts_created: 1,
          alerts_deduplicated: 1,
          alerts_suppressed: 0,
          runtime_seconds: 1,
          details: { source_id: 1 }
        }
      ],
      recent_detection_runs: [
        {
          run_id: 8,
          started_at: "2026-05-22T00:00:02Z",
          finished_at: "2026-05-22T00:00:03Z",
          detection_type: "hybrid",
          status: "completed",
          logs_evaluated: 2,
          alerts_created: 1,
          alerts_deduplicated: 1,
          alerts_suppressed: 0,
          top_attack_types: [{ name: "port_scan", count: 1 }],
          runtime_seconds: 1,
          details: { source_id: 1 }
        }
      ]
    };
    const rawFallbackSource = {
      source_id: 2,
      name: "scenario-raw-fallback",
      source_type: "sample",
      parser_profile: "raw_fallback",
      host: null,
      port: null,
      enabled: true,
      last_seen: "2026-05-22T00:02:01Z",
      last_log_received_at: "2026-05-22T00:02:01Z",
      logs_received_count: 3,
      parse_success_count: 0,
      parse_failure_count: 3,
      latest_error: "raw_fallback parser profile preserved raw evidence with limited structured fields",
      created_at: "2026-05-22T00:02:00Z",
      updated_at: "2026-05-22T00:02:01Z",
      health: {
        source_id: 2,
        status: "error",
        enabled: true,
        logs_received_count: 3,
        parse_success_count: 0,
        parse_failure_count: 3,
        parse_success_rate: 0,
        last_seen: "2026-05-22T00:02:01Z",
        last_log_received_at: "2026-05-22T00:02:01Z",
        latest_error: "raw_fallback parser profile preserved raw evidence with limited structured fields",
        recommendation: "Error: repeated parser failures. Pause response decisions from this source until format is reviewed.",
        warnings: ["Raw fallback preserves evidence but structured fields may be limited."]
      },
      quality: {
        raw_logs: 3,
        normalized_logs: 3,
        unknown_app_count: 3,
        unknown_app_rate: 100,
        alert_count: 0,
        parse_failure_examples: [{ raw_log_id: 21, error: "raw fallback preserved evidence", raw_line_excerpt: "not-a-firewall-line" }],
        warnings: ["Parser profile has limited structured fields."]
      },
      recent_ingestion_runs: [],
      recent_detection_runs: []
    };
    const url = route.request().url();
    await route.fulfill({
      json: url.match(/\/api\/sources\/2(\?|$)/) ? rawFallbackSource : url.match(/\/api\/sources\/1(\?|$)/) ? source : [source, rawFallbackSource]
    });
  });
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
            threat_positive: { precision: 0.9663, recall: 0.7653, f1: 0.8542 },
            per_class: {
              benign: { recall: 0 },
              suspicious: { recall: 0.4257 },
              malicious: { recall: 0.6256 }
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
        reviewed_label_distribution: { benign: 193, benign_unusual: 449, suspicious: 333, malicious: 331, needs_context: 19 },
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
          class_coverage: {
            benign: {
              label: "benign",
              total: 407,
              reviewed_total: 43,
              train_count: 407,
              test_count: 0,
              reviewed_train_count: 43,
              reviewed_test_count: 0,
              exists_in_train: true,
              exists_in_test: false
            },
            malicious: {
              label: "malicious",
              total: 315,
              reviewed_total: 315,
              train_count: 76,
              test_count: 239,
              reviewed_train_count: 76,
              reviewed_test_count: 239,
              exists_in_train: true,
              exists_in_test: true
            }
          },
          warnings: ["benign exists in training but not in the time-split test window."]
        },
        model_readiness_checklist: { status: "candidate_improved", passed: 6, total: 7, items: [], message: "candidate" },
        soc_triage_mode: {
          recommended_ai_mode: "SOC triage decision support",
          primary_signal: "threat_positive review priority",
          flat_5_class_status: "not_production_promoted",
          response_automation_allowed: false,
          production_promoted: false,
          limitations: [
            "Threat-positive triage is useful for analyst review.",
            "Exact class separation still needs review.",
            "Benign and needs_context exact classification remain weak.",
            "Response actions remain simulated and analyst-approved."
          ],
          review_profiles: [
            {
              profile: "conservative",
              precision: null,
              recall: null,
              false_positives: null,
              false_negatives: null,
              estimated_review_queue_size: null,
              guidance: "Fewer false positives and smaller review queue; run the final SOC report for measured profile metrics."
            },
            {
              profile: "balanced",
              precision: 0.9663,
              recall: 0.7653,
              f1: 0.8542,
              false_positives: 8,
              false_negatives: 23,
              estimated_review_queue_size: 245,
              guidance: "Default dashboard framing from the latest supervised run."
            },
            {
              profile: "recall_high",
              precision: null,
              recall: null,
              false_positives: null,
              false_negatives: null,
              estimated_review_queue_size: null,
              guidance: "Catches more threat-positive rows but increases analyst review queue; diagnostic only."
            }
          ]
        },
        decision_support_only: true
      }
    })
  );
  await page.route("**/api/dashboard/detection-ml-productization**", async (route) =>
    route.fulfill({
      json: {
        ok: true,
        phase: "v3.72",
        status: "completed",
        generated_at: "2026-06-27T08:00:00Z",
        read_only: true,
        readiness: {
          decision: "diagnostic_evaluation_passed",
          required_checks_passed: 5,
          required_checks_total: 5,
          advisory_checks_passed: 2,
          advisory_checks_total: 3,
          blockers: [],
          advisories: ["controlled scenario quality included"],
          production_ready: false,
          model_activation_allowed: false,
          response_automation_allowed: false
        },
        checks: [
          { name: "rule pack and scenario corpus contract passes", required: true, passed: true },
          { name: "current database unchanged by unified evaluation", required: true, passed: true },
          { name: "response automation remains disabled", required: true, passed: true }
        ],
        rule_contract: {
          ok: true,
          implemented_rule_count: 18,
          documented_rule_count: 18,
          registered_scenario_count: 24,
          issues: []
        },
        scenario_quality: {
          included: false,
          status: "skipped",
          recommendation: "Use --include-scenarios for temporary-DB controlled detection quality validation."
        },
        supervised_output_policy: {
          available: true,
          status: "decision_support_contract_ready",
          checks_passed: 7,
          checks_total: 7,
          recommended_supervised_strategy: "binary_soc_review_queue",
          exact_classification_policy: "explanation_or_ranking_only",
          dashboard_guidance_ready: true,
          runtime_activation_allowed: false,
          response_automation_allowed: false,
          blocked_uses: ["automatic response from supervised ML output"]
        },
        training_target_contract: {
          available: true,
          status: "safe_queue_target_adapter_ready",
          checks_passed: 5,
          checks_total: 5,
          recommended_training_target: "binary_soc_review_queue",
          exact_label_policy: "explanation_or_ranking_only",
          runtime_activation_allowed: false,
          production_promotion_allowed: false,
          response_automation_allowed: false
        },
        training_data: {
          available: true,
          mode: "lightweight_no_feature_generation",
          total_label_rows: 2672,
          trainable_label_rows: 2672,
          trainable_log_count_estimate: 2672,
          reviewed_label_rows: 1965,
          weak_or_unreviewed_label_rows: 707,
          feature_generation_ran: false
        },
        safety: {
          current_database_mutated: false,
          counts_before: { ml_labels: 2672, ml_model_runs: 41, response_actions: 0 },
          counts_after: { ml_labels: 2672, ml_model_runs: 41, response_actions: 0 },
          production_promoted: false,
          model_activated: false,
          model_artifact_written: false,
          labels_written: false,
          response_actions_created: 0,
          response_automation_allowed: false,
          real_firewall_blocking_enabled: false,
          raw_logs_included: false
        }
      }
    })
  );
  await page.route("**/api/dashboard/validation-summary", async (route) =>
    route.fulfill({
      json: {
        available: true,
        ok: true,
        generated_at: "2026-06-04T11:00:00Z",
        scenario_count: 14,
        passed_count: 14,
        failed_count: 0,
        failed_scenarios: [],
        latest_report_name: "detection_validation_20260604T110000Z.json",
        latest_markdown_name: "detection_validation_20260604T110000Z.md",
        latest_risk_calibration_name: "detection_validation_20260604T110000Z_risk_calibration.md",
        validation_scope: "controlled small-subnet / lab-scale threat detection validation",
        response_mode: "simulated analyst-approved only",
        production_readiness_claim: false,
        generalization: {
          available: true,
          ok: true,
          generated_at: "2026-06-05T01:00:00Z",
          scenario_count: 14,
          variant_count: 70,
          passed_count: 70,
          failed_count: 0,
          false_positive_count: 0,
          false_negative_count: 0,
          failed_families: [],
          latest_report_name: "detection_generalization_20260605T010000Z.json",
          latest_markdown_name: "detection_generalization_20260605T010000Z.md",
          validation_scope: "controlled synthetic detection generalization validation",
          use_temp_db: true,
          response_mode: "simulated analyst-approved only",
          production_readiness_claim: false,
          synthetic_variants_only: true
        },
        layered: {
          available: true,
          ok: true,
          generated_at: "2026-06-05T01:40:00Z",
          scenario_count: 14,
          variant_count: 42,
          mode_count: 4,
          mode_run_count: 168,
          passed_count: 168,
          failed_count: 0,
          false_positive_count: 0,
          false_negative_count: 0,
          mode_summary: [
            {
              mode: "rules_only",
              tests: 42,
              passed_count: 42,
              failed_count: 0,
              false_positive_count: 0,
              false_negative_count: 0,
              rule_contribution_count: 24,
              anomaly_contribution_count: 0,
              supervised_contribution_count: 0,
              hybrid_contribution_count: 0
            }
          ],
          latest_report_name: "layered_detection_20260605T014000Z.json",
          latest_markdown_name: "layered_detection_20260605T014000Z.md",
          validation_scope: "controlled layered detection contribution validation",
          use_temp_db: true,
          response_mode: "simulated analyst-approved only",
          production_readiness_claim: false
        },
        e2e_workflow: {
          available: true,
          ok: true,
          generated_at: "2026-06-05T02:00:00Z",
          scenario_count: 3,
          passed_count: 3,
          failed_count: 0,
          simulate_response: true,
          response_actions_created: 3,
          alert_count: 6,
          case_count: 3,
          latest_report_name: "e2e_workflow_validation_20260605T020000Z.json",
          latest_markdown_name: "e2e_workflow_validation_20260605T020000Z.md",
          validation_scope: "controlled end-to-end ATDR workflow validation",
          use_temp_db: true,
          response_mode: "simulated analyst-approved only",
          production_readiness_claim: false
        },
        reliability: {
          available: true,
          ok: true,
          scenario_count: 14,
          scenario_passed_count: 14,
          variant_count: 70,
          variant_passed_count: 70,
          mode_run_count: 168,
          mode_passed_count: 168,
          e2e_scenario_count: 3,
          e2e_passed_count: 3,
          false_positive_count: 0,
          false_negative_count: 0,
          alert_volume: 18,
          production_readiness_claim: false
        },
        benchmark: {
          available: true,
          ok: true,
          total_rows: 10,
          rows_mapped: 10,
          dataset_name: "benchmark_snapshot_demo",
          snapshot_id: "demo1234",
          detection_mode: "hybrid",
          precision: 1,
          recall: 1,
          f1: 1,
          threat_positive_f1: 1,
          false_positive_count: 0,
          false_negative_count: 0,
          alert_volume: 1,
          readiness_decision: "candidate_only",
          production_readiness_claim: false
        },
        v13_ai: {
          available: true,
          ok: true,
          reviewed_label_count: 1528,
          weak_label_count: 437,
          minimum_target_classes_met: 3,
          minimum_target_class_count: 5,
          minimum_label_gap: 44,
          best_candidate: "extra_trees",
          threat_positive_f1: 0.91,
          suspicious_recall: 0.75,
          malicious_recall: 0.6,
          readiness_decision: "analyst_review_eligible",
          production_status: "not_production_promoted",
          response_automation_allowed: false
        },
        v14_ai: {
          available: true,
          ok: true,
          best_strategy: "three_class_soc_triage",
          best_profile: "calibrated_low_noise",
          threat_positive_precision: 0.91,
          threat_positive_recall: 0.92,
          threat_positive_f1: 0.915,
          benign_like_false_positive_rate: 0.06,
          suspicious_recall: 0.95,
          malicious_recall: 0.7,
          calibration_status: "passed",
          readiness_decision: "analyst_review_eligible",
          production_promoted: false,
          response_automation_allowed: false,
          false_positives_improved: true,
          current_blocker: "malicious recall and calibration",
          quic_mitigation_status: "validated candidate; not activated",
          confirmed_noisy_pattern: "normal QUIC/443",
          quic_false_positive_count: 42,
          actionable_review_rows: 200,
          actionable_review_excludes_manual: true,
          malicious_recovery_review_rows: 150
        },
        v15_ai: {
          available: true,
          ok: true,
          benchmark_label_count: 240,
          benchmark_target_met: true,
          best_candidate: "hierarchical_two_stage_extra_trees",
          best_profile: "malicious_recall_recovery",
          threat_positive_f1: 0.91,
          threat_positive_recall: 0.92,
          benign_like_false_positive_rate: 0.08,
          suspicious_recall: 0.9,
          malicious_recall: 0.66,
          calibration_status: "passed",
          readiness_decision: "benchmark_validated_candidate",
          checks_passed: 8,
          checks_total: 8,
          production_promoted: false,
          model_activated: false,
          response_automation_allowed: false
        },
        v16_ai: {
          available: true,
          ok: true,
          external_label_count: 320,
          preferred_target_met: true,
          source_count: 5,
          scenario_count: 14,
          candidate_name: "v1_5_random_forest_three_class_transfer",
          threat_positive_f1: 0.7278,
          threat_positive_recall: 0.7471,
          benign_like_false_positive_rate: 0.3467,
          suspicious_recall: 0.35,
          malicious_recall: 0.8889,
          calibration_status: "weak",
          overfitting_status: "significant_generalization_gap",
          overfitting_warning: true,
          threat_f1_gap: 0.2722,
          readiness_decision: "internal_benchmark_validated_candidate",
          checks_passed: 4,
          checks_total: 8,
          external_benchmark_validated: false,
          production_promoted: false,
          model_activated: false,
          response_automation_allowed: false
        },
        v17_ai: {
          available: true,
          ok: true,
          external_label_count: 320,
          best_profile: "hybrid_external_balanced",
          threat_positive_precision: 0.9533,
          threat_positive_recall: 0.8412,
          threat_positive_f1: 0.8937,
          benign_like_false_positive_rate: 0.0467,
          suspicious_recall: 0.7875,
          malicious_recall: 0.7222,
          macro_f1: 0.8328,
          calibration_status: "weak",
          calibration_ece: 0.0867,
          calibration_brier: 0.0848,
          calibration_max_gap: 0.2246,
          queue_size: 150,
          cost_sensitive_total: 313,
          overfitting_status: "significant_generalization_gap",
          overfitting_warning: true,
          readiness_decision: "internal_benchmark_validated_candidate",
          checks_passed: 8,
          checks_total: 12,
          external_benchmark_validated: false,
          failed_checks: ["external_threat_positive_recall", "confidence_calibration", "external_suspicious_recall", "overfitting_gap_limited"],
          review_sample_rows: 300,
          production_promoted: false,
          model_activated: false,
          response_automation_allowed: false
        },
        v18_ai: {
          available: true,
          ok: true,
          external_label_count: 320,
          best_profile: "external_recall_plus",
          threat_positive_precision: 0.9568,
          threat_positive_recall: 0.9118,
          threat_positive_f1: 0.9338,
          benign_like_false_positive_rate: 0.0467,
          suspicious_recall: 0.9375,
          malicious_recall: 0.8556,
          macro_f1: 0.9201,
          weighted_f1: 0.9215,
          calibration_status: "passed",
          calibration_method: "bucket_smoothing",
          calibration_ece: 0.0118,
          calibration_brier: 0.0607,
          calibration_max_gap: 0.0418,
          queue_size: 162,
          overfitting_status: "moderate_generalization_gap",
          overfitting_warning: true,
          readiness_decision: "external_benchmark_validated_candidate",
          readiness_version: "v6",
          checks_passed: 12,
          checks_total: 12,
          external_benchmark_validated: true,
          failed_checks: [],
          baseline_false_negatives: 27,
          remaining_false_negatives: 15,
          recovered_false_negatives: 12,
          independent_revalidation_recommended: true,
          production_promoted: false,
          model_activated: false,
          response_automation_allowed: false
        },
        v19_ai: {
          available: true,
          ok: true,
          independent_label_count: 500,
          independent_source_count: 6,
          independent_scenario_count: 16,
          exact_overlap_rows: 0,
          best_profile: "external_recall_plus",
          threat_positive_precision: 0.8679,
          threat_positive_recall: 0.9346,
          threat_positive_f1: 0.9,
          benign_like_false_positive_rate: 0.1542,
          suspicious_recall: 0.9538,
          malicious_recall: 0.8769,
          macro_f1: 0.86,
          weighted_f1: 0.87,
          calibration_status: "passed",
          calibration_method: "isotonic",
          calibration_ece: 0.02,
          calibration_brier: 0.08,
          calibration_max_gap: 0.06,
          generalization_status: "significant_independent_gap",
          controlled_real_source_available: true,
          controlled_real_source_validated: true,
          readiness_decision: "external_benchmark_validated_candidate",
          readiness_version: "v7",
          checks_passed: 15,
          checks_total: 17,
          external_benchmark_validated: true,
          independent_holdout_validated: false,
          failed_checks: ["independent_benign_false_positive_rate", "performance_smoke_healthy"],
          production_promoted: false,
          model_activated: false,
          response_automation_allowed: false,
          real_firewall_blocking_enabled: false
        },
        v19b_ai: {
          available: true,
          ok: true,
          independent_label_count: 500,
          independent_source_count: 6,
          independent_scenario_count: 16,
          exact_overlap_rows: 0,
          best_profile: "independent_fpr_stabilized",
          threat_positive_precision: 0.917,
          threat_positive_recall: 0.9346,
          threat_positive_f1: 0.9257,
          benign_like_false_positive_rate: 0.0917,
          suspicious_recall: 0.9538,
          malicious_recall: 0.8769,
          macro_f1: 0.91,
          weighted_f1: 0.91,
          calibration_status: "passed",
          calibration_method: "bucket_smoothing",
          calibration_ece: 0.0027,
          calibration_brier: 0.0646,
          calibration_max_gap: 0.04,
          controlled_real_source_available: true,
          controlled_real_source_validated: true,
          readiness_decision: "controlled_real_source_validated_candidate",
          readiness_version: "v7b",
          checks_passed: 20,
          checks_total: 20,
          external_benchmark_validated: true,
          independent_holdout_validated: true,
          failed_checks: [],
          fpr_blocker_resolved: true,
          false_positives_reduced: 15,
          analyst_review_boundary_count: 15,
          minimum_false_positive_reduction_needed: 1,
          production_promoted: false,
          model_activated: false,
          response_automation_allowed: false,
          real_firewall_blocking_enabled: false
        },
        v20_ai: {
          available: true,
          ok: true,
          independent_label_count: 700,
          independent_source_count: 7,
          independent_scenario_count: 16,
          exact_overlap_rows: 0,
          near_overlap_rows: 335,
          best_profile: "independent_fpr_stabilized",
          candidate_hash: "abc123",
          threat_positive_precision: 0.8906,
          threat_positive_recall: 0.9459,
          threat_positive_f1: 0.9174,
          benign_like_false_positive_rate: 0.1303,
          suspicious_recall: 0.8556,
          malicious_recall: 0.9,
          macro_f1: 0.868,
          weighted_f1: 0.8753,
          calibration_status: "passed",
          calibration_method: "raw_confidence",
          calibration_ece: 0.0757,
          calibration_brier: 0.0751,
          calibration_max_gap: 0.1878,
          controlled_real_source_available: true,
          controlled_real_source_validated: true,
          readiness_decision: "final_controlled_validation_candidate",
          readiness_version: "v8",
          checks_passed: 22,
          checks_total: 22,
          external_benchmark_validated: true,
          independent_holdout_validated: true,
          fresh_blind_revalidated: true,
          final_controlled_validation_passed: true,
          threshold_tuning_performed: false,
          failed_checks: [],
          production_promoted: false,
          model_activated: false,
          response_automation_allowed: false,
          real_firewall_blocking_enabled: false
        },
        v330_detection_ml_quality: {
          available: true,
          ok: true,
          generated_at: "2026-06-22T07:49:25Z",
          split: "time",
          model_type: "random_forest",
          class_weight: "balanced",
          training_rows: 1870,
          test_rows: 802,
          baseline_profile: "balanced",
          baseline_threat_positive_precision: 0.5067,
          baseline_threat_positive_recall: 0.9913,
          baseline_threat_positive_f1: 0.6706,
          baseline_benign_like_false_positive_rate: 0.7211,
          baseline_suspicious_recall: 1.0,
          baseline_malicious_recall: 0.6835,
          baseline_macro_f1: 0.3139,
          baseline_weighted_f1: 0.294,
          best_profile: "low_noise_soc_queue",
          best_threat_positive_precision: 0.9488,
          best_threat_positive_recall: 0.5948,
          best_threat_positive_f1: 0.7312,
          best_benign_like_false_positive_rate: 0.024,
          best_suspicious_recall: 0.336,
          best_malicious_recall: 0.5642,
          best_review_queue_size_estimate: 215,
          calibration_status: "weak",
          calibration_ece: 0.3725,
          calibration_brier: 0.2385,
          calibration_max_gap: 0.4194,
          top_patterns: [
            ["app=quic-base|action=allow|port=443", 312],
            ["app=incomplete|action=allow|port=80", 37]
          ],
          review_sample: { generated: true, rows: 200, path: "ml_baseline_reviews/v3_30_detection_quality_review_sample.csv" },
          readiness_decision: "candidate_only",
          checks_passed: 2,
          checks_total: 6,
          blockers: ["benign-like false-positive rate within target"],
          production_promoted: false,
          model_activated: false,
          response_automation_allowed: false,
          real_firewall_blocking_enabled: false,
          diagnostic_only: true
        },
        v355_soc_queue: {
          available: true,
          ok: true,
          generated_at: "2026-06-23T17:00:06Z",
          phase: "v3.55",
          best_strategy: "binary_review_queue_queue_only",
          policy_name: "binary_review_queue",
          policy_description: "Only model whether a row enters the SOC review queue.",
          recommended_use: "diagnostic_soc_review_queue_score",
          exact_severity_status: "explanation_or_ranking_only",
          evaluated_splits: 5,
          passing_splits: 5,
          split_stability_passed: true,
          queue_f1_min: 0.9725,
          queue_f1_max: 0.9962,
          queue_recall_min: 0.948,
          queue_precision_min: 0.9907,
          benign_like_false_positive_rate_max: 0.04,
          critical_recall_min: 0.948,
          macro_f1_min: 0.7481,
          weighted_f1_min: 0.9589,
          calibration_status: "passed",
          calibration_ece: 0.007,
          calibration_brier: 0.0224,
          calibration_max_gap: 0.0224,
          threshold_selected_on: ["train_internal_calibration"],
          readiness_decision: "candidate_only",
          checks_passed: 10,
          checks_total: 10,
          blockers: [],
          production_promoted: false,
          model_activated: false,
          model_artifact_written: false,
          labels_written: false,
          response_automation_allowed: false,
          diagnostic_only: true
        },
        v357_queue_evidence_agreement: {
          available: true,
          ok: true,
          generated_at: "2026-06-24T10:20:00Z",
          phase: "v3.57",
          policy_name: "binary_review_queue",
          recommended_use: "diagnostic_queue_rule_hybrid_agreement_review",
          evaluated_splits: 5,
          passing_splits: 4,
          queue_f1_min: 0.9725,
          queue_recall_min: 0.948,
          queue_precision_min: 0.9907,
          queue_false_positive_rate_max: 0.04,
          agreement_rate_min: 0.884,
          agreement_rate_max: 0.9888,
          calibration_ece_max: 0.0137,
          category_counts: {
            queue_and_evidence_agree_review: 3376,
            evidence_only_review: 310,
            queue_and_evidence_agree_non_review: 324
          },
          top_evidence_only_patterns: [["app=quic-base|action=allow|port=443", 71]],
          top_queue_only_patterns: [],
          aggregate_blockers: ["grouped_stratified: evidence-only review rate above 0.10"],
          readiness_decision: "diagnostic_only",
          checks_passed: 7,
          checks_total: 8,
          blockers: ["evidence-only misses remain reviewable"],
          production_promoted: false,
          model_activated: false,
          model_artifact_written: false,
          labels_written: false,
          raw_logs_included: false,
          response_automation_allowed: false,
          diagnostic_only: true
        },
        v359_supervised_output_policy: {
          available: true,
          ok: true,
          generated_at: "2026-06-24T11:20:00Z",
          phase: "v3.59",
          decision: "decision_support_contract_ready",
          contract_ready_for_runtime_activation: false,
          contract_ready_for_dashboard_guidance: true,
          recommended_supervised_strategy: "binary_soc_review_queue",
          exact_classification_policy: "explanation_or_ranking_only",
          checks_passed: 7,
          checks_total: 7,
          blockers: [],
          queue_status: "stable",
          queue_readiness_decision: "candidate_only",
          queue_evaluated_splits: 5,
          queue_passing_splits: 5,
          queue_f1_min: 0.9725,
          queue_recall_min: 0.948,
          queue_precision_min: 0.9907,
          queue_benign_like_false_positive_rate_max: 0.04,
          queue_calibration_status: "passed",
          queue_calibration_ece: 0.007,
          agreement_status: "usable_with_review",
          agreement_readiness_decision: "diagnostic_only",
          agreement_evaluated_splits: 5,
          agreement_passing_splits: 4,
          agreement_rate_min: 0.884,
          agreement_fpr_max: 0.04,
          exact_severity_status: "unstable",
          exact_stable_policy_count: 0,
          exact_evaluated_policy_count: 6,
          allowed_output_statuses: {
            soc_review_queue_score: "allowed_for_decision_support",
            exact_severity_or_attack_label: "explanation_or_ranking_only",
            rule_hybrid_evidence: "primary_detection_evidence"
          },
          blocked_uses: [
            "automatic response from supervised ML output",
            "real firewall blocking from supervised ML output",
            "marking AI-generated labels as human-reviewed"
          ],
          production_promoted: false,
          model_activated: false,
          model_artifact_written: false,
          labels_written: false,
          raw_logs_included: false,
          response_automation_allowed: false,
          real_firewall_blocking_enabled: false,
          diagnostic_only: true
        },
        v30_production_readiness: {
          available: true,
          status: "real_source_pilot_ready",
          version: "v9",
          checks_passed: 8,
          checks_total: 11,
          production_ready: false,
          production_readiness_claim: false,
          production_promoted: false,
          model_activated: false,
          response_automation_allowed: false,
          real_firewall_blocking_enabled: false,
          real_source_pilot_validated: false,
          real_device_forwarding_validated: false,
          simulated_source_pilot_status: "validated",
          simulated_source_validated: true,
          simulated_source: {
            status: "validated",
            simulated_source_validated: true,
            real_device_forwarding_validated: false,
            source_name: "lab-firewall-sim-1",
            source_health: "warning",
            raw_logs: 100,
            normalized_logs: 100,
            parse_success_count: 97,
            parse_failure_count: 3,
            detection_runs: 1
          },
          postgres_lab_validated: false,
          postgres_lab_status: "blocked_by_environment",
          database_kind: "sqlite",
          sqlite_local_workflow_valid: true,
          backup_restore_validated: false,
          backup_restore_status: "planned",
          production_doctor_status: "warnings",
          production_doctor_blockers: [],
          production_doctor_warnings: ["Real-device pilot pending."],
          docs: {
            gap_assessment: true,
            real_device_pilot: true,
            postgres_lab: true,
            postgres_shared_lab_readiness: true,
            backup_restore_retention: true,
            observability: true,
            ml_monitoring: true,
            track: true
          },
          message: "v3.0 is a production-readiness track gate."
        },
        drift: {
          available: true,
          ok: true,
          recent_rows: 1000,
          baseline_rows: 5000,
          unknown_app_rate: 0.05,
          parse_failure_rate: 0,
          alert_rate: 0.02,
          warning_count: 0,
          production_readiness_claim: false
        }
      }
    })
  );
  await page.route("**/api/ml/supervised/models", async (route) =>
    route.fulfill({
      json: {
        active_artifact_exists: false,
        response_automation_allowed: false,
        models: [
          {
            model_id: 1,
            model_type: "random_forest",
            model_version: "candidate-smoke",
            operation: "train_supervised",
            readiness_decision: "eligible_for_analyst_review",
            metrics: { f1: 0.72 },
            created_at: "2026-05-22T00:00:00Z",
            is_active_path: false
          }
        ]
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
  await page.route("**/api/ml/stage1-threat-recall-review/export**", async (route) =>
    route.fulfill({
      body: "log_id,timestamp,source,src_ip,dst_ip,dst_port,app,action,current_label,reviewed_status,model_prediction,threat_positive_score,rule_evidence,anomaly_score,hybrid_risk,reason_selected,evidence_summary,human_review_decision,human_review_attack_type,human_review_confidence,human_review_note\n1,2026-05-20T00:00:00Z,smoke,198.51.100.7,10.0.0.1,995,incomplete,allow,suspicious,true,benign,0.22,rule_score=45,-0.1,71,Stage 1 false negative,test,,unknown_anomaly,3,\n",
      headers: { "content-type": "text/csv", "content-disposition": 'attachment; filename="stage1-threat-recall-review-sample.csv"' }
    })
  );
  await page.route("**/api/ml/benign-final-gap-review/export**", async (route) =>
    route.fulfill({
      body: "log_id,timestamp,source,src_ip,dst_ip,dst_port,app,action,current_label,reviewed_status,model_prediction,benign_probability,threat_positive_probability,reason_selected,evidence_summary,human_review_decision,human_review_attack_type,human_review_confidence,human_review_note\n1,2026-05-20T00:00:00Z,smoke,10.0.0.5,203.0.113.1,443,ssl,allow,benign,true,suspicious,0.18,0.42,benign/suspicious boundary,test,,normal,3,\n",
      headers: { "content-type": "text/csv", "content-disposition": 'attachment; filename="benign-needs-context-final-gap-sample.csv"' }
    })
  );
  await page.route("**/api/ml/final-small-label-gap/export**", async (route) =>
    route.fulfill({
      body: "log_id,timestamp,source,src_ip,dst_ip,dst_port,app,action,current_label,reviewed_status,model_prediction,benign_probability,threat_positive_probability,reason_selected,evidence_summary,human_review_decision,human_review_attack_type,human_review_confidence,human_review_note\n1,2026-05-20T00:00:00Z,smoke,10.0.0.5,203.0.113.1,443,ssl,allow,benign,true,suspicious,0.18,0.42,final benign gap,test,,normal,3,\n",
      headers: { "content-type": "text/csv", "content-disposition": 'attachment; filename="final-small-label-gap-sample.csv"' }
    })
  );
  await page.route("**/api/ml/soc-triage-final-recommendation/export**", async (route) =>
    route.fulfill({
      body: "# SOC Triage Final Recommendation\n\nRecommended AI mode: SOC triage decision support.\n",
      headers: { "content-type": "text/markdown", "content-disposition": 'attachment; filename="soc-triage-final-recommendation.md"' }
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
        class_coverage: {
          benign: {
            label: "benign",
            total: 407,
            reviewed_total: 43,
            train_count: 407,
            test_count: 0,
            reviewed_train_count: 43,
            reviewed_test_count: 0,
            exists_in_train: true,
            exists_in_test: false
          },
          malicious: {
            label: "malicious",
            total: 315,
            reviewed_total: 315,
            train_count: 76,
            test_count: 239,
            reviewed_train_count: 76,
            reviewed_test_count: 239,
            exists_in_train: true,
            exists_in_test: true
          }
        },
        warnings: ["benign exists in training but not in the time-split test window."]
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
  await page.route("**/api/users/dev-email-outbox**", async (route) => route.fulfill({ json: [] }));
  await page.route("**/api/users/*/send-verification", async (route) =>
    route.fulfill({
      json: {
        created: false,
        status: "disabled",
        message: "Email verification is disabled; no token was created.",
        user_id: 1,
        email: "admin@school.example",
        expires_at: null,
        delivery_mode: "disabled",
        delivery_status: "disabled",
        outbox_id: null
      }
    })
  );
  await page.route("**/api/users", async (route) =>
    route.fulfill({
      json: [
        {
          id: 1,
          username: "admin",
          email: "admin@school.example",
          full_name: "Admin",
          role: "admin",
          is_active: true,
          email_verified: true,
          auth_provider: "local",
          external_subject: null,
          last_login_at: "2026-05-22T00:00:00Z",
          invited_at: null,
          disabled_at: null,
          created_at: "2026-05-22T00:00:00Z"
        }
      ]
    })
  );
  await page.route("**/api/demo/import-sample", async (route) =>
    {
      const body = JSON.parse(route.request().postData() || "{}") as { limit?: number | null; sample_path?: string | null };
      const source = body.sample_path ? String(body.sample_path).split(/[\\/]/).pop() || "custom.log" : "paloalto-demo.txt";
      const available = body.sample_path ? Number(body.limit ?? 1000) : 2;
      return route.fulfill({
        json: {
          source,
          source_label: source,
          sample_file: source,
          requested_limit: body.limit ?? null,
          available_lines: available,
          imported: Math.min(Number(body.limit ?? available), available),
          raw_logs_imported: Math.min(Number(body.limit ?? available), available),
          normalized_logs_created: Math.min(Number(body.limit ?? available), available),
          parsed: Math.min(Number(body.limit ?? available), available),
          parsed_successfully: Math.min(Number(body.limit ?? available), available),
          failed: 0,
          parse_failures: 0,
          duplicate_raw_logs: 0,
          alerts_created: 0,
          alerts_deduplicated: 0,
          run_id: 7,
          source_id: 1,
          safe_sample_note: body.sample_path
            ? null
            : "Sample file paloalto-demo.txt contains 2 non-empty log lines. To test a larger import, choose a larger sample file or use replay_logs --sample-path <path>."
        }
      });
    }
  );
  await page.route("**/api/demo/run-detection", async (route) =>
    route.fulfill({ json: { logs_evaluated: 1000, created_alerts: 4, deduplicated_alert_updates: 2, suppressed_alerts: 0, detection_run_id: 8 } })
  );
  await page.route("**/api/demo/train-ml", async (route) =>
    route.fulfill({
      json: {
        trained: true,
        status: "trained",
        training_log_count: 1000,
        contamination: 0.02,
        model_type: "IsolationForest",
        model_path: "C:\\Users\\User\\Desktop\\ATDR\\models\\very\\long\\windows\\path\\isolation_forest.joblib",
        feature_columns: Array.from({ length: 80 }, (_, index) => `very_long_feature_name_${index}_with_more_text_to_force_wrapping`),
        feature_summary: {
          huge: Array.from({ length: 60 }, (_, index) => ({ feature: `feature_${index}`, value: `long-value-${index}` }))
        }
      }
    })
  );
  await page.route("**/api/demo/apply-ml", async (route) =>
    route.fulfill({ json: { scored: 1000, anomalies: 14, anomaly_rate: 1.4, model_path: "models/isolation_forest.joblib" } })
  );
  await page.route("**/api/demo/export-bundle", async (route) =>
    route.fulfill({
      json: {
        export_dir: "C:\\Users\\User\\Desktop\\ATDR\\demo_exports\\atdr_demo_bundle_with_a_very_long_name",
        files: { "dashboard_summary.json": "...", "ml_evaluation.json": "..." },
        counts: { total_logs: 1200, total_alerts: 12 }
      }
    })
  );
}

async function chooseSafeSelect(page: Page, ariaLabel: string, optionName: string) {
  await page.getByRole("button", { name: ariaLabel }).click();
  await expect(page.locator('[data-atdr-dropdown-open="true"]')).toHaveCount(1);
  await page.getByRole("option", { name: optionName, exact: true }).click();
  await expect(page.locator('[data-atdr-dropdown-open="true"]')).toHaveCount(0);
}

test("login page loads", async ({ page }) => {
  await page.route("**/api/auth/me", (route) => route.fulfill({ status: 401, json: { detail: "Not authenticated" } }));
  await page.goto("/login");
  await expect(page.getByText("MFU ATDR SOC Console")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeVisible();
});

test("legacy browser credential query is blocked and removed", async ({ page }) => {
  await page.route("**/api/auth/me", (route) => route.fulfill({ status: 401, json: { detail: "Not authenticated" } }));
  await page.route("**/api/auth/mfu-iam/public-status", async (route) =>
    route.fulfill({
      json: {
        enabled: true,
        b2b_ready: false,
        mock_enabled: false,
        template_shell_enabled: true,
        template_shell_ready: true,
        handoff_enabled: true,
        handoff_ready: true,
        google_sso_enabled: false,
        google_client_id_configured: false,
        allowed_domains: ["lamduan.mfu.ac.th"],
        domain_hints: ["lamduan.mfu.ac.th"],
        default_role: "analyst",
        auth_require_2fa: true,
        mode: "template_shell_secure_handoff",
        secrets_exposed: false
      }
    })
  );
  await page.goto("/login?mfu_token=tiny-token&next=/assistant");

  await expect(page.getByText("A legacy browser-token handoff was blocked. Start from the approved MFU application shell.")).toBeVisible();
  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
  expect(page.url()).not.toContain("tiny-token");
  expect(page.url()).not.toContain("mfu_token");
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
  await expect(page.getByText("Controlled Validation", { exact: true })).toBeVisible();
  await expect(page.getByText("Validation reports")).toBeVisible();
  await page.getByText("Validation reports").click();
  await expect(page.getByText("Generalization", { exact: true })).toBeVisible();
  await expect(page.getByText("70/70 variants")).toBeVisible();
  await expect(page.getByText("FP 0 | FN 0")).toHaveCount(3);
  await expect(page.getByText("Layered Modes")).toBeVisible();
  await expect(page.getByText("168/168 mode runs")).toBeVisible();
  await expect(page.getByText("E2E Workflow")).toBeVisible();
  await expect(page.getByText("3/3 passed")).toBeVisible();
  await expect(page.getByText("Reliability")).toBeVisible();
  await expect(page.getByText("14/14 scenarios")).toBeVisible();
  await expect(page.getByText("Benchmark", { exact: true })).toBeVisible();
  await expect(page.getByText("700 fresh blind | F1 0.9174")).toBeVisible();
  await expect(page.getByText("Drift", { exact: true })).toBeVisible();
  await expect(page.getByText("0 warnings")).toBeVisible();
  await expect(page.getByText("Lab-Scale Validation")).toBeVisible();
  await expect(page.getByText("Manual Approval Required", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Final Controlled Validation Candidate", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Real device validation remains future work.")).not.toBeVisible();
  await expect(page.getByText("Operations Health")).toBeVisible();
  await expect(page.getByTestId("operational-warnings")).toContainText("Database migration revision is not at Alembic head.");
  await expect(page.getByText("Log Sources")).toBeVisible();
  await expect(page.getByText("local_import")).toBeVisible();
  await expect(page.getByRole("button", { name: /scenario-raw-fallback/ })).toBeVisible();
  await page.getByText("local_import").click();
  await expect(page.getByText("Parser Profile", { exact: true })).toBeVisible();
  await expect(page.getByText("Troubleshooting Hints")).toBeVisible();
  await expect(page.getByText("Parser profile behavior")).toBeVisible();
  await expect(page.getByText("Recent Detection Runs")).toBeVisible();
  await expect(page.getByText("Run attack types: port_scan (1)")).toBeVisible();
  await page.getByRole("button", { name: "Close details" }).click();
  await page.getByRole("button", { name: /scenario-raw-fallback/ }).click();
  await expect(page.getByText("Raw fallback preserves evidence but structured fields may be limited.")).toBeVisible();
  await expect(page.getByText("raw fallback preserved evidence")).toBeVisible();
  await page.getByRole("button", { name: "Close details" }).click();
  await expect(page.getByText("Latest Ingestion Run")).toBeVisible();
  await expect(page.getByText("Latest Detection Run")).toBeVisible();
  await expect(page.getByText("Active Jobs")).toBeVisible();
  await expect(page.getByTestId("operation-queue-panel")).toContainText("0 queued / 0 running");
  await expect(page.getByTestId("operation-queue-panel")).toContainText("idle");
  await expect(page.getByText("Stale Jobs")).toBeVisible();
  await expect(page.getByText("Response Mode")).toBeVisible();
  await expect(page.getByText("Config: local lab profile")).toBeVisible();

  await page.goto("/ml");
  await expect(page.getByRole("heading", { name: "Model status and review operations" })).toBeVisible();
  await expect(page.getByText("Controlled Validation", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Current AI governance snapshot")).toBeVisible();
  await expect(page.getByText("Threat F1", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("0.9174", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Benign FPR")).toBeVisible();
  await expect(page.getByText("0.1303", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Macro F1")).toBeVisible();
  await expect(page.getByText("0.868", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Weighted F1")).toBeVisible();
  await expect(page.getByText("0.8753", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Review focus: benign and suspicious separation need more analyst-verified examples.")).not.toBeVisible();
  await expect(page.getByTestId("detection-ml-productization-panel")).toContainText("Detection / ML Productization");
  await expect(page.getByTestId("detection-ml-productization-panel")).toContainText("diagnostic evaluation passed");
  await expect(page.getByTestId("detection-ml-productization-panel")).toContainText("18 implemented rules");
  await expect(page.getByText("Detection Quality Revalidation")).toBeVisible();
  await expect(page.getByText("False-positive noise")).toBeVisible();
  await expect(page.getByText("Baseline FPR")).toBeVisible();
  await expect(page.getByText("0.7211", { exact: true })).toBeVisible();
  await expect(page.getByText("low noise soc queue", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("weak", { exact: true }).first()).toBeVisible();
  await page.getByText("View v3.30 diagnostic notes").click();
  await expect(page.getByText(/estimated queue\s*215/)).toBeVisible();
  await expect(page.getByText("app=quic-base|action=allow|port=443").first()).toBeVisible();
  await expect(page.getByText("SOC Review Queue Diagnostic")).toBeVisible();
  await expect(page.getByText("5/5 splits")).toBeVisible();
  await expect(page.getByText("Queue F1 Min").first()).toBeVisible();
  await expect(page.locator(".panel").filter({ hasText: "Queue F1 Min" }).filter({ hasText: "0.9725" }).first()).toBeVisible();
  await expect(page.locator(".panel").filter({ hasText: "FPR Max" }).first()).toBeVisible();
  await expect(page.locator(".panel").filter({ hasText: "FPR Max" }).filter({ hasText: "0.04" }).first()).toBeVisible();
  await page.getByText("View v3.55 queue diagnostic notes").click();
  await expect(page.getByText("binary_review_queue_queue_only")).toBeVisible();
  await expect(page.getByText("explanation or ranking only").first()).toBeVisible();
  await expect(page.getByText("train_internal_calibration")).toBeVisible();
  await expect(page.getByText("Queue / Evidence Agreement")).toBeVisible();
  await expect(page.getByText("4/5 splits")).toBeVisible();
  await expect(page.getByText("Agreement Min", { exact: true })).toBeVisible();
  await expect(page.locator(".panel").filter({ hasText: "Agreement Min" }).filter({ hasText: "0.884" }).first()).toBeVisible();
  await expect(page.getByText("Evidence-Only", { exact: true })).toBeVisible();
  await expect(page.getByText("310", { exact: true })).toBeVisible();
  await page.getByText("View queue/evidence disagreement notes").click();
  await expect(page.getByText("app=quic-base|action=allow|port=443").nth(1)).toBeVisible();
  await expect(page.getByText("evidence-only misses remain reviewable")).toBeVisible();
  await expect(page.getByText("Supervised Output Policy")).toBeVisible();
  await expect(page.getByText("Queue scoring is decision support. Exact labels stay explanation/ranking only.")).toBeVisible();
  await expect(page.getByText("binary soc review queue")).toBeVisible();
  await expect(page.getByText("Explanation Only")).toBeVisible();
  await expect(page.getByText("activation disabled")).toBeVisible();
  await page.getByText("View supervised output contract").click();
  await expect(page.getByText("automatic response from supervised ML output")).toBeVisible();
  await expect(page.getByText(/Stable policies\s*0\/6/)).toBeVisible();
  await page.getByText("Technical validation details").click();
  await expect(page.getByText(/1528 reviewed \| minimum gaps 44/)).toBeVisible();
  await expect(page.getByText("Recommended AI Mode")).toBeVisible();
  await expect(page.getByText("SOC triage decision support")).toBeVisible();
  await expect(page.getByText("SOC Triage Mode")).toBeVisible();
  await expect(page.getByText("Analyst Review", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Manual Approval Required", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Response Automation Disabled", { exact: true }).first()).toBeVisible();
  await expect(
    page.getByText(/Main blocker:\s*No v2.0 metric blocker; real hardware validation remains future work/),
  ).toBeVisible();
  await expect(page.getByText(/Calibration:\s*passed \/ raw_confidence/)).toBeVisible();
  await expect(
    page.getByText(/700 independent rows \| Threat F1 0.9174 \| final_controlled_validation_candidate/),
  ).toBeVisible();
  await expect(page.getByText("Fresh blind readiness v8 22/22")).toBeVisible();
  await expect(page.getByText(/fresh blind passed \| FPR 0.1303/)).toBeVisible();
  await expect(page.getByText("v1.8 external benchmark passed")).toBeVisible();
  await expect(page.getByText(/Current blockers:\s*none/)).toBeVisible();
  await expect(page.getByText(/Fresh blind holdout:\s*700 rows \| 7 sources \| passed/)).toBeVisible();
  await expect(page.getByText(/Validation profile:\s*independent_fpr_stabilized/)).toBeVisible();
  await expect(page.getByText(/Fresh blind metrics:\s*F1 0.9174 \| Recall 0.9459 \| FPR 0.1303/)).toBeVisible();
  await expect(page.getByText(/Controlled source:\s*validated in safe replay\/source workflow/)).toBeVisible();
  await expect(
    page.getByText(/Review boundary:\s*15 ambiguous rows routed to analyst review; 15 false positives removed/),
  ).toBeVisible();
  await expect(
    page.getByText(/Final controlled validation:\s*passed; candidate remains decision support only/),
  ).toBeVisible();
  await expect(page.getByText("Decision Support Only", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Response Automation Disabled", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Import Benchmark Review CSV")).toBeVisible();
  await page.getByText("CSV import rules").click();
  await expect(page.getByText(/Files containing `benchmark_row_id` must use Benchmark Review Import/)).toBeVisible();
  await expect(page.getByText(/Confirmed noisy pattern:\s*normal QUIC\/443/)).toBeVisible();
  await expect(page.getByText(/False positives:\s*improved/)).toBeVisible();
  await expect(page.getByText(/QUIC\/443 mitigation:\s*validated candidate; not activated/)).toBeVisible();
  await expect(page.getByText("Actionable review sample excludes protected manual labels", { exact: true })).toBeVisible();
  await expect(page.getByText("Model remains decision support only", { exact: true })).toBeVisible();
  await expect(page.getByText("Response automation disabled", { exact: true })).toBeVisible();
  await expect(page.getByText("Not Production Promoted", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Final Controlled Validation Candidate", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Technical Review Notes")).not.toBeVisible();
  await page.getByText("Model validation diagnostics").click();
  await expect(page.getByText("Technical Review Notes")).toBeVisible();
  await page.getByText("Technical Review Notes").click();
  await expect(page.getByText("Malicious reviewed target is met; do not prioritize malicious-heavy review unless evidence is strong.")).toBeVisible();
  await expect(page.getByText("Suspicious reviewed target is met; continue only focused boundary cleanup.")).toBeVisible();
  await expect(page.getByText("Benign labels are under-reviewed.")).toBeVisible();
  await expect(page.getByText("Needs_context labels are under-reviewed.")).toBeVisible();
  await expect(page.getByText("Benign recall is the current blocker")).toBeVisible();
  await expect(page.getByText("Stage 1 threat-positive recall still needs calibration.")).toBeVisible();
  await expect(page.getByText("Stage 2 suspicious/malicious separation is promising, but Stage 1 must catch threat-positive rows first.")).toBeVisible();
  await expect(page.getByText("Current time split has class imbalance; metrics are unstable.")).toBeVisible();
  await expect(page.getByText("Model remains decision support only.")).toBeVisible();
  await expect(page.getByText("Analyst Review Gate")).toBeVisible();
  await expect(page.getByText("Weak labels require analyst review before model claims.")).toBeVisible();
});

test("deep-linked alert and log drawers render", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/alerts?alert=1");
  await expect(page.getByRole("heading", { name: "Critical: Smoke alert" })).toBeVisible();
  await expect(page.getByText("Why flagged?")).toBeVisible();
  await expect(page.getByText("Supervised Triage Signal")).toBeVisible();
  await expect(page.getByText("Review priority only; not automatic truth.")).toBeVisible();
  await expect(page.getByText("ML output is decision support.")).toBeVisible();
  await expect(page.getByText("Alert Occurrences")).toBeVisible();
  await expect(page.getByText("Related Log Count")).toBeVisible();
  await expect(page.getByText("Grouped alert metadata")).toBeVisible();
  await expect(page.getByText("Discovery / Network Service Discovery (T1046)")).toBeVisible();
  await page.getByRole("link", { name: "Ask Assistant", exact: true }).first().click();
  await expect(page).toHaveURL(/\/assistant\?alert=1/);
  await expect(page.getByLabel("Analyst question")).toHaveValue("Explain alert 1 and what an analyst should check next.");
  await expect(page.getByText("Alert context #1")).toBeVisible();
  await page.goto("/alerts");
  await page.getByText("Active Case Grouping").click();
  await page.getByRole("link", { name: "Ask Assistant about case" }).click();
  await expect(page).toHaveURL(/\/assistant\?case=smoke-case/);
  await expect(page.getByText("Case context smoke-case")).toBeVisible();
  await page.goto("/alerts?alert=1");
  await page.getByRole("link", { name: "Ask Assistant", exact: true }).nth(1).click();
  await expect(page).toHaveURL(/\/assistant\?alert=1&log=1/);
  await expect(page.getByText("Alert context #1")).toBeVisible();
  await expect(page.getByText("Log context #1")).toBeVisible();
  await page.goto("/logs?log=1");
  await expect(page.getByText("Why flagged?")).toBeVisible();
  await expect(page.getByText("Linked alert evidence exists for this normalized log.")).toBeVisible();
  await expect(page.getByRole("link", { name: "Ask Assistant about this log" })).toBeVisible();
  await page.getByRole("link", { name: "Ask Assistant about this log" }).click();
  await expect(page).toHaveURL(/\/assistant\?log=1/);
  await expect(page.getByText("Log context #1")).toBeVisible();
  await page.goto("/logs?log=1");
  await expect(page.getByText("Decision Support", { exact: true })).toBeVisible();
  await expect(page.getByText("Automation Disabled", { exact: true })).toBeVisible();
  await expect(page.getByText("Analyst ML Label")).toBeVisible();
  await expect(page.getByText("Raw Evidence", { exact: true })).toBeVisible();
});

test("operations queue shows safe queued-job cancellation", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  let cancelled = false;
  const queuedJob = {
    job_id: 91,
    job_type: "run_detection",
    status: "queued",
    requested_by: "admin",
    started_at: null,
    finished_at: null,
    progress_current: 0,
    progress_total: 1,
    result_summary: {},
    error_summary: null,
    related_ingestion_run_id: null,
    related_detection_run_id: null,
    related_ml_model_run_id: null,
    attempt_count: 0,
    max_attempts: 1,
    next_attempt_at: "2026-05-22T00:00:03Z",
    lease_expires_at: null,
    can_cancel: !cancelled,
    can_retry: false,
    details: { limit: 100 },
    created_at: "2026-05-22T00:00:02Z",
    updated_at: "2026-05-22T00:00:03Z"
  };
  await page.route("**/api/jobs**", async (route) => {
    const url = route.request().url();
    if (route.request().method() === "POST" && url.includes("/91/cancel")) {
      cancelled = true;
      return route.fulfill({ json: { ...queuedJob, status: "cancelled", finished_at: "2026-05-22T00:00:04Z", can_cancel: false } });
    }
    if (url.includes("/api/jobs/summary")) {
      return route.fulfill({
        json: {
          counts: { cancelled: cancelled ? 1 : 0, completed: 0, failed: 0, queued: cancelled ? 0 : 1, retry_wait: 0, running: 0 },
          active_count: cancelled ? 0 : 1,
          failed_count: 0,
          stale_count: 0,
          stale_job_ids: [],
          latest_failed_job: null,
          latest_successful_job: null,
          queue: { queued: cancelled ? 0 : 1, retry_wait: 0, running: 0, failed: 0 },
          worker: { enabled: false, status: "idle", worker_id: "test-worker", last_seen_at: "2026-05-22T00:00:03Z", current_job_id: null },
          retention_policy: {}
        }
      });
    }
    return route.fulfill({ json: [{ ...queuedJob, status: cancelled ? "cancelled" : "queued", can_cancel: !cancelled }] });
  });

  await page.goto("/overview");
  await page.getByText("Recent Run History").click();
  const cancel = page.getByLabel("Cancel operation job 91");
  await expect(cancel).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept());
  await cancel.click();
  await expect(cancel).not.toBeVisible();
  await expect(page.getByTestId("operation-queue-panel")).toContainText("0 queued / 0 running");
});

test("resumable import progress and admin controls stay compact", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  let resumed = false;
  const importJob = {
    job_id: 193,
    job_type: "import_logs",
    status: "failed",
    requested_by: "admin",
    started_at: "2026-07-13T10:00:00Z",
    finished_at: "2026-07-13T10:00:03Z",
    progress_current: 500,
    progress_total: 2000,
    progress_percentage: 25,
    checkpoint_line: 500,
    checkpoint_bytes: 125000,
    checkpoint_at: "2026-07-13T10:00:02Z",
    chunk_commits: 1,
    cancellation_requested: false,
    resume_eligible: true,
    resume_ineligible_reason: null,
    resume_of_job_id: null,
    original_job_id: 193,
    resume_expires_at: "2026-07-14T10:00:00Z",
    result_summary: {},
    error_summary: "Worker interruption after a committed checkpoint.",
    attempt_count: 1,
    max_attempts: 1,
    can_cancel: false,
    can_retry: false,
    can_resume: true,
    details: { input_name: "firewall.log" },
    created_at: "2026-07-13T10:00:00Z",
    updated_at: "2026-07-13T10:00:03Z"
  };
  await page.route("**/api/jobs**", async (route) => {
    const url = route.request().url();
    if (route.request().method() === "POST" && url.includes("/193/resume")) {
      resumed = true;
      return route.fulfill({ json: { ...importJob, job_id: 194, status: "queued", can_resume: false, resume_of_job_id: 193 } });
    }
    if (url.includes("/api/jobs/summary")) {
      return route.fulfill({
        json: {
          counts: { failed: 1, queued: resumed ? 1 : 0, retry_wait: 0, running: 0, cancel_requested: 0, completed: 0, cancelled: 0 },
          active_count: resumed ? 1 : 0,
          failed_count: 1,
          stale_count: 0,
          stale_job_ids: [],
          latest_failed_job: importJob,
          latest_successful_job: null,
          queue: { queued: resumed ? 1 : 0, retry_wait: 0, running: 0, cancel_requested: 0, failed: 1 },
          worker: { enabled: false, status: "idle" },
          staging: { state: "healthy", pressure: false },
          retention_policy: {},
          health_status: "warning",
          warnings: []
        }
      });
    }
    return route.fulfill({ json: [importJob] });
  });

  await page.goto("/overview");
  await expect(page.getByTestId("latest-job-progress")).toContainText("500 of 2000 lines committed");
  await expect(page.getByTestId("operation-queue-panel")).toContainText("Import Staging");
  await page.getByText("Recent Run History").click();
  await expect(page.getByLabel("Resume operation job 193")).toBeVisible();
  await expect(page.getByText("Technical details")).toBeVisible();
  await page.getByLabel("Resume operation job 193").click();
  await expect.poll(() => resumed).toBe(true);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test("admin can stage a durable import without exposing a local path", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  let uploadSeen = false;
  await page.route("**/api/jobs/import", async (route) => {
    uploadSeen = true;
    const body = route.request().postDataBuffer();
    expect(body?.length ?? 0).toBeGreaterThan(0);
    return route.fulfill({
      json: {
        job_id: 195,
        job_type: "import_logs",
        status: "queued",
        requested_by: "admin",
        progress_current: 0,
        progress_total: 2,
        progress_percentage: 0,
        result_summary: {},
        attempt_count: 0,
        max_attempts: 1,
        can_cancel: true,
        can_resume: false,
        details: { input_name: "safe.log", available_lines: 2 },
        created_at: "2026-07-13T10:00:00Z",
        updated_at: "2026-07-13T10:00:00Z"
      }
    });
  });

  await page.goto("/demo");
  const durable = page.getByTestId("durable-import-control");
  await durable.locator('input[type="file"]').setInputFiles({
    name: "safe.log",
    mimeType: "text/plain",
    buffer: Buffer.from("safe synthetic line one\nsafe synthetic line two\n")
  });
  await durable.getByRole("button", { name: "Queue import" }).click();
  await expect.poll(() => uploadSeen).toBe(true);
  await expect(page.getByText("Import queued")).toBeVisible();
  await expect(page.getByTestId("technical-details")).toHaveCount(0);
});

test("analyst cannot access admin routes", async ({ page }) => {
  await mockApi(page, "analyst");
  await seedSession(page, "analyst");
  await page.goto("/users");
  await expect(page.getByText("Access denied")).toBeVisible();
});

test("admin settings shows external IAM groundwork", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/users");

  await expect(page.getByText("External IAM")).toBeVisible();
  await expect(page.getByText("School-email login groundwork")).toBeVisible();
  await expect(page.getByText("Local login only").first()).toBeVisible();
  await expect(page.getByText("School Email Policy")).toBeVisible();
  await expect(page.getByText("Email Login", { exact: true })).toBeVisible();
  expect(await page.getByText("Enabled", { exact: true }).count()).toBeGreaterThanOrEqual(1);
  expect(await page.getByText("Not configured").count()).toBeGreaterThanOrEqual(2);
  await expect(page.getByText("Local username/password login remains active.")).toBeVisible();
  await expect(page.getByText("MFU IAM Adapter")).toBeVisible();
  await expect(page.getByText("School-email integration readiness")).toBeVisible();
  await expect(page.getByText("B2B Client")).toBeVisible();
  await expect(page.getByText("Admin API")).toBeVisible();
  await expect(page.getByText("Permission Bootstrap")).toBeVisible();
  await expect(page.getByText("Secrets", { exact: true })).toBeVisible();
  await expect(page.getByText("Account Notifications")).toBeVisible();
  await expect(page.getByText("Email verification foundation")).toBeVisible();
  await expect(page.getByText("Verification disabled")).toBeVisible();
  await expect(page.getByText("Delivery Mode")).toBeVisible();
  await expect(page.getByText("Login Requirement")).toBeVisible();
  await expect(page.getByText("Admin Action Requirement")).toBeVisible();
  await expect(page.getByText("Verification is optional by default.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Send verification" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Send verification" })).toBeDisabled();
  await expect(page.getByText("SMTP_PASSWORD")).not.toBeVisible();
});

test("SOC assistant page is read-only and contains long responses safely", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async (text: string) => {
          (window as unknown as { __copiedBrief?: string }).__copiedBrief = String(text);
        }
      }
    });
  });
  await mockApi(page);
  await seedSession(page);
  await page.goto("/assistant");

  await expect(page.getByRole("heading", { name: "Read-only analyst guidance" })).toBeVisible();
  await expect(page.getByText("Read Only", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Decision Support Only", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Response Automation Disabled", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Simulation Mode", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Raw logs are excluded by default.")).toBeVisible();
  await expect(page.getByTestId("assistant-presets")).toContainText("Alert Triage");
  await expect(page.getByTestId("assistant-presets")).toContainText("False Positive Review");
  await expect(page.getByTestId("assistant-presets")).toContainText("Source Health");
  await expect(page.getByTestId("assistant-presets")).toContainText("Case Handoff");
  await expect(page.getByTestId("assistant-presets")).toContainText("AI Governance");
  await expect(page.getByTestId("assistant-presets")).toContainText("How-To");
  await expect(page.getByTestId("assistant-presets")).toContainText("SOC Playbook");
  await expect(page.getByRole("button", { name: "Latest Critical Alert", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "AI Governance Summary", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Controlled Validation Scenario", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Response Safety", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Latest Critical", exact: true })).toBeVisible();
  await expect(page.getByTestId("assistant-presets").getByRole("button", { name: "Explain Current Alert", exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Likely False Positive?", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Detection Runs", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "ML Status", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Controlled Scenario", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Alert Brief", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Leadership Brief", exact: true })).toBeVisible();
  await expect(page.getByTestId("assistant-history")).toContainText("Summarize failed jobs.");
  await expect(page.getByTestId("assistant-history")).toContainText("Local");

  await page.getByRole("button", { name: "AI Governance Summary", exact: true }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("What supervised ML output is safe?");
  await page.getByRole("button", { name: "Controlled Validation Scenario", exact: true }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("How do I run a controlled validation scenario?");
  await page.getByRole("button", { name: "Response Safety", exact: true }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("What are response safety rules?");
  await page.getByRole("button", { name: "Source Warnings", exact: true }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Which sources have warnings?");
  await expect(page.getByTestId("assistant-response-panel")).toContainText("The assistant is read-only");

  await page.getByLabel("Analyst question").fill("Why was alert 1 flagged?");
  await page.getByRole("button", { name: "Ask assistant" }).click();
  const panel = page.getByTestId("assistant-response-panel");
  await expect(panel).toContainText("The assistant is read-only");
  await expect(panel).toContainText("Evidence");
  await expect(panel).toContainText("Risk interpretation");
  await expect(panel).toContainText("False-positive/noise review");
  await expect(panel).toContainText("ATT&CK mapping");
  await expect(panel).toContainText("Related context");
  await expect(panel).toContainText("What to check next");
  await expect(panel.getByTestId("assistant-answer-sections")).toBeVisible();
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("Local Deterministic Answer");
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("Raw logs");
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("Not included");
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("Secrets");
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("Not exposed");
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("soc_evidence_grounded_structured_v2");
  await expect(panel).toContainText("Safety note");
  await expect(panel).toContainText("Alert detail");
  await expect(panel.getByTestId("assistant-citations")).toContainText("/api/alerts/{alert_id}");
  await expect(panel.getByTestId("assistant-citation-open-alert-detail-1")).toHaveAttribute("href", "/alerts?alert=1");
  await expect(panel.getByTestId("assistant-citation-open-log-detail-1")).toHaveAttribute("href", "/logs?log=1");
  await expect(panel.getByTestId("assistant-citation-open-source-1")).toHaveAttribute("href", "/overview?source=1");
  await expect(panel.getByTestId("assistant-citation-open-detection-run-8")).toHaveAttribute("href", "/?detection_run=8");
  await expect(panel.getByTestId("assistant-citation-open-operation-job-3")).toHaveAttribute("href", "/?job=3");
  await expect(panel.getByTestId("assistant-citation-open-ml-report-api")).toHaveAttribute("href", "/ml");
  await expect(panel.getByText("Text reference")).toBeVisible();
  await expect(panel.getByTestId("assistant-feedback-controls")).toContainText("Answer quality");
  await panel.getByLabel("Optional note").fill("Clear enough for triage.");
  await panel.getByRole("button", { name: "Helpful", exact: true }).click();
  await expect(panel).toContainText("Feedback recorded");
  const feedbackReview = page.getByTestId("assistant-feedback-summary");
  await expect(feedbackReview).toContainText("Feedback review");
  await expect(feedbackReview).toContainText("No Auto Tuning");
  await expect(feedbackReview).toContainText("Unsafe / Incorrect");
  await expect(feedbackReview).toContainText("Review recommended");
  await expect(feedbackReview).toContainText("helpful");
  await expect(feedbackReview).toContainText("No action");
  await feedbackReview.getByRole("button", { name: "Feedback rating filter" }).click();
  await page.getByRole("option", { name: "Incorrect" }).click();
  await feedbackReview.getByRole("button", { name: "Feedback context filter" }).click();
  await page.getByRole("option", { name: "Alert" }).click();
  await panel.getByRole("button", { name: "Copy brief" }).click();
  await expect(panel.getByText("Brief copied")).toBeVisible();
  await panel.getByRole("button", { name: "Summarize source health." }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Summarize source health.");
  await panel.getByText("Technical context").click();
  await expect(panel.getByTestId("assistant-technical-context")).toContainText("raw_log_context_included");
  await expect(page.getByRole("button", { name: "Record simulated block" })).not.toBeVisible();

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
  expect(overflow).toBe(false);

  await page.goto("/assistant?source=1");
  await expect(page.getByText("Source context #1")).toBeVisible();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Summarize source 1 health and what an analyst should check next.");
  await page.getByRole("button", { name: "Generate Brief" }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Create investigation brief for source 1.");
  await page.getByTestId("assistant-presets").getByRole("button", { name: "Source Health" }).first().click();
  await expect(page.getByTestId("assistant-response-panel")).toContainText("The assistant is read-only");

  await page.goto("/assistant?log=1");
  await expect(page.getByText("Log context #1")).toBeVisible();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Why was log 1 flagged or not flagged?");

  await page.goto("/assistant?case=smoke-case");
  await expect(page.getByText("Case context smoke-case")).toBeVisible();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Summarize case smoke-case and related alert group.");

  await page.goto("/assistant");
  await page.getByRole("button", { name: "Latest Critical", exact: true }).click();
  await page.getByTestId("assistant-citation-open-alert-detail-1").click();
  await expect(page).toHaveURL(/\/alerts\?alert=1/);
});

test("SOC assistant provider telemetry shows guarded external LLM state", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/assistant/chat", async (route) =>
    route.fulfill({
      json: {
        answer:
          "Summary\n- Alert #3225 remains evidence-grounded by ATDR local context.\n\nEvidence\n- Provider answer was guarded because it did not contain enough evidence detail.\n\nWhat to check next\n- Review linked logs and source health before response.",
        mode: "deterministic_local_llm_guarded_gemini",
        external_provider_used: true,
        safety: ["Read Only", "Decision Support Only", "Response Automation Disabled", "Simulation Mode"],
        context_used: ["alert_detail", "alert_evidence"],
        citations: [{ label: "Alert detail", source: "/api/alerts/{alert_id}", reference_id: "3225" }],
        redaction_applied: true,
        raw_log_context_included: false,
        suggested_followups: ["What logs are related?", "What should an analyst verify before response?"],
        details: {
          assistant_audit_id: 3225,
          llm: {
            used: true,
            provider: "gemini",
            model_configured: true,
            fallback_reason: null,
            raw_log_context_included: false,
            secrets_exposed: false,
            context_characters: 1400,
            prompt_contract: "soc_evidence_grounded_structured_v2",
            provider_called: true,
            answer_used: false,
            answer_guard_reason: "provider_answer_too_short_for_evidence_context"
          },
          answer_sections: {
            summary: ["Alert #3225 remains evidence-grounded by ATDR local context."],
            evidence: ["Provider answer was guarded because it did not contain enough evidence detail."],
            what_to_check_next: ["Review linked logs and source health before response."],
            safety_note: ["The assistant is read-only."]
          }
        },
        conversation_id: "guarded-assistant-conversation",
        active_context: { alert_id: 3225, log_id: null, source_id: null, case_id: null, primary: "alert" }
      }
    })
  );
  await seedSession(page);
  await page.goto("/assistant");
  await page.getByLabel("Analyst question").fill("Why was alert 3225 flagged?");
  await page.getByRole("button", { name: "Ask assistant" }).click();

  const telemetry = page.getByTestId("assistant-provider-telemetry");
  await expect(telemetry).toContainText("External LLM Guarded");
  await expect(telemetry).toContainText("Gemini");
  await expect(telemetry).toContainText("too short");
  await expect(telemetry).toContainText("Raw logs");
  await expect(telemetry).toContainText("Not included");
  await expect(telemetry).toContainText("Secrets");
  await expect(telemetry).toContainText("Not exposed");
  await expect(telemetry).toContainText("soc_evidence_grounded_structured_v2");
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Alert #3225");
  await expect(page.getByText("ASSISTANT_LLM_API_KEY")).not.toBeVisible();
  await expect(page.getByRole("button", { name: "Record simulated block" })).not.toBeVisible();
});

test("SOC assistant follow-up questions keep the previous alert context", async ({ page }) => {
  const assistantRequests: Array<Record<string, unknown>> = [];
  await mockApi(page);
  await page.route("**/api/assistant/chat", async (route) => {
    const payload = route.request().postDataJSON() as Record<string, unknown>;
    assistantRequests.push(payload);
    const alertId = Number(payload.alert_id ?? 1717);
    const logId = Number(payload.log_id ?? 9001);
    const question = String(payload.question ?? "").toLowerCase();
    const isLogFollowUp = question.includes("that log") || (question.includes("log") && !question.includes("related"));
    await route.fulfill({
      json: {
        answer:
          isLogFollowUp
            ? "Summary\n- Log context was retained.\n\nEvidence\n- The log is linked to the previous alert.\n\nWhat to check next\n- Review nearby logs before containment."
            : "Summary\n- Alert context was retained.\n\nEvidence\n- Related logs are available from the alert evidence list.\n\nWhat to check next\n- Review related logs before containment.",
        mode: "deterministic_local",
        external_provider_used: false,
        safety: ["Read Only", "Decision Support Only", "Response Automation Disabled", "Simulation Mode"],
        context_used: isLogFollowUp ? ["log_detail", "why_flagged"] : ["alert_detail", "alert_evidence"],
        citations: [
          ...(isLogFollowUp
            ? [
                { label: "Log detail", source: "/api/logs/{log_id}", reference_id: String(logId) },
                { label: "Linked alert", source: "/api/alerts/{alert_id}", reference_id: String(alertId) }
              ]
            : [
                { label: "Alert detail", source: "/api/alerts/{alert_id}", reference_id: String(alertId) },
                { label: "Related log", source: "/api/logs/{log_id}", reference_id: "9001" }
              ]),
          { label: "Source", source: "/api/sources/{source_id}", reference_id: "44" }
        ],
        redaction_applied: true,
        raw_log_context_included: false,
        suggested_followups: ["What logs are related?", "What is the recommended next step?"],
        details: {
          assistant_audit_id: 1717,
          answer_sections: {
            summary: [isLogFollowUp ? `Log #${logId} context was retained.` : `Alert #${alertId} context was retained.`],
            evidence: [isLogFollowUp ? `Linked alert #${alertId} is available.` : "Related log #9001 is linked as alert evidence."],
            what_to_check_next: [isLogFollowUp ? "Review nearby logs before containment." : "Review related logs before containment."],
            safety_note: ["The assistant is read-only."]
          }
        },
        conversation_id: String(payload.conversation_id ?? "follow-up-conversation"),
        active_context: isLogFollowUp
          ? { alert_id: alertId, log_id: logId, source_id: 44, case_id: null, primary: "log" }
          : { alert_id: alertId, log_id: 9001, source_id: 44, case_id: null, primary: "alert" }
      }
    });
  });
  await seedSession(page);
  await page.goto("/assistant");

  await page.getByLabel("Analyst question").fill("Why was alert 1717 flagged?");
  await page.getByRole("button", { name: "Ask assistant" }).click();
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Alert #1717 context was retained.");
  await page.getByRole("button", { name: "What logs are related?" }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("What logs are related?");
  await expect(page.getByText("Using alert #1717")).toBeVisible();

  expect(assistantRequests.length).toBeGreaterThanOrEqual(2);
  expect(assistantRequests[0].alert_id).toBe(1717);
  expect(assistantRequests[1].alert_id).toBe(1717);
  expect(typeof assistantRequests[0].conversation_id).toBe("string");
  expect(assistantRequests[1].conversation_id).toBe(assistantRequests[0].conversation_id);
  expect(assistantRequests[1].log_id).toBeNull();
  expect(assistantRequests[1].source_id).toBeNull();
  await page.getByRole("button", { name: "What is the recommended next step?" }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("What is the recommended next step?");
  expect(assistantRequests.length).toBeGreaterThanOrEqual(3);
  expect(assistantRequests[2].alert_id).toBe(1717);
  expect(assistantRequests[2].log_id).toBeNull();
  expect(assistantRequests[2].source_id).toBeNull();
  await page.getByLabel("Analyst question").fill("Why was that log flagged?");
  await page.getByRole("button", { name: "Ask assistant" }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Why was that log flagged?");
  await expect(page.getByText("Using log #9001")).toBeVisible();
  expect(assistantRequests.length).toBeGreaterThanOrEqual(4);
  expect(assistantRequests[3].alert_id).toBe(1717);
  expect(assistantRequests[3].log_id).toBe(9001);
  await page.getByLabel("Analyst question").fill("Why was alert 35 flagged?");
  await page.getByRole("button", { name: "Ask assistant" }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Why was alert 35 flagged?");
  await expect(page.getByText("Using alert #35")).toBeVisible();
  expect(assistantRequests.length).toBeGreaterThanOrEqual(5);
  expect(assistantRequests[4].alert_id).toBe(35);
  expect(assistantRequests[4].log_id).toBeNull();
  expect(assistantRequests[4].source_id).toBeNull();
  await page.getByRole("button", { name: "Latest Critical Alert", exact: true }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Explain the latest critical alert.");
  expect(assistantRequests.length).toBeGreaterThanOrEqual(6);
  expect(assistantRequests[5].alert_id).toBeNull();
  expect(assistantRequests[5].log_id).toBeNull();
  expect(assistantRequests[5].source_id).toBeNull();
  expect(assistantRequests[5].reset_context).toBe(true);
});

test("SOC assistant clear context removes URL-scoped alert before the next question", async ({ page }) => {
  const assistantRequests: Array<Record<string, unknown>> = [];
  await mockApi(page);
  await page.route("**/api/assistant/chat", async (route) => {
    const payload = route.request().postDataJSON() as Record<string, unknown>;
    assistantRequests.push(payload);
    await route.fulfill({
      json: {
        answer: "Summary\n- Context cleared request answered.\n\nEvidence\n- No stale alert context was sent.\n\nWhat to check next\n- Continue with the selected workflow.",
        mode: "deterministic_local",
        external_provider_used: false,
        safety: ["Read Only", "Decision Support Only", "Response Automation Disabled", "Simulation Mode"],
        context_used: ["source_health"],
        citations: [{ label: "Source API", source: "/api/sources", reference_id: null }],
        redaction_applied: true,
        raw_log_context_included: false,
        suggested_followups: ["Show latest critical alerts."],
        details: {
          answer_sections: {
            summary: ["Context cleared request answered."],
            evidence: ["No stale alert context was sent."],
            what_to_check_next: ["Continue with the selected workflow."],
            safety_note: ["The assistant is read-only."]
          }
        },
        conversation_id: String(payload.conversation_id ?? "clear-context-conversation"),
        active_context: { alert_id: null, log_id: null, source_id: null, case_id: null, primary: null }
      }
    });
  });
  await seedSession(page);
  await page.goto("/assistant?alert=1&prompt=Why%20was%20alert%201%20flagged%3F");
  await expect(page.getByText("Using alert #1")).toBeVisible();

  await page.getByRole("button", { name: "Clear context" }).click();
  await expect(page.getByText("Using alert #1")).not.toBeVisible();
  await expect(page).toHaveURL(/\/assistant$/);

  await page.getByLabel("Analyst question").fill("Summarize source health.");
  await page.getByRole("button", { name: "Ask assistant" }).click();
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Context cleared request answered.");
  expect(assistantRequests.at(-1)?.alert_id).toBeNull();
  expect(assistantRequests.at(-1)?.log_id).toBeNull();
  expect(assistantRequests.at(-1)?.source_id).toBeNull();
  expect(assistantRequests.at(-1)?.reset_context).toBe(true);
  expect(typeof assistantRequests.at(-1)?.conversation_id).toBe("string");
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
  await chooseSafeSelect(page, "Log source filter", "scenario-raw-fallback");
  await page.getByPlaceholder("Search IP, app, rule, action, protocol, or zone").click();
  await chooseSafeSelect(page, "Log sort", "Sort by source IP");
  await page.getByPlaceholder("Search IP, app, rule, action, protocol, or zone").click();
  await chooseSafeSelect(page, "Table density", "Compact");
  await page.getByRole("button", { name: "Save view" }).click();

  await page.goto("/alerts");
  await chooseSafeSelect(page, "Alert source filter", "scenario-raw-fallback");
  await page.getByPlaceholder("Source IP", { exact: true }).click();
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
  await expect(page.getByRole("heading", { name: "Model status and review operations" })).toBeVisible();
  await expect(page.getByText("Current AI governance snapshot")).toBeVisible();
  await expect(page.getByText("Threat F1", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("0.9174", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Production Readiness Track")).not.toBeVisible();
  await expect(page.getByText("Review focus: benign and suspicious separation need more analyst-verified examples.")).not.toBeVisible();
  await page.getByText("Operational readiness details").click();
  await expect(page.getByText("Production Readiness Track")).toBeVisible();
  await expect(page.getByText("Not Production Ready")).toBeVisible();
  await expect(page.getByText("real_source_pilot_ready")).toBeVisible();
  await page.getByText("Operational readiness details").click();
  await page.getByText("Review exports and technical reports").click();
  await expect(page.getByRole("button", { name: "General Active Learning Sample" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Malicious-Focused Sample" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Round 5 Threat Boundary" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Training-Window Threat Sample" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Stage 1 Recall Sample" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Benign Gap Sample" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Final Small Gap Sample" })).toBeVisible();
  await expect(page.getByRole("button", { name: "SOC Triage Recommendation" })).toBeVisible();
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
  await page.getByRole("button", { name: "Stage 1 Recall Sample" }).click();
  await page.getByRole("button", { name: "Benign Gap Sample" }).click();
  await page.getByRole("button", { name: "Final Small Gap Sample" }).click();
  await page.getByRole("button", { name: "SOC Triage Recommendation" }).click();
  await page.getByRole("button", { name: "Download Model Report" }).click();
  await expect(page.locator('[data-atdr-dropdown-open="true"]')).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});

test("demo action results summarize imports and contain long ML details", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/demo");

  await page.getByRole("button", { name: "Import sample logs" }).click();
  await expect(page.getByTestId("action-result-import")).toContainText("Requested limit");
  await expect(page.getByTestId("action-result-import")).toContainText("Available lines");
  await expect(page.getByTestId("action-result-import")).toContainText("Raw logs imported");
  await expect(page.getByTestId("action-result-import")).toContainText("Alerts created");
  await expect(page.getByText("contains 2 non-empty log lines")).toBeVisible();

  await page.getByRole("button", { name: "Train ML model" }).click();
  const mlResult = page.getByTestId("action-result-ml-train");
  await expect(mlResult).toContainText("Feature count");
  await mlResult.getByRole("button", { name: "View technical details" }).click();
  await expect(mlResult.getByTestId("technical-details")).toBeVisible();

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
  expect(overflow).toBe(false);
});

test("demo import limit is editable and custom sample path is sent", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/demo");

  const limitInput = page.getByLabel("Log import limit");
  await limitInput.fill("");
  await expect(limitInput).toHaveValue("");
  await limitInput.fill("1000");
  await expect(limitInput).toHaveValue("1000");

  await page.getByLabel("Sample log file path").fill("C:\\Users\\User\\Downloads\\paloalto-firewall(1).log");
  await page.getByRole("button", { name: "Import sample logs" }).click();

  const importResult = page.getByTestId("action-result-import");
  await expect(importResult).toContainText("Requested limit");
  await expect(importResult).toContainText("1000");
  await expect(importResult).toContainText("Available lines");
  await expect(importResult).toContainText("Raw logs imported");
  await expect(importResult).toContainText("paloalto-firewall(1).log");
  await expect(page.getByText("contains 2 non-empty log lines")).not.toBeVisible();
});

test("demo import strips copy-as-path quotes before sending sample path", async ({ page }) => {
  let postedPath = "";
  await mockApi(page);
  await page.route("**/api/demo/import-sample", async (route) => {
    const body = JSON.parse(route.request().postData() || "{}") as { sample_path?: string | null };
    postedPath = body.sample_path ?? "";
    await route.fulfill({
      json: {
        source: "paloalto-firewall(1).log",
        source_label: "paloalto-firewall(1).log",
        requested_limit: 2000,
        available_lines: 2000,
        raw_logs_imported: 2000,
        normalized_logs_created: 2000,
        parsed_successfully: 2000,
        parse_failures: 0,
        duplicate_raw_logs: 0,
        alerts_created: 0,
        alerts_deduplicated: 0,
        safe_sample_note: null
      }
    });
  });
  await seedSession(page);
  await page.goto("/demo");
  await page.getByLabel("Sample log file path").fill('"C:\\Users\\User\\Downloads\\paloalto-firewall(1).log"');
  await page.getByRole("button", { name: "Import sample logs" }).click();
  await expect(page.getByTestId("action-result-import")).toContainText("2000");
  expect(postedPath).toBe("C:\\Users\\User\\Downloads\\paloalto-firewall(1).log");
});
