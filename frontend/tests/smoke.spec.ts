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
  await expect(page.getByText("Controlled Validation", { exact: true })).toBeVisible();
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
  await expect(page.getByText("Drift")).toBeVisible();
  await expect(page.getByText("0 warnings")).toBeVisible();
  await expect(page.getByText("Lab-Scale Validation")).toBeVisible();
  await expect(page.getByText("Manual Approval Required")).toBeVisible();
  await expect(page.getByText("Final Controlled Validation Candidate", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Real device validation remains future work.")).toBeVisible();
  await expect(page.getByText("Operations Health")).toBeVisible();
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
  await expect(page.getByText("Response Mode")).toBeVisible();
  await expect(page.getByText("Config: local lab profile")).toBeVisible();

  await page.goto("/ml");
  await expect(page.getByText("Analyst Review Eligible.")).toBeVisible();
  await expect(page.getByText(/1528 reviewed \| minimum gaps 44/)).toBeVisible();
  await expect(page.getByText("Recommended AI Mode")).toBeVisible();
  await expect(page.getByText("SOC triage decision support")).toBeVisible();
  await expect(page.getByText("SOC Triage Mode")).toBeVisible();
  await expect(page.getByText("Analyst Review", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Manual Approval Required")).toBeVisible();
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
  await expect(page.getByText(/Files containing `benchmark_row_id` must use Benchmark Review Import/)).toBeVisible();
  await expect(page.getByText(/Confirmed noisy pattern:\s*normal QUIC\/443/)).toBeVisible();
  await expect(page.getByText(/False positives:\s*improved/)).toBeVisible();
  await expect(page.getByText(/QUIC\/443 mitigation:\s*validated candidate; not activated/)).toBeVisible();
  await expect(page.getByText("Actionable review sample excludes protected manual labels", { exact: true })).toBeVisible();
  await expect(page.getByText("Model remains decision support only", { exact: true })).toBeVisible();
  await expect(page.getByText("Response automation disabled", { exact: true })).toBeVisible();
  await expect(page.getByText("Not Production Promoted", { exact: true })).toBeVisible();
  await expect(page.getByText("Final Controlled Validation Candidate", { exact: true }).first()).toBeVisible();
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

test("admin settings shows external IAM groundwork", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/users");

  await expect(page.getByText("External IAM")).toBeVisible();
  await expect(page.getByText("School-email login groundwork")).toBeVisible();
  await expect(page.getByText("Local login only").first()).toBeVisible();
  await expect(page.getByText("School Email Policy")).toBeVisible();
  await expect(page.getByText("Email Login", { exact: true })).toBeVisible();
  await expect(page.getByText("Enabled", { exact: true })).toBeVisible();
  expect(await page.getByText("Not configured").count()).toBeGreaterThanOrEqual(2);
  await expect(page.getByText("External school-email login can be enabled later through OIDC.")).toBeVisible();
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
  await expect(page.getByRole("heading", { name: "AI is assistive, explainable, and audited." })).toBeVisible();
  await expect(page.getByText("AI Model Evaluation")).toBeVisible();
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
  await expect(page.getByText("Review focus: benign and suspicious separation need more analyst-verified examples.")).toBeVisible();
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
