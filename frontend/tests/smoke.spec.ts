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
  let detectionReviewRevision = 0;
  let detectionReviewReviewed = 0;
  let assistantReviewRevision = 0;
  let assistantReviewReviewed = 0;
  let manualAnchorReviewRevision = 0;
  let manualAnchorReviewReviewed = 0;
  let supplementalAnchorReviewRevision = 0;
  let supplementalAnchorReviewReviewed = 0;
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
    evidence_count: 150,
    evidence_log_ids: [1],
    evidence_log_ids_truncated: true,
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
        auth_mode: "local_recovery",
        local_login_enabled: true,
        template_shell_required: false,
        enabled: false,
        b2b_ready: false,
        mock_enabled: false,
        google_sso_enabled: false,
        google_client_id_configured: false,
        allowed_domains: [],
        domain_hints: [],
        default_role: "analyst",
        auth_require_2fa: false,
        mode: "local_recovery",
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/auth/mfu-iam/status", async (route) =>
    route.fulfill({
      json: {
        auth_mode: "local_recovery",
        local_login_enabled: true,
        template_shell_required: false,
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
  const reviewProgress = (workspace: "detection" | "assistant") => {
    const total = workspace === "detection" ? 40 : 8;
    const reviewed = workspace === "detection" ? detectionReviewReviewed : assistantReviewReviewed;
    return {
      workspace,
      available: true,
      prepared: true,
      integrity_status: "valid",
      total,
      reviewed,
      remaining: total - reviewed,
      invalid: 0,
      progress_percent: (reviewed / total) * 100,
      owner_assigned: true,
      owned_by_current_user: true,
      can_review: true,
      completed: reviewed === total,
      closed: false,
      next_pending_index: reviewed < total ? reviewed : null,
      evaluation_ready: reviewed === total,
      human_acceptance_passed: workspace === "assistant" && reviewed === total ? true : null,
      message: workspace === "detection" ? "Predictions remain withheld while the reviewer records independent decisions." : "Review protected answers without sending content back to the provider.",
      predictions_exposed: false,
      model_scores_exposed: false,
      raw_logs_exposed: false,
      private_paths_exposed: false,
      import_ready: false
    };
  };
  const detectionItem = (rowIndex: number) => ({
    workspace: "detection",
    row_index: rowIndex,
    display_position: rowIndex + 1,
    total: 40,
    revision: detectionReviewRevision,
    reviewed: rowIndex < detectionReviewReviewed,
    evidence: {
      evidence_role: "untouched_future_validation",
      pattern: rowIndex % 2 ? "scan_like" : "routine_web",
      review_priority: "high",
      event_time_utc: "2026-05-20T10:00:00+00:00",
      log_type: "TRAFFIC",
      application: rowIndex % 2 ? "unknown" : "ssl",
      action: rowIndex % 2 ? "deny" : "allow",
      protocol: "tcp",
      destination_port: rowIndex % 2 ? "22" : "443",
      source_zone: "untrust",
      destination_zone: "trust",
      source_event_count: rowIndex % 2 ? "20" : "2",
      source_unique_destinations: rowIndex % 2 ? "10" : "1"
    },
    existing_review: rowIndex < detectionReviewReviewed ? {
      decision_group: "benign_like",
      decision: "benign",
      attack_type: "none",
      confidence: 92,
      rationale: "Independent human review found routine allowed web traffic."
    } : null,
    next_pending_index: detectionReviewReviewed < 40 ? detectionReviewReviewed : null,
    predictions_exposed: false,
    model_scores_exposed: false,
    raw_logs_exposed: false,
    ip_addresses_exposed: false,
    fingerprints_exposed: false,
    import_ready: false
  });
  const assistantItem = (rowIndex: number) => ({
    workspace: "assistant",
    row_index: rowIndex,
    display_position: rowIndex + 1,
    total: 8,
    revision: assistantReviewRevision,
    reviewed: rowIndex < assistantReviewReviewed,
    context_type: rowIndex % 2 ? "case" : "alert",
    question: "What evidence supports this triage result?",
    answer: "The bounded ATDR evidence supports analyst review. No action was executed.",
    citations: "/api/alerts/{alert_id}#sanitized",
    existing_review: null,
    next_pending_index: assistantReviewReviewed < 8 ? assistantReviewReviewed : null,
    raw_log_context_included: false,
    action_executed: false,
    secrets_exposed: false,
    import_ready: false
  });
  const manualAnchorProgress = () => ({
    workspace: "manual_anchors",
    available: true,
    prepared: true,
    integrity_status: "valid",
    total: 120,
    reviewed: manualAnchorReviewReviewed,
    remaining: 120 - manualAnchorReviewReviewed,
    invalid: 0,
    progress_percent: (manualAnchorReviewReviewed / 120) * 100,
    revision: manualAnchorReviewRevision,
    owner_assigned: true,
    owned_by_current_user: true,
    can_review: true,
    completed: manualAnchorReviewReviewed === 120,
    closed: false,
    evaluation_ready: false,
    protocol_locked: true,
    protocol_valid: true,
    class_support: { benign_like: manualAnchorReviewReviewed, suspicious: 0, malicious: 0 },
    minimum_class_support: { benign_like: 20, suspicious: 15, malicious: 10 },
    class_support_passed: false,
    coverage_counts: { routine_benign_control: 20, scan_like_behavior: 20 },
    coverage_strata: ["routine_benign_control", "scan_like_behavior"],
    next_pending_index: manualAnchorReviewReviewed < 120 ? manualAnchorReviewReviewed : null,
    message: "Record genuine human decisions using approved evidence only.",
    predictions_exposed: false,
    model_scores_exposed: false,
    assisted_labels_exposed: false,
    raw_logs_exposed: false,
    ip_addresses_exposed: false,
    source_identities_exposed: false,
    fingerprints_exposed: false,
    private_paths_exposed: false,
    reviewer_identity_exposed: false,
    import_ready: false,
    automatic_import_performed: false,
    model_activation_performed: false,
    response_action_performed: false,
    secrets_exposed: false
  });
  const manualAnchorItem = (rowIndex: number) => ({
    workspace: "manual_anchors",
    row_index: rowIndex,
    display_position: rowIndex + 1,
    total: 120,
    revision: manualAnchorReviewRevision,
    reviewed: rowIndex < manualAnchorReviewReviewed,
    closed: false,
    coverage_stratum: rowIndex % 2 ? "scan_like_behavior" : "routine_benign_control",
    evidence: {
      evidence_role: "development_fit",
      selection_stratum: rowIndex % 2 ? "scan_like_behavior" : "routine_benign_control",
      event_time_utc: "2026-08-01T00:00:00+00:00",
      log_type: "TRAFFIC",
      application: rowIndex % 2 ? "unknown-udp" : "ssl",
      action: rowIndex % 2 ? "deny" : "allow",
      protocol: rowIndex % 2 ? "udp" : "tcp",
      destination_port: rowIndex % 2 ? "4040" : "443",
      source_zone: "untrust",
      destination_zone: "trust",
      source_event_count: rowIndex % 2 ? "20" : "2",
      source_unique_destinations: rowIndex % 2 ? "10" : "1"
    },
    existing_review: null,
    next_pending_index: manualAnchorReviewReviewed < 120 ? manualAnchorReviewReviewed : null,
    predictions_exposed: false,
    model_scores_exposed: false,
    assisted_labels_exposed: false,
    raw_logs_exposed: false,
    ip_addresses_exposed: false,
    source_identities_exposed: false,
    fingerprints_exposed: false,
    private_paths_exposed: false,
    reviewer_identity_exposed: false,
    import_ready: false,
    automatic_import_performed: false,
    model_activation_performed: false,
    response_action_performed: false,
    secrets_exposed: false
  });
  const manualAnchorOperation = (nextItem: ReturnType<typeof manualAnchorItem> | null) => ({
    ok: true,
    workspace: "manual_anchors",
    status: "manual_anchor_review_saved",
    revision: manualAnchorReviewRevision,
    progress: manualAnchorProgress(),
    next_item: nextItem,
    authoritative_mutations: { labels: 0, model_runs: 0, detection_runs: 0, alerts: 0, response_actions: 0 },
    import_performed: false,
    model_activation_performed: false,
    response_action_performed: false
  });
  const supplementalAnchorProgress = () => ({
    workspace: "supplemental_threat_anchors",
    available: true,
    prepared: true,
    integrity_status: "valid",
    total: 60,
    reviewed: supplementalAnchorReviewReviewed,
    remaining: 60 - supplementalAnchorReviewReviewed,
    invalid: 0,
    progress_percent: (supplementalAnchorReviewReviewed / 60) * 100,
    revision: supplementalAnchorReviewRevision,
    owner_assigned: true,
    owned_by_current_user: true,
    can_review: true,
    completed: supplementalAnchorReviewReviewed === 60,
    closed: false,
    combined_support_visible: false,
    combined_class_support: {},
    minimum_class_support: {},
    combined_support_passed: false,
    ready_for_relocked_protocol: false,
    proposed_protocol_created: false,
    coverage_counts: {
      vendor_threat_high: 10,
      c2_exfiltration: 10,
      brute_force_access: 10,
      scan_behavior: 10,
      denied_high_risk_service: 8,
      unknown_correlated_transport: 7,
      hard_negative: 5
    },
    coverage_strata: [
      "vendor_threat_high",
      "c2_exfiltration",
      "brute_force_access",
      "scan_behavior",
      "denied_high_risk_service",
      "unknown_correlated_transport",
      "hard_negative"
    ],
    next_pending_index: supplementalAnchorReviewReviewed < 60 ? supplementalAnchorReviewReviewed : null,
    evaluation_execution_count: 0,
    message: "Record independent human decisions using deterministic evidence only.",
    predictions_exposed: false,
    model_scores_exposed: false,
    assisted_labels_exposed: false,
    raw_logs_exposed: false,
    ip_addresses_exposed: false,
    source_identities_exposed: false,
    fingerprints_exposed: false,
    private_paths_exposed: false,
    reviewer_identity_exposed: false,
    import_ready: false,
    automatic_import_performed: false,
    model_activation_performed: false,
    response_action_performed: false,
    secrets_exposed: false
  });
  const supplementalAnchorItem = (rowIndex: number) => ({
    workspace: "supplemental_threat_anchors",
    row_index: rowIndex,
    display_position: rowIndex + 1,
    total: 60,
    revision: supplementalAnchorReviewRevision,
    reviewed: rowIndex < supplementalAnchorReviewReviewed,
    closed: false,
    coverage_stratum: rowIndex % 2 ? "scan_behavior" : "vendor_threat_high",
    evidence: {
      evidence_role: "development_fit",
      selection_stratum: rowIndex % 2 ? "scan_behavior" : "vendor_threat_high",
      event_time_utc: "2026-08-01T00:00:00+00:00",
      log_type: rowIndex % 2 ? "TRAFFIC" : "THREAT",
      application: rowIndex % 2 ? "unknown-tcp" : "web-browsing",
      action: "deny",
      protocol: "tcp",
      destination_port: rowIndex % 2 ? "22" : "443",
      source_zone: "untrust",
      destination_zone: "trust",
      source_event_count: "24",
      source_unique_destinations: "12",
      source_unique_destination_ports: "9",
      rule_evidence: rowIndex % 2 ? "repeated denied high-risk service attempts" : "high-severity vendor threat record",
      rule_evidence_score: "5"
    },
    existing_review: null,
    next_pending_index: supplementalAnchorReviewReviewed < 60 ? supplementalAnchorReviewReviewed : null,
    predictions_exposed: false,
    model_scores_exposed: false,
    assisted_labels_exposed: false,
    raw_logs_exposed: false,
    ip_addresses_exposed: false,
    source_identities_exposed: false,
    fingerprints_exposed: false,
    private_paths_exposed: false,
    reviewer_identity_exposed: false,
    import_ready: false,
    automatic_import_performed: false,
    model_activation_performed: false,
    response_action_performed: false,
    secrets_exposed: false
  });
  const supplementalAnchorOperation = (nextItem: ReturnType<typeof supplementalAnchorItem> | null) => ({
    ok: true,
    workspace: "supplemental_threat_anchors",
    status: "supplemental_threat_anchor_review_saved",
    revision: supplementalAnchorReviewRevision,
    progress: supplementalAnchorProgress(),
    next_item: nextItem,
    authoritative_mutations: { labels: 0, model_runs: 0, detection_runs: 0, alerts: 0, response_actions: 0 },
    evaluation_execution_count: 0,
    evaluation_claim_created: false,
    import_performed: false,
    model_activation_performed: false,
    response_action_performed: false
  });
  const operation = (workspace: "detection" | "assistant", nextItem: ReturnType<typeof detectionItem> | ReturnType<typeof assistantItem> | null) => ({
    ok: true,
    workspace,
    status: `${workspace}_review_saved`,
    revision: workspace === "detection" ? detectionReviewRevision : assistantReviewRevision,
    progress: reviewProgress(workspace),
    next_item: nextItem,
    authoritative_mutations: { labels: 0, model_runs: 0, detection_runs: 0, alerts: 0, response_actions: 0 },
    import_performed: false,
    model_activation_performed: false,
    response_action_performed: false,
    details: {}
  });
  await page.route("**/api/evidence-review/status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.37.0",
        detection: reviewProgress("detection"),
        assistant: reviewProgress("assistant"),
        safeguards: ["Human Decisions Only", "Predictions Withheld", "No Auto Import", "No Model Activation", "No Response Actions"],
        aggregate_only_for_non_owner: true,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/evidence-review/evaluation-status", async (route) =>
    route.fulfill({
      json: {
        ok: true,
        version: "v5.39.0",
        status: "human_review_required",
        detection: {
          available: true,
          total: 40,
          reviewed: detectionReviewReviewed,
          remaining: 40 - detectionReviewReviewed,
          invalid: 0,
          completed: detectionReviewReviewed === 40,
          closed: false,
          evaluation_ready: detectionReviewReviewed === 40,
          owner_contract_valid: true
        },
        assistant: {
          available: true,
          total: 8,
          reviewed: assistantReviewReviewed,
          remaining: 8 - assistantReviewReviewed,
          invalid: 0,
          completed: assistantReviewReviewed === 8,
          closed: false,
          evaluation_ready: assistantReviewReviewed === 8,
          owner_contract_valid: true,
          human_acceptance_passed: null
        },
        reviews_complete: false,
        reviews_closed: false,
        freeze_ready: false,
        evidence_frozen: false,
        evaluation_attempted: false,
        evaluation_completed: false,
        evaluation_execution_count: 0,
        executed_now: false,
        metrics_available: false,
        blind_metrics: {},
        assistant_metrics: {},
        activation_decision: {
          lifecycle: "shadow_observation",
          activate_candidate: false,
          eligible_for_manual_activation_review: false,
          production_promoted: false,
          model_activated: false,
          model_promoted: false,
          response_automation_allowed: false,
          rules_remain_alert_authoritative: true,
          blockers: []
        },
        message: "Complete and close all 40 detection decisions and eight Assistant assessments before the frozen evaluation.",
        safety: {
          predictions_exposed_before_completion: false,
          digests_exposed: false,
          reviewer_identities_exposed: false,
          external_provider_called: false,
          model_activated: false,
          automatic_response_enabled: false
        }
      }
    })
  );
  await page.route("**/api/evidence-review/blind-evidence/status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.41-governed-blind-evidence-v1",
        status: "Insufficient Sources",
        qualifying_collection_count: 1,
        independent_source_count: 1,
        required_source_count: 2,
        collection_window_count: 1,
        required_window_count: 3,
        candidate_rows: 40,
        target_review_rows: 240,
        review_pack_available: false,
        human_reviewed_rows: 0,
        human_review_complete: false,
        class_support: { benign_like: 0, suspicious: 0, malicious: 0 },
        prediction_sealed_separately: false,
        metrics_available: false,
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        model_activated: false,
        model_promoted: false,
        response_automation_allowed: false,
        raw_logs_exposed: false,
        ip_addresses_exposed: false,
        private_paths_exposed: false,
        source_identities_exposed: false,
        fingerprints_exposed: false,
        secrets_exposed: false,
        message: "Additional independently verified sources or collection windows are required."
      }
    })
  );
  await page.route("**/api/evidence-review/candidate-freeze/status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.42-development-candidate-freeze-v1",
        status: "No Candidate Frozen",
        best_candidate: "hierarchical_two_stage",
        passing_folds: 0,
        required_folds: 3,
        candidate_frozen: false,
        calibration_status: "weak",
        blind_evidence_status: "Insufficient Sources",
        supervised_phases_remaining: 5,
        blockers: ["Temporal stability gate failed."],
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        model_activated: false,
        model_promoted: false,
        response_automation_allowed: false,
        private_paths_exposed: false,
        digests_exposed: false,
        blind_predictions_exposed: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/evidence-review/temporal-stability/status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.43-development-temporal-stability-repair-v1",
        status: "No Candidate Frozen",
        best_variant: "temporal_provenance_balanced_weighting",
        passing_folds: 0,
        required_folds: 3,
        candidate_frozen: false,
        calibration_status: "weak",
        queue_stability_status: "unstable",
        feature_ablation_status: "complete",
        supervised_phases_remaining: 5,
        blockers: ["Temporal stability gate failed."],
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        model_activated: false,
        model_promoted: false,
        response_automation_allowed: false,
        private_paths_exposed: false,
        digests_exposed: false,
        blind_predictions_exposed: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/evidence-review/development-model-repair/status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.45-development-only-supervised-repair-v1",
        status: "development_repair_incomplete",
        generated_at: "2026-08-21T00:00:00+00:00",
        diagnostic_leader: "calibrated_extra_trees_flat_5class",
        passing_views: 0,
        required_views: 3,
        candidate_freeze_ready: false,
        candidate_frozen: false,
        isolation_forest_reliable: false,
        supervised_phases_remaining: 5,
        blockers: ["Manual-anchor stability gate failed."],
        lifecycle_state: "shadow_observation",
        model_activated: false,
        model_promoted: false,
        response_automation_allowed: false,
        future_labels_opened: false,
        private_paths_returned: false,
        fingerprints_returned: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/evidence-review/manual-anchor-transfer/status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.46-manual-anchor-transfer-repair-v1",
        status: "manual_anchor_transfer_incomplete",
        generated_at: "2026-08-21T00:00:00+00:00",
        diagnostic_leader: "manual_anchor_prioritized_extra_trees",
        passing_views: 1,
        required_views: 3,
        manual_anchor_transfer_status: "improved",
        calibration_status: "weak",
        manual_anchor_queue_f1: 0.79,
        manual_anchor_fpr: 0.12,
        manual_anchor_suspicious_recall: 0.71,
        manual_anchor_malicious_recall: 0.84,
        queue_f1_transfer_gap: 0.18,
        candidate_freeze_ready: false,
        candidate_frozen: false,
        isolation_forest_reliable: false,
        supervised_phases_remaining: 5,
        blockers: ["Manual-anchor gate failed."],
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        model_activated: false,
        model_promoted: false,
        response_automation_allowed: false,
        future_labels_opened: false,
        private_paths_returned: false,
        fingerprints_returned: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/evidence-review/manual-anchor-acquisition/status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.47-prediction-blind-manual-anchor-acquisition-v1",
        status: "ready_for_human_review",
        generated_at: "2026-08-21T00:00:00+00:00",
        selected_rows: 120,
        target_rows: 120,
        represented_strata: 8,
        coverage_counts: {
          unknown_transport: 20,
          incomplete_allow_80: 20,
          scan_like_behavior: 20
        },
        coverage_gate_passed: true,
        review_status: "ready_for_human_review",
        reviewed_rows: 0,
        total_review_rows: 120,
        invalid_review_rows: 0,
        class_support: { benign_like: 0, suspicious: 0, malicious: 0 },
        ready_for_fixed_revalidation: false,
        independent_source_count: 1,
        second_real_source_present: false,
        development_evidence_only: true,
        workspace_created: true,
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        model_activated: false,
        model_promoted: false,
        response_automation_allowed: false,
        future_labels_opened: false,
        predictions_exposed: false,
        assisted_labels_exposed: false,
        private_paths_returned: false,
        fingerprints_returned: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/evidence-review/manual-anchors/revalidation-status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.48-protected-manual-anchor-fixed-revalidation-v1",
        status: "ready_for_human_review",
        protocol: {
          version: "v5.48-fixed-development-protocol-v1",
          locked: true,
          valid: true,
          strategy_count: 8,
          eligible_roles: ["development_fit", "calibration", "threshold"],
          quality_gates_unchanged: true,
          evaluation_labels_accessed: false,
          digest_exposed: false
        },
        review: {
          status: "ready_for_human_review",
          total: 120,
          reviewed: manualAnchorReviewReviewed,
          remaining: 120 - manualAnchorReviewReviewed,
          invalid: 0,
          class_support: { benign_like: manualAnchorReviewReviewed, suspicious: 0, malicious: 0 },
          minimum_class_support: { benign_like: 20, suspicious: 15, malicious: 10 },
          closed: false,
          ready_for_fixed_revalidation: false
        },
        evaluation_attempted: false,
        evaluation_execution_count: 0,
        metrics_available: false,
        diagnostic_leader: null,
        leader_metrics: {},
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        model_activated: false,
        model_promoted: false,
        response_automation_allowed: false,
        automatic_import_performed: false,
        predictions_exposed: false,
        raw_logs_exposed: false,
        private_paths_exposed: false,
        fingerprints_exposed: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/evidence-review/combined-manual-anchors/revalidation-status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.49b-immutable-combined-fixed-revalidation-v1",
        status: "combined_fixed_revalidation_completed",
        custody: {
          original_reviewed: 120,
          supplemental_reviewed: 60,
          combined_reviewed: 180,
          remaining: 0,
          invalid: 0,
          reviews_closed: true,
          reviews_immutable: true,
          combined_class_support: {
            benign_like: 95,
            suspicious: 39,
            malicious: 27
          },
          minimum_class_support: {
            benign_like: 20,
            suspicious: 15,
            malicious: 10
          },
          combined_support_passed: true,
          old_evaluation_execution_count: 0
        },
        protocol: {
          version: "v5.49b-combined-fixed-protocol-v1",
          locked: true,
          valid: true,
          immutable: true,
          strategy_count: 8,
          combined_rows: 180,
          contracts_unchanged: true,
          supplemental_evidence_threat_enriched: true,
          representative_of_production_prevalence: false,
          digest_exposed: false
        },
        evaluation_attempted: true,
        evaluation_execution_count: 1,
        metrics_available: true,
        strategy_count: 8,
        evaluated_strategy_count: 8,
        strategies: [],
        diagnostic_candidate: null,
        diagnostic_candidate_qualified: false,
        selection_bias_notice: "Supplemental evidence was threat-enriched; queue rate and precision are diagnostic and are not field-prevalence estimates.",
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        model_activated: false,
        model_promoted: false,
        active_artifact_written: false,
        response_automation_allowed: false,
        real_firewall_blocking_enabled: false,
        labels_written: 0,
        model_runs_written: 0,
        detection_runs_written: 0,
        alerts_written: 0,
        response_actions_written: 0,
        predictions_exposed: false,
        raw_logs_exposed: false,
        ip_addresses_exposed: false,
        source_identities_exposed: false,
        private_paths_exposed: false,
        fingerprints_exposed: false,
        digests_exposed: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/evidence-review/manual-anchors/status", async (route) =>
    route.fulfill({ json: manualAnchorProgress() })
  );
  await page.route("**/api/evidence-review/manual-anchors/start", async (route) =>
    route.fulfill({ json: manualAnchorOperation(manualAnchorItem(manualAnchorReviewReviewed)) })
  );
  await page.route("**/api/evidence-review/manual-anchors/items", async (route) => {
    const url = new URL(route.request().url());
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 20);
    const reviewState = url.searchParams.get("review_state") ?? "all";
    const candidates = Array.from({ length: 120 }, (_, rowIndex) => manualAnchorItem(rowIndex))
      .filter((item) => reviewState === "all" || (reviewState === "reviewed" ? item.reviewed : !item.reviewed));
    return route.fulfill({
      json: {
        workspace: "manual_anchors",
        offset,
        limit,
        filtered_total: candidates.length,
        items: candidates.slice(offset, offset + limit).map((item) => ({
          row_index: item.row_index,
          display_position: item.display_position,
          reviewed: item.reviewed,
          coverage_stratum: item.coverage_stratum,
          evidence: item.evidence
        })),
        predictions_exposed: false,
        raw_logs_exposed: false,
        private_paths_exposed: false,
        reviewer_identities_exposed: false,
        secrets_exposed: false
      }
    });
  });
  await page.route("**/api/evidence-review/manual-anchors/items/*", async (route) => {
    const rowIndex = Number(new URL(route.request().url()).pathname.split("/").at(-1));
    if (route.request().method() === "POST") {
      manualAnchorReviewReviewed = Math.max(manualAnchorReviewReviewed, rowIndex + 1);
      manualAnchorReviewRevision += 1;
      return route.fulfill({ json: manualAnchorOperation(manualAnchorItem(manualAnchorReviewReviewed)) });
    }
    return route.fulfill({ json: manualAnchorItem(rowIndex) });
  });
  await page.route("**/api/evidence-review/manual-anchors/close", async (route) =>
    route.fulfill({ json: manualAnchorOperation(null) })
  );
  await page.route("**/api/evidence-review/supplemental-threat-anchors/acquisition-status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.49a-supplemental-threat-anchor-recovery-v1",
        status: "ready_for_human_review",
        generated_at: "2026-08-29T00:00:00+00:00",
        original_review: {
          total: 120,
          reviewed: 120,
          remaining: 0,
          invalid: 0,
          closed: true,
          immutable: true,
          evaluation_execution_count: 0
        },
        selected_rows: 60,
        target_rows: 60,
        coverage_counts: supplementalAnchorProgress().coverage_counts,
        represented_threat_strata: 7,
        threat_enriched_rows: 55,
        coverage_gate_passed: true,
        exclusion_counts: { original_anchor: 120, locked_role: 80, duplicate_group: 12 },
        review: {
          status: "ready_for_human_review",
          total: 60,
          reviewed: supplementalAnchorReviewReviewed,
          remaining: 60 - supplementalAnchorReviewReviewed,
          invalid: 0,
          complete: supplementalAnchorReviewReviewed === 60,
          closed: false
        },
        combined_support_visible: false,
        combined_class_support: {},
        minimum_class_support: {},
        combined_support_passed: false,
        ready_for_relocked_protocol: false,
        proposed_protocol_created: false,
        evaluation_execution_count: 0,
        evaluation_claim_created: false,
        evaluation_result_created: false,
        predictions_used_for_selection: false,
        predictions_exposed: false,
        assisted_labels_exposed: false,
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        model_activated: false,
        model_promoted: false,
        response_automation_allowed: false,
        raw_logs_exposed: false,
        ip_addresses_exposed: false,
        private_paths_returned: false,
        fingerprints_returned: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/evidence-review/supplemental-threat-anchors/status", async (route) =>
    route.fulfill({ json: supplementalAnchorProgress() })
  );
  await page.route("**/api/evidence-review/supplemental-threat-anchors/start", async (route) =>
    route.fulfill({ json: supplementalAnchorOperation(supplementalAnchorItem(supplementalAnchorReviewReviewed)) })
  );
  await page.route("**/api/evidence-review/supplemental-threat-anchors/items", async (route) => {
    const url = new URL(route.request().url());
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 20);
    const reviewState = url.searchParams.get("review_state") ?? "all";
    const coverageStratum = url.searchParams.get("coverage_stratum") ?? "";
    const candidates = Array.from({ length: 60 }, (_, rowIndex) => supplementalAnchorItem(rowIndex))
      .filter((item) => reviewState === "all" || (reviewState === "reviewed" ? item.reviewed : !item.reviewed))
      .filter((item) => !coverageStratum || item.coverage_stratum === coverageStratum);
    return route.fulfill({
      json: {
        workspace: "supplemental_threat_anchors",
        offset,
        limit,
        filtered_total: candidates.length,
        items: candidates.slice(offset, offset + limit).map((item) => ({
          row_index: item.row_index,
          display_position: item.display_position,
          reviewed: item.reviewed,
          coverage_stratum: item.coverage_stratum,
          evidence: item.evidence
        })),
        predictions_exposed: false,
        raw_logs_exposed: false,
        private_paths_exposed: false,
        reviewer_identities_exposed: false,
        secrets_exposed: false
      }
    });
  });
  await page.route("**/api/evidence-review/supplemental-threat-anchors/items/*", async (route) => {
    const rowIndex = Number(new URL(route.request().url()).pathname.split("/").at(-1));
    if (route.request().method() === "POST") {
      supplementalAnchorReviewReviewed = Math.max(supplementalAnchorReviewReviewed, rowIndex + 1);
      supplementalAnchorReviewRevision += 1;
      return route.fulfill({ json: supplementalAnchorOperation(supplementalAnchorItem(supplementalAnchorReviewReviewed)) });
    }
    return route.fulfill({ json: supplementalAnchorItem(rowIndex) });
  });
  await page.route("**/api/evidence-review/supplemental-threat-anchors/close", async (route) =>
    route.fulfill({ json: supplementalAnchorOperation(null) })
  );
  await page.route("**/api/evidence-review/detection/start", async (route) => route.fulfill({ json: operation("detection", detectionItem(detectionReviewReviewed)) }));
  await page.route("**/api/evidence-review/assistant/start", async (route) => route.fulfill({ json: operation("assistant", assistantItem(assistantReviewReviewed)) }));
  await page.route("**/api/evidence-review/detection/items/*", async (route) => {
    const rowIndex = Number(new URL(route.request().url()).pathname.split("/").at(-1));
    if (route.request().method() === "POST") {
      detectionReviewReviewed = Math.max(detectionReviewReviewed, rowIndex + 1);
      detectionReviewRevision += 1;
      return route.fulfill({ json: operation("detection", detectionReviewReviewed < 40 ? detectionItem(detectionReviewReviewed) : null) });
    }
    return route.fulfill({ json: detectionItem(rowIndex) });
  });
  await page.route("**/api/evidence-review/assistant/items/*", async (route) => {
    const rowIndex = Number(new URL(route.request().url()).pathname.split("/").at(-1));
    if (route.request().method() === "POST") {
      assistantReviewReviewed = Math.max(assistantReviewReviewed, rowIndex + 1);
      assistantReviewRevision += 1;
      return route.fulfill({ json: operation("assistant", assistantReviewReviewed < 8 ? assistantItem(assistantReviewReviewed) : null) });
    }
    return route.fulfill({ json: assistantItem(rowIndex) });
  });
  await page.route("**/api/evidence-review/*/complete", async (route) => {
    const workspace = new URL(route.request().url()).pathname.includes("/assistant/") ? "assistant" : "detection";
    return route.fulfill({ json: operation(workspace, null) });
  });
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
        llm_max_output_tokens: 800,
        llm_max_visible_chars: 4000,
        llm_circuit_breaker_failures: 3,
        llm_circuit_breaker_cooldown_seconds: 60,
        llm_operational: {
          status: "idle",
          calls_attempted: 0,
          calls_succeeded: 0,
          calls_failed: 0,
          fallbacks: 0,
          circuit_open: false,
          estimated_cost_usd: 0,
          secrets_exposed: false
        },
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
          "Verdict: Alert #1 was flagged because denied traffic touched 32 destination ports in five minutes.\nKey evidence:\n- Policy deny and scanning-like behavior.\nNext check: Review the related logs.",
        mode: "deterministic_local",
        response_mode: "alert_explanation",
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
            failure_category: "grounding_rejection",
            raw_log_context_included: false,
            secrets_exposed: false,
            prompt_contract: "soc_intent_aware_concise_v4",
            provider_called: false,
            answer_used: false,
            answer_guard_reason: null
          },
          alert: { id: 1, severity: "Critical" },
          answer_sections: {
            response_mode: ["alert_explanation"],
            direct_answer: ["Alert #1 was flagged because denied traffic touched 32 destination ports in five minutes."],
            summary: ["Alert #1: Critical policy_deny with risk score 88.", "Detection source: rule, anomaly, hybrid."],
            key_evidence: ["Policy deny and scanning-like behavior."],
            evidence: ["Policy deny and scanning-like behavior."],
            next_steps: ["Review the related logs."],
            what_to_check_next: ["Review the related logs."],
            citations: ["Alert detail: /api/alerts/{alert_id} #1", "Detection rule catalog: docs/DETECTION_RULE_CATALOG.md"]
          },
          evidence_detail: {
            evidence: ["Flagged as suspicious because action=deny.", "ATT&CK mapping: Discovery / Network Service Discovery / T1046."],
            risk_interpretation: ["Evidence strength: moderate confidence."],
            limitations: ["Parser context may be incomplete."],
            related_context: ["Alert detail: /api/alerts/{alert_id} #1"]
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
        detection_operations: {
          primary_rule_alert_volume: [{ name: "policy_deny", count: 4 }],
          source_alert_volume: [{ source_id: 1, name: "local_import", count: 3 }],
          analyst_dispositions: { open: 4, resolved: 8 },
          deduplication: {
            unique_alerts: 12,
            total_occurrences: 18,
            deduplicated_updates: 6,
            occurrences_per_alert: 1.5
          },
          parser_warning_context: {
            status: "limited_fields",
            parse_failure_count: 0,
            unknown_application_rows: 2,
            message: "Unknown application values limit context but do not by themselves indicate a detection failure."
          },
          accuracy_evidence: {
            status: "insufficient_evidence",
            value: null,
            message: "Operational alert volume and analyst dispositions are workload measures, not accuracy."
          }
        },
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
        warnings: [],
        parser_quality_state: "healthy",
        parser_contract_state: "current_contract",
        runtime_parser_error_count: 0,
        runtime_parser_error_rate: 0,
        structural_warning_count: 0,
        unresolved_application_count: 0,
        unresolved_application_rate: 0,
        generic_syslog_count: 0,
        raw_fallback_count: 0,
        operational_alerts: []
      },
      quality: {
        raw_logs: 2,
        normalized_logs: 2,
        unknown_app_count: 0,
        unknown_app_rate: 0,
        alert_count: 1,
        parse_failure_examples: [],
        warnings: [],
        parser_quality: {},
        parser_quality_state: "healthy",
        parser_contract_state: "current_contract",
        runtime_observed_rows: 2,
        legacy_contract_rows: 0,
        parser_error_count: 0,
        parser_error_rate: 0,
        structural_warning_count: 0,
        compatible_layout_count: 2,
        extended_layout_count: 0,
        partial_layout_count: 0,
        unsupported_layout_count: 0,
        unresolved_application_count: 0,
        unresolved_application_rate: 0,
        absent_application_count: 0,
        not_applicable_application_count: 0,
        generic_syslog_count: 0,
        raw_fallback_count: 0,
        operational_alerts: []
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
      latest_error: null,
      created_at: "2026-05-22T00:02:00Z",
      updated_at: "2026-05-22T00:02:01Z",
      health: {
        source_id: 2,
        status: "warning",
        enabled: true,
        logs_received_count: 3,
        parse_success_count: 0,
        parse_failure_count: 3,
        parse_success_rate: 0,
        last_seen: "2026-05-22T00:02:01Z",
        last_log_received_at: "2026-05-22T00:02:01Z",
        latest_error: null,
        recommendation: "Warning: review parser errors, structural layout alerts, or raw fallback usage. Unresolved applications alone are not failures.",
        warnings: ["Raw fallback preserves evidence but structured fields may be limited."],
        parser_quality_state: "warning",
        parser_contract_state: "current_contract",
        runtime_parser_error_count: 0,
        runtime_parser_error_rate: 0,
        structural_warning_count: 0,
        unresolved_application_count: 0,
        unresolved_application_rate: 0,
        generic_syslog_count: 0,
        raw_fallback_count: 3,
        operational_alerts: [
          {
            code: "prolonged_raw_fallback",
            severity: "warning",
            message: "Raw fallback preserves evidence but structured fields may be limited."
          }
        ]
      },
      quality: {
        raw_logs: 3,
        normalized_logs: 3,
        unknown_app_count: 3,
        unknown_app_rate: 100,
        alert_count: 0,
        parse_failure_examples: [],
        warnings: ["Parser profile has limited structured fields."],
        parser_quality: {},
        parser_quality_state: "warning",
        parser_contract_state: "current_contract",
        runtime_observed_rows: 3,
        legacy_contract_rows: 0,
        parser_error_count: 0,
        parser_error_rate: 0,
        structural_warning_count: 0,
        compatible_layout_count: 0,
        extended_layout_count: 0,
        partial_layout_count: 0,
        unsupported_layout_count: 0,
        unresolved_application_count: 0,
        unresolved_application_rate: 0,
        absent_application_count: 0,
        not_applicable_application_count: 3,
        generic_syslog_count: 0,
        raw_fallback_count: 3,
        operational_alerts: [
          {
            code: "prolonged_raw_fallback",
            severity: "warning",
            message: "Raw fallback preserves evidence but structured fields may be limited."
          }
        ]
      },
      recent_ingestion_runs: [],
      recent_detection_runs: []
    };
    const url = route.request().url();
    if (url.includes("/reparse-impact-preview")) {
      return route.fulfill({
        json: {
          version: "v5.13-runtime-parser-quality-v1",
          status: "preview_complete",
          scope: "selected_source",
          preview_only: true,
          reparse_performed: false,
          database_mutated: false,
          total_rows: 2,
          rows_scanned: 2,
          coverage_complete: true,
          current_contract_metadata_rows: 2,
          legacy_contract_rows_scanned: 0,
          parser_profiles: { palo_alto: 2 },
          parser_contract_versions: { "palo_alto_syslog_v5.12": 2 },
          compatibility_statuses: { supported_known_layout: 2 },
          application_resolution_statuses: { identified: 2 },
          raw_evidence_accessed: false,
          raw_logs_returned: false,
          private_paths_included: false,
          ip_addresses_included: false,
          source_identity_included: false,
          labels_accessed: false,
          alerts_created: 0,
          response_actions_created: 0
        }
      });
    }
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
  await page.route("**/api/ml/evidence-snapshot", async (route) =>
    route.fulfill({
      json: {
        schema_version: "1.1",
        schema_aware_abstention: {
          contract_version: "v5.20-schema-aware-abstention-v1",
          expected_schema_id: "palo_alto",
          required_features: ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "app"],
          compatible_status: "compatible",
          fail_closed: true,
          incompatible_evidence_scored: false,
          rules_remain_authoritative: true,
          decision_support_only: true,
          production_promoted: false,
          response_automation_allowed: false,
          runtime: {
            rows_checked: 4,
            abstained_count: 1,
            abstention_rate: 0.25,
            reason_counts: { schema_profile_mismatch: 1 }
          }
        },
        canonical_evidence: {
          available: true,
          status: "completed_candidate_only",
          snapshot_id: "v41-test-snapshot",
          generated_at: "2026-07-14T06:02:49Z",
          version: "v4.1",
          evidence_type: "controlled_development_validation",
          readiness_decision: "candidate_only",
          selected_strategy: "pooled_schema_aware_calibrated_extra_trees",
          selection_scope: "development_only_not_activation",
          evaluated_splits: 3,
          calibration_passed_splits: 0,
          dataset: {
            dataset_id: "cse-cic-ids2018-v401-development-days",
            title: "CSE-CIC-IDS2018 development-only evidence",
            publisher: "Canadian Institute for Cybersecurity",
            role: "development_only_not_final_external_evidence",
            accepted_rows: 16817,
            provider_ground_truth: true,
            human_reviewed: false
          },
          metric_ranges: {
            queue_precision: { min: 0.8595, max: 0.9312 },
            queue_recall: { min: 0.9432, max: 0.9983 },
            queue_f1: { min: 0.9237, max: 0.9524 },
            benign_like_false_positive_rate: { min: 0.0882, max: 0.1997 },
            suspicious_recall: { min: 0.9931, max: 1 },
            malicious_recall: { min: 0.9275, max: 0.9978 }
          },
          worst_split: { split_mode: "random_seed_42", metrics: { queue_f1: 0.9237 } },
          calibration: {
            status: "weak",
            passed: false,
            brier_score: 0.1144,
            expected_calibration_error: 0.173,
            max_confidence_accuracy_gap: 0.5666
          },
          safety: {
            development_only: true,
            model_activated: false,
            model_artifact_written: false,
            production_promoted: false,
            response_automation_allowed: false,
            real_firewall_blocking_enabled: false,
            database_counts_unchanged: true
          },
          limitations: ["Development-only evidence.", "Calibration remains weak."]
        },
        operational_models: {
          isolation_forest: {
            role: "assistive_anomaly_signal",
            artifact_exists: true,
            model_type: "IsolationForest",
            anomaly_rate_percent: 0.98,
            decision_support_only: true
          },
          active_supervised_artifact: {
            artifact_exists: true,
            metadata_status: "metadata_unknown",
            metadata_unknown: true,
            model_type: null,
            feature_set: null,
            message: "Active artifact metadata unknown.",
            production_promoted: false,
            response_automation_allowed: false
          },
          diagnostic_candidates: {
            registry_entry_count: 26,
            latest_candidate: null,
            canonical_candidate_is_active: false
          }
        },
        safety: {
          decision_support_only: true,
          production_promoted: false,
          response_automation_allowed: false,
          real_firewall_blocking_enabled: false,
          secrets_exposed: false,
          local_paths_exposed: false
        }
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
        active_artifact_exists: true,
        active_artifact_metadata_unknown: true,
        response_automation_allowed: false,
        models: [
          {
            model_id: 0,
            model_type: "unknown",
            model_version: "active-unregistered",
            operation: "active_artifact",
            readiness_decision: "unknown_active_artifact",
            metrics: {},
            created_at: null,
            is_active_path: true,
            active_artifact_metadata_unknown: true
          },
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
  await page.route("**/api/ml/supervised/shadow-observations/summary", async (route) =>
    route.fulfill({
      json: {
        ok: true,
        version: "v5.9-longitudinal-shadow-observation-v1",
        status: "no_longitudinal_observations",
        observation_enabled: false,
        shadow_scoring_enabled: false,
        observation_count: 0,
        source_filter_applied: false,
        since_filter_applied: false,
        latest: null,
        trend: [],
        trend_count: 0,
        drift_status_counts: {},
        runtime_status_counts: {},
        queue_rate: { minimum: null, mean: null, maximum: null },
        rule_disagreement_rate: { minimum: null, mean: null, maximum: null },
        independent_evidence: {
          status: "independent_evidence_required",
          qualified: false,
          source_device_count: 0,
          independent_time_window_count: 0,
          blind_metrics_available: false
        },
        retention: {
          retention_days: 90,
          automatic_cleanup_enabled: false,
          append_only_between_explicit_retention_runs: true
        },
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        model_activated: false,
        production_promoted: false,
        response_automation_allowed: false,
        real_firewall_blocking_enabled: false,
        raw_logs_included: false,
        private_paths_included: false,
        fingerprints_included: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/ml/supervised/shadow-operations/acceptance", async (route) =>
    route.fulfill({
      json: {
        ok: true,
        version: "v5.10-detection-operations-shadow-acceptance-v1",
        status: "insufficient_operational_evidence",
        evidence_role: "reused_development_operational_evidence_only",
        independent_validation: false,
        observation_count: 0,
        source_scope_count: 0,
        time_scope_count: 0,
        latest_observation_at: null,
        queue_rate: { minimum: null, mean: null, maximum: null, range: null },
        rule_shadow_disagreement_rate: { minimum: null, mean: null, maximum: null, range: null },
        isolation_forest_anomaly_rate: { minimum: null, mean: null, maximum: null, range: null },
        runtime_seconds: { minimum: null, mean: null, maximum: null, range: null },
        quality: {},
        drift: { current_state: "Insufficient Evidence", status_counts: {} },
        failed_observation_count: 0,
        insufficient_evidence_count: 0,
        contract_mismatch_count: 0,
        warnings: ["No governed historical observations have been recorded."],
        gates: [],
        gates_passed: 2,
        gates_total: 8,
        operational_acceptance_passed: false,
        accuracy_metrics_calculated: false,
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        isolation_forest_advisory_only: true,
        model_activated: false,
        production_promoted: false,
        response_automation_allowed: false,
        real_firewall_blocking_enabled: false,
        source_identifiers_included: false,
        raw_logs_included: false,
        ip_addresses_included: false,
        private_paths_included: false,
        fingerprints_included: false,
        labels_accessed: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/ml/supervised/shadow-operations/diagnostics", async (route) =>
    route.fulfill({
      json: {
        ok: true,
        version: "v5.11-operational-drift-root-cause-v1",
        status: "insufficient_operational_evidence",
        observation_count: 0,
        source_scope_count: 0,
        current_state: "Insufficient Evidence",
        rows: [],
        root_cause_counts: {},
        operational_metrics: {
          queue_rate: { minimum: null, mean: null, maximum: null, range: null },
          rule_shadow_disagreement_rate: { minimum: null, mean: null, maximum: null, range: null },
          isolation_forest_anomaly_rate: { minimum: null, mean: null, maximum: null, range: null }
        },
        thresholds: { minimum_rows: 50, drift_total_variation: 0.25, ood_total_variation: 0.5 },
        hysteresis: {
          drift_escalation_observations: 2,
          drift_recovery_stable_observations: 2,
          ood_escalation_observations: 1,
          ood_recovery_sufficient_observations: 3,
          insufficient_evidence_clears_warning: false
        },
        cadence: {
          enabled: false,
          dependencies_ready: false,
          scheduler_mode: "external_due_check_only",
          always_on_scheduler_enabled: false,
          cadence_minutes: 60,
          active_job: false,
          latest_status: "not_run",
          last_completed_at: null,
          next_due_at: null,
          due: false,
          bounded_source_count: 8,
          bounded_windows_per_source: 3,
          duplicate_suppression: true,
          idempotent_retry: true,
          cooperative_cancellation: true
        },
        accuracy_metrics_calculated: false,
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        isolation_forest_advisory_only: true,
        model_activated: false,
        production_promoted: false,
        response_automation_allowed: false,
        real_firewall_blocking_enabled: false,
        source_identifiers_included: false,
        raw_logs_included: false,
        ip_addresses_included: false,
        private_paths_included: false,
        fingerprints_included: false,
        labels_accessed: false,
        secrets_exposed: false
      }
    })
  );
  await page.route("**/api/ml/supervised/shadow-operations/parser-quality", async (route) =>
    route.fulfill({
      json: {
        ok: true,
        version: "v5.12-parser-profile-baseline-repair-v1",
        status: "parser_profile_diagnostics_available",
        parser_contract_version: "palo_alto_syslog_v5.12",
        observation_count: 1,
        source_scope_count: 1,
        current_state: "Stable",
        old_state_counts: { "Drift Warning": 1 },
        repaired_state_counts: { Stable: 1 },
        baseline_scope_counts: {
          parser_profile_source_type: 1,
          global_fallback: 0
        },
        legacy_warning_windows_reclassified: 1,
        baseline_catalog: {
          status: "governed_parser_baseline_available",
          available: true,
          minimum_support: 200,
          parser_contract_version: "palo_alto_syslog_v5.12",
          provenance: {
            evidence_role: "governed_development_fit_aggregate",
            selection_labels_used: false,
            accuracy_metrics_used: false,
            source_identity_used: false,
            locked_final_evidence_used: false,
            baseline_report_committed: false
          }
        },
        rows: [
          {
            source_scope: "source-scope-01",
            time_scope: "time-scope-01",
            rows_evaluated: 100,
            old_drift_state: "Drift Warning",
            raw_repaired_state: "Stable",
            drift_state: "Stable",
            queue_rate: 0.2,
            disagreement_rate: 0.1,
            isolation_anomaly_rate: 0,
            baseline_selection: {
              status: "profile_source_type_baseline_selected",
              scope: "parser_profile_source_type",
              comparable: true,
              parser_profile: "palo_alto",
              source_type: "firewall",
              support_rows: 352312
            },
            application_total_variation: 0.1,
            schema_total_variation: 0,
            quality: {
              rows: 100,
              parser_error_rate: 0,
              parser_structural_warning_per_row: 0,
              required_missing_per_row: 0,
              unresolved_application_rate: 0.08
            },
            quality_absolute_delta: {
              parser_error_rate: 0,
              parser_structural_warning_per_row: 0,
              required_missing_per_row: 0,
              unresolved_application_rate: 0.006
            },
            compatibility_status_counts: { known_layout: 100 },
            application_resolution_counts: { identified: 92, unresolved: 8 },
            root_cause_codes: ["no_material_aggregate_shift"],
            accuracy_metrics_calculated: false
          }
        ],
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        isolation_forest_advisory_only: true,
        model_activated: false,
        production_promoted: false,
        response_automation_allowed: false,
        real_firewall_blocking_enabled: false,
        source_identifiers_included: false,
        raw_logs_included: false,
        ip_addresses_included: false,
        private_paths_included: false,
        labels_accessed: false,
        accuracy_metrics_calculated: false,
        secrets_exposed: false
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
        model_path: "D:\\Synthetic\\ATDR\\models\\very\\long\\windows\\path\\isolation_forest.joblib",
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
        export_dir: "D:\\Synthetic\\ATDR\\demo_exports\\atdr_demo_bundle_with_a_very_long_name",
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
  await page.route("**/api/auth/mfu-iam/public-status", (route) =>
    route.fulfill({
      json: {
        auth_mode: "local_recovery",
        local_login_enabled: true,
        template_shell_required: false,
        enabled: false,
        b2b_ready: false,
        mock_enabled: false,
        google_sso_enabled: false,
        google_client_id_configured: false,
        allowed_domains: [],
        domain_hints: [],
        default_role: "analyst",
        auth_require_2fa: false,
        mode: "local_recovery",
        secrets_exposed: false
      }
    })
  );
  await page.goto("/login");
  await expect(page.getByText("MFU ATDR SOC Console")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in for recovery", exact: true })).toBeVisible();
});

test("legacy browser credential query is blocked and removed", async ({ page }) => {
  await page.route("**/api/auth/me", (route) => route.fulfill({ status: 401, json: { detail: "Not authenticated" } }));
  await page.route("**/api/auth/mfu-iam/public-status", async (route) =>
    route.fulfill({
      json: {
        auth_mode: "template_shell",
        local_login_enabled: false,
        template_shell_required: true,
        enabled: true,
        b2b_ready: false,
        mock_enabled: false,
        template_shell_enabled: true,
        template_shell_ready: true,
        handoff_enabled: true,
        handoff_ready: true,
        template_shell_launch_url: "http://localhost:8080/#/pages/login",
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
  await expect(page.getByRole("link", { name: "Return to MFU Sign In" })).toBeVisible();
  await expect(page.getByLabel("Username or email")).toHaveCount(0);
  expect(page.url()).not.toContain("tiny-token");
  expect(page.url()).not.toContain("mfu_token");
});

test("school handoff errors are actionable and do not expose credentials", async ({ page }) => {
  await page.route("**/api/auth/me", (route) => route.fulfill({ status: 401, json: { detail: "Not authenticated" } }));
  await page.route("**/api/auth/mfu-iam/public-status", (route) =>
    route.fulfill({
      json: {
        auth_mode: "template_shell",
        local_login_enabled: false,
        template_shell_required: true,
        enabled: true,
        b2b_ready: false,
        mock_enabled: false,
        template_shell_enabled: true,
        template_shell_ready: true,
        handoff_enabled: true,
        handoff_ready: true,
        template_shell_launch_url: "http://localhost:8080/#/pages/login",
        google_sso_enabled: true,
        google_client_id_configured: true,
        allowed_domains: ["lamduan.mfu.ac.th"],
        domain_hints: ["lamduan.mfu.ac.th"],
        default_role: "analyst",
        auth_require_2fa: true,
        mode: "template_shell_secure_handoff",
        secrets_exposed: false
      }
    })
  );

  await page.goto("/login?handoff_error=handoff_expired_or_used");

  await expect(page.getByText("The one-time sign-in handoff expired or was already used. Sign in again from the MFU shell.")).toBeVisible();
  await expect(page.getByRole("link", { name: "Return to MFU Sign In" })).toHaveAttribute(
    "href",
    "http://localhost:8080/#/pages/login"
  );
  await expect(page.getByText(/token|secret/i)).toHaveCount(0);
});

test("protected login preserves a safe alert deep link", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/auth/me", (route) => {
    const authorization = route.request().headers().authorization;
    return authorization
      ? route.fulfill({ json: { id: 1, username: "admin", full_name: "Smoke User", role: "admin", is_active: true } })
      : route.fulfill({ status: 401, json: { detail: "Not authenticated" } });
  });
  await page.route("**/api/auth/login", (route) =>
    route.fulfill({
      json: {
        access_token: "recovery-token",
        token_type: "bearer",
        expires_in_minutes: 30,
        username: "admin",
        role: "admin"
      }
    })
  );

  await page.goto("/alerts?alert=1#evidence");
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("Username or email").fill("admin");
  await page.getByLabel("Password").fill("test-password");
  await page.getByRole("button", { name: "Sign in for recovery" }).click();

  await expect(page).toHaveURL(/\/alerts\?alert=1#evidence$/);
  await expect(page.getByRole("heading", { name: "Critical: Smoke alert" })).toBeVisible();
});

test("login rejects malicious redirect state", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/auth/me", (route) => {
    const authorization = route.request().headers().authorization;
    return authorization
      ? route.fulfill({ json: { id: 1, username: "admin", full_name: "Smoke User", role: "admin", is_active: true } })
      : route.fulfill({ status: 401, json: { detail: "Not authenticated" } });
  });
  await page.route("**/api/auth/login", (route) =>
    route.fulfill({
      json: {
        access_token: "recovery-token",
        token_type: "bearer",
        expires_in_minutes: 30,
        username: "admin",
        role: "admin"
      }
    })
  );

  await page.goto("/login");
  await page.evaluate(() => {
    window.history.replaceState(
      { usr: { from: "/\\\\attacker.example/redirect" }, key: "unsafe-redirect", idx: 0 },
      "",
      "/login"
    );
  });
  await page.reload();
  await page.getByLabel("Username or email").fill("admin");
  await page.getByLabel("Password").fill("test-password");
  await page.getByRole("button", { name: "Sign in for recovery" }).click();

  await expect(page).toHaveURL(/\/overview$/);
  expect(new URL(page.url()).origin).toBe("http://127.0.0.1:4173");
});

test("unknown routes fail closed to the authenticated overview", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);

  await page.goto("/not-an-atdr-route?next=https://attacker.example");

  await expect(page).toHaveURL(/\/overview$/);
  await expect(page.getByText("MFU Security Operations")).toBeVisible();
});

test("core analyst routes render with mocked API", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  for (const path of ["/overview", "/alerts", "/logs", "/response", "/controls", "/audit", "/tuning", "/ml"]) {
    await page.goto(path);
    await expect(page.getByText("MFU Security Operations")).toBeVisible();
    await expect(page.getByText("API health check failed")).not.toBeVisible();
  }
});

test("critical pages show concise API failure states", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);

  await page.unroute("**/api/dashboard/summary");
  await page.route("**/api/dashboard/summary", (route) =>
    route.fulfill({ status: 503, json: { detail: "Overview service is temporarily unavailable." } })
  );
  await page.goto("/overview");
  await expect(page.getByRole("alert")).toContainText("Overview service is temporarily unavailable.");

  await page.unroute("**/api/response/blocked-ips");
  await page.route("**/api/response/blocked-ips", (route) =>
    route.fulfill({ status: 503, json: { detail: "Response status is temporarily unavailable." } })
  );
  await page.goto("/response");
  await expect(page.getByRole("alert")).toContainText("Response status is temporarily unavailable.");

  await page.unroute("**/api/ml/report");
  await page.route("**/api/ml/report", (route) =>
    route.fulfill({ status: 503, json: { detail: "AI Governance data is temporarily unavailable." } })
  );
  await page.goto("/ml");
  await expect(page.getByRole("alert")).toContainText("AI Governance data is temporarily unavailable.");
});

test("browser history preserves the assistant investigation session", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);

  await page.goto("/assistant?alert=1");
  await page.getByLabel("Analyst question").fill("Why was alert 1 flagged?");
  await page.getByRole("button", { name: "Ask assistant" }).click();
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Alert #1 was flagged");

  await page.getByRole("link", { name: "Alerts", exact: true }).first().click();
  await expect(page).toHaveURL(/\/alerts$/);
  await page.goBack();
  await expect(page).toHaveURL(/\/assistant\?alert=1$/);
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Alert #1 was flagged");

  await page.goForward();
  await expect(page).toHaveURL(/\/alerts$/);
});

test("overview system health panel and ML governance wording render", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);

  await page.goto("/overview");
  await expect(page.getByText("System Health")).toBeVisible();
  const detectionOperations = page.getByTestId("detection-operations-panel");
  await expect(detectionOperations).toContainText("Detection Operations");
  await expect(detectionOperations).toContainText("Primary Rule Volume");
  await expect(detectionOperations).toContainText("policy deny");
  await expect(detectionOperations).toContainText("Source-Scoped Alert Volume");
  await expect(detectionOperations.getByRole("link", { name: /local_import/ })).toHaveAttribute("href", "/overview?source=1");
  await expect(detectionOperations).toContainText("Analyst Dispositions");
  await expect(detectionOperations).toContainText("Occurrences / Alert");
  await expect(page.getByTestId("detection-accuracy-state")).toContainText("not accuracy");
  await expect(page.getByTestId("detection-parser-context")).toContainText("Unknown application values limit context");
  await expect(page.getByTestId("detection-run-trend")).not.toHaveAttribute("open", "");
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
  await expect(page.getByText("Canonical ML Evidence", { exact: true })).toBeVisible();
  await expect(page.getByText("3 development splits | Snapshot v41-test-snapshot")).toBeVisible();
  await expect(page.getByText("candidate only | controlled development validation")).toBeVisible();
  await expect(page.getByText("Drift", { exact: true })).toBeVisible();
  await expect(page.getByText("0 warnings")).toBeVisible();
  await expect(page.getByText("Lab-Scale Validation")).toBeVisible();
  await expect(page.getByText("Manual Approval Required", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Canonical Evidence Available", { exact: true })).toBeVisible();
  await expect(page.getByText("Real device validation remains future work.")).not.toBeVisible();
  await expect(page.getByText("Operations Health")).toBeVisible();
  await expect(page.getByTestId("operational-warnings")).toContainText("Database migration revision is not at Alembic head.");
  await expect(page.getByText("Log Sources")).toBeVisible();
  await expect(page.getByRole("button", { name: /local_import file_import/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /scenario-raw-fallback/ })).toBeVisible();
  await page.getByRole("button", { name: /local_import file_import/ }).click();
  await expect(page.getByText("Parser Profile", { exact: true })).toBeVisible();
  await expect(page.getByText("Troubleshooting Hints")).toBeVisible();
  await expect(page.getByText("Parser profile behavior")).toBeVisible();
  await expect(page.getByText("Contract State")).toBeVisible();
  await expect(page.getByText("Parser Quality", { exact: true })).toBeVisible();
  await expect(page.getByTestId("historical-contract-preview")).toContainText("No log is reparsed or changed.");
  await page.getByRole("button", { name: "Preview impact" }).click();
  await expect(page.getByTestId("historical-contract-preview")).toContainText("Database mutated: no.");
  await expect(page.getByText("Recent Detection Runs")).toBeVisible();
  await expect(page.getByText("Run attack types: port_scan (1)")).toBeVisible();
  await page.getByRole("button", { name: "Close details" }).click();
  await page.getByRole("button", { name: /scenario-raw-fallback/ }).click();
  await expect(page.getByTestId("source-parser-alerts")).toContainText("prolonged raw fallback");
  await expect(page.getByText("Raw fallback preserves evidence but structured fields may be limited.", { exact: true })).toBeVisible();
  await expect(page.getByText("Fallback / Failed Rows", { exact: true })).toBeVisible();
  await expect(page.getByText("Runtime Parser Errors", { exact: true })).toBeVisible();
  await expect(page.getByText("Latest Errors", { exact: true })).not.toBeVisible();
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
  await expect(page.getByText("Canonical ML Evidence", { exact: true })).toBeVisible();
  await expect(page.getByText("Controlled validation snapshot", { exact: true })).toBeVisible();
  await expect(page.getByText("Queue F1", { exact: true })).toBeVisible();
  await expect(page.getByText("0.9237-0.9524", { exact: true })).toBeVisible();
  await expect(page.getByText("Benign FPR", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("0.0882-0.1997", { exact: true })).toBeVisible();
  await expect(page.getByText("Evidence Provenance", { exact: true })).toBeVisible();
  await expect(page.getByText("CSE-CIC-IDS2018 development-only evidence", { exact: true })).toBeVisible();
  await expect(page.getByText("Supervised Artifact", { exact: true })).toBeVisible();
  await expect(page.getByTestId("schema-aware-abstention")).toContainText("Fail closed");
  await expect(page.getByTestId("schema-aware-abstention")).toContainText("1 of 4 runtime rows abstained");
  await page.getByText("Schema compatibility policy", { exact: true }).click();
  await expect(page.getByText("Incompatible evidence scored: no", { exact: true })).toBeVisible();
  const modelRegistry = page.getByTestId("supervised-model-registry");
  await expect(modelRegistry.getByText("Metadata unknown", { exact: true })).toBeVisible();
  await expect(modelRegistry.getByText("active metadata unavailable", { exact: true })).toBeVisible();
  await expect(modelRegistry.getByText("Lifecycle", { exact: true })).toBeVisible();
  await expect(modelRegistry.getByText("Response Automation", { exact: true })).toBeVisible();
  await page.getByText("Artifact Metadata", { exact: true }).click();
  await expect(page.getByText("The v4.9 reliability-lock candidates are", { exact: false })).toBeVisible();
  await expect(page.getByText("active artifact ready", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Review focus: benign and suspicious separation need more analyst-verified examples.")).not.toBeVisible();
  await expect(page.getByTestId("detection-ml-productization-panel")).toContainText("Detection / ML Productization");
  await expect(page.getByTestId("detection-ml-productization-panel")).toContainText("diagnostic evaluation passed");
  await expect(page.getByTestId("detection-ml-productization-panel")).toContainText("18 implemented rules");
  const currentPolicy = page.getByTestId("ml-governance-policy");
  await expect(currentPolicy).toContainText("Current Operating Policy");
  await expect(page.getByText("SOC triage decision support")).toBeVisible();
  await expect(currentPolicy).toContainText("threat positive review priority");
  await expect(currentPolicy).toContainText("not production promoted");
  await expect(page.getByText("Decision Support Only", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Response Automation Disabled", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Detection Quality Revalidation")).toHaveCount(0);
  await expect(page.getByText("SOC Review Queue Diagnostic")).toHaveCount(0);
  await expect(page.getByText("Technical validation details")).toHaveCount(0);
  await expect(page.getByText("v1.8 external benchmark passed")).toHaveCount(0);
  await expect(page.getByText("Import Benchmark Review CSV")).toBeVisible();
  await page.getByText("CSV import rules").click();
  await expect(page.getByText(/Files containing `benchmark_row_id` must use Benchmark Review Import/)).toBeVisible();
  await expect(page.getByText("Not Production Promoted", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Technical Review Notes")).not.toBeVisible();
  await page.getByText("Latest registered training run").click();
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

test("AI Governance shows governed supervised shadow status without selecting the legacy artifact", async ({ page }) => {
  await mockApi(page);
  await page.unroute("**/api/ml/supervised/shadow-observations/summary");
  await page.route("**/api/ml/supervised/shadow-observations/summary", async (route) =>
    route.fulfill({
      json: {
        ok: true,
        version: "v5.9-longitudinal-shadow-observation-v1",
        status: "longitudinal_observations_available",
        observation_enabled: true,
        shadow_scoring_enabled: true,
        observation_count: 2,
        source_filter_applied: false,
        since_filter_applied: false,
        latest: {
          observation_id: 2,
          candidate_name: "calibrated_hist_gradient_boosting",
          candidate_version: "v5.6-private-panos-model-repair-v1",
          status: "evaluated_shadow_read_only",
          contract_matched: true,
          window_start: "2026-07-26T01:00:00Z",
          window_end: "2026-07-26T02:00:00Z",
          observed_start: "2026-07-26T01:00:00Z",
          observed_end: "2026-07-26T02:00:00Z",
          requested_limit: 100,
          rows_evaluated: 100,
          queue_count: 47,
          queue_rate: 0.47,
          score_mean: 0.42,
          score_p95: 0.81,
          confidence_mean: 0.76,
          confidence_p95: 0.91,
          drift_status: "Drift Warning",
          application_total_variation: 0.262,
          schema_total_variation: 0.06,
          disagreement_count: 58,
          disagreement_rate: 0.58,
          isolation_anomaly_count: 9,
          isolation_anomaly_rate: 0.09,
          runtime_seconds: 0.7,
          failure_code: null,
          created_at: "2026-07-26T02:01:00Z",
          raw_logs_included: false,
          ip_addresses_included: false,
          private_paths_included: false,
          fingerprints_included: false,
          secrets_exposed: false
        },
        trend: [
          {
            observation_id: 1,
            created_at: "2026-07-25T02:01:00Z",
            queue_rate: 0.41,
            disagreement_rate: 0.49,
            drift_status: "Stable"
          },
          {
            observation_id: 2,
            created_at: "2026-07-26T02:01:00Z",
            queue_rate: 0.47,
            disagreement_rate: 0.58,
            drift_status: "Drift Warning"
          }
        ],
        trend_count: 2,
        drift_status_counts: { Stable: 1, "Drift Warning": 1 },
        runtime_status_counts: { evaluated_shadow_read_only: 2 },
        queue_rate: { minimum: 0.41, mean: 0.44, maximum: 0.47 },
        rule_disagreement_rate: { minimum: 0.49, mean: 0.535, maximum: 0.58 },
        independent_evidence: {
          status: "independent_evidence_required",
          qualified: false,
          source_device_count: 0,
          independent_time_window_count: 0,
          blind_metrics_available: false
        },
        retention: {
          retention_days: 90,
          automatic_cleanup_enabled: false,
          append_only_between_explicit_retention_runs: true
        },
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        model_activated: false,
        production_promoted: false,
        response_automation_allowed: false,
        real_firewall_blocking_enabled: false,
        raw_logs_included: false,
        private_paths_included: false,
        fingerprints_included: false,
        secrets_exposed: false
      }
    })
  );
  await page.unroute("**/api/ml/supervised/shadow-operations/acceptance");
  await page.route("**/api/ml/supervised/shadow-operations/acceptance", async (route) =>
    route.fulfill({
      json: {
        ok: true,
        version: "v5.10-detection-operations-shadow-acceptance-v1",
        status: "operational_shadow_acceptance_warning",
        evidence_role: "reused_development_operational_evidence_only",
        independent_validation: false,
        observation_count: 2,
        source_scope_count: 1,
        time_scope_count: 2,
        latest_observation_at: "2026-07-26T02:01:00Z",
        queue_rate: { minimum: 0.41, mean: 0.44, maximum: 0.47, range: 0.06 },
        rule_shadow_disagreement_rate: { minimum: 0.49, mean: 0.535, maximum: 0.58, range: 0.09 },
        isolation_forest_anomaly_rate: { minimum: 0.07, mean: 0.08, maximum: 0.09, range: 0.02 },
        runtime_seconds: { minimum: 0.6, mean: 0.65, maximum: 0.7, range: 0.1 },
        quality: {},
        drift: { current_state: "Drift Warning", status_counts: { Stable: 1, "Drift Warning": 1 } },
        failed_observation_count: 0,
        insufficient_evidence_count: 1,
        contract_mismatch_count: 0,
        warnings: ["1 scope has insufficient operational evidence."],
        gates: [],
        gates_passed: 7,
        gates_total: 8,
        operational_acceptance_passed: false,
        accuracy_metrics_calculated: false,
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        isolation_forest_advisory_only: true,
        model_activated: false,
        production_promoted: false,
        response_automation_allowed: false,
        real_firewall_blocking_enabled: false,
        source_identifiers_included: false,
        raw_logs_included: false,
        ip_addresses_included: false,
        private_paths_included: false,
        fingerprints_included: false,
        labels_accessed: false,
        secrets_exposed: false
      }
    })
  );
  await page.unroute("**/api/ml/supervised/shadow-operations/diagnostics");
  await page.route("**/api/ml/supervised/shadow-operations/diagnostics", async (route) =>
    route.fulfill({
      json: {
        ok: true,
        version: "v5.11-operational-drift-root-cause-v1",
        status: "operational_diagnostics_available",
        observation_count: 2,
        source_scope_count: 1,
        current_state: "Drift Warning",
        rows: [
          {
            source_scope: "source-scope-01",
            time_scope: "time-scope-01",
            observation_time: "2026-07-25T02:01:00Z",
            rows_evaluated: 100,
            raw_drift_state: "Stable",
            drift_state: "Stable",
            queue_rate: 0.41,
            disagreement_rate: 0.49,
            isolation_anomaly_rate: 0.07,
            score_mean: 0.38,
            score_p95: 0.79,
            application_total_variation: 0.19,
            schema_total_variation: 0.01,
            unknown_app_rate: 0.02,
            parser_warning_per_row: 0.01,
            runtime_seconds: 0.6,
            root_cause_codes: ["no_material_aggregate_shift"],
            quality_warning: "No material aggregate quality shift detected.",
            accuracy_metrics_calculated: false
          },
          {
            source_scope: "source-scope-01",
            time_scope: "time-scope-02",
            observation_time: "2026-07-26T02:01:00Z",
            rows_evaluated: 100,
            raw_drift_state: "Drift Warning",
            drift_state: "Drift Warning",
            queue_rate: 0.47,
            disagreement_rate: 0.58,
            isolation_anomaly_rate: 0.09,
            score_mean: 0.42,
            score_p95: 0.81,
            application_total_variation: 0.262,
            schema_total_variation: 0.06,
            unknown_app_rate: 0.04,
            parser_warning_per_row: 0.02,
            runtime_seconds: 0.7,
            root_cause_codes: ["application_distribution_shift"],
            quality_warning: "Application mix differs from the governed baseline.",
            accuracy_metrics_calculated: false
          }
        ],
        root_cause_counts: {
          application_distribution_shift: 1,
          no_material_aggregate_shift: 1
        },
        operational_metrics: {
          queue_rate: { minimum: 0.41, mean: 0.44, maximum: 0.47, range: 0.06 },
          rule_shadow_disagreement_rate: { minimum: 0.49, mean: 0.535, maximum: 0.58, range: 0.09 },
          isolation_forest_anomaly_rate: { minimum: 0.07, mean: 0.08, maximum: 0.09, range: 0.02 }
        },
        thresholds: { minimum_rows: 50, drift_total_variation: 0.25, ood_total_variation: 0.5 },
        hysteresis: {
          drift_escalation_observations: 2,
          drift_recovery_stable_observations: 2,
          ood_escalation_observations: 1,
          ood_recovery_sufficient_observations: 3,
          insufficient_evidence_clears_warning: false
        },
        cadence: {
          enabled: false,
          dependencies_ready: true,
          scheduler_mode: "external_due_check_only",
          always_on_scheduler_enabled: false,
          cadence_minutes: 60,
          active_job: false,
          latest_status: "not_run",
          last_completed_at: null,
          next_due_at: null,
          due: false,
          bounded_source_count: 8,
          bounded_windows_per_source: 3,
          duplicate_suppression: true,
          idempotent_retry: true,
          cooperative_cancellation: true
        },
        accuracy_metrics_calculated: false,
        lifecycle_state: "shadow_observation",
        rules_alert_authoritative: true,
        isolation_forest_advisory_only: true,
        model_activated: false,
        production_promoted: false,
        response_automation_allowed: false,
        real_firewall_blocking_enabled: false,
        source_identifiers_included: false,
        raw_logs_included: false,
        ip_addresses_included: false,
        private_paths_included: false,
        fingerprints_included: false,
        labels_accessed: false,
        secrets_exposed: false
      }
    })
  );
  await page.unroute("**/api/ml/supervised/models");
  await page.route("**/api/ml/supervised/models", async (route) =>
    route.fulfill({
      json: {
        ok: true,
        active_model_path: "supervised_candidates/v5.1-soc-queue-smoke.joblib",
        active_artifact_exists: true,
        active_artifact_metadata_status: "registered",
        active_artifact_metadata_unknown: false,
        lifecycle_state: "shadow_observation",
        governed_lifecycle: {
          lifecycle_state: "shadow_observation",
          configured_lifecycle_state: "shadow_observation",
          model_run_id: 42,
          lifecycle_run_id: 43,
          model_version: "v5.1-soc-queue-smoke",
          model_type: "calibrated_extra_trees",
          target_mode: "binary_soc_review_queue",
          feature_set_version: "v5.1-causal-soc-queue-features-v1",
          calibration_method: "sigmoid_on_dedicated_calibration_partition",
          calibration_status: "weak_or_unstable",
          validation_status: "shadow_only",
          decision_support_eligible: false,
          shadow_safety_passed: true,
          threshold: 0.85,
          status_message: "Supervised SOC queue is observing in shadow and cannot alter alerts.",
          telemetry: {
            inference_count: 4,
            queue_rate: 0.25,
            latency_ms: { p95: 12.4 },
            missing_feature_rate: 0
          },
          durable_telemetry: {
            available: true,
            snapshot_id: 44,
            telemetry: {
              inference_count: 100,
              queue_rate: 0.18,
              latency_ms: { p95: 14.2 },
              missing_feature_rate: 0.01
            },
            drift_warnings: [],
            raw_logs_included: false,
            private_identifiers_included: false,
            response_actions_created: 0
          },
          reliability_validation: {
            available: true,
            lifecycle_decision: "shadow_observation",
            strict_passing_splits: 0,
            required_splits: 6,
            evaluated_splits: 5,
            failed_closed_splits: ["source_holdout"],
            selected_diagnostic_strategy: "calibrated_binary_hist_gradient_boosting_sigmoid",
            candidate_selected: false,
            governance_outcome: "no_supervised_candidate_selected",
            drift_warning_splits: 3,
            temporal_fpr: 0.9976,
            temporal_queue_rate: 0.998,
            ood_rate: 0.0733,
            confidence_instability_rate: 0.024,
            abstention_rate_range: { min: 0.0197, max: 0.7513, mean: 0.2172, range: 0.7316 },
            coverage_rate_range: { min: 0.2487, max: 0.9803, mean: 0.7828, range: 0.7316 },
            rolling_temporal: { evaluated: 3, required: 3, failed_closed: [] },
            evidence_lock_status: "locked_and_matched",
            shadow_drift_status: "OOD Warning",
            shadow_drift_findings: [
              "application distribution shift=0.7428",
              "schema distribution shift=0.5791"
            ],
            development_evidence_rows: 1467,
            excluded_evidence_rows: 768,
            locked_temporal_final_rows: 532,
            quarantined_evidence_rows: 236,
            independent_labeled_evidence_sufficient: false,
            v56_available: true,
            v56_status: "evaluated",
            v56_lifecycle_state: "shadow_observation",
            v56_private_rows_processed: 773551,
            v56_overlap_rows_excluded: 120000,
            v56_drift_status: "Stable",
            v56_assisted_training_rows: 409741,
            v56_assisted_human_reviewed_rows: 0,
            v56_diagnostic_candidate: "calibrated_hist_gradient_boosting",
            v56_future_queue_f1: 0.9889,
            v56_future_benign_fpr: 0.0211,
            v56_future_suspicious_recall: 1,
            v56_future_malicious_recall: 1,
            v56_future_calibration_status: "weak",
            v56_future_calibration_ece: 0.0155,
            v56_isolation_future_fpr: 0.0057,
            v56_isolation_future_threat_capture: 0.4576,
            v56_candidate_activated: false,
            v56_response_automation_allowed: false,
            v56_independent_validation_claimed: false,
            v56_blockers: [
              "independent multi device evidence",
              "genuine human ground truth for private evidence"
            ],
            v57_available: true,
            v57_status: "independent_evidence_required",
            v57_lifecycle_state: "shadow_observation",
            v57_frozen_candidate: "calibrated_hist_gradient_boosting",
            v57_candidate_model_type: "HistGradientBoostingClassifier",
            v57_candidate_calibration: "sigmoid",
            v57_candidate_threshold: 0.3,
            v57_evidence_status: "independent_evidence_required",
            v57_evidence_qualified: false,
            v57_source_device_count: 0,
            v57_independent_time_windows: 0,
            v57_prediction_freeze_status: "not_run",
            v57_blind_validation_status: "not_run_independent_evidence_required",
            v57_blind_queue_f1: null,
            v57_blind_benign_fpr: null,
            v57_isolation_status: "pending_independent_labels",
            v57_candidate_activated: false,
            v57_rules_alert_authoritative: true,
            v57_response_automation_allowed: false,
            v57_blockers: [
              "independent source time evidence",
              "blind validation completed"
            ],
            temporal_root_causes: [
              "chronological label prevalence changed materially",
              "application mix changed materially between fit and final windows"
            ],
            blockers: [
              "No supervised strategy passes every required internal split",
              "Locked external benchmark does not pass strict gates"
            ],
            source_holdout_limitation: "Source-disjoint validation failed closed because independent devices are limited.",
            layered_after: {
              passed_count: 288,
              mode_run_count: 288,
              failed_count: 0,
              false_positive_count: 0,
              false_negative_count: 0
            },
            rules_alert_authoritative: true,
            eligible_for_activation: false,
            production_promoted: false,
            response_automation_allowed: false
          },
          governed_shadow_runtime: {
            ok: true,
            version: "v5.8-governed-shadow-runtime-v1",
            status: "evaluated_shadow_read_only",
            enabled: true,
            lifecycle_state: "shadow_observation",
            candidate_contract_matched: true,
            candidate_contract: {
              status: "candidate_contract_matched",
              matched: true,
              candidate_name: "calibrated_hist_gradient_boosting",
              model_type: "HistGradientBoostingClassifier",
              calibration_method: "sigmoid",
              threshold: 0.3,
              feature_count: 40,
              active: false,
              production_promoted: false,
              response_automation_allowed: false,
              rules_alert_authoritative: true,
              fallback_model_used: false
            },
            independent_evidence: {
              status: "independent_evidence_required",
              qualified: false,
              source_device_count: 0,
              independent_time_window_count: 0,
              blind_validation_status: "not_run_independent_evidence_required",
              blind_metrics_available: false
            },
            telemetry: {
              rows_evaluated: 100,
              queue_count: 47,
              queue_rate: 0.47,
              drift: {
                status: "Drift Warning",
                rows_evaluated: 100,
                application_total_variation: 0.262,
                schema_total_variation: 0.06
              },
              rule_shadow_agreement: {
                both_queue: 15,
                rule_only: 26,
                shadow_only: 32,
                neither: 27,
                disagreement_count: 58,
                disagreement_rate: 0.58,
                rules_alert_authoritative: true
              },
              isolation_forest: {
                advisory_only: true,
                persisted_anomaly_count: 9,
                persisted_anomaly_rate: 0.09,
                new_isolation_scoring_performed: false,
                alert_authority: false
              },
              accuracy_metrics_calculated: false,
              labels_accessed: false
            },
            safety: {
              configured_database_unchanged: true,
              active_model_artifacts_unchanged: true,
              frozen_candidate_artifact_unchanged: true,
              alerts_created: 0,
              labels_created: 0,
              model_runs_created: 0,
              detection_runs_created: 0,
              response_actions_created: 0
            },
            rules_alert_authoritative: true,
            model_activated: false,
            production_promoted: false,
            response_automation_allowed: false,
            fallback_model_used: false
          },
          production_promoted: false,
          response_automation_allowed: false,
          rule_detection_authoritative: true
        },
        legacy_artifact_exists: true,
        legacy_artifact_selected: false,
        models: [
          {
            model_id: 42,
            model_name: "supervised_soc_queue",
            model_version: "v5.1-soc-queue-smoke",
            model_type: "calibrated_extra_trees",
            display_model_type: "Calibrated ExtraTrees",
            display_feature_set: "v5.1-causal-soc-queue-features-v1",
            operation: "train_supervised",
            status: "registered_candidate",
            actor: "test",
            model_path: "supervised_candidates/v5.1-soc-queue-smoke.joblib",
            artifact_exists: true,
            is_active_path: true,
            lifecycle_state: "shadow_observation",
            metrics: { f1: 0.2363 },
            readiness_decision: "candidate_only",
            analyst_review_eligible: true,
            production_promoted: false,
            response_automation_allowed: false
          }
        ],
        production_promoted: false,
        response_automation_allowed: false,
        decision_support_only: true
      }
    })
  );
  await seedSession(page);

  await page.goto("/ml");
  const candidateFreeze = page.getByTestId("candidate-freeze-readiness");
  await expect(candidateFreeze).toContainText("No Candidate Frozen");
  await expect(candidateFreeze).toContainText("hierarchical two stage");
  await expect(candidateFreeze).toContainText("0/3");
  await expect(candidateFreeze).toContainText("weak");
  await expect(candidateFreeze).toContainText("Rules Authoritative");
  await expect(candidateFreeze).toContainText("No Model Activation");
  const candidateFreezeOverflow = await candidateFreeze.evaluate(
    (element) => element.scrollWidth > element.clientWidth + 1
  );
  expect(candidateFreezeOverflow).toBe(false);
  const temporalStability = page.getByTestId("temporal-stability-readiness");
  await expect(temporalStability).toContainText("No Candidate Frozen");
  await expect(temporalStability).toContainText("temporal provenance balanced weighting");
  await expect(temporalStability).toContainText("0/3");
  await expect(temporalStability).toContainText("weak");
  await expect(temporalStability).toContainText("unstable");
  await expect(temporalStability).toContainText("Rules Authoritative");
  const temporalStabilityOverflow = await temporalStability.evaluate(
    (element) => element.scrollWidth > element.clientWidth + 1
  );
  expect(temporalStabilityOverflow).toBe(false);
  const manualAnchorTransfer = page.getByTestId("manual-anchor-transfer-readiness");
  await expect(manualAnchorTransfer).toContainText("manual anchor transfer incomplete");
  await expect(manualAnchorTransfer).toContainText("improved");
  await expect(manualAnchorTransfer).toContainText("1/3 views passed");
  await expect(manualAnchorTransfer).toContainText("79.0%");
  await expect(manualAnchorTransfer).toContainText("12.0%");
  await expect(manualAnchorTransfer).toContainText("weak");
  await expect(manualAnchorTransfer).toContainText("Rules Authoritative");
  await expect(manualAnchorTransfer).toContainText("Shadow Observation");
  const manualAnchorTransferOverflow = await manualAnchorTransfer.evaluate(
    (element) => element.scrollWidth > element.clientWidth + 1
  );
  expect(manualAnchorTransferOverflow).toBe(false);
  const manualAnchorAcquisition = page.getByTestId("manual-anchor-acquisition-readiness");
  await expect(manualAnchorAcquisition).toContainText("ready for human review");
  await expect(manualAnchorAcquisition).toContainText("120/120");
  await expect(manualAnchorAcquisition).toContainText("8 coverage strata");
  await expect(manualAnchorAcquisition).toContainText("0/120");
  await expect(manualAnchorAcquisition).toContainText("Second source still required");
  await expect(manualAnchorAcquisition).toContainText("Predictions Withheld");
  await expect(manualAnchorAcquisition).toContainText("No Auto Import");
  const manualAnchorAcquisitionOverflow = await manualAnchorAcquisition.evaluate(
    (element) => element.scrollWidth > element.clientWidth + 1
  );
  expect(manualAnchorAcquisitionOverflow).toBe(false);
  const combinedRevalidation = page.getByTestId("combined-fixed-revalidation-status");
  await expect(combinedRevalidation).toContainText("combined fixed revalidation completed");
  await expect(combinedRevalidation).toContainText("180/180");
  await expect(combinedRevalidation).toContainText("95/39/27");
  await expect(combinedRevalidation).toContainText("1/1");
  await expect(combinedRevalidation).toContainText("8/8 strategies evaluated");
  await expect(combinedRevalidation).toContainText("None qualified");
  await expect(combinedRevalidation).toContainText("Rules Authoritative");
  await expect(combinedRevalidation).toContainText("No Model Activation");
  const combinedRevalidationOverflow = await combinedRevalidation.evaluate(
    (element) => element.scrollWidth > element.clientWidth + 1
  );
  expect(combinedRevalidationOverflow).toBe(false);
  const developmentRepair = page.getByTestId("development-model-repair-readiness");
  await expect(developmentRepair).toContainText("development repair incomplete");
  await expect(developmentRepair).toContainText("calibrated extra trees flat 5class");
  await expect(developmentRepair).toContainText("0/3");
  await expect(developmentRepair).toContainText("Blocked");
  await expect(developmentRepair).toContainText("Advisory Only");
  await expect(developmentRepair).toContainText("Rules Authoritative");
  await expect(developmentRepair).toContainText("No Model Activation");
  const developmentRepairOverflow = await developmentRepair.evaluate(
    (element) => element.scrollWidth > element.clientWidth + 1
  );
  expect(developmentRepairOverflow).toBe(false);
  const blindEvidence = page.getByTestId("blind-evidence-readiness");
  await expect(blindEvidence).toContainText("Insufficient Sources");
  await expect(blindEvidence).toContainText("1/2");
  await expect(blindEvidence).toContainText("1/3");
  await expect(blindEvidence).toContainText("40/240");
  await expect(blindEvidence).toContainText("Predictions Withheld");
  await expect(blindEvidence).toContainText("Rules Authoritative");
  await expect(blindEvidence).toContainText("No Model Activation");
  const blindEvidenceOverflow = await blindEvidence.evaluate(
    (element) => element.scrollWidth > element.clientWidth + 1
  );
  expect(blindEvidenceOverflow).toBe(false);
  const registry = page.getByTestId("supervised-model-registry");
  await expect(registry.getByText("shadow active", { exact: true })).toBeVisible();
  await expect(registry.getByText("shadow observation", { exact: true }).first()).toBeVisible();
  await expect(registry.getByText("Calibrated ExtraTrees", { exact: true }).first()).toBeVisible();
  await expect(registry.getByText("v5.1-causal-soc-queue-features-v1", { exact: true }).first()).toBeVisible();
  await expect(registry.getByText("weak or unstable", { exact: true })).toBeVisible();
  await expect(registry.getByText("shadow only", { exact: true })).toBeVisible();
  await expect(registry.getByText("Response Automation", { exact: true })).toBeVisible();
  const reliability = page.getByTestId("shadow-reliability-summary");
  await expect(reliability).toContainText("0/6");
  await expect(reliability).toContainText("288/288");
  await expect(reliability).toContainText("100");
  await expect(reliability).toContainText("18.0%");
  await expect(reliability).toContainText("14.2 ms");
  await expect(reliability).toContainText("99.8%");
  await expect(reliability).toContainText("7.3%");
  await expect(reliability).toContainText("75.1%");
  await expect(reliability).toContainText("3/3 rolling windows evaluated");
  await expect(reliability).toContainText("Evidence Drift");
  await expect(reliability).toContainText("OOD Warning");
  await expect(reliability).toContainText("Development Evidence");
  await expect(reliability).toContainText("1467");
  await expect(reliability).toContainText("768 locked or quarantined");
  const governedShadow = page.getByTestId("governed-shadow-runtime");
  await expect(governedShadow).toContainText("Frozen Diagnostic Candidate");
  await expect(governedShadow).toContainText("Shadow Scoring Enabled");
  await expect(governedShadow).toContainText("Candidate Contract Matched");
  await expect(governedShadow).toContainText("Independent Evidence Pending");
  await expect(governedShadow).toContainText("Rules Authoritative");
  await expect(governedShadow).toContainText("Response Automation Disabled");
  await expect(governedShadow).toContainText("100");
  await expect(governedShadow).toContainText("47.0%");
  await expect(governedShadow).toContainText("Drift Warning");
  await expect(governedShadow).toContainText("58.0%");
  const longitudinal = page.getByTestId("longitudinal-shadow-observation");
  await expect(longitudinal).toContainText("Longitudinal Shadow Observation");
  await expect(longitudinal).toContainText("2");
  await expect(longitudinal).toContainText("1 / 2");
  await expect(longitudinal).toContainText("Drift Warning");
  await expect(longitudinal).toContainText("44.0%");
  await expect(longitudinal).toContainText("53.5%");
  await expect(longitudinal).toContainText("0 / 1");
  await expect(longitudinal).toContainText("7/8");
  await expect(longitudinal).toContainText("Operational Warning");
  await expect(longitudinal).toContainText("View operational warnings (1)");
  await expect(longitudinal).toContainText("Rules Authoritative");
  await expect(longitudinal).toContainText("Shadow Observation");
  await expect(longitudinal).toContainText("No Model Activation");
  await expect(longitudinal).toContainText("Response Automation Disabled");
  await expect(longitudinal).toContainText("Raw Evidence Excluded");
  await expect(longitudinal).toContainText("still required");
  const diagnostics = page.getByTestId("shadow-monitoring-diagnostics");
  await diagnostics.getByText("Operational drift diagnostics (2)").click();
  await expect(diagnostics).toContainText("source-scope-01");
  await expect(diagnostics).toContainText("Application mix differs from the governed baseline.");
  await expect(diagnostics).toContainText("Monitoring Cadence Disabled");
  await expect(diagnostics).toContainText("No Accuracy Metrics");
  const diagnosticsOverflow = await diagnostics.evaluate(
    (element) => element.scrollWidth > element.clientWidth + 1
  );
  expect(diagnosticsOverflow).toBe(false);
  const parserDiagnostics = page.getByTestId("parser-profile-diagnostics");
  await parserDiagnostics.getByText("Parser profile baseline (1)").click();
  await expect(parserDiagnostics).toContainText("palo alto syslog v5.12");
  await expect(parserDiagnostics).toContainText(
    "Unresolved application values are tracked as data quality, not parser failures."
  );
  await expect(parserDiagnostics).toContainText("parser profile source type");
  await expect(parserDiagnostics).toContainText("No Accuracy Metrics");
  const parserDiagnosticsOverflow = await parserDiagnostics.evaluate(
    (element) => element.scrollWidth > element.clientWidth + 1
  );
  expect(parserDiagnosticsOverflow).toBe(false);
  const longitudinalOverflow = await longitudinal.evaluate(
    (element) => element.scrollWidth > element.clientWidth + 1
  );
  expect(longitudinalOverflow).toBe(false);
  await reliability.getByText("View reliability blockers").click();
  await expect(reliability).toContainText("No supervised strategy passes every required internal split");
  await expect(reliability).toContainText("No supervised candidate was selected or made eligible for activation.");
  await expect(reliability).toContainText("v5.6 private chronology: 773551 rows, drift Stable");
  await expect(reliability).toContainText("calibrated_hist_gradient_boosting");
  await expect(reliability).toContainText("Assisted evidence is non-human");
  await expect(reliability).toContainText("v5.6: independent multi device evidence.");
  await expect(reliability).toContainText("v5.6: genuine human ground truth for private evidence.");
  await expect(reliability).toContainText("Frozen Diagnostic Candidate");
  await expect(reliability).toContainText("Independent Evidence Pending");
  await expect(reliability).toContainText("Rules Authoritative");
  await expect(reliability).toContainText("Response Automation Disabled");
  await expect(reliability).toContainText("No independent metrics are shown");
  await expect(reliability).toContainText("v5.7: independent source time evidence.");
  await expect(reliability).toContainText("Temporal drift: chronological label prevalence changed materially.");
  await expect(reliability).toContainText("Shadow evidence: application distribution shift=0.7428.");
  await expect(page.getByText("Artifact Metadata", { exact: true })).toHaveCount(0);
  await expect(page.getByText("active artifact ready", { exact: true })).toHaveCount(0);
});

test("deep-linked alert and log drawers render", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/alerts?alert=1");
  await expect(page.getByRole("heading", { name: "Critical: Smoke alert" })).toBeVisible();
  await expect(page.getByText("Why flagged?")).toBeVisible();
  await expect(page.getByText("What happened", { exact: true })).toBeVisible();
  await expect(page.getByText("Evidence strength", { exact: true })).toBeVisible();
  await expect(page.getByText("Missing context", { exact: true })).toBeVisible();
  await expect(page.getByText("Recommended checks", { exact: true })).toBeVisible();
  await page.getByText("Detection layer detail", { exact: true }).click();
  await expect(page.getByText("Rule Authority")).toBeVisible();
  await expect(page.getByText("Anomaly Advisory")).toBeVisible();
  await expect(page.getByText("Supervised Shadow")).toBeVisible();
  await expect(page.getByText("Hybrid Interpretation")).toBeVisible();
  await expect(page.getByText("Review priority only; not automatic truth.")).toBeVisible();
  await expect(page.getByText("ML output is decision support.")).toBeVisible();
  await expect(page.getByText("Alert Occurrences")).toBeVisible();
  await expect(page.getByText("Related Log Count")).toBeVisible();
  await expect(page.getByText("Showing the first 1 of 150 linked logs.")).toBeVisible();
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

test("alert detail shows supervised schema abstention without a false score", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.route("**/api/alerts/1", (route) =>
    route.fulfill({
      json: {
        id: 1,
        title: "Critical: Schema-gated alert",
        alert_type: "policy_deny",
        src_ip: "203.0.113.10",
        dst_ip: "10.0.0.5",
        threat_score: 88,
        severity: "Critical",
        status: "open",
        explanation: "Deterministic rule evidence created this alert.",
        matched_rules_json: [{ code: "policy_deny", title: "Policy deny", explanation: "Denied traffic." }],
        recommended_response: "Review related logs.",
        created_at: "2026-08-01T00:00:00Z",
        updated_at: "2026-08-01T00:00:00Z",
        evidence_count: 1,
        evidence_log_ids: [1],
        source_ids: [1],
        source_names: ["generic-source"],
        detection_summary: {
          detection_source: ["rule"],
          attack_type: "policy_violation",
          attack_mapping: {
            attack_type: "policy_violation",
            tactic: "Defense Evasion",
            technique: "Policy violation",
            technique_id: "ATDR-RULE",
            description: "Deterministic policy evidence."
          },
          matched_rule_names: ["Policy deny"],
          anomaly: { present: false },
          supervised: {
            predicted_label: null,
            malicious_probability: 0,
            confidence: 0,
            abstained: true,
            missing_required_features: ["app", "action"],
            schema_compatibility: { status: "incompatible_schema" },
            decision_support_only: true
          },
          hybrid_risk: {},
          behavior_window: {},
          top_evidence_points: ["Policy deny: Denied traffic."],
          why_flagged: "Flagged by deterministic policy-deny evidence."
        }
      }
    })
  );

  await page.goto("/alerts?alert=1");
  await page.getByText("Detection layer detail", { exact: true }).click();
  const shadow = page.getByText("Supervised Shadow").locator("..");
  await expect(shadow).toContainText("Abstained");
  await expect(shadow).toContainText("Schema incompatible_schema");
  await expect(shadow).toContainText("Missing: app, action");
  await expect(shadow).not.toContainText("Threat-positive score 0");
  await expect(page.getByText("Rule Authority")).toBeVisible();
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
    details: {
      input_name: "firewall.log",
      raw_logs_imported: 500,
      parsed_successfully: 492,
      parse_failures: 8,
      duplicate_raw_logs: 12
    },
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
  await expect(page.getByTestId("latest-job-counters")).toContainText("Raw imported: 500");
  await expect(page.getByTestId("latest-job-counters")).toContainText("Parsed: 492");
  await expect(page.getByTestId("latest-job-counters")).toContainText("Failed: 8");
  await expect(page.getByTestId("latest-job-counters")).toContainText("Duplicates: 12");
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
  await expect(page.getByText("Normal access uses the MFU application shell.")).toBeVisible();
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

  await expect(page.getByRole("heading", { name: "Evidence-grounded analyst guidance" })).toBeVisible();
  await expect(page.getByText("Read Only", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Decision Support Only", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Response Automation Disabled", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Raw Logs Disabled", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Raw logs are excluded by default.")).toBeVisible();
  await page.getByText("More analyst playbooks").click();
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
  await expect(page.getByTestId("assistant-direct-answer")).toBeVisible();

  await page.getByLabel("Analyst question").fill("Why was alert 1 flagged?");
  await page.getByRole("button", { name: "Ask assistant" }).click();
  const panel = page.getByTestId("assistant-response-panel");
  await expect(panel.getByTestId("assistant-answer-sections")).toBeVisible();
  await expect(panel.getByTestId("assistant-direct-answer")).toContainText("Alert explanation");
  await expect(panel.getByTestId("assistant-direct-answer")).toContainText("Alert #1 was flagged");
  await expect(panel.getByText("Read Only", { exact: true }).first()).toBeVisible();
  await expect(panel.getByText("Decision Support Only", { exact: true })).toBeVisible();
  await expect(panel.getByText("Response Automation Disabled", { exact: true })).toBeVisible();
  await expect(panel.getByText("Simulation Mode", { exact: true })).toHaveCount(0);
  const evidenceItem = panel.getByTestId("assistant-section-evidence").getByText("Flagged as suspicious because action=deny.");
  await expect(evidenceItem).not.toBeVisible();
  await panel.getByText("Evidence and reasoning").click();
  await expect(evidenceItem).toBeVisible();
  await expect(panel.getByTestId("assistant-provider-telemetry")).not.toBeVisible();
  await panel.getByText("Sources and provider details").click();
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("Local Evidence Assistant");
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("Raw logs");
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("Not included");
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("Secrets");
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("Not exposed");
  await expect(panel.getByTestId("assistant-provider-telemetry")).toContainText("soc_intent_aware_concise_v4");
  await expect(panel.getByTestId("assistant-citations")).toContainText("Grounded In");
  await expect(panel.getByTestId("assistant-citations")).toContainText("/api/alerts/{alert_id}");
  await expect(panel.getByTestId("assistant-citation-open-alert-detail-1")).toHaveAttribute("href", "/alerts?alert=1");
  await expect(panel.getByTestId("assistant-citation-open-log-detail-1")).toHaveAttribute("href", "/logs?log=1");
  await expect(panel.getByTestId("assistant-citation-open-source-1")).toHaveAttribute("href", "/overview?source=1");
  await expect(panel.getByTestId("assistant-citation-open-detection-run-8")).toHaveAttribute("href", "/?detection_run=8");
  await expect(panel.getByTestId("assistant-citation-open-operation-job-3")).toHaveAttribute("href", "/?job=3");
  await expect(panel.getByTestId("assistant-citation-open-ml-report-api")).toHaveAttribute("href", "/ml");
  await expect(panel.getByText("Text reference")).toBeVisible();
  await panel.getByText("Rate answer quality").click();
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
  await feedbackReview.getByText("Feedback quality review").click();
  await feedbackReview.getByRole("button", { name: "Feedback rating filter" }).click();
  await page.getByRole("option", { name: "Incorrect" }).click();
  await feedbackReview.getByRole("button", { name: "Feedback context filter" }).click();
  await page.getByRole("option", { name: "Alert" }).click();
  await panel.getByRole("button", { name: "Copy answer" }).click();
  await expect(panel.getByText("Answer copied")).toBeVisible();
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
  await expect(page.getByTestId("assistant-direct-answer")).toBeVisible();

  await page.goto("/assistant?log=1");
  await expect(page.getByText("Log context #1")).toBeVisible();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Why was log 1 flagged or not flagged?");

  await page.goto("/assistant?case=smoke-case");
  await expect(page.getByText("Case context smoke-case")).toBeVisible();
  await expect(page.getByLabel("Analyst question")).toHaveValue("Summarize case smoke-case and related alert group.");

  await page.goto("/assistant");
  await page.getByRole("button", { name: "Latest Critical Alert", exact: true }).click();
  await page.getByText("Sources and provider details").click();
  await page.getByTestId("assistant-citation-open-alert-detail-1").click();
  await expect(page).toHaveURL(/\/alerts\?alert=1/);
});

test("evidence review workspace saves blind decisions without exposing hidden data", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/evidence-review");

  await expect(page.getByRole("heading", { name: "Evidence Review" })).toBeVisible();
  await expect(page.getByText("Human Decisions Only", { exact: true })).toBeVisible();
  await expect(page.getByText("Predictions Withheld", { exact: true }).first()).toBeVisible();
  await expect(page.getByTestId("frozen-evaluation-status")).toContainText("Human Review Required");
  await expect(page.getByTestId("frozen-evaluation-status")).toContainText("Shadow Observation");
  await expect(page.getByTestId("detection-review-metrics")).toContainText("0/40");
  const evidence = page.getByTestId("detection-approved-evidence");
  await expect(evidence).toContainText("routine_web");
  await expect(page.getByTestId("detection-evidence-fields")).not.toContainText(/prediction|model score|rule score|review token|fingerprint/i);

  await chooseSafeSelect(page, "Detection review category", "Benign-like");
  await chooseSafeSelect(page, "Detection final decision", "Benign");
  await page.getByLabel("Attack type optional").fill("none");
  await page.getByLabel("Confidence (1-100)").fill("92");
  await page.getByLabel("Rationale").fill("Independent human review found routine allowed web traffic.");
  await page.getByText("I confirm this is my independent human decision based only on the evidence shown.").click();
  await page.getByRole("button", { name: "Save decision" }).click();
  await expect(page.getByTestId("detection-review-metrics")).toContainText("1/40");

  await page.getByRole("tab", { name: "Assistant Acceptance" }).click();
  await expect(page.getByTestId("assistant-review-metrics")).toContainText("0/8");
  await expect(page.getByTestId("assistant-protected-answer")).toContainText("No action was executed");
  await expect(page.getByTestId("assistant-protected-answer")).not.toContainText(/raw log|api key|private path/i);
  for (const label of ["Correctness", "Evidence grounding", "Citation accuracy", "Relevance", "Concision", "Usefulness", "Privacy", "Safety"]) {
    await chooseSafeSelect(page, `${label} score`, "5 / 5");
  }
  await chooseSafeSelect(page, "Assistant overall decision", "Accept");
  await page.getByText("I confirm these scores and this decision are my independent human assessment.").click();
  await page.getByRole("button", { name: "Save assessment" }).click();
  await expect(page.getByTestId("assistant-review-metrics")).toContainText("1/8");

  await page.evaluate(async () => {
    for (let rowIndex = 1; rowIndex < 8; rowIndex += 1) {
      await fetch(`/api/evidence-review/assistant/items/${rowIndex}`, { method: "POST", body: "{}" });
    }
  });
  await page.reload();
  await page.getByRole("tab", { name: /Assistant Acceptance/ }).click();
  await expect(page.getByTestId("assistant-review-metrics")).toContainText("8/8");
  await expect(page.getByTestId("evidence-review-workflow-notice")).toContainText("Select Close review");
  await expect(page.getByTestId("assistant-review-complete")).toBeVisible();
  await expect(page.getByRole("button", { name: "Close review" })).toBeVisible();
  const closePanelBox = await page.getByTestId("assistant-review-complete").boundingBox();
  const protectedAnswerBox = await page.getByTestId("assistant-protected-answer").boundingBox();
  expect(closePanelBox?.y).toBeLessThan(protectedAnswerBox?.y ?? 0);

  const horizontalScroll = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(horizontalScroll).toBeLessThanOrEqual(1);
  await expect(page.getByRole("button", { name: /run detection|activate model|response action/i })).toHaveCount(0);
});

test("manual-anchor workspace is prediction-blind, responsive, and saves with next navigation", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/evidence-review");
  await page.getByRole("tab", { name: "Manual Anchors" }).click();

  await expect(page.getByTestId("manual-anchor-protocol-status")).toContainText("Protocol Locked");
  await expect(page.getByTestId("manual_anchors-review-metrics")).toContainText("0/120");
  await expect(page.getByTestId("manual-anchor-approved-evidence")).toContainText("Predictions Withheld");
  await expect(page.getByTestId("manual-anchor-evidence-fields")).not.toContainText(/prediction|model score|review token|fingerprint|source ip|raw log/i);
  await expect(page.getByText("No Auto Import", { exact: true })).toBeVisible();

  await chooseSafeSelect(page, "Manual anchor final decision", "Benign");
  await page.getByLabel("Confidence (1-100)").fill("94");
  await page.getByLabel("Rationale").fill("Independent analyst review supports routine allowed traffic.");
  await page.getByText("I confirm this is my independent human decision based only on the approved evidence shown.").click();
  await page.getByRole("button", { name: "Save and next" }).click();
  await expect(page.getByTestId("manual_anchors-review-metrics")).toContainText("1/120");

  const horizontalScroll = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(horizontalScroll).toBeLessThanOrEqual(1);
  await expect(page.getByRole("button", { name: /run detection|activate model|response action|import/i })).toHaveCount(0);
});

test("supplemental threat-anchor workspace preserves custody and hides class support while open", async ({ page }) => {
  await mockApi(page);
  await seedSession(page);
  await page.goto("/evidence-review");
  await page.getByRole("tab", { name: "Supplemental Threat Anchors" }).click();

  const custody = page.getByTestId("supplemental-anchor-custody-status");
  await expect(custody).toContainText("120/120 Closed");
  await expect(custody).toContainText("60");
  await expect(custody).toContainText("7");
  await expect(custody).toContainText("Prediction-Blind Pack Ready");
  await expect(page.getByTestId("supplemental_threat_anchors-review-metrics")).toContainText("0/60");
  await expect(page.getByTestId("supplemental-anchor-combined-support")).toHaveCount(0);

  const evidence = page.getByTestId("supplemental-anchor-approved-evidence");
  await expect(evidence).toContainText("Predictions Withheld");
  await expect(evidence).toContainText("Deterministic Evidence");
  await expect(evidence).toContainText("Rule Evidence");
  await expect(page.getByTestId("supplemental-anchor-evidence-fields")).not.toContainText(/prediction|model score|review token|fingerprint|source ip|destination ip|raw log|class support|quota/i);

  await chooseSafeSelect(page, "Supplemental threat anchor final decision", "Malicious");
  await page.getByPlaceholder("e.g. port_scan").fill("brute_force");
  await page.getByLabel("Confidence (1-100)").fill("93");
  await page.getByLabel("Rationale").fill("Repeated denied high-risk access attempts support threat classification.");
  await page.getByText("I confirm this is my independent human decision based only on the approved evidence shown.").click();
  await page.getByRole("button", { name: "Save and next" }).click();
  await expect(page.getByTestId("supplemental_threat_anchors-review-metrics")).toContainText("1/60");

  const horizontalScroll = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(horizontalScroll).toBeLessThanOrEqual(1);
  await expect(page.getByRole("button", { name: /run detection|activate model|response action|import/i })).toHaveCount(0);
});

test("evidence review advances to Assistant acceptance after detection closes", async ({ page }) => {
  await mockApi(page);
  await page.unroute("**/api/evidence-review/status");
  await page.route("**/api/evidence-review/status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.37.0",
        detection: {
          workspace: "detection",
          available: true,
          prepared: true,
          integrity_status: "valid",
          total: 40,
          reviewed: 40,
          remaining: 0,
          invalid: 0,
          progress_percent: 100,
          owner_assigned: true,
          owned_by_current_user: true,
          can_review: true,
          completed: true,
          closed: true,
          next_pending_index: null,
          evaluation_ready: true,
          message: "Detection review is complete and closed.",
          predictions_exposed: false,
          model_scores_exposed: false,
          raw_logs_exposed: false,
          private_paths_exposed: false,
          import_ready: false
        },
        assistant: {
          workspace: "assistant",
          available: true,
          prepared: false,
          integrity_status: "valid",
          total: 8,
          reviewed: 0,
          remaining: 8,
          invalid: 0,
          progress_percent: 0,
          owner_assigned: false,
          owned_by_current_user: false,
          can_review: true,
          completed: false,
          closed: false,
          next_pending_index: 0,
          evaluation_ready: false,
          human_acceptance_passed: null,
          message: "Review protected answers without sending content back to the provider.",
          predictions_exposed: false,
          model_scores_exposed: false,
          raw_logs_exposed: false,
          private_paths_exposed: false,
          import_ready: false
        },
        safeguards: ["Human Decisions Only", "Predictions Withheld", "No Auto Import", "No Model Activation", "No Response Actions"],
        aggregate_only_for_non_owner: true,
        secrets_exposed: false
      }
    })
  );
  await seedSession(page);
  await page.goto("/evidence-review");

  await expect(page.getByRole("tab", { name: /Assistant Acceptance/ })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("detection-tab-progress")).toHaveText("40/40 Closed");
  await expect(page.getByTestId("assistant-tab-progress")).toHaveText("0/8");
  await expect(page.getByTestId("evidence-review-workflow-notice")).toContainText("Complete Assistant Acceptance");
  await expect(page.getByTestId("assistant-review-empty-state")).toContainText("Workspace ready");
});

test("evidence review workspace explains unavailable private packs without leaking details", async ({ page }) => {
  await mockApi(page);
  await page.unroute("**/api/evidence-review/status");
  await page.route("**/api/evidence-review/status", async (route) =>
    route.fulfill({
      json: {
        version: "v5.37.0",
        detection: {
          workspace: "detection",
          available: false,
          prepared: false,
          integrity_status: "unavailable",
          owner_assigned: false,
          owned_by_current_user: false,
          can_review: true,
          message: "The private sealed detection pack is not available on this machine."
        },
        assistant: {
          workspace: "assistant",
          available: false,
          prepared: false,
          integrity_status: "not_prepared",
          owner_assigned: false,
          owned_by_current_user: false,
          can_review: true,
          message: "The protected Assistant acceptance pack has not been prepared yet."
        },
        safeguards: ["Human Decisions Only", "Predictions Withheld", "No Auto Import", "No Model Activation", "No Response Actions"],
        aggregate_only_for_non_owner: true,
        secrets_exposed: false
      }
    })
  );
  await seedSession(page);
  await page.goto("/evidence-review");

  await expect(page.getByTestId("detection-review-empty-state")).toContainText("Private pack unavailable");
  await expect(page.getByTestId("detection-review-empty-state")).not.toContainText(/\\|ml_baseline_reviews|\.csv/i);
  await page.getByRole("tab", { name: "Assistant Acceptance" }).click();
  await expect(page.getByTestId("assistant-review-empty-state")).toContainText("Workspace ready");
  await expect(page.getByRole("button", { name: "Start review" })).toBeVisible();
});

test("SOC assistant provider telemetry shows guarded external LLM state", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/assistant/chat", async (route) =>
    route.fulfill({
      json: {
        answer: "Verdict: Alert #3225 remains supported by local ATDR evidence.\nNext check: Review linked logs before response.",
        mode: "deterministic_local_llm_guarded_gemini",
        response_mode: "alert_explanation",
        external_provider_used: true,
        safety: ["Read Only", "Decision Support Only", "Response Automation Disabled", "Simulation Mode"],
        context_used: ["alert_detail", "alert_evidence"],
        citations: [{ label: "Alert detail", source: "/api/alerts/{alert_id}", reference_id: "3225" }],
        redaction_applied: true,
        raw_log_context_included: false,
        suggested_followups: ["What logs are related to alert 3225?", "What should an analyst verify for alert 3225 before response?"],
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
            prompt_contract: "soc_intent_aware_concise_v4",
            provider_called: true,
            answer_used: false,
            answer_guard_reason: "provider_answer_contains_unsupported_alert_id",
            failure_category: "grounding_rejection",
            latency_ms: 85,
            attempts: 1,
            usage: { input_tokens: 120, output_tokens: 45, total_tokens: 165 }
          },
          answer_sections: {
            response_mode: ["alert_explanation"],
            direct_answer: ["Alert #3225 remains supported by local ATDR evidence."],
            key_evidence: ["Local alert evidence retained the requested record."],
            next_steps: ["Review linked logs before response."],
            citations: ["Alert detail: /api/alerts/{alert_id} #3225"]
          },
          evidence_detail: { evidence: ["Local alert evidence retained the requested record."] }
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

  await page.getByText("Sources and provider details").click();
  const telemetry = page.getByTestId("assistant-provider-telemetry");
  await expect(telemetry).toContainText("Gemini Fallback: Local Evidence Assistant");
  await expect(telemetry).toContainText("Gemini");
  await expect(telemetry).toContainText("outside the supplied ATDR context");
  await expect(telemetry).toContainText("Raw logs");
  await expect(telemetry).toContainText("Not included");
  await expect(telemetry).toContainText("Secrets");
  await expect(telemetry).toContainText("Not exposed");
  await expect(telemetry).toContainText("grounding rejection");
  await expect(telemetry).toContainText("soc_intent_aware_concise_v4");
  await expect(telemetry).toContainText("45");
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Alert #3225");
  await expect(page.getByText("ASSISTANT_LLM_API_KEY")).not.toBeVisible();
  await expect(page.getByRole("button", { name: "Record simulated block" })).not.toBeVisible();
});

test("SOC assistant labels Gemini only after an answer uses the provider", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/assistant/status", async (route) =>
    route.fulfill({
      json: {
        available: true,
        mode: "external_llm_configured",
        external_provider_configured: true,
        external_provider_used_by_default: false,
        provider: "gemini",
        model_configured: true,
        llm_enabled: true,
        llm_provider_configured: true,
        llm_provider_name: "gemini",
        llm_ready: true,
        llm_model_configured: true,
        llm_secret_configured: true,
        llm_base_url_configured: false,
        llm_timeout_seconds: 15,
        llm_max_retries: 2,
        llm_max_prompt_chars: 12000,
        llm_max_output_tokens: 800,
        llm_max_visible_chars: 4000,
        llm_circuit_breaker_failures: 3,
        llm_circuit_breaker_cooldown_seconds: 60,
        llm_operational: {
          status: "healthy",
          calls_attempted: 3,
          calls_succeeded: 3,
          calls_failed: 0,
          fallbacks: 0,
          circuit_open: false,
          estimated_cost_usd: 0.001,
          secrets_exposed: false
        },
        conversation_history_turns: 4,
        rate_limit_requests: 30,
        rate_limit_window_seconds: 60,
        llm_secrets_exposed: false,
        redaction_enabled: true,
        raw_log_context_allowed: false,
        max_context_rows: 20,
        safety: ["Read Only", "Decision Support Only", "Response Automation Disabled"]
      }
    })
  );
  await page.route("**/api/assistant/chat", async (route) =>
    route.fulfill({
      json: {
        answer: "Alert #77 is supported by bounded ATDR evidence.",
        mode: "external_llm_gemini",
        response_mode: "alert_explanation",
        external_provider_used: true,
        safety: ["Read Only", "Decision Support Only", "Response Automation Disabled"],
        context_used: ["alert_detail", "external_llm:gemini"],
        citations: [{ label: "Alert detail", source: "/api/alerts/{alert_id}", reference_id: "77" }],
        redaction_applied: true,
        raw_log_context_included: false,
        suggested_followups: ["What logs are related?"],
        details: {
          answer_sections: {
            response_mode: ["alert_explanation"],
            direct_answer: ["Alert #77 is supported by bounded ATDR evidence."],
            key_evidence: ["ATDR alert detail was supplied."],
            next_steps: ["Review linked evidence."],
            citations: ["Alert detail: /api/alerts/{alert_id} #77"]
          },
          evidence_detail: { evidence: ["ATDR alert detail was supplied."] },
          llm: {
            used: true,
            provider: "gemini",
            provider_called: true,
            answer_used: true,
            structured_output_valid: true,
            raw_log_context_included: false,
            secrets_exposed: false,
            prompt_contract: "soc_intent_aware_concise_v4"
          }
        },
        conversation_id: "gemini-verified-conversation",
        active_context: { alert_id: 77, log_id: null, source_id: null, case_id: null, primary: "alert" }
      }
    })
  );
  await seedSession(page);
  await page.goto("/assistant");
  await expect(page.getByText("Gemini Configured", { exact: true })).toBeVisible();
  await expect(page.getByText("healthy", { exact: true })).toBeVisible();
  await expect(page.getByText("Gemini Assisted", { exact: true })).toHaveCount(0);
  await page.getByLabel("Analyst question").fill("Why was alert 77 flagged?");
  await page.getByRole("button", { name: "Ask assistant" }).click();
  await expect(page.getByText("Gemini Assisted", { exact: true }).first()).toBeVisible();
  await page.getByText("Sources and provider details").click();
  await expect(page.getByTestId("assistant-citations")).toContainText("Alert detail");
  await expect(page.getByText("ASSISTANT_LLM_API_KEY")).toHaveCount(0);
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
    const isRelatedFollowUp = question.includes("related");
    const isNextFollowUp = question.includes("next step") || question.includes("check next");
    const isLatestCritical = question.includes("latest critical");
    const responseMode = isLogFollowUp
      ? "alert_explanation"
      : isRelatedFollowUp
        ? "related_logs"
        : isNextFollowUp
          ? "safe_next_step"
          : isLatestCritical
            ? "list_summary"
            : "alert_explanation";
    const answer = isLogFollowUp
      ? `Verdict: Log #${logId} remains linked to alert #${alertId}.`
      : isRelatedFollowUp
        ? `Related logs for alert #${alertId}:\n- Log #9001 is linked evidence.`
        : isNextFollowUp
          ? `Prioritized checks for alert #${alertId}:\n1. Review log #9001.\n2. Confirm source context before response.`
          : isLatestCritical
            ? `Latest critical alert: Alert #${alertId}.`
            : `Verdict: Alert #${alertId} context was retained.`;
    await route.fulfill({
      json: {
        answer,
        mode: "deterministic_local",
        response_mode: responseMode,
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
        suggested_followups: [
          `What logs are related to alert ${alertId}?`,
          `What should an analyst check next for alert ${alertId}?`
        ],
        details: {
          assistant_audit_id: 1717,
          answer_sections: {
            response_mode: [responseMode],
            direct_answer: [answer.split("\n")[0]],
            key_evidence: isLogFollowUp ? [`Linked alert #${alertId} is available.`] : [],
            related_logs: isRelatedFollowUp ? ["Log #9001 is linked evidence."] : [],
            next_steps: isNextFollowUp ? ["Review log #9001.", "Confirm source context before response."] : [],
            list_items: isLatestCritical ? [`Alert #${alertId}`] : [],
            citations: [`Alert detail: /api/alerts/{alert_id} #${alertId}`]
          },
          evidence_detail: {
            evidence: [isLogFollowUp ? `Linked alert #${alertId} is available.` : "Related log #9001 is linked as alert evidence."]
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
  const requestCountBeforeNavigation = assistantRequests.length;
  await page.goto("/alerts");
  await expect(page).toHaveURL(/\/alerts$/);
  await page.goto("/assistant");
  await expect(page.getByLabel("Analyst question")).toHaveValue("Why was alert 1717 flagged?");
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Alert #1717 context was retained.");
  await expect(page.getByText("Using alert #1717")).toBeVisible();
  expect(assistantRequests).toHaveLength(requestCountBeforeNavigation);
  await page.getByRole("button", { name: "What logs are related to alert 1717?" }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("What logs are related to alert 1717?");
  await expect(page.getByText("Using alert #1717")).toBeVisible();
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Related logs for alert #1717");
  await expect(page.getByTestId("assistant-response-panel")).not.toContainText("Verdict: Alert #1717 context was retained.");

  expect(assistantRequests.length).toBeGreaterThanOrEqual(2);
  expect(assistantRequests[0].alert_id).toBe(1717);
  expect(assistantRequests[1].alert_id).toBe(1717);
  expect(typeof assistantRequests[0].conversation_id).toBe("string");
  expect(assistantRequests[1].conversation_id).toBe(assistantRequests[0].conversation_id);
  expect(assistantRequests[1].log_id).toBeNull();
  expect(assistantRequests[1].source_id).toBeNull();
  await page.getByRole("button", { name: "What should an analyst check next for alert 1717?" }).click();
  await expect(page.getByLabel("Analyst question")).toHaveValue("What should an analyst check next for alert 1717?");
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Prioritized checks for alert #1717");
  await expect(page.getByTestId("assistant-response-panel")).not.toContainText("Related logs for alert #1717");
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
  await expect.poll(() => page.evaluate(() => window.sessionStorage.getItem("atdr.assistant.session.v1"))).toBeNull();

  await page.getByLabel("Analyst question").fill("Summarize source health.");
  await page.getByRole("button", { name: "Ask assistant" }).click();
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Context cleared request answered.");
  expect(assistantRequests.at(-1)?.alert_id).toBeNull();
  expect(assistantRequests.at(-1)?.log_id).toBeNull();
  expect(assistantRequests.at(-1)?.source_id).toBeNull();
  expect(assistantRequests.at(-1)?.reset_context).toBe(true);
  expect(typeof assistantRequests.at(-1)?.conversation_id).toBe("string");
});

test("SOC assistant session storage is resilient and clears on logout", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.addInitScript(() => {
    window.sessionStorage.setItem("atdr.assistant.session.v1", "{malformed-json");
  });
  await mockApi(page);
  await seedSession(page);
  await page.goto("/assistant");
  await expect(page.getByLabel("Analyst question")).toHaveValue("What is the latest critical alert?");
  expect(pageErrors).toEqual([]);

  await page.getByLabel("Analyst question").fill("Why was alert 1 flagged?");
  await page.getByRole("button", { name: "Ask assistant" }).click();
  await expect(page.getByTestId("assistant-response-panel")).toContainText("Alert #1");
  await expect.poll(() => page.evaluate(() => Boolean(window.sessionStorage.getItem("atdr.assistant.session.v1")))).toBe(true);

  await page.getByRole("button", { name: "Logout" }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect(await page.evaluate(() => window.sessionStorage.getItem("atdr.assistant.session.v1"))).toBeNull();
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
  await expect(page.getByText("Canonical ML Evidence", { exact: true })).toBeVisible();
  await expect(page.getByText("Queue F1", { exact: true })).toBeVisible();
  await expect(page.getByText("0.9237-0.9524", { exact: true })).toBeVisible();
  await expect(page.getByText("Production Readiness Track")).not.toBeVisible();
  await expect(page.getByText("Review focus: benign and suspicious separation need more analyst-verified examples.")).not.toBeVisible();
  await page.getByText("Current limitations").click();
  await expect(page.getByText("Exact class separation still needs review.")).toBeVisible();
  await page.getByText("Current limitations").click();
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

  await page.getByLabel("Sample log file path").fill("D:\\Synthetic\\paloalto-firewall.log");
  await page.getByRole("button", { name: "Import sample logs" }).click();

  const importResult = page.getByTestId("action-result-import");
  await expect(importResult).toContainText("Requested limit");
  await expect(importResult).toContainText("1000");
  await expect(importResult).toContainText("Available lines");
  await expect(importResult).toContainText("Raw logs imported");
  await expect(importResult).toContainText("paloalto-firewall.log");
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
        source: "synthetic-copy-path.log",
        source_label: "synthetic-copy-path.log",
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
  await page.getByLabel("Sample log file path").fill('"D:\\Synthetic\\paloalto-firewall.log"');
  await page.getByRole("button", { name: "Import sample logs" }).click();
  await expect(page.getByTestId("action-result-import")).toContainText("2000");
  expect(postedPath).toBe("D:\\Synthetic\\paloalto-firewall.log");
});

test("core SOC pages fit projector, laptop, and mobile viewports", async ({ page }, testInfo) => {
  test.setTimeout(90_000);
  await seedSession(page);
  await mockApi(page);
  const viewports = [
    { name: "projector", width: 1920, height: 1080 },
    { name: "laptop", width: 1366, height: 768 },
    { name: "mobile", width: 390, height: 844 }
  ];
  const routes = ["overview", "alerts", "logs", "assistant", "ml", "evidence-review", "response", "users"];
  const routeHeadings: Record<string, RegExp> = {
    overview: /ATDR lab SOC status/i,
    alerts: /Prioritize, investigate, contain, and document alerts/i,
    logs: /Search raw evidence and normalized firewall events/i,
    assistant: /Evidence-grounded analyst guidance/i,
    ml: /Model status and review operations/i,
    "evidence-review": /Evidence Review/i,
    response: /Containment actions stay simulated by default/i,
    users: /Manage analyst and admin access/i
  };

  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    for (const routeName of routes) {
      await page.goto(`/${routeName}`);
      await expect(page.locator("main")).toBeVisible();
      await expect(page.locator("main")).not.toBeEmpty();
      await expect(page.getByRole("heading", { level: 1, name: routeHeadings[routeName] })).toBeVisible();
      const overflowMetrics = await page.evaluate(() => ({
        overflow: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) - window.innerWidth,
        innerWidth: window.innerWidth,
        htmlScrollWidth: document.documentElement.scrollWidth,
        htmlClientWidth: document.documentElement.clientWidth,
        bodyScrollWidth: document.body.scrollWidth,
        bodyClientWidth: document.body.clientWidth
      }));
      const overflowNodes = await page.evaluate(() => {
        const viewportWidth = window.innerWidth;
        const isContainedByHorizontalScroller = (element: Element) => {
          let ancestor = element.parentElement;
          while (ancestor && ancestor !== document.body) {
            const overflowX = window.getComputedStyle(ancestor).overflowX;
            if (["auto", "scroll", "hidden", "clip"].includes(overflowX)) {
              const rect = ancestor.getBoundingClientRect();
              return rect.left >= -1 && rect.right <= viewportWidth + 1;
            }
            ancestor = ancestor.parentElement;
          }
          return false;
        };
        return Array.from(document.querySelectorAll("body *"))
          .filter((element) => {
            const rect = element.getBoundingClientRect();
            return (
              (rect.left < -1 || rect.right > viewportWidth + 1) &&
              !isContainedByHorizontalScroller(element)
            );
          })
          .map((element) => {
            const rect = element.getBoundingClientRect();
            return {
              tag: element.tagName.toLowerCase(),
              className: element.getAttribute("class") ?? "",
              text: (element.textContent ?? "").trim().slice(0, 80),
              left: Math.round(rect.left),
              right: Math.round(rect.right),
              width: Math.round(rect.width)
            };
          })
          .slice(0, 8);
      });
      expect(
        overflowNodes,
        `${routeName} elements cross ${viewport.name} viewport: ${JSON.stringify({ ...overflowMetrics, overflowNodes })}`
      ).toEqual([]);
      await page.screenshot({ path: testInfo.outputPath(`${viewport.name}-${routeName}.png`), fullPage: false });
      await page.evaluate(() => window.scrollTo(999, window.scrollY));
      const horizontalScroll = await page.evaluate(() => window.scrollX);
      expect(horizontalScroll, `${routeName} can scroll horizontally at ${viewport.name}`).toBeLessThanOrEqual(1);
      await page.evaluate(() => window.scrollTo(0, 0));
    }
  }
});
