import argparse
import json
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT, Settings, validate_runtime_settings


REQUIRED_FILES = {
    "nginx_config": "deploy/nginx/atdr.conf.example",
    "nginx_runbook": "deploy/nginx/README.md",
    "prometheus_config": "deploy/monitoring/prometheus.yml.example",
    "prometheus_rules": "deploy/monitoring/atdr-alerts.yml",
    "monitoring_runbook": "deploy/monitoring/README.md",
    "managed_secrets": "deploy/secrets/README.md",
    "api_service": "deploy/systemd/atdr-api.service.example",
    "readiness_timer": "deploy/systemd/atdr-readiness-check.timer.example",
    "audit_timer": "deploy/systemd/atdr-audit-retention-report.timer.example",
    "staging_timer": "deploy/systemd/atdr-staging-cleanup-report.timer.example",
    "backup_timer": "deploy/systemd/atdr-backup-verify.timer.example",
}

SCHEDULED_SERVICE_FILES = (
    "deploy/systemd/atdr-readiness-check.service.example",
    "deploy/systemd/atdr-audit-retention-report.service.example",
    "deploy/systemd/atdr-staging-cleanup-report.service.example",
    "deploy/systemd/atdr-backup-verify.service.example",
)


def _read(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def validate_deployment_operations(*, settings: Settings | None = None) -> dict:
    settings = settings or Settings()
    files = {name: (PROJECT_ROOT / path).is_file() for name, path in REQUIRED_FILES.items()}
    missing = sorted(name for name, exists in files.items() if not exists)
    try:
        nginx = _read(REQUIRED_FILES["nginx_config"])
        rules = _read(REQUIRED_FILES["prometheus_rules"])
        api_service = _read(REQUIRED_FILES["api_service"])
        secret_guide = _read(REQUIRED_FILES["managed_secrets"])
        scheduled_services = [_read(path) for path in SCHEDULED_SERVICE_FILES]
    except OSError:
        nginx = rules = api_service = secret_guide = ""
        scheduled_services = []
    nginx_controls = {
        "http_redirect": "return 301 https://$host$request_uri" in nginx,
        "https": "ssl_certificate" in nginx and "TLSv1.2 TLSv1.3" in nginx,
        "secure_headers": "Strict-Transport-Security" in nginx and "Content-Security-Policy" in nginx,
        "request_limit": "client_max_body_size" in nginx,
        "timeouts": "proxy_read_timeout" in nginx and "proxy_connect_timeout" in nginx,
        "websocket_compatible": "proxy_set_header Upgrade" in nginx,
        "metrics_restricted": "location = /metrics" in nginx and "deny all" in nginx,
        "forwarded_chain_overwritten": "X-Forwarded-For $remote_addr" in nginx
        and "$proxy_add_x_forwarded_for" not in nginx,
        "spa_fallback": "try_files $uri $uri/ /index.html" in nginx,
    }
    required_alerts = {
        "ATDRTargetDown",
        "ATDRServiceNotReady",
        "ATDRDatabaseUnavailable",
        "ATDRDatabasePoolSaturation",
        "ATDRBackupUnavailableOrStale",
        "ATDRUnsafeRuntimeConfiguration",
        "ATDRResponseSimulationDisabled",
        "ATDROperationQueueBacklog",
        "ATDRStaleOperationWorker",
        "ATDRRepeatedOperationFailures",
        "ATDRRecentIngestionFailure",
        "ATDRRecentDetectionFailure",
        "ATDRStagingPressure",
    }
    missing_alerts = sorted(alert for alert in required_alerts if f"alert: {alert}" not in rules)
    destructive_scheduled_flags = any(
        marker in content for content in scheduled_services for marker in (" --apply", " --execute", " --confirm")
    )
    runtime_issues = validate_runtime_settings(settings)
    ok = bool(
        not missing
        and all(nginx_controls.values())
        and not missing_alerts
        and len(scheduled_services) == len(SCHEDULED_SERVICE_FILES)
        and not destructive_scheduled_flags
        and "--no-proxy-headers" in api_service
        and "JWT_SECRET_KEY" in secret_guide
        and settings.response_simulation
        and not settings.assistant_allow_raw_log_context
        and not runtime_issues
    )
    return {
        "ok": ok,
        "status": "deployment_operations_valid" if ok else "deployment_operations_invalid",
        "files": files,
        "missing_files": missing,
        "nginx_controls": nginx_controls,
        "missing_monitoring_alerts": missing_alerts,
        "scheduled_service_count": len(scheduled_services),
        "scheduled_destructive_flags_present": destructive_scheduled_flags,
        "uvicorn_generic_proxy_headers_disabled": "--no-proxy-headers" in api_service,
        "trusted_proxy_headers_enabled": settings.trust_proxy_headers,
        "trusted_proxy_network_count": len(settings.trusted_proxy_cidr_list),
        "runtime_issue_count": len(runtime_issues),
        "response_simulation": settings.response_simulation,
        "assistant_raw_log_context": settings.assistant_allow_raw_log_context,
        "secrets_exposed": False,
        "production_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate ATDR deployment-security and operations artifacts.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = validate_deployment_operations()
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
