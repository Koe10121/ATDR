from functools import lru_cache
from ipaddress import ip_network
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _is_documentation_placeholder(value: str) -> bool:
    clean = value.strip().lower()
    return not clean or any(marker in clean for marker in ("replace-during", "replace-with", "change-this", "placeholder"))


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or .env."""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "MFU ATDR"
    database_url: str = Field(default="sqlite:///./atdr.db", alias="DATABASE_URL")
    db_pool_size: int = Field(default=5, alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=10, alias="DB_MAX_OVERFLOW")
    db_pool_timeout_seconds: int = Field(default=30, alias="DB_POOL_TIMEOUT_SECONDS")
    db_connect_timeout_seconds: int = Field(default=10, alias="DB_CONNECT_TIMEOUT_SECONDS")
    db_pool_pre_ping: bool = Field(default=True, alias="DB_POOL_PRE_PING")
    db_statement_timeout_ms: int = Field(default=30000, alias="DB_STATEMENT_TIMEOUT_MS")
    auto_create_tables: bool = Field(default=True, alias="AUTO_CREATE_TABLES")
    response_simulation: bool = Field(default=True, alias="RESPONSE_SIMULATION")
    response_provider: str = Field(default="simulation", alias="RESPONSE_PROVIDER")
    default_import_limit: int | None = Field(default=5000, alias="DEFAULT_IMPORT_LIMIT")
    min_alert_score: int = Field(default=30, alias="MIN_ALERT_SCORE")
    ml_model_path: str = Field(default="atdr/models/isolation_forest.joblib", alias="ML_MODEL_PATH")
    supervised_model_path: str = Field(default="atdr/models/supervised_classifier.joblib", alias="SUPERVISED_MODEL_PATH")
    ml_contamination: float = Field(default=0.03, alias="ML_CONTAMINATION")
    api_base_url: str = Field(default="http://127.0.0.1:8000", alias="API_BASE_URL")
    jwt_secret_key: str = Field(default="change-this-dev-secret", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=480, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    demo_admin_username: str = Field(default="admin", alias="DEMO_ADMIN_USERNAME")
    demo_admin_password: str = Field(default="admin123", alias="DEMO_ADMIN_PASSWORD")
    demo_analyst_username: str = Field(default="analyst", alias="DEMO_ANALYST_USERNAME")
    demo_analyst_password: str = Field(default="analyst123", alias="DEMO_ANALYST_PASSWORD")
    demo_sample_log_path: str = Field(default="data/samples/paloalto-demo.txt", alias="DEMO_SAMPLE_LOG_PATH")
    demo_import_limit: int = Field(default=5000, alias="DEMO_IMPORT_LIMIT")
    environment: str = Field(default="development", alias="ENVIRONMENT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")
    service_version: str = Field(default="0.1.0", alias="SERVICE_VERSION")
    cors_allowed_origins: str = Field(
        default="http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:8501,http://localhost:8501",
        alias="CORS_ALLOWED_ORIGINS",
    )
    security_headers_enabled: bool = Field(default=True, alias="SECURITY_HEADERS_ENABLED")
    trust_proxy_headers: bool = Field(default=False, alias="TRUST_PROXY_HEADERS")
    trusted_proxy_cidrs: str = Field(default="127.0.0.1/32,::1/128", alias="TRUSTED_PROXY_CIDRS")
    deployment_rehearsal_approved: bool = Field(default=False, alias="DEPLOYMENT_REHEARSAL_APPROVED")
    deployment_public_base_url: str = Field(default="", alias="DEPLOYMENT_PUBLIC_BASE_URL")
    deployment_dns_name: str = Field(default="", alias="DEPLOYMENT_DNS_NAME")
    deployment_tls_certificate_path: str = Field(default="", alias="DEPLOYMENT_TLS_CERTIFICATE_PATH")
    deployment_tls_private_key_path: str = Field(default="", alias="DEPLOYMENT_TLS_PRIVATE_KEY_PATH")
    deployment_prometheus_url: str = Field(default="", alias="DEPLOYMENT_PROMETHEUS_URL")
    deployment_secret_provider: str = Field(default="disabled", alias="DEPLOYMENT_SECRET_PROVIDER")
    syslog_enabled: bool = Field(default=False, alias="SYSLOG_ENABLED")
    syslog_host: str = Field(default="127.0.0.1", alias="SYSLOG_HOST")
    syslog_port: int = Field(default=5514, alias="SYSLOG_PORT")
    syslog_batch_size: int = Field(default=100, alias="SYSLOG_BATCH_SIZE")
    login_rate_limit_attempts: int = Field(default=5, alias="LOGIN_RATE_LIMIT_ATTEMPTS")
    login_rate_limit_window_seconds: int = Field(default=300, alias="LOGIN_RATE_LIMIT_WINDOW_SECONDS")
    # The MFU shell is the normal entry path. Local credentials are available
    # only when an operator explicitly selects the recovery/test profile.
    auth_mode: str = Field(default="template_shell", alias="ATDR_AUTH_MODE")
    oidc_enabled: bool = Field(default=False, alias="OIDC_ENABLED")
    oidc_provider_name: str = Field(default="", alias="OIDC_PROVIDER_NAME")
    oidc_client_id: str = Field(default="", alias="OIDC_CLIENT_ID")
    oidc_client_secret: str = Field(default="", alias="OIDC_CLIENT_SECRET")
    oidc_issuer_url: str = Field(default="", alias="OIDC_ISSUER_URL")
    oidc_allowed_domains: str = Field(default="", alias="OIDC_ALLOWED_DOMAINS")
    oidc_default_role: str = Field(default="analyst", alias="OIDC_DEFAULT_ROLE")
    mfu_iam_enabled: bool = Field(default=False, alias="MFU_IAM_ENABLED")
    mfu_iam_base_url: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_BASE_URL", "IAM_SDK_BASE_URL"),
    )
    mfu_iam_client_id: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_CLIENT_ID", "IAM_SDK_CLIENT_ID"),
    )
    mfu_iam_client_secret: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_CLIENT_SECRET", "IAM_SDK_CLIENT_SECRET"),
    )
    mfu_iam_audience: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_AUDIENCE", "IAM_SDK_AUDIENCE"),
    )
    mfu_iam_scope: str = Field(default="", validation_alias=AliasChoices("MFU_IAM_SCOPE", "IAM_SDK_SCOPE"))
    mfu_iam_timeout_ms: int = Field(
        default=5000,
        validation_alias=AliasChoices("MFU_IAM_TIMEOUT_MS", "IAM_SDK_TIMEOUT_MS"),
    )
    mfu_iam_token_path: str = Field(
        default="/api/v1/b2b/token",
        validation_alias=AliasChoices("MFU_IAM_TOKEN_PATH", "IAM_SDK_TOKEN_PATH"),
    )
    mfu_iam_introspect_path: str = Field(
        default="/api/v1/b2b/introspect",
        validation_alias=AliasChoices("MFU_IAM_INTROSPECT_PATH", "IAM_SDK_INTROSPECT_PATH"),
    )
    mfu_iam_profile_path: str = Field(
        default="/api/v1/b2b/clients/me",
        validation_alias=AliasChoices("MFU_IAM_PROFILE_PATH", "IAM_SDK_PROFILE_PATH"),
    )
    mfu_iam_admin_base_path: str = Field(
        default="/api/v1/b2b/admin",
        validation_alias=AliasChoices("MFU_IAM_ADMIN_BASE_PATH", "IAM_SDK_ADMIN_BASE_PATH"),
    )
    mfu_iam_admin_client_id: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_ADMIN_CLIENT_ID", "IAM_ADMIN_CLIENT_ID"),
    )
    mfu_iam_admin_client_secret: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_ADMIN_CLIENT_SECRET", "IAM_ADMIN_CLIENT_SECRET"),
    )
    mfu_iam_admin_audience: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_ADMIN_AUDIENCE", "IAM_ADMIN_AUDIENCE"),
    )
    mfu_iam_admin_scope: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_ADMIN_SCOPE", "IAM_ADMIN_SCOPE"),
    )
    mfu_iam_compat_profile: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_COMPAT_PROFILE", "IAM_COMPAT_PROFILE"),
    )
    mfu_iam_allowed_domains: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_ALLOWED_DOMAINS", "IAM_SDK_ALLOWED_DOMAINS"),
    )
    mfu_iam_default_role: str = Field(default="analyst", alias="MFU_IAM_DEFAULT_ROLE")
    mfu_iam_mock_enabled: bool = Field(default=False, alias="MFU_IAM_MOCK_ENABLED")
    mfu_iam_template_shell_enabled: bool = Field(default=False, alias="MFU_IAM_TEMPLATE_SHELL_ENABLED")
    mfu_iam_template_shell_base_url: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_TEMPLATE_SHELL_BASE_URL", "TEMPLATE_SHELL_BASE_URL", "PROJECT_BASE_URL", "BASE_SERVER_URL"),
    )
    mfu_iam_template_shell_me_path: str = Field(default="/api/v1/auth/me", alias="MFU_IAM_TEMPLATE_SHELL_ME_PATH")
    mfu_iam_template_shell_header: str = Field(default="x-access-token", alias="MFU_IAM_TEMPLATE_SHELL_HEADER")
    # The template owns school sign-in. ATDR receives only a short-lived, one-time
    # handoff code and exchanges it server-to-server; no template bearer token is
    # carried in an ATDR URL or retained by the React application.
    mfu_iam_handoff_enabled: bool = Field(default=False, alias="MFU_IAM_HANDOFF_ENABLED")
    mfu_iam_handoff_exchange_path: str = Field(
        default="/api/v1/atdr/handoff/exchange",
        alias="MFU_IAM_HANDOFF_EXCHANGE_PATH",
    )
    mfu_iam_handoff_shared_secret: str = Field(default="", alias="MFU_IAM_HANDOFF_SHARED_SECRET")
    mfu_iam_handoff_secret_header: str = Field(
        default="x-atdr-handoff-secret",
        alias="MFU_IAM_HANDOFF_SECRET_HEADER",
    )
    mfu_iam_handoff_frontend_url: str = Field(
        default="http://127.0.0.1:5173",
        alias="MFU_IAM_HANDOFF_FRONTEND_URL",
    )
    mfu_iam_handoff_cookie_name: str = Field(default="atdr_session", alias="MFU_IAM_HANDOFF_COOKIE_NAME")
    mfu_iam_handoff_cookie_secure: bool = Field(default=False, alias="MFU_IAM_HANDOFF_COOKIE_SECURE")
    mfu_iam_handoff_allowed_origins: str = Field(default="", alias="MFU_IAM_HANDOFF_ALLOWED_ORIGINS")
    mfu_iam_handoff_allowed_return_paths: str = Field(
        default="/overview,/alerts,/logs,/assistant,/response,/audit,/ml",
        alias="MFU_IAM_HANDOFF_ALLOWED_RETURN_PATHS",
    )
    mfu_iam_template_shell_launch_url: str = Field(default="", alias="MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL")
    mfu_iam_admin_groups: str = Field(default="", alias="MFU_IAM_ADMIN_GROUPS")
    mfu_iam_admin_emails: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_ADMIN_EMAILS", "MFU_IAM_ADMIN_EMAIL_ALLOWLIST"),
    )
    mfu_iam_permission_source: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_PERMISSION_SOURCE", "PROJECT_PERMISSION_SOURCE"),
    )
    mfu_iam_permission_bootstrap_mode: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_PERMISSION_BOOTSTRAP_MODE", "PROJECT_PERMISSION_BOOTSTRAP_MODE"),
    )
    mfu_iam_permission_root_path: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_PERMISSION_ROOT_PATH", "PROJECT_PERMISSION_ROOT_PATH"),
    )
    mfu_iam_permission_paths: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_PERMISSION_PATHS", "PROJECT_PERMISSION_PATHS"),
    )
    mfu_iam_project_account_email: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_PROJECT_ACCOUNT_EMAIL", "PROJECT_PERMISSION_ACCOUNT_EMAIL"),
    )
    mfu_iam_auth_require_2fa: bool = Field(
        default=False,
        validation_alias=AliasChoices("MFU_IAM_AUTH_REQUIRE_2FA", "PROJECT_AUTH_REQUIRE_2FA"),
    )
    mfu_iam_audit_retention_days: int = Field(
        default=90,
        validation_alias=AliasChoices("MFU_IAM_AUDIT_RETENTION_DAYS", "PROJECT_AUDIT_RETENTION_DAYS"),
    )
    mfu_iam_managed_client_id: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_MANAGED_CLIENT_ID", "PROJECT_IAM_MANAGED_CLIENT_ID"),
    )
    mfu_iam_managed_client_endpoint: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_MANAGED_CLIENT_ENDPOINT", "PROJECT_IAM_MANAGED_CLIENT_ENDPOINT"),
    )
    mfu_iam_managed_client_owner_email: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_MANAGED_CLIENT_OWNER_EMAIL", "PROJECT_IAM_MANAGED_CLIENT_OWNER_EMAIL"),
    )
    mfu_iam_managed_client_allowed_scopes: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_MANAGED_CLIENT_ALLOWED_SCOPES", "PROJECT_IAM_MANAGED_CLIENT_ALLOWED_SCOPES"),
    )
    mfu_iam_managed_client_allowed_audiences: str = Field(
        default="",
        validation_alias=AliasChoices(
            "MFU_IAM_MANAGED_CLIENT_ALLOWED_AUDIENCES",
            "PROJECT_IAM_MANAGED_CLIENT_ALLOWED_AUDIENCES",
        ),
    )
    mfu_iam_init_admin_emails: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_INIT_ADMIN_EMAILS", "PROJECT_INIT_ADMIN_EMAILS"),
    )
    mfu_iam_init_seed_admin_email: str = Field(
        default="",
        validation_alias=AliasChoices("MFU_IAM_INIT_SEED_ADMIN_EMAIL", "PROJECT_INIT_SEED_ADMIN_EMAIL"),
    )
    google_sso_enabled: bool = Field(default=False, alias="GOOGLE_SSO_ENABLED")
    google_client_id: str = Field(default="", alias="GOOGLE_CLIENT_ID")
    school_email_domains: str = Field(default="", alias="SCHOOL_EMAIL_DOMAINS")
    require_school_email: bool = Field(default=False, alias="REQUIRE_SCHOOL_EMAIL")
    local_email_login_enabled: bool = Field(default=True, alias="LOCAL_EMAIL_LOGIN_ENABLED")
    smtp_enabled: bool = Field(default=False, alias="SMTP_ENABLED")
    smtp_host: str = Field(default="", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_username: str = Field(default="", alias="SMTP_USERNAME")
    smtp_password: str = Field(default="", alias="SMTP_PASSWORD")
    smtp_from_email: str = Field(default="", alias="SMTP_FROM_EMAIL")
    smtp_use_tls: bool = Field(default=True, alias="SMTP_USE_TLS")
    email_notifications_enabled: bool = Field(default=False, alias="EMAIL_NOTIFICATIONS_ENABLED")
    email_verification_enabled: bool = Field(default=False, alias="EMAIL_VERIFICATION_ENABLED")
    email_delivery_mode: str = Field(default="disabled", alias="EMAIL_DELIVERY_MODE")
    email_verification_code_ttl_minutes: int = Field(default=15, alias="EMAIL_VERIFICATION_CODE_TTL_MINUTES")
    email_verification_code_length: int = Field(default=6, alias="EMAIL_VERIFICATION_CODE_LENGTH")
    email_verification_required_for_login: bool = Field(default=False, alias="EMAIL_VERIFICATION_REQUIRED_FOR_LOGIN")
    email_verification_required_for_admin_actions: bool = Field(
        default=False,
        alias="EMAIL_VERIFICATION_REQUIRED_FOR_ADMIN_ACTIONS",
    )
    dashboard_summary_cache_seconds: int = Field(default=30, alias="DASHBOARD_SUMMARY_CACHE_SECONDS")
    job_stale_after_minutes: int = Field(default=60, alias="JOB_STALE_AFTER_MINUTES")
    job_retention_days: int = Field(default=30, alias="JOB_RETENTION_DAYS")
    run_history_retention_days: int = Field(default=90, alias="RUN_HISTORY_RETENTION_DAYS")
    operation_worker_enabled: bool = Field(default=False, alias="OPERATION_WORKER_ENABLED")
    operation_worker_poll_seconds: float = Field(default=1.0, alias="OPERATION_WORKER_POLL_SECONDS")
    operation_worker_lease_seconds: int = Field(default=900, alias="OPERATION_WORKER_LEASE_SECONDS")
    operation_worker_heartbeat_seconds: int = Field(default=15, alias="OPERATION_WORKER_HEARTBEAT_SECONDS")
    operation_worker_deployment_id: str = Field(default="local", alias="OPERATION_WORKER_DEPLOYMENT_ID")
    operation_worker_concurrency: int = Field(default=1, alias="OPERATION_WORKER_CONCURRENCY")
    operation_worker_shutdown_grace_seconds: int = Field(
        default=120,
        alias="OPERATION_WORKER_SHUTDOWN_GRACE_SECONDS",
    )
    operation_job_default_max_attempts: int = Field(default=1, alias="OPERATION_JOB_DEFAULT_MAX_ATTEMPTS")
    operation_job_max_attempts: int = Field(default=3, alias="OPERATION_JOB_MAX_ATTEMPTS")
    operation_job_retry_delay_seconds: int = Field(default=60, alias="OPERATION_JOB_RETRY_DELAY_SECONDS")
    operation_job_max_input_bytes: int = Field(default=52_428_800, alias="OPERATION_JOB_MAX_INPUT_BYTES")
    ingestion_chunk_size: int = Field(default=500, alias="INGESTION_CHUNK_SIZE")
    ingestion_progress_update_interval: int = Field(default=500, alias="INGESTION_PROGRESS_UPDATE_INTERVAL")
    operation_max_queued_imports: int = Field(default=10, alias="OPERATION_MAX_QUEUED_IMPORTS")
    operation_max_queued_jobs_per_actor: int = Field(default=5, alias="OPERATION_MAX_QUEUED_JOBS_PER_ACTOR")
    operation_staging_max_total_bytes: int = Field(default=1_073_741_824, alias="OPERATION_STAGING_MAX_TOTAL_BYTES")
    operation_staging_min_free_bytes: int = Field(default=268_435_456, alias="OPERATION_STAGING_MIN_FREE_BYTES")
    operation_staging_retention_hours: int = Field(default=24, alias="OPERATION_STAGING_RETENTION_HOURS")
    operation_staging_root: str = Field(default="", alias="OPERATION_STAGING_ROOT")
    operation_staging_shared: bool = Field(default=False, alias="OPERATION_STAGING_SHARED")
    operation_staging_storage_id: str = Field(default="local", alias="OPERATION_STAGING_STORAGE_ID")
    operation_queue_backlog_warning: int = Field(default=25, alias="OPERATION_QUEUE_BACKLOG_WARNING")
    operation_job_failure_warning_count: int = Field(default=3, alias="OPERATION_JOB_FAILURE_WARNING_COUNT")
    operation_job_failure_warning_window_minutes: int = Field(
        default=60,
        alias="OPERATION_JOB_FAILURE_WARNING_WINDOW_MINUTES",
    )
    backup_directory: str = Field(default="", alias="ATDR_BACKUP_DIRECTORY")
    backup_max_age_hours: float = Field(default=30.0, alias="ATDR_BACKUP_MAX_AGE_HOURS")
    audit_retention_days: int = Field(default=365, alias="AUDIT_RETENTION_DAYS")
    audit_retention_min_days: int = Field(default=90, alias="AUDIT_RETENTION_MIN_DAYS")
    audit_retention_batch_size: int = Field(default=500, alias="AUDIT_RETENTION_BATCH_SIZE")
    assistant_enabled: bool = Field(default=False, alias="ASSISTANT_ENABLED")
    assistant_provider: str = Field(default="disabled", alias="ASSISTANT_PROVIDER")
    assistant_model: str = Field(default="", alias="ASSISTANT_MODEL")
    assistant_api_key: str = Field(default="", alias="ASSISTANT_API_KEY")
    assistant_llm_enabled: bool = Field(default=False, alias="ASSISTANT_LLM_ENABLED")
    assistant_llm_provider: str = Field(default="", alias="ASSISTANT_LLM_PROVIDER")
    assistant_llm_model: str = Field(default="", alias="ASSISTANT_LLM_MODEL")
    assistant_llm_api_key: str = Field(default="", alias="ASSISTANT_LLM_API_KEY")
    assistant_llm_base_url: str = Field(default="", alias="ASSISTANT_LLM_BASE_URL")
    assistant_llm_timeout_seconds: float = Field(default=15.0, alias="ASSISTANT_LLM_TIMEOUT_SECONDS")
    assistant_llm_max_retries: int = Field(default=2, alias="ASSISTANT_LLM_MAX_RETRIES")
    assistant_llm_max_prompt_chars: int = Field(default=12000, alias="ASSISTANT_LLM_MAX_PROMPT_CHARS")
    assistant_conversation_history_turns: int = Field(default=4, alias="ASSISTANT_CONVERSATION_HISTORY_TURNS")
    assistant_rate_limit_requests: int = Field(default=30, alias="ASSISTANT_RATE_LIMIT_REQUESTS")
    assistant_rate_limit_window_seconds: int = Field(default=60, alias="ASSISTANT_RATE_LIMIT_WINDOW_SECONDS")
    assistant_max_context_rows: int = Field(default=20, alias="ASSISTANT_MAX_CONTEXT_ROWS")
    assistant_redact_ips: bool = Field(default=True, alias="ASSISTANT_REDACT_IPS")
    assistant_allow_raw_log_context: bool = Field(default=False, alias="ASSISTANT_ALLOW_RAW_LOG_CONTEXT")

    @property
    def resolved_model_path(self) -> Path:
        path = Path(self.ml_model_path)
        if not path.is_absolute():
            return PROJECT_ROOT / path
        return path

    @property
    def resolved_supervised_model_path(self) -> Path:
        path = Path(self.supervised_model_path)
        if not path.is_absolute():
            return PROJECT_ROOT / path
        return path

    @property
    def cors_origins(self) -> list[str]:
        origins = [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]
        return origins or ["http://127.0.0.1:8501"]

    @property
    def trusted_proxy_cidr_list(self) -> list[str]:
        return [value.strip() for value in self.trusted_proxy_cidrs.split(",") if value.strip()]

    @property
    def school_email_domain_list(self) -> list[str]:
        domains = self.school_email_domains or self.oidc_allowed_domains
        return [domain.strip().lower() for domain in domains.split(",") if domain.strip()]

    @property
    def mfu_iam_allowed_domain_list(self) -> list[str]:
        return [domain.strip().lower() for domain in self.mfu_iam_allowed_domains.split(",") if domain.strip()]

    @property
    def mfu_iam_permission_path_list(self) -> list[str]:
        return [path.strip() for path in self.mfu_iam_permission_paths.split(",") if path.strip()]

    @property
    def mfu_iam_init_admin_email_list(self) -> list[str]:
        return [email.strip().lower() for email in self.mfu_iam_init_admin_emails.split(",") if email.strip()]

    @property
    def mfu_iam_admin_email_list(self) -> list[str]:
        return [email.strip().lower() for email in self.mfu_iam_admin_emails.split(",") if email.strip()]

    @property
    def mfu_iam_admin_group_list(self) -> list[str]:
        return [group.strip().lower() for group in self.mfu_iam_admin_groups.split(",") if group.strip()]

    @property
    def mfu_iam_handoff_allowed_origin_list(self) -> list[str]:
        return [origin.strip().rstrip("/") for origin in self.mfu_iam_handoff_allowed_origins.split(",") if origin.strip()]

    @property
    def mfu_iam_handoff_allowed_return_path_list(self) -> list[str]:
        values = [path.strip() for path in self.mfu_iam_handoff_allowed_return_paths.split(",") if path.strip()]
        return [path if path.startswith("/") else f"/{path}" for path in values]

    @property
    def normalized_auth_mode(self) -> str:
        return self.auth_mode.strip().lower()

    @property
    def local_login_enabled(self) -> bool:
        return self.normalized_auth_mode == "local_recovery"

    @property
    def template_shell_required(self) -> bool:
        return self.normalized_auth_mode == "template_shell"

    @property
    def mfu_iam_domain_hints(self) -> list[str]:
        emails = [
            self.mfu_iam_project_account_email,
            self.mfu_iam_managed_client_owner_email,
            self.mfu_iam_init_seed_admin_email,
            *self.mfu_iam_init_admin_email_list,
        ]
        domains: list[str] = []
        for email in emails:
            clean = email.strip().lower()
            if "@" not in clean:
                continue
            domain = clean.rsplit("@", 1)[-1]
            if domain and domain not in domains:
                domains.append(domain)
        return domains


def validate_runtime_settings(settings: Settings) -> list[str]:
    issues: list[str] = []
    auth_mode = settings.normalized_auth_mode
    if auth_mode not in {"template_shell", "local_recovery"}:
        issues.append("ATDR_AUTH_MODE must be 'template_shell' or 'local_recovery'.")
    if auth_mode == "template_shell":
        if not settings.mfu_iam_enabled:
            issues.append("MFU_IAM_ENABLED must be true when ATDR_AUTH_MODE=template_shell.")
        if not settings.mfu_iam_template_shell_enabled:
            issues.append("MFU_IAM_TEMPLATE_SHELL_ENABLED must be true when ATDR_AUTH_MODE=template_shell.")
        if not settings.mfu_iam_handoff_enabled:
            issues.append("MFU_IAM_HANDOFF_ENABLED must be true when ATDR_AUTH_MODE=template_shell.")
        if not settings.mfu_iam_template_shell_launch_url.strip():
            issues.append("MFU_IAM_TEMPLATE_SHELL_LAUNCH_URL is required when ATDR_AUTH_MODE=template_shell.")
        if _is_documentation_placeholder(settings.jwt_secret_key):
            issues.append("JWT_SECRET_KEY must be a generated private value when ATDR_AUTH_MODE=template_shell.")
    if settings.db_pool_size <= 0:
        issues.append("DB_POOL_SIZE must be greater than zero.")
    if settings.db_max_overflow < 0:
        issues.append("DB_MAX_OVERFLOW must be zero or greater.")
    if settings.db_pool_timeout_seconds <= 0:
        issues.append("DB_POOL_TIMEOUT_SECONDS must be greater than zero.")
    if settings.db_connect_timeout_seconds <= 0:
        issues.append("DB_CONNECT_TIMEOUT_SECONDS must be greater than zero.")
    if settings.db_statement_timeout_ms < 0:
        issues.append("DB_STATEMENT_TIMEOUT_MS must be zero or greater.")
    if settings.environment.lower() == "production":
        if settings.jwt_secret_key in {"change-this-dev-secret", "change-this-secret-before-production"}:
            issues.append("JWT_SECRET_KEY must be changed for production.")
        if settings.auto_create_tables:
            issues.append("AUTO_CREATE_TABLES must be false in production; use Alembic migrations.")
        if not settings.response_simulation:
            issues.append("RESPONSE_SIMULATION should remain true until a firewall connector is formally approved.")
        if "*" in settings.cors_origins:
            issues.append("CORS_ALLOWED_ORIGINS must not include '*' in production.")
    trusted_proxy_cidrs = settings.trusted_proxy_cidr_list
    if settings.trust_proxy_headers and not trusted_proxy_cidrs:
        issues.append("TRUSTED_PROXY_CIDRS is required when TRUST_PROXY_HEADERS=true.")
    for cidr in trusted_proxy_cidrs:
        try:
            ip_network(cidr, strict=False)
        except ValueError:
            issues.append("TRUSTED_PROXY_CIDRS must contain only valid IP addresses or CIDR networks.")
            break
    if settings.syslog_enabled and settings.syslog_host in {"0.0.0.0", "::"} and settings.environment.lower() != "production":
        issues.append("SYSLOG_HOST binds publicly outside production; use 127.0.0.1 for lab demo mode.")
    if not settings.response_simulation and settings.response_provider.lower() in {"simulation", "none", "manual"}:
        issues.append("RESPONSE_PROVIDER must name an approved connector before RESPONSE_SIMULATION is disabled.")
    if settings.oidc_default_role not in {"admin", "analyst"}:
        issues.append("OIDC_DEFAULT_ROLE must be 'admin' or 'analyst'.")
    if settings.oidc_enabled:
        if not settings.oidc_provider_name.strip():
            issues.append("OIDC_PROVIDER_NAME is required when OIDC_ENABLED=true.")
        if not settings.oidc_client_id.strip():
            issues.append("OIDC_CLIENT_ID is required when OIDC_ENABLED=true.")
        if not settings.oidc_client_secret.strip():
            issues.append("OIDC_CLIENT_SECRET is required when OIDC_ENABLED=true.")
        if not settings.oidc_issuer_url.strip():
            issues.append("OIDC_ISSUER_URL is required when OIDC_ENABLED=true.")
        if not settings.oidc_allowed_domains.strip():
            issues.append("OIDC_ALLOWED_DOMAINS is required when OIDC_ENABLED=true.")
    if settings.mfu_iam_default_role not in {"admin", "analyst"}:
        issues.append("MFU_IAM_DEFAULT_ROLE must be 'admin' or 'analyst'.")
    if settings.mfu_iam_enabled and auth_mode == "template_shell":
        template_shell_enabled = settings.mfu_iam_template_shell_enabled
        # Shell handoff and direct IAM B2B are separate contracts. A selected
        # shell profile must never demand unrelated B2B client credentials.
        b2b_required = False
        if template_shell_enabled and not settings.mfu_iam_template_shell_base_url.strip():
            issues.append("MFU_IAM_TEMPLATE_SHELL_BASE_URL is required when MFU_IAM_TEMPLATE_SHELL_ENABLED=true.")
        if settings.mfu_iam_handoff_enabled:
            if not template_shell_enabled:
                issues.append("MFU_IAM_TEMPLATE_SHELL_ENABLED must be true when MFU_IAM_HANDOFF_ENABLED=true.")
            if _is_documentation_placeholder(settings.mfu_iam_handoff_shared_secret):
                issues.append("MFU_IAM_HANDOFF_SHARED_SECRET is required when MFU_IAM_HANDOFF_ENABLED=true.")
            if not settings.mfu_iam_handoff_exchange_path.strip().startswith("/"):
                issues.append("MFU_IAM_HANDOFF_EXCHANGE_PATH must start with '/'.")
            if not settings.mfu_iam_handoff_frontend_url.strip().startswith(("http://", "https://")):
                issues.append("MFU_IAM_HANDOFF_FRONTEND_URL must be an http(s) URL when MFU_IAM_HANDOFF_ENABLED=true.")
            if not settings.mfu_iam_handoff_allowed_origin_list:
                issues.append("MFU_IAM_HANDOFF_ALLOWED_ORIGINS is required when MFU_IAM_HANDOFF_ENABLED=true.")
            if not settings.mfu_iam_handoff_allowed_return_path_list:
                issues.append("MFU_IAM_HANDOFF_ALLOWED_RETURN_PATHS is required when MFU_IAM_HANDOFF_ENABLED=true.")
            if not settings.mfu_iam_handoff_cookie_name.strip():
                issues.append("MFU_IAM_HANDOFF_COOKIE_NAME is required when MFU_IAM_HANDOFF_ENABLED=true.")
            if settings.environment.lower() == "production" and not settings.mfu_iam_handoff_cookie_secure:
                issues.append("MFU_IAM_HANDOFF_COOKIE_SECURE must be true in production.")
        if not settings.mfu_iam_base_url.strip() and b2b_required:
            issues.append("MFU_IAM_BASE_URL is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_client_id.strip() and b2b_required:
            issues.append("MFU_IAM_CLIENT_ID is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_client_secret.strip() and b2b_required:
            issues.append("MFU_IAM_CLIENT_SECRET is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_audience.strip() and b2b_required:
            issues.append("MFU_IAM_AUDIENCE is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_token_path.strip() and b2b_required:
            issues.append("MFU_IAM_TOKEN_PATH is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_introspect_path.strip() and b2b_required:
            issues.append("MFU_IAM_INTROSPECT_PATH is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_profile_path.strip() and b2b_required:
            issues.append("MFU_IAM_PROFILE_PATH is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_allowed_domains.strip():
            issues.append("MFU_IAM_ALLOWED_DOMAINS is required when MFU_IAM_ENABLED=true.")
        if settings.mfu_iam_timeout_ms <= 0:
            issues.append("MFU_IAM_TIMEOUT_MS must be greater than zero when MFU_IAM_ENABLED=true.")
        if settings.mfu_iam_admin_client_id.strip() and not settings.mfu_iam_admin_client_secret.strip():
            issues.append("MFU_IAM_ADMIN_CLIENT_SECRET is required when MFU_IAM_ADMIN_CLIENT_ID is configured.")
        if settings.mfu_iam_admin_client_secret.strip() and not settings.mfu_iam_admin_client_id.strip():
            issues.append("MFU_IAM_ADMIN_CLIENT_ID is required when MFU_IAM_ADMIN_CLIENT_SECRET is configured.")
    if settings.google_sso_enabled and not settings.google_client_id.strip():
        issues.append("GOOGLE_CLIENT_ID is required when GOOGLE_SSO_ENABLED=true.")
    if settings.require_school_email and not settings.school_email_domain_list:
        issues.append("SCHOOL_EMAIL_DOMAINS or OIDC_ALLOWED_DOMAINS is required when REQUIRE_SCHOOL_EMAIL=true.")
    if settings.smtp_enabled:
        if not settings.smtp_host.strip():
            issues.append("SMTP_HOST is required when SMTP_ENABLED=true.")
        if not settings.smtp_from_email.strip():
            issues.append("SMTP_FROM_EMAIL is required when SMTP_ENABLED=true.")
    delivery_mode = settings.email_delivery_mode.strip().lower()
    if delivery_mode not in {"disabled", "log_only", "dev_outbox", "smtp"}:
        issues.append("EMAIL_DELIVERY_MODE must be disabled, log_only, dev_outbox, or smtp.")
    if settings.email_verification_code_ttl_minutes <= 0:
        issues.append("EMAIL_VERIFICATION_CODE_TTL_MINUTES must be greater than zero.")
    if not 4 <= settings.email_verification_code_length <= 12:
        issues.append("EMAIL_VERIFICATION_CODE_LENGTH must be between 4 and 12.")
    if delivery_mode == "smtp" and (settings.email_notifications_enabled or settings.email_verification_enabled):
        if not settings.smtp_host.strip():
            issues.append("SMTP_HOST is required when EMAIL_DELIVERY_MODE=smtp.")
        if not settings.smtp_from_email.strip():
            issues.append("SMTP_FROM_EMAIL is required when EMAIL_DELIVERY_MODE=smtp.")
    if settings.email_verification_required_for_login and not settings.email_verification_enabled:
        issues.append("EMAIL_VERIFICATION_ENABLED must be true before EMAIL_VERIFICATION_REQUIRED_FOR_LOGIN can be true.")
    if settings.email_verification_required_for_admin_actions and not settings.email_verification_enabled:
        issues.append(
            "EMAIL_VERIFICATION_ENABLED must be true before EMAIL_VERIFICATION_REQUIRED_FOR_ADMIN_ACTIONS can be true."
        )
    if settings.dashboard_summary_cache_seconds < 0:
        issues.append("DASHBOARD_SUMMARY_CACHE_SECONDS must be zero or greater.")
    if settings.job_stale_after_minutes <= 0:
        issues.append("JOB_STALE_AFTER_MINUTES must be greater than zero.")
    if settings.job_retention_days <= 0:
        issues.append("JOB_RETENTION_DAYS must be greater than zero.")
    if settings.run_history_retention_days <= 0:
        issues.append("RUN_HISTORY_RETENTION_DAYS must be greater than zero.")
    if settings.operation_worker_poll_seconds <= 0:
        issues.append("OPERATION_WORKER_POLL_SECONDS must be greater than zero.")
    if settings.operation_worker_lease_seconds <= 0:
        issues.append("OPERATION_WORKER_LEASE_SECONDS must be greater than zero.")
    if settings.operation_worker_heartbeat_seconds <= 0:
        issues.append("OPERATION_WORKER_HEARTBEAT_SECONDS must be greater than zero.")
    if not settings.operation_worker_deployment_id.strip():
        issues.append("OPERATION_WORKER_DEPLOYMENT_ID must not be empty.")
    if settings.operation_worker_concurrency <= 0:
        issues.append("OPERATION_WORKER_CONCURRENCY must be greater than zero.")
    if settings.operation_worker_shutdown_grace_seconds <= 0:
        issues.append("OPERATION_WORKER_SHUTDOWN_GRACE_SECONDS must be greater than zero.")
    if settings.database_url.lower().startswith("sqlite") and settings.operation_worker_concurrency != 1:
        issues.append("OPERATION_WORKER_CONCURRENCY must be 1 for the SQLite local profile.")
    if settings.operation_job_default_max_attempts <= 0:
        issues.append("OPERATION_JOB_DEFAULT_MAX_ATTEMPTS must be greater than zero.")
    if settings.operation_job_max_attempts < settings.operation_job_default_max_attempts:
        issues.append("OPERATION_JOB_MAX_ATTEMPTS must be greater than or equal to OPERATION_JOB_DEFAULT_MAX_ATTEMPTS.")
    if settings.operation_job_retry_delay_seconds <= 0:
        issues.append("OPERATION_JOB_RETRY_DELAY_SECONDS must be greater than zero.")
    if settings.operation_job_max_input_bytes <= 0:
        issues.append("OPERATION_JOB_MAX_INPUT_BYTES must be greater than zero.")
    if settings.ingestion_chunk_size <= 0:
        issues.append("INGESTION_CHUNK_SIZE must be greater than zero.")
    if settings.ingestion_progress_update_interval <= 0:
        issues.append("INGESTION_PROGRESS_UPDATE_INTERVAL must be greater than zero.")
    if settings.operation_max_queued_imports <= 0:
        issues.append("OPERATION_MAX_QUEUED_IMPORTS must be greater than zero.")
    if settings.operation_max_queued_jobs_per_actor <= 0:
        issues.append("OPERATION_MAX_QUEUED_JOBS_PER_ACTOR must be greater than zero.")
    if settings.operation_staging_max_total_bytes <= 0:
        issues.append("OPERATION_STAGING_MAX_TOTAL_BYTES must be greater than zero.")
    if settings.operation_staging_min_free_bytes < 0:
        issues.append("OPERATION_STAGING_MIN_FREE_BYTES must be zero or greater.")
    if settings.operation_staging_retention_hours <= 0:
        issues.append("OPERATION_STAGING_RETENTION_HOURS must be greater than zero.")
    storage_id = settings.operation_staging_storage_id.strip()
    if not storage_id:
        issues.append("OPERATION_STAGING_STORAGE_ID must not be empty.")
    if settings.operation_staging_shared:
        if not settings.operation_staging_root.strip():
            issues.append("OPERATION_STAGING_ROOT is required when OPERATION_STAGING_SHARED=true.")
        elif not Path(settings.operation_staging_root).expanduser().is_absolute():
            issues.append("OPERATION_STAGING_ROOT must be absolute when OPERATION_STAGING_SHARED=true.")
        if storage_id.lower() == "local":
            issues.append("OPERATION_STAGING_STORAGE_ID must be an explicit shared-storage identifier when shared staging is enabled.")
    if settings.operation_queue_backlog_warning <= 0:
        issues.append("OPERATION_QUEUE_BACKLOG_WARNING must be greater than zero.")
    if settings.operation_job_failure_warning_count <= 0:
        issues.append("OPERATION_JOB_FAILURE_WARNING_COUNT must be greater than zero.")
    if settings.operation_job_failure_warning_window_minutes <= 0:
        issues.append("OPERATION_JOB_FAILURE_WARNING_WINDOW_MINUTES must be greater than zero.")
    if settings.backup_max_age_hours <= 0:
        issues.append("ATDR_BACKUP_MAX_AGE_HOURS must be greater than zero.")
    if settings.audit_retention_min_days <= 0:
        issues.append("AUDIT_RETENTION_MIN_DAYS must be greater than zero.")
    if settings.audit_retention_days < settings.audit_retention_min_days:
        issues.append("AUDIT_RETENTION_DAYS must be greater than or equal to AUDIT_RETENTION_MIN_DAYS.")
    if settings.audit_retention_batch_size <= 0:
        issues.append("AUDIT_RETENTION_BATCH_SIZE must be greater than zero.")
    if settings.assistant_max_context_rows <= 0:
        issues.append("ASSISTANT_MAX_CONTEXT_ROWS must be greater than zero.")
    if settings.assistant_enabled and settings.assistant_provider.lower() in {"", "disabled", "none"}:
        issues.append("ASSISTANT_PROVIDER must name an approved provider when ASSISTANT_ENABLED=true.")
    if settings.assistant_enabled and not settings.assistant_api_key.strip():
        issues.append("ASSISTANT_API_KEY is required when ASSISTANT_ENABLED=true.")
    if settings.assistant_enabled and settings.assistant_allow_raw_log_context:
        issues.append("ASSISTANT_ALLOW_RAW_LOG_CONTEXT must remain false until a privacy review approves raw-log sharing.")
    if settings.assistant_llm_enabled:
        if settings.assistant_llm_provider.strip().lower() not in {
            "gemini",
            "google",
            "google_gemini",
            "openai",
            "openai_compatible",
            "openai-compatible",
            "claude",
            "anthropic",
            "mock",
        }:
            issues.append("ASSISTANT_LLM_PROVIDER must be gemini, openai_compatible, claude, anthropic, or mock when enabled.")
        if not settings.assistant_llm_api_key.strip() and settings.assistant_llm_provider.strip().lower() != "mock":
            issues.append("ASSISTANT_LLM_API_KEY is required when ASSISTANT_LLM_ENABLED=true.")
        if settings.assistant_llm_timeout_seconds <= 0:
            issues.append("ASSISTANT_LLM_TIMEOUT_SECONDS must be greater than zero.")
        if not 0 <= settings.assistant_llm_max_retries <= 5:
            issues.append("ASSISTANT_LLM_MAX_RETRIES must be between zero and five.")
        if not 2000 <= settings.assistant_llm_max_prompt_chars <= 50000:
            issues.append("ASSISTANT_LLM_MAX_PROMPT_CHARS must be between 2000 and 50000.")
        if settings.assistant_allow_raw_log_context:
            issues.append("ASSISTANT_ALLOW_RAW_LOG_CONTEXT must remain false for external LLM use by default.")
    if not 0 <= settings.assistant_conversation_history_turns <= 10:
        issues.append("ASSISTANT_CONVERSATION_HISTORY_TURNS must be between zero and ten.")
    if settings.assistant_rate_limit_requests <= 0:
        issues.append("ASSISTANT_RATE_LIMIT_REQUESTS must be greater than zero.")
    if settings.assistant_rate_limit_window_seconds <= 0:
        issues.append("ASSISTANT_RATE_LIMIT_WINDOW_SECONDS must be greater than zero.")
    return issues


@lru_cache
def get_settings() -> Settings:
    return Settings()
