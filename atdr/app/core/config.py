from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or .env."""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "MFU ATDR"
    database_url: str = Field(default="sqlite:///./atdr.db", alias="DATABASE_URL")
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
    demo_sample_log_path: str = Field(default="paloalto-firewall(1).log", alias="DEMO_SAMPLE_LOG_PATH")
    demo_import_limit: int = Field(default=5000, alias="DEMO_IMPORT_LIMIT")
    environment: str = Field(default="development", alias="ENVIRONMENT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")
    service_version: str = Field(default="0.1.0", alias="SERVICE_VERSION")
    cors_allowed_origins: str = Field(
        default="http://127.0.0.1:8501,http://localhost:8501",
        alias="CORS_ALLOWED_ORIGINS",
    )
    security_headers_enabled: bool = Field(default=True, alias="SECURITY_HEADERS_ENABLED")
    syslog_enabled: bool = Field(default=False, alias="SYSLOG_ENABLED")
    syslog_host: str = Field(default="127.0.0.1", alias="SYSLOG_HOST")
    syslog_port: int = Field(default=5514, alias="SYSLOG_PORT")
    syslog_batch_size: int = Field(default=100, alias="SYSLOG_BATCH_SIZE")
    login_rate_limit_attempts: int = Field(default=5, alias="LOGIN_RATE_LIMIT_ATTEMPTS")
    login_rate_limit_window_seconds: int = Field(default=300, alias="LOGIN_RATE_LIMIT_WINDOW_SECONDS")
    oidc_enabled: bool = Field(default=False, alias="OIDC_ENABLED")
    oidc_provider_name: str = Field(default="", alias="OIDC_PROVIDER_NAME")
    oidc_client_id: str = Field(default="", alias="OIDC_CLIENT_ID")
    oidc_client_secret: str = Field(default="", alias="OIDC_CLIENT_SECRET")
    oidc_issuer_url: str = Field(default="", alias="OIDC_ISSUER_URL")
    oidc_allowed_domains: str = Field(default="", alias="OIDC_ALLOWED_DOMAINS")
    oidc_default_role: str = Field(default="analyst", alias="OIDC_DEFAULT_ROLE")
    mfu_iam_enabled: bool = Field(default=False, alias="MFU_IAM_ENABLED")
    mfu_iam_base_url: str = Field(default="", alias="MFU_IAM_BASE_URL")
    mfu_iam_client_id: str = Field(default="", alias="MFU_IAM_CLIENT_ID")
    mfu_iam_client_secret: str = Field(default="", alias="MFU_IAM_CLIENT_SECRET")
    mfu_iam_audience: str = Field(default="", alias="MFU_IAM_AUDIENCE")
    mfu_iam_allowed_domains: str = Field(default="", alias="MFU_IAM_ALLOWED_DOMAINS")
    mfu_iam_default_role: str = Field(default="analyst", alias="MFU_IAM_DEFAULT_ROLE")
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
    assistant_enabled: bool = Field(default=False, alias="ASSISTANT_ENABLED")
    assistant_provider: str = Field(default="disabled", alias="ASSISTANT_PROVIDER")
    assistant_model: str = Field(default="", alias="ASSISTANT_MODEL")
    assistant_api_key: str = Field(default="", alias="ASSISTANT_API_KEY")
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
    def school_email_domain_list(self) -> list[str]:
        domains = self.school_email_domains or self.oidc_allowed_domains
        return [domain.strip().lower() for domain in domains.split(",") if domain.strip()]

    @property
    def mfu_iam_allowed_domain_list(self) -> list[str]:
        return [domain.strip().lower() for domain in self.mfu_iam_allowed_domains.split(",") if domain.strip()]


def validate_runtime_settings(settings: Settings) -> list[str]:
    issues: list[str] = []
    if settings.environment.lower() == "production":
        if settings.jwt_secret_key in {"change-this-dev-secret", "change-this-secret-before-production"}:
            issues.append("JWT_SECRET_KEY must be changed for production.")
        if settings.auto_create_tables:
            issues.append("AUTO_CREATE_TABLES must be false in production; use Alembic migrations.")
        if not settings.response_simulation:
            issues.append("RESPONSE_SIMULATION should remain true until a firewall connector is formally approved.")
        if "*" in settings.cors_origins:
            issues.append("CORS_ALLOWED_ORIGINS must not include '*' in production.")
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
    if settings.mfu_iam_enabled:
        if not settings.mfu_iam_base_url.strip():
            issues.append("MFU_IAM_BASE_URL is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_client_id.strip():
            issues.append("MFU_IAM_CLIENT_ID is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_client_secret.strip():
            issues.append("MFU_IAM_CLIENT_SECRET is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_audience.strip():
            issues.append("MFU_IAM_AUDIENCE is required when MFU_IAM_ENABLED=true.")
        if not settings.mfu_iam_allowed_domains.strip():
            issues.append("MFU_IAM_ALLOWED_DOMAINS is required when MFU_IAM_ENABLED=true.")
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
    if settings.assistant_max_context_rows <= 0:
        issues.append("ASSISTANT_MAX_CONTEXT_ROWS must be greater than zero.")
    if settings.assistant_enabled and settings.assistant_provider.lower() in {"", "disabled", "none"}:
        issues.append("ASSISTANT_PROVIDER must name an approved provider when ASSISTANT_ENABLED=true.")
    if settings.assistant_enabled and not settings.assistant_api_key.strip():
        issues.append("ASSISTANT_API_KEY is required when ASSISTANT_ENABLED=true.")
    if settings.assistant_enabled and settings.assistant_allow_raw_log_context:
        issues.append("ASSISTANT_ALLOW_RAW_LOG_CONTEXT must remain false until a privacy review approves raw-log sharing.")
    return issues


@lru_cache
def get_settings() -> Settings:
    return Settings()
