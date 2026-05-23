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

    @property
    def resolved_model_path(self) -> Path:
        path = Path(self.ml_model_path)
        if not path.is_absolute():
            return PROJECT_ROOT / path
        return path

    @property
    def cors_origins(self) -> list[str]:
        origins = [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]
        return origins or ["http://127.0.0.1:8501"]


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
    return issues


@lru_cache
def get_settings() -> Settings:
    return Settings()
