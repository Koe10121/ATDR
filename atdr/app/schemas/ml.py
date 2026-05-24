from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


MLLabelValue = Literal["benign", "benign_unusual", "suspicious", "malicious", "needs_context"]
MLAttackType = Literal[
    "normal",
    "port_scan",
    "brute_force",
    "dos_ddos",
    "malware_c2",
    "policy_violation",
    "data_exfiltration_suspicion",
    "unknown_anomaly",
]
MLLabelSource = Literal["manual", "assisted_rule", "assisted_ml", "assisted_hybrid"]


class MLLabelCreate(BaseModel):
    log_id: int = Field(ge=1)
    label: MLLabelValue
    attack_type: MLAttackType = "unknown_anomaly"
    confidence: int = Field(ge=1, le=5)
    review_note: str | None = Field(default=None, max_length=5000)
    label_source: MLLabelSource = "manual"
    reviewed: bool = True


class MLLabelUpdate(BaseModel):
    label: MLLabelValue | None = None
    attack_type: MLAttackType | None = None
    confidence: int | None = Field(default=None, ge=1, le=5)
    review_note: str | None = Field(default=None, max_length=5000)
    label_source: MLLabelSource | None = None
    reviewed: bool | None = None


class MLLabelRead(BaseModel):
    id: int
    log_id: int
    label: str
    attack_type: str
    confidence: int
    reviewer: str
    review_note: str | None = None
    label_source: str = "manual"
    reviewed: bool = True
    created_at: datetime


class MLLabelImportResult(BaseModel):
    created: int
    updated: int
    skipped: int = 0
    protected_manual: int = 0
    failed: int
    errors: list[dict[str, Any]] = Field(default_factory=list)


class MLReviewQueueItem(BaseModel):
    log_id: int
    generated_time: datetime | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    app: str | None = None
    action: str | None = None
    protocol: str | None = None
    src_zone: str | None = None
    dst_zone: str | None = None
    app_risk: int | None = None
    is_anomaly: bool
    anomaly_score: float | None = None
    rule_score: int
    supervised_prediction: str | None = None
    malicious_probability: float
    hybrid_risk_score: int
    priority_score: int
    priority_reasons: list[str]
    existing_label: MLLabelRead | None = None
    alert_ids: list[int] = Field(default_factory=list)


class MLRunRequest(BaseModel):
    limit: int | None = Field(default=None, ge=1, le=100000)
    baseline_only: bool = False
    max_app_risk: int = Field(default=3, ge=1, le=5)
    exclude_unknown_apps: bool = True
    exclude_existing_anomalies: bool = True


class MLDatasetProfileRead(BaseModel):
    total_logs: int
    generated_time_min: datetime | None = None
    generated_time_max: datetime | None = None
    current_anomaly_logs: int
    current_anomaly_rate: float
    deny_drop_logs: int
    deny_drop_rate: float
    high_risk_logs: int
    high_risk_rate: float
    unknown_app_logs: int
    unknown_app_rate: float
    baseline_max_app_risk: int
    baseline_candidate_count: int
    baseline_candidate_rate: float
    action_distribution: list[dict[str, Any]]
    app_risk_distribution: list[dict[str, Any]]
    protocol_distribution: list[dict[str, Any]]
    top_apps: list[dict[str, Any]]
    top_src_zones: list[dict[str, Any]]
    top_dst_zones: list[dict[str, Any]]
    recommendations: list[str]


class MLModelRunRead(BaseModel):
    id: int
    model_name: str
    model_version: str | None = None
    operation: str
    status: str
    actor: str
    model_path: str
    artifact_sha256: str | None = None
    artifact_size_bytes: int | None = None
    training_log_count: int | None = None
    scored_log_count: int | None = None
    anomaly_count: int | None = None
    anomaly_rate: float | None = None
    contamination: float | None = None
    feature_columns: list[str] = Field(default_factory=list)
    feature_summary: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    message: str
    created_at: datetime


class MLStatusRead(BaseModel):
    model_name: str
    model_path: str
    artifact_exists: bool
    artifact_sha256: str | None = None
    artifact_size_bytes: int | None = None
    contamination: float
    feature_columns: list[str]
    latest_training: MLModelRunRead | None = None
    latest_scoring: MLModelRunRead | None = None
    total_logs: int
    current_anomaly_logs: int
    current_anomaly_rate: float


class MLScoreStats(BaseModel):
    count: int
    min: float | None = None
    avg: float | None = None
    max: float | None = None


class MLRunComparison(BaseModel):
    latest: MLModelRunRead | None = None
    previous: MLModelRunRead | None = None
    anomaly_rate_delta: float | None = None
    interpretation: str


class MLAnomalySample(BaseModel):
    id: int
    generated_time: datetime | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    app: str | None = None
    action: str | None = None
    protocol: str | None = None
    dst_port: int | None = None
    bytes: int | None = None
    packets: int | None = None
    app_risk: int | None = None
    anomaly_score: float | None = None


class MLEvaluationReportRead(BaseModel):
    model_status: MLStatusRead
    dataset_profile: MLDatasetProfileRead
    scored_log_count: int
    anomaly_count: int
    anomaly_rate: float
    score_stats_all: MLScoreStats
    score_stats_anomalies: MLScoreStats
    run_comparison: MLRunComparison
    drift_signals: list[dict[str, Any]]
    top_anomalous_src_ips: list[dict[str, Any]]
    top_anomalous_dst_ips: list[dict[str, Any]]
    top_anomalous_apps: list[dict[str, Any]]
    top_anomalous_dst_ports: list[dict[str, Any]]
    top_anomalous_protocols: list[dict[str, Any]]
    sample_anomalies: list[MLAnomalySample]
    recommendations: list[str]
