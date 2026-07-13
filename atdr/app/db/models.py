from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint, func, true
from sqlalchemy.orm import Mapped, foreign, mapped_column, relationship

from atdr.app.db.database import Base


class LogSource(Base):
    __tablename__ = "log_sources"
    __table_args__ = (UniqueConstraint("name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    parser_profile: Mapped[str] = mapped_column(String(64), default="palo_alto", nullable=False, index=True)
    host: Mapped[str | None] = mapped_column(String(255), index=True)
    port: Mapped[int | None] = mapped_column(Integer, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_log_received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    logs_received_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    parse_success_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    parse_failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    latest_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    raw_logs: Mapped[list["RawLog"]] = relationship(
        back_populates="source",
        primaryjoin=lambda: LogSource.id == foreign(RawLog.source_id),
    )


class RawLog(Base):
    __tablename__ = "raw_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int | None] = mapped_column(Integer, index=True)
    raw_line: Mapped[str] = mapped_column(Text, nullable=False)
    syslog_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    device_hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    normalized: Mapped["NormalizedLog"] = relationship(
        back_populates="raw_log",
        cascade="all, delete-orphan",
        uselist=False,
    )
    source: Mapped[LogSource | None] = relationship(
        back_populates="raw_logs",
        primaryjoin=lambda: foreign(RawLog.source_id) == LogSource.id,
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), index=True, nullable=False, default="analyst")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    auth_provider: Mapped[str] = mapped_column(String(32), default="local", nullable=False, index=True)
    external_subject: Mapped[str | None] = mapped_column(String(255), index=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    invited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class NormalizedLog(Base):
    __tablename__ = "normalized_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    raw_log_id: Mapped[int] = mapped_column(ForeignKey("raw_logs.id"), nullable=False, index=True)

    receive_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    generated_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    log_type: Mapped[str | None] = mapped_column(String(64), index=True)
    subtype: Mapped[str | None] = mapped_column(String(128), index=True)
    serial: Mapped[str | None] = mapped_column(String(128), index=True)

    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    nat_src_ip: Mapped[str | None] = mapped_column(String(64))
    nat_dst_ip: Mapped[str | None] = mapped_column(String(64))
    rule_name: Mapped[str | None] = mapped_column(String(255), index=True)
    src_user: Mapped[str | None] = mapped_column(String(255))
    dst_user: Mapped[str | None] = mapped_column(String(255))
    app: Mapped[str | None] = mapped_column(String(255), index=True)
    vsys: Mapped[str | None] = mapped_column(String(128))
    src_zone: Mapped[str | None] = mapped_column(String(128), index=True)
    dst_zone: Mapped[str | None] = mapped_column(String(128), index=True)
    inbound_interface: Mapped[str | None] = mapped_column(String(128))
    outbound_interface: Mapped[str | None] = mapped_column(String(128))
    log_action: Mapped[str | None] = mapped_column(String(128))
    session_id: Mapped[str | None] = mapped_column(String(128), index=True)
    repeat_count: Mapped[int | None] = mapped_column(Integer)
    src_port: Mapped[int | None] = mapped_column(Integer, index=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, index=True)
    protocol: Mapped[str | None] = mapped_column(String(64), index=True)
    action: Mapped[str | None] = mapped_column(String(64), index=True)
    bytes: Mapped[int | None] = mapped_column(Integer)
    bytes_sent: Mapped[int | None] = mapped_column(Integer)
    bytes_received: Mapped[int | None] = mapped_column(Integer)
    packets: Mapped[int | None] = mapped_column(Integer)
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    elapsed_time: Mapped[int | None] = mapped_column(Integer)
    category: Mapped[str | None] = mapped_column(String(255))
    src_country: Mapped[str | None] = mapped_column(String(255), index=True)
    dst_country: Mapped[str | None] = mapped_column(String(255), index=True)
    packets_sent: Mapped[int | None] = mapped_column(Integer)
    packets_received: Mapped[int | None] = mapped_column(Integer)
    session_end_reason: Mapped[str | None] = mapped_column(String(255))
    device_name: Mapped[str | None] = mapped_column(String(255), index=True)
    action_source: Mapped[str | None] = mapped_column(String(255))
    rule_uuid: Mapped[str | None] = mapped_column(String(128), index=True)
    high_res_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    app_subcategory: Mapped[str | None] = mapped_column(String(255))
    app_category: Mapped[str | None] = mapped_column(String(255), index=True)
    app_technology: Mapped[str | None] = mapped_column(String(255))
    app_risk: Mapped[int | None] = mapped_column(Integer, index=True)
    app_characteristic: Mapped[str | None] = mapped_column(Text)
    anomaly_score: Mapped[float | None] = mapped_column(Float, index=True)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    parsed_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    raw_log: Mapped[RawLog] = relationship(back_populates="normalized")
    alert_evidence: Mapped[list["AlertEvidence"]] = relationship(back_populates="normalized_log")
    ml_labels: Mapped[list["MLLabel"]] = relationship(
        back_populates="log",
        cascade="all, delete-orphan",
        order_by="MLLabel.created_at",
    )


Index("ix_normalized_src_generated", NormalizedLog.src_ip, NormalizedLog.generated_time)
Index("ix_normalized_action_generated", NormalizedLog.action, NormalizedLog.generated_time)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    alert_type: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    threat_score: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, default="open", nullable=False)
    assigned_to: Mapped[str | None] = mapped_column(String(128), index=True)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    priority_owner: Mapped[str | None] = mapped_column(String(128), index=True)
    escalation_reason: Mapped[str | None] = mapped_column(Text)
    ticket_reference: Mapped[str | None] = mapped_column(String(255), index=True)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    matched_rules_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    recommended_response: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    evidence: Mapped[list["AlertEvidence"]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
    )
    response_actions: Mapped[list["ResponseAction"]] = relationship(back_populates="alert")
    notes: Mapped[list["AlertNote"]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="AlertNote.created_at",
    )


class AlertNote(Base):
    __tablename__ = "alert_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), nullable=False, index=True)
    author: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    alert: Mapped[Alert] = relationship(back_populates="notes")


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), nullable=False, index=True)
    normalized_log_id: Mapped[int] = mapped_column(ForeignKey("normalized_logs.id"), nullable=False, index=True)

    alert: Mapped[Alert] = relationship(back_populates="evidence")
    normalized_log: Mapped[NormalizedLog] = relationship(back_populates="alert_evidence")


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    target_ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    result_message: Mapped[str] = mapped_column(Text, nullable=False)
    executed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    alert: Mapped[Alert | None] = relationship(back_populates="response_actions")


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(128), nullable=False)
    target_value: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AccountEmailVerificationToken(Base):
    __tablename__ = "account_email_verification_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(64), default="email_verification", nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    created_by: Mapped[str | None] = mapped_column(String(128), index=True)
    delivery_mode: Mapped[str] = mapped_column(String(32), default="disabled", nullable=False, index=True)
    delivery_status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)


class EmailNotificationEvent(Base):
    __tablename__ = "email_notification_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    recipient_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    body_preview: Mapped[str] = mapped_column(Text, nullable=False)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    delivery_mode: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    delivery_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    created_by: Mapped[str | None] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    error_summary: Mapped[str | None] = mapped_column(Text)


class AssistantFeedback(Base):
    __tablename__ = "assistant_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    actor_username: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    answer_summary: Mapped[str | None] = mapped_column(Text)
    answer_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    context_type: Mapped[str | None] = mapped_column(String(64), index=True)
    context_reference: Mapped[str | None] = mapped_column(String(255), index=True)
    rating: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    feedback_note: Mapped[str | None] = mapped_column(Text)
    external_provider_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    raw_log_context_included: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    action_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    action_executed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    assistant_audit_id: Mapped[int | None] = mapped_column(ForeignKey("audit_logs.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    app: Mapped[str | None] = mapped_column(String(255), index=True)
    alert_type: Mapped[str | None] = mapped_column(String(128), index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    suppressed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    review_status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    review_notes: Mapped[str | None] = mapped_column(Text)
    reviewed_by: Mapped[str | None] = mapped_column(String(128), index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_by: Mapped[str | None] = mapped_column(String(128))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WatchlistItem(Base):
    __tablename__ = "watchlist_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    indicator_value: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity_boost: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    match_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    disabled_by: Mapped[str | None] = mapped_column(String(128))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MLModelRun(Base):
    __tablename__ = "ml_model_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(128), index=True)
    operation: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    model_path: Mapped[str] = mapped_column(String(500), nullable=False)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    artifact_size_bytes: Mapped[int | None] = mapped_column(Integer)
    training_log_count: Mapped[int | None] = mapped_column(Integer)
    scored_log_count: Mapped[int | None] = mapped_column(Integer)
    anomaly_count: Mapped[int | None] = mapped_column(Integer)
    anomaly_rate: Mapped[float | None] = mapped_column(Float)
    contamination: Mapped[float | None] = mapped_column(Float)
    feature_columns_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    feature_summary_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    metrics_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


class IngestionRun(Base):
    __tablename__ = "ingestion_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    source_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    input_name: Mapped[str | None] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True, default="running", nullable=False)
    total_lines_received: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw_logs_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    parsed_successfully: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    parse_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duplicate_raw_logs: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_deduplicated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_suppressed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    runtime_seconds: Mapped[float | None] = mapped_column(Float)
    error_summary: Mapped[str | None] = mapped_column(Text)
    details_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class DetectionRun(Base):
    __tablename__ = "detection_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    detection_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, default="running", nullable=False)
    logs_evaluated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_deduplicated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_suppressed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    top_attack_types_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    runtime_seconds: Mapped[float | None] = mapped_column(Float)
    error_summary: Mapped[str | None] = mapped_column(Text)
    details_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class OperationJob(Base):
    __tablename__ = "operation_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, default="queued", nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    progress_current: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    progress_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    checkpoint_line: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    checkpoint_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    checkpoint_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    chunk_commits: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    input_size_bytes: Mapped[int | None] = mapped_column(Integer)
    input_fingerprint: Mapped[str | None] = mapped_column(String(64))
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    cancellation_requested_by: Mapped[str | None] = mapped_column(String(128))
    resume_of_job_id: Mapped[int | None] = mapped_column(Integer, index=True)
    original_job_id: Mapped[int | None] = mapped_column(Integer, index=True)
    resume_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    result_summary_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_summary: Mapped[str | None] = mapped_column(Text)
    related_ingestion_run_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_runs.id"), index=True)
    related_detection_run_id: Mapped[int | None] = mapped_column(ForeignKey("detection_runs.id"), index=True)
    related_ml_model_run_id: Mapped[int | None] = mapped_column(ForeignKey("ml_model_runs.id"), index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    claim_generation: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    staging_storage_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    details_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        index=True,
    )


class OperationWorkerHeartbeat(Base):
    __tablename__ = "operation_worker_heartbeats"

    worker_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default="idle", nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    current_job_id: Mapped[int | None] = mapped_column(ForeignKey("operation_jobs.id"), index=True)
    details_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class MLLabel(Base):
    __tablename__ = "ml_labels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    log_id: Mapped[int] = mapped_column(ForeignKey("normalized_logs.id"), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    attack_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    reviewer: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    review_note: Mapped[str | None] = mapped_column(Text)
    label_source: Mapped[str] = mapped_column(String(32), default="manual", server_default="manual", nullable=False, index=True)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true(), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    log: Mapped[NormalizedLog] = relationship(back_populates="ml_labels")


Index("ix_ml_labels_log_created", MLLabel.log_id, MLLabel.created_at)
Index("ix_ml_labels_reviewed_label", MLLabel.reviewed, MLLabel.label)
Index("ix_ml_labels_source_reviewed", MLLabel.label_source, MLLabel.reviewed)
Index("ix_ml_labels_label_label_source", MLLabel.label, MLLabel.label_source)
Index("ix_ml_model_runs_model_operation_created", MLModelRun.model_name, MLModelRun.operation, MLModelRun.created_at)
Index("ux_operation_jobs_idempotency_key", OperationJob.idempotency_key, unique=True)
Index("ix_operation_jobs_queue_claim", OperationJob.status, OperationJob.next_attempt_at, OperationJob.created_at)
Index("ix_operation_jobs_original_status", OperationJob.original_job_id, OperationJob.status)
Index("ix_normalized_anomaly_app", NormalizedLog.is_anomaly, NormalizedLog.app)
Index("ix_normalized_anomaly_dst_port", NormalizedLog.is_anomaly, NormalizedLog.dst_port)
Index("ix_alert_status_severity_updated", Alert.status, Alert.severity, Alert.updated_at)
