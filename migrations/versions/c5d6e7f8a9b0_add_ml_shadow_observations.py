"""add aggregate ML shadow observations

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
Create Date: 2026-07-27 10:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "c5d6e7f8a9b0"
down_revision = "b4c5d6e7f8a9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ml_shadow_observations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("observation_key", sa.String(length=64), nullable=False),
        sa.Column("candidate_name", sa.String(length=128), nullable=False),
        sa.Column("candidate_version", sa.String(length=128), nullable=False),
        sa.Column("contract_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("contract_matched", sa.Boolean(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observed_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observed_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_limit", sa.Integer(), nullable=False),
        sa.Column("rows_evaluated", sa.Integer(), nullable=False),
        sa.Column("queue_count", sa.Integer(), nullable=False),
        sa.Column("queue_rate", sa.Float(), nullable=False),
        sa.Column("score_mean", sa.Float(), nullable=True),
        sa.Column("score_p95", sa.Float(), nullable=True),
        sa.Column("confidence_mean", sa.Float(), nullable=True),
        sa.Column("confidence_p95", sa.Float(), nullable=True),
        sa.Column("missing_feature_values", sa.Integer(), nullable=False),
        sa.Column("feature_values_checked", sa.Integer(), nullable=False),
        sa.Column("drift_status", sa.String(length=32), nullable=False),
        sa.Column("application_total_variation", sa.Float(), nullable=True),
        sa.Column("schema_total_variation", sa.Float(), nullable=True),
        sa.Column("rule_both_queue", sa.Integer(), nullable=False),
        sa.Column("rule_only", sa.Integer(), nullable=False),
        sa.Column("shadow_only", sa.Integer(), nullable=False),
        sa.Column("neither_queue", sa.Integer(), nullable=False),
        sa.Column("disagreement_count", sa.Integer(), nullable=False),
        sa.Column("disagreement_rate", sa.Float(), nullable=False),
        sa.Column("isolation_anomaly_count", sa.Integer(), nullable=False),
        sa.Column("isolation_anomaly_rate", sa.Float(), nullable=False),
        sa.Column("runtime_seconds", sa.Float(), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("aggregate_json", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "observation_key",
            name="uq_ml_shadow_observations_observation_key",
        ),
    )
    op.create_index(
        "ix_ml_shadow_observations_candidate_name",
        "ml_shadow_observations",
        ["candidate_name"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_candidate_version",
        "ml_shadow_observations",
        ["candidate_version"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_contract_matched",
        "ml_shadow_observations",
        ["contract_matched"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_source_id",
        "ml_shadow_observations",
        ["source_id"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_window_start",
        "ml_shadow_observations",
        ["window_start"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_window_end",
        "ml_shadow_observations",
        ["window_end"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_status",
        "ml_shadow_observations",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_drift_status",
        "ml_shadow_observations",
        ["drift_status"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_created_by",
        "ml_shadow_observations",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_created_at",
        "ml_shadow_observations",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_source_window",
        "ml_shadow_observations",
        ["source_id", "window_start", "window_end"],
        unique=False,
    )
    op.create_index(
        "ix_ml_shadow_observations_candidate_created",
        "ml_shadow_observations",
        ["candidate_version", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_ml_shadow_observations_candidate_created",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_source_window",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_created_at",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_created_by",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_drift_status",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_status",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_window_end",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_window_start",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_source_id",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_contract_matched",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_candidate_version",
        table_name="ml_shadow_observations",
    )
    op.drop_index(
        "ix_ml_shadow_observations_candidate_name",
        table_name="ml_shadow_observations",
    )
    op.drop_table("ml_shadow_observations")
