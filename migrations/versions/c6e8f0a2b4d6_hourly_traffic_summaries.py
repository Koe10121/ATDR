"""hourly traffic summaries for live syslog logs that are deleted

Revision ID: c6e8f0a2b4d6
Revises: b5d7e9f1a3c4
Create Date: 2026-10-08 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c6e8f0a2b4d6"
down_revision: str | None = "b5d7e9f1a3c4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Logs from the live syslog feed are deleted after SYSLOG_RETENTION_HOURS; each source address's traffic in
    # each hour is kept here.
    op.create_table(
        "traffic_hourly_summaries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("hour_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("src_ip", sa.String(length=64), nullable=True),
        sa.Column("connections", sa.Integer(), nullable=False),
        sa.Column("denied", sa.Integer(), nullable=False),
        sa.Column("bytes_sent", sa.BigInteger(), nullable=False),
        sa.Column("bytes_received", sa.BigInteger(), nullable=False),
        sa.Column("destinations", sa.Integer(), nullable=False),
        sa.Column("destination_ports", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hour_start", "source_id", "src_ip", name="uq_traffic_hourly_summary"),
    )
    op.create_index("ix_traffic_hourly_summaries_hour_start", "traffic_hourly_summaries", ["hour_start"])
    op.create_index("ix_traffic_hourly_summaries_source_id", "traffic_hourly_summaries", ["source_id"])
    op.create_index("ix_traffic_hourly_summaries_src_ip", "traffic_hourly_summaries", ["src_ip"])


def downgrade() -> None:
    op.drop_index("ix_traffic_hourly_summaries_src_ip", table_name="traffic_hourly_summaries")
    op.drop_index("ix_traffic_hourly_summaries_source_id", table_name="traffic_hourly_summaries")
    op.drop_index("ix_traffic_hourly_summaries_hour_start", table_name="traffic_hourly_summaries")
    op.drop_table("traffic_hourly_summaries")
