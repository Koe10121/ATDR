"""newest log time is read from an index

Revision ID: b5d7e9f1a3c4
Revises: a8f1c0d2e3b4
Create Date: 2026-10-08 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "b5d7e9f1a3c4"
down_revision: str | None = "a8f1c0d2e3b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Automatic detection asks for the newest log's event time on every look; without an index on the same
    # expression that read every stored log (1.9 s at 638,000 logs).
    op.create_index(
        "ix_normalized_logs_event_time",
        "normalized_logs",
        [sa.text("coalesce(generated_time, receive_time, high_res_timestamp, start_time)")],
    )


def downgrade() -> None:
    op.drop_index("ix_normalized_logs_event_time", table_name="normalized_logs")
