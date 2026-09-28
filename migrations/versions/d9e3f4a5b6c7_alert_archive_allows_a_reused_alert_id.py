"""alert_archive.original_alert_id is no longer unique

SQLite numbers new alerts from the highest remaining id, so after a rebuild the
new alerts reuse the ids of the ones it archived. The next rebuild archives those
and needs a second archive row for the same original id.

Downgrading restores the unique index, which fails while any id is archived twice.

Revision ID: d9e3f4a5b6c7
Revises: c8d2e3f4a5b6
Create Date: 2026-09-28 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op


revision: str = "d9e3f4a5b6c7"
down_revision: str | None = "c8d2e3f4a5b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEX = "ix_alert_archive_original_alert_id"


def upgrade() -> None:
    op.drop_index(INDEX, table_name="alert_archive")
    op.create_index(INDEX, "alert_archive", ["original_alert_id"], unique=False)


def downgrade() -> None:
    op.drop_index(INDEX, table_name="alert_archive")
    op.create_index(INDEX, "alert_archive", ["original_alert_id"], unique=True)
