"""alert ids are never reused

Revision ID: a8f1c0d2e3b4
Revises: 7c2e91f4b0a3
Create Date: 2026-10-04 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
import sqlalchemy as sa


revision: str = "a8f1c0d2e3b4"
down_revision: str | None = "7c2e91f4b0a3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _sqlite_online() -> bool:
    # PostgreSQL's sequence never hands a number out twice, so only SQLite needs this; an offline SQL script
    # cannot read the highest number used so far.
    return not context.is_offline_mode() and op.get_bind().dialect.name == "sqlite"


def upgrade() -> None:
    # SQLite numbers a new row one above the highest row still in the table. A rebuild archives the alerts on
    # the list, so the next alerts took numbers that archived alerts, audit entries and reports already used
    # (the 4 October 2026 rehearsal numbered new alerts from #2638 while #3985 was in the archive).
    # AUTOINCREMENT makes SQLite remember the highest number it has given.
    if not _sqlite_online():
        return
    with op.batch_alter_table("alerts", recreate="always", table_kwargs={"sqlite_autoincrement": True}):
        pass
    bind = op.get_bind()
    highest = bind.execute(sa.text(
        "SELECT MAX(used) FROM (SELECT MAX(id) AS used FROM alerts UNION ALL SELECT MAX(original_alert_id) FROM alert_archive)"
    )).scalar()
    bind.execute(sa.text("DELETE FROM sqlite_sequence WHERE name IN ('alerts', '_alembic_tmp_alerts')"))
    bind.execute(sa.text("INSERT INTO sqlite_sequence (name, seq) VALUES ('alerts', :highest)"), {"highest": int(highest or 0)})


def downgrade() -> None:
    if not _sqlite_online():
        return
    with op.batch_alter_table("alerts", recreate="always", table_kwargs={"sqlite_autoincrement": False}):
        pass
