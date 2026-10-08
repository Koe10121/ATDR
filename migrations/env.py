from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base
from atdr.app.db.engine import create_configured_engine
from atdr.app.db import models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url)
target_metadata = Base.metadata

# Indexes on an expression are created by their own migration. SQLite cannot read them back to compare, and
# PostgreSQL may read back the same expression in another form, so drift checks leave them out.
EXPRESSION_INDEXES = frozenset({"ix_normalized_logs_event_time"})


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    return not (type_ == "index" and name in EXPRESSION_INDEXES)


def run_migrations_offline() -> None:
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        include_object=include_object,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_configured_engine(settings, poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True, include_object=include_object)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
