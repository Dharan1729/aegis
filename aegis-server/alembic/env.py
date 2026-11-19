import asyncio
from logging.config import fileConfig

from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from app import models  # noqa: F401 - registers tables on Base.metadata
from app.config import settings
from app.db import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", settings.database_url)

target_metadata = Base.metadata

# The Dockerfile CMD runs `alembic upgrade head` on every container start,
# including on every replica in a multi-replica deployment. Without
# serialization, two replicas starting simultaneously can both read the
# same current revision and both attempt to apply the same migration,
# racing on the alembic_version table and potentially double-applying DDL.
# A Postgres transaction-scoped advisory lock (pg_advisory_xact_lock) held
# for the migration run means only one replica actually migrates at a
# time; the rest block on the lock, then find themselves already at head
# and no-op. Transaction-scoped (vs. session-scoped pg_advisory_lock) so
# the lock releases automatically on commit *or* rollback — no separate
# unlock call to forget in a failure path. This value is arbitrary but
# must stay stable — changing it would let a stale replica bypass the
# lock a differently-versioned one is holding.
_MIGRATION_LOCK_KEY = 847_362_915_003


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    try:
        async with connectable.connect() as connection:
            # Blocks here until any other replica's migration transaction
            # commits or rolls back — see comment on _MIGRATION_LOCK_KEY above.
            await connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _MIGRATION_LOCK_KEY})
            await connection.run_sync(do_run_migrations)
            # Alembic's own begin_transaction() detects the transaction the lock
            # query above already opened and, seeing one active, defers commit
            # to the caller instead of committing it itself — so this explicit
            # commit is load-bearing, not redundant. Without it every migration
            # (lock-protected or not) silently rolls back on connection close.
            await connection.commit()
    finally:
        # Not just cleanup-on-the-happy-path: a raised exception from a
        # genuinely broken migration must not skip disposing the engine's
        # own connections either.
        await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
