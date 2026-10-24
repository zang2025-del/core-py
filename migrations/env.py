"""Alembic environment.

The database URL is read from the application's own settings rather than from
``alembic.ini``. Two sources of truth for "which database is this" is how a
migration lands on the wrong one -- and it is always discovered afterwards.
"""

from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

ROOT = Path(__file__).resolve().parent.parent
for extra in (str(ROOT), str(ROOT / "src")):
    if extra not in sys.path:
        sys.path.insert(0, extra)

from permgate.config import get_settings  # noqa: E402
from permgate.storage.models import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ``config.attributes`` is Alembic's documented hook for a caller that needs to
# supply its own connection -- it is how the migration test points the
# environment at a throwaway database without touching the process environment
# or the cached settings object.
_url = config.attributes.get("sqlalchemy_url") or get_settings().database_url
# ``set_main_option`` goes through ``configparser``, which reads ``%`` as the
# start of an interpolation. A percent-encoded query parameter -- or a password
# containing one -- therefore fails with "invalid interpolation syntax" raised
# from inside Alembic, naming nothing that helps. Doubling is the documented
# escape, and ``get_main_option`` unescapes it again, so the two directions stay
# symmetric.
config.set_main_option("sqlalchemy.url", _url.replace("%", "%%"))

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting.

    Used to review a migration before it runs, which for a change to the audit
    table is the only responsible way to ship one.
    """
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            # SQLite cannot ALTER most things in place and batch mode rewrites
            # the table instead. Without it, a column change works on
            # PostgreSQL and silently fails on the default deployment.
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
