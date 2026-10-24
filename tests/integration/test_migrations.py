"""The migrations and the models describe the same schema.

This is the test that catches the most common way a schema change goes wrong in
production: someone edits ``models.py``, the test suite passes against a
database built by ``create_all``, and the migration that real deployments run is
never updated. Everything works locally and the deploy fails -- or worse,
deploys and is missing a column.

``compare_metadata`` is Alembic's own diff, so this asserts against the tool
that would generate the migration rather than against a hand-written
expectation that could drift with it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from permgate.storage.models import Base

ROOT = Path(__file__).resolve().parent.parent.parent


def _alembic_config(url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    # The hook migrations/env.py reads. See the comment there.
    config.attributes["sqlalchemy_url"] = url
    return config


@pytest.fixture
def migrated_url(tmp_path) -> str:
    url = f"sqlite+pysqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    command.upgrade(_alembic_config(url), "head")
    return url


class TestMigrations:
    def test_upgrade_head_creates_every_table(self, migrated_url: str):
        engine = create_engine(migrated_url)
        try:
            tables = set(inspect(engine).get_table_names())
        finally:
            engine.dispose()
        assert {"projects", "grants", "decisions", "alembic_version"} <= tables

    def test_the_models_and_the_migrations_agree(self, migrated_url: str):
        """If this fails, someone changed a model without generating a
        migration. Run ``alembic revision --autogenerate``."""
        engine = create_engine(migrated_url)
        try:
            with engine.connect() as connection:
                context = MigrationContext.configure(
                    connection, opts={"compare_type": True, "render_as_batch": True}
                )
                diff = compare_metadata(context, Base.metadata)
        finally:
            engine.dispose()
        assert diff == [], f"models and migrations have diverged: {diff}"

    def test_the_grant_uniqueness_constraint_survives_the_migration(self, migrated_url: str):
        """The constraint the whole idempotency story rests on. A migration that
        silently drops it would still pass every other test in this suite,
        because the application-layer pre-check would keep hiding the race."""
        engine = create_engine(migrated_url)
        try:
            constraints = inspect(engine).get_unique_constraints("grants")
        finally:
            engine.dispose()
        names = {constraint["name"] for constraint in constraints}
        assert "uq_grant_project_tool_scope" in names

        columns = {constraint["name"]: constraint["column_names"] for constraint in constraints}
        assert columns["uq_grant_project_tool_scope"] == ["project_id", "tool", "scope"]

    def test_scope_is_not_nullable_in_the_migrated_schema(self, migrated_url: str):
        """Nullable `scope` would make that UNIQUE constraint do nothing for
        tool-level grants, on every database that treats NULLs as distinct."""
        engine = create_engine(migrated_url)
        try:
            columns = {column["name"]: column for column in inspect(engine).get_columns("grants")}
        finally:
            engine.dispose()
        assert columns["scope"]["nullable"] is False

    def test_downgrade_then_upgrade_round_trips(self, tmp_path):
        """A migration with no working downgrade is a migration you cannot back
        out of at 3am."""
        url = f"sqlite+pysqlite:///{(tmp_path / 'roundtrip.db').as_posix()}"
        config = _alembic_config(url)
        command.upgrade(config, "head")
        command.downgrade(config, "base")

        engine = create_engine(url)
        try:
            remaining = set(inspect(engine).get_table_names())
        finally:
            engine.dispose()
        assert not {"projects", "grants", "decisions"} & remaining

        command.upgrade(config, "head")
        engine = create_engine(url)
        try:
            rebuilt = set(inspect(engine).get_table_names())
        finally:
            engine.dispose()
        assert {"projects", "grants", "decisions"} <= rebuilt
