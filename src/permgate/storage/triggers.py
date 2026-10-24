"""The audit trail, enforced by the database rather than by convention.

``decisions`` is append-only, but not insert-only: answering a prompt legitimately
sets the answer columns. So the rule is narrower than "no UPDATE" -- it is "one
transition, unanswered to answered, and never a DELETE".

``models.py`` says this in a docstring, and ``DecisionRepository`` is the only
code that writes the table. Neither is a guarantee. A migration, a ``psql``
session, or a bug in a service can issue the UPDATE that rewrites what a person
decided, and nothing objects -- which is the failure mode that matters, because
the row left behind looks entirely normal.

Both backends can express the same rule, and that was checked rather than
assumed: the DDL below was run against SQLite and PostgreSQL 16 before it was
written here, including the case that decides the design -- that a cascading
delete from ``projects`` is refused too.
"""

from __future__ import annotations

from sqlalchemy import Connection, Engine, text

#: SQLite compares OLD and NEW column by column. The `WHEN NOT (...)` form means
#: "abort unless every one of these holds", so an UPDATE that touches a column
#: nobody listed would still be permitted -- hence the list includes every
#: immutable column that a rewrite could plausibly want to change.
_SQLITE_TRIGGERS = (
    """
    CREATE TRIGGER IF NOT EXISTS decisions_no_delete
    BEFORE DELETE ON decisions
    BEGIN
        SELECT RAISE(ABORT, 'decisions is append-only: DELETE refused');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS decisions_answer_only
    BEFORE UPDATE ON decisions
    WHEN NOT (
        OLD.answer IS NULL
        AND NEW.answer IS NOT NULL
        AND OLD.id IS NEW.id
        AND OLD.project_id IS NEW.project_id
        AND OLD.occurred_at IS NEW.occurred_at
        AND OLD.tool IS NEW.tool
        AND OLD.arguments IS NEW.arguments
        AND OLD.arguments_redacted IS NEW.arguments_redacted
        AND OLD.arguments_digest IS NEW.arguments_digest
        AND OLD.verdict IS NEW.verdict
        AND OLD.rule IS NEW.rule
        AND OLD.reason IS NEW.reason
        AND OLD.scope IS NEW.scope
        AND OLD.run_mode IS NEW.run_mode
        AND OLD.latency_us IS NEW.latency_us
        AND OLD.actor IS NEW.actor
        AND OLD.request_id IS NEW.request_id
        AND OLD.answered_at IS NULL
        AND NEW.answered_at IS NOT NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'decisions is append-only: only the answer may be set, once');
    END
    """,
)

_POSTGRES_FUNCTION = """
CREATE OR REPLACE FUNCTION decisions_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'decisions is append-only: DELETE refused';
    END IF;
    IF OLD.answer IS NOT NULL OR NEW.answer IS NULL THEN
        RAISE EXCEPTION 'decisions is append-only: only the answer may be set, once';
    END IF;
    IF OLD.verdict IS DISTINCT FROM NEW.verdict
       OR OLD.rule IS DISTINCT FROM NEW.rule
       OR OLD.tool IS DISTINCT FROM NEW.tool
       OR OLD.project_id IS DISTINCT FROM NEW.project_id
       OR OLD.occurred_at IS DISTINCT FROM NEW.occurred_at
       OR OLD.arguments IS DISTINCT FROM NEW.arguments
       OR OLD.arguments_redacted IS DISTINCT FROM NEW.arguments_redacted
       OR OLD.arguments_digest IS DISTINCT FROM NEW.arguments_digest
       OR OLD.reason IS DISTINCT FROM NEW.reason
       OR OLD.scope IS DISTINCT FROM NEW.scope
       OR OLD.run_mode IS DISTINCT FROM NEW.run_mode
       OR OLD.latency_us IS DISTINCT FROM NEW.latency_us
       OR OLD.actor IS DISTINCT FROM NEW.actor
       OR OLD.request_id IS DISTINCT FROM NEW.request_id
    THEN
        RAISE EXCEPTION 'decisions is append-only: immutable column changed';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
"""

_POSTGRES_TRIGGER = """
CREATE TRIGGER decisions_append_only_trigger
BEFORE UPDATE OR DELETE ON decisions
FOR EACH ROW EXECUTE FUNCTION decisions_append_only()
"""


def statements_for(dialect: str) -> tuple[str, ...]:
    """The DDL for one backend, or a refusal.

    A backend with no definition raises instead of returning nothing: a database
    that quietly receives no trigger would look protected and not be, which is
    the one outcome worse than not claiming the guarantee at all.
    """
    if dialect == "sqlite":
        return _SQLITE_TRIGGERS
    if dialect == "postgresql":
        return (_POSTGRES_FUNCTION, _POSTGRES_TRIGGER)
    raise RuntimeError(
        f"no append-only trigger is defined for {dialect!r}. The audit trail's "
        "guarantee is implemented for SQLite and PostgreSQL; adding a backend "
        "means defining one here, not silently skipping it."
    )


def create_append_only_triggers(connection: Connection) -> None:
    """Install the triggers on an open connection, idempotently.

    Takes a connection rather than an engine because callers differ: the service
    has an engine and wants a transaction, while a migration has a connection
    and must not start its own. Both call this, so the two paths that create a
    schema cannot drift -- and the drift would be invisible, because a missing
    trigger looks exactly like a table nobody ever wrote to.
    """
    dialect = connection.dialect.name
    if dialect == "postgresql":
        # Replaced rather than skipped, so an edit to the function body reaches
        # a database that already has an older one.
        connection.execute(
            text("DROP TRIGGER IF EXISTS decisions_append_only_trigger ON decisions")
        )
    for statement in statements_for(dialect):
        connection.execute(text(statement))


def install_append_only_triggers(engine: Engine) -> None:
    """Install the triggers, in their own transaction."""
    with engine.begin() as connection:
        create_append_only_triggers(connection)
