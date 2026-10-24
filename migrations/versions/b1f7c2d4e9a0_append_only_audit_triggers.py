"""Make the audit trail append-only in the database, not only in the service.

`models.py` has called `decisions` append-only since the first revision, and it
was true of the code -- `DecisionRepository` issues no UPDATE against the table
except the answer transition, and no DELETE at all. It was not true of the
database. A migration, an operator with `psql`, or a future bug could rewrite the
verdict on a recorded decision and leave a row that looks entirely normal.

Three things this revision settles, each of which was measured on both backends
before it was written:

* **DELETE is refused**, including the cascade from `projects`. Deleting a
  workspace no longer quietly erases its audit trail; the audit trail wins, and
  the delete fails. That is the intended precedence -- an audit table that can be
  emptied by deleting its parent is not an audit table.
* **UPDATE is refused except the answer transition**, unanswered to answered,
  once. Rewriting an answer, a verdict or the recorded arguments all abort.
* **The rule is identical on SQLite and PostgreSQL**, which is why it is a
  trigger rather than an application check: the service is not the only thing
  that can write to a database.

Revision ID: b1f7c2d4e9a0
Revises: 9a79219fd73c
Create Date: 2026-10-24 16:05:12.884210

"""

from collections.abc import Sequence

from alembic import op

from permgate.storage.triggers import statements_for

# revision identifiers, used by Alembic.
revision: str = "b1f7c2d4e9a0"
down_revision: str | Sequence[str] | None = "9a79219fd73c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS decisions_append_only_trigger ON decisions")
    for statement in statements_for(dialect):
        op.execute(statement)


def downgrade() -> None:
    """Downgrade schema.

    Dropping the trigger is the whole revert: the rows were never changed, so
    there is no data to undo.
    """
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS decisions_append_only_trigger ON decisions")
        op.execute("DROP FUNCTION IF EXISTS decisions_append_only()")
        return
    op.execute("DROP TRIGGER IF EXISTS decisions_answer_only")
    op.execute("DROP TRIGGER IF EXISTS decisions_no_delete")
