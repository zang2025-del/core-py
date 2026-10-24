"""Record that arguments were withheld, rather than storing them as a bare NULL.

The audit row keeps a digest of every call already, so a row whose arguments are
missing still proves *which* call it was. What it could not say was *why* the
column is empty, and those are different facts: an operator turned raw storage
off for the whole deployment, or this one call looked like it touched a
credential and was withheld on its own. A reader deciding whether to go looking
for the arguments needs to know which.

So the reason becomes a column. ``server_default`` is set rather than the column
being left nullable because every existing row was written before redaction
existed, and none of them were redacted -- ``False`` is the accurate value for
them, not "unknown".

Revision ID: c4e8a1b6d2f3
Revises: b1f7c2d4e9a0
Create Date: 2026-10-24 17:22:41.603915

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from permgate.storage.triggers import create_append_only_triggers

# revision identifiers, used by Alembic.
revision: str = "c4e8a1b6d2f3"
down_revision: str | Sequence[str] | None = "b1f7c2d4e9a0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # `batch_alter_table` because SQLite cannot ALTER TABLE ADD COLUMN with a
    # non-constant default; the batch form rebuilds the table instead, which is
    # what the rest of these migrations do for the same reason.
    with op.batch_alter_table("decisions", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "arguments_redacted",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
    # The rebuild on SQLite is a CREATE/copy/DROP/rename, and a trigger belongs
    # to a table by name -- so the append-only triggers from b1f7 are gone by
    # here, and this migration would silently un-protect every existing
    # deployment. It would not be caught by the test suite either: every test
    # builds its schema through `create_schema`, which installs the triggers
    # after the tables, so the tests pass whether or not this line is here.
    create_append_only_triggers(op.get_bind())


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("decisions", schema=None) as batch_op:
        batch_op.drop_column("arguments_redacted")
    # Same rebuild, same reason as in `upgrade`.
    create_append_only_triggers(op.get_bind())
