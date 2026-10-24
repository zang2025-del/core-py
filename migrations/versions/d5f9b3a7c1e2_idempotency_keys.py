"""Store a caller's idempotency keys, and the responses they produced.

``POST /v1/decisions`` is not safe to retry on its own: a retried ``ASK`` raises
a second prompt for a call a human is already looking at, and a retried ``ALLOW``
puts two rows in the audit trail for one command. A retry is what any client does
after a timeout, and a timeout is when the service is most likely to be slow --
so "the client should not retry" is not a control, and the retry has to be made
harmless instead.

The response is stored in this table rather than reconstructed from
``decisions``, so a replay works on a deployment that has turned audit storage
off. That makes this a response cache, not a second audit trail, and the
distinction is load-bearing: a replay writes nothing to ``decisions``, so the
trail still holds one row per command that actually ran.

Revision ID: d5f9b3a7c1e2
Revises: c4e8a1b6d2f3
Create Date: 2026-10-24 18:05:12.441902

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d5f9b3a7c1e2"
down_revision: str | Sequence[str] | None = "c4e8a1b6d2f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "idempotency_keys",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("client", sa.String(length=64), nullable=False),
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("response", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        # The constraint, not the application, decides what a duplicate is --
        # the same reasoning as ``grants``. Two requests that arrive together
        # both see nothing and both insert, and the database has to pick the
        # winner or a retried call lands twice.
        sa.UniqueConstraint("client", "key", name="uq_idempotency_client_key"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("idempotency_keys")
