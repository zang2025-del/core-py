"""SQLAlchemy models.

Five tables, and the shape of each one is a decision worth stating.

``clients``
    Who is allowed to call the service, and ``client_roots`` -- which project
    roots each one may name. Without these two, the service answers "may this
    command run?" without ever asking who is asking, and ``project_root`` is
    whatever string the caller felt like sending: a client could name a
    colleague's workspace and inherit their grants. The gateway's whole subject
    is who may vouch for what, so it cannot leave its own caller unidentified.
    The token is stored as a digest, never as the secret itself, for the same
    reason a password is.

``projects``
    Grants are scoped to a project, so a project has to be a row rather than a
    string repeated on every grant. The row is keyed on the **resolved** project
    root, and the filename-safe form of it lives in ``storage/keys.py``.

``grants``
    The standing pre-approvals. ``scope`` is **NOT NULL with an empty-string
    default** rather than nullable, and that is not a style preference: SQLite,
    PostgreSQL and MySQL all treat NULLs as distinct in a UNIQUE index, so
    ``UNIQUE(project_id, tool, scope)`` with a nullable ``scope`` would happily
    accept two identical tool-level grants. Empty string means "no scope,
    tool-level" and makes the constraint do its job.

``decisions``
    The audit trail. **Append-only, and the database enforces it** -- not just
    the service. A trigger refuses every DELETE, including the one that arrives
    by cascade from ``projects``, and refuses every UPDATE except the single
    transition from unanswered to answered. Before that trigger existed the rule
    lived in a docstring and in the fact that one repository was the only writer;
    both are true statements about the code and neither is a constraint on the
    database. Every request writes exactly one row, including the ones that were
    allowed -- an audit log that only records refusals cannot answer "what did
    the agent actually run last Tuesday", which is the question people ask.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Client(Base):
    """One caller allowed to use the gateway.

    ``token_hash`` is a SHA-256 of the bearer token, never the token itself. A
    database is copied to a backup, read by an operator, and restored into a
    staging environment; a table of live credentials turns every one of those
    into a leak, and a digest cannot be replayed.

    ``revoked_at`` is a timestamp rather than a row deletion. Deleting the row
    would erase the fact that the token ever existed -- and an audit trail with
    a hole where a client used to be is worse than one that says "revoked on
    the 3rd".
    """

    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
        doc="Stable human label. This is what lands in ``decisions.actor``.",
    )
    token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
        doc="SHA-256 hex digest of the bearer token.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    roots: Mapped[list[ClientRoot]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )

    @property
    def active(self) -> bool:
        return self.revoked_at is None


class ClientRoot(Base):
    """One project root a client is allowed to name.

    A client with no rows here may name nothing: the allowlist is the grant, not
    the absence of a rule. That keeps "this token is valid" and "this token may
    touch your workspace" two separate questions, which they are -- the first
    is authentication and the second is authorisation, and collapsing them is
    how a leaked read-only token becomes a write.
    """

    __tablename__ = "client_roots"
    __table_args__ = (
        # Same reasoning as ``grants``: the constraint, not the application,
        # decides what a duplicate is.
        UniqueConstraint("client_id", "prefix", name="uq_client_root_prefix"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[int] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    prefix: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        doc="A normalised project root. Matching is component-wise, not a "
        "string prefix: see ``api/security.py`` for why /srv/app-2 must not "
        "match an allowlist entry of /srv/app.",
    )

    client: Mapped[Client] = relationship(back_populates="roots")


class Project(Base):
    """One workspace the gateway has seen a request for."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    root: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True, index=True)
    key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        doc="Filename-safe, collision-resistant key derived from the root.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    grants: Mapped[list[Grant]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Grant(Base):
    """A standing pre-approval, scoped to one project.

    Two shapes share this table, and the difference is the whole security model:

    * ``scope == ""`` -- tool-level. Broad, therefore **weak**: it covers
      unflagged calls only.
    * ``scope == "git push"`` -- narrowed to a command family. Narrow, therefore
      **strong**: it covers that family, flagged calls included.
    """

    __tablename__ = "grants"
    __table_args__ = (
        # The constraint that makes concurrent "always allow" clicks idempotent
        # instead of duplicating. See the module docstring on why scope is "".
        UniqueConstraint("project_id", "tool", "scope", name="uq_grant_project_tool_scope"),
        Index("ix_grant_project_tool", "project_id", "tool"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )

    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    granted_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    note: Mapped[str | None] = mapped_column(String(512), nullable=True)

    project: Mapped[Project] = relationship(back_populates="grants")

    @property
    def key(self) -> str:
        """``bash`` or ``bash:git push`` -- the form the engine compares against."""
        return self.tool if not self.scope else f"{self.tool}:{self.scope}"


class Decision(Base):
    """One evaluated tool call. Append-only.

    Every request lands here, allow or deny. The row is written inside the same
    transaction as the grant it may have created, so a crash cannot leave a
    grant with no record of who asked for it.

    Nothing can rewrite it afterwards. The answer columns are the one exception,
    and only from null to a value, once -- enforced by a database trigger rather
    than by this class or by the service that writes it.
    """

    __tablename__ = "decisions"
    __table_args__ = (
        Index("ix_decision_project_time", "project_id", "occurred_at"),
        Index("ix_decision_verdict_time", "verdict", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    arguments: Mapped[str | None] = mapped_column(
        Text, nullable=True, doc="JSON, or NULL when argument storage is off."
    )
    arguments_redacted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
        doc="True when the arguments were withheld because the call looked like "
        "it touched a credential. Distinguishes that from NULL-because-the-"
        "operator-turned-storage-off, which is a different reason to have "
        "nothing and a different thing to tell a reader.",
    )
    arguments_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="SHA-256 of the canonicalised arguments. Present even when the "
        "arguments themselves are not stored, so a row still proves which call it was.",
    )

    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    rule: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope: Mapped[str | None] = mapped_column(String(255), nullable=True)
    run_mode: Mapped[str] = mapped_column(String(16), nullable=False)

    latency_us: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # Set when a human answered the prompt this decision raised.
    answer: Mapped[str | None] = mapped_column(String(16), nullable=True)
    answered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    answer_actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    granted_key: Mapped[str | None] = mapped_column(
        String(255), nullable=True, doc="Grant recorded by the answer, if any."
    )


class SchemaVersion(Base):
    """Which migrations have run.

    Alembic keeps its own table, but the service also records a version it can
    read without invoking Alembic -- a process that starts against a database
    newer than itself has to refuse rather than guess.
    """

    __tablename__ = "schema_version"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
