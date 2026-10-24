"""Engine and session construction.

Kept apart from the models so the models stay importable without pulling in a
driver, and apart from the repositories so that swapping SQLite for PostgreSQL
is a URL change rather than a code change.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings


def create_db_engine(settings: Settings) -> Engine:
    """Build the engine for ``settings.database_url``.

    Two settings are applied only where they mean something, because applying
    them blindly is how a service ends up with a pool argument that SQLite
    silently ignores and a reader assumes is doing work.
    """
    url = settings.database_url
    kwargs: dict[str, object] = {"echo": settings.db_echo, "future": True}

    if url.startswith("sqlite"):
        # SQLite refuses a connection shared across threads unless told
        # otherwise, and the server is threaded. ``check_same_thread=False`` is
        # safe here only because SQLAlchemy's pool hands one connection to one
        # thread at a time -- it is not a licence to pass sessions around.
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs["pool_size"] = settings.db_pool_size
        kwargs["max_overflow"] = settings.db_max_overflow
        kwargs["pool_pre_ping"] = True  # a connection idle past a proxy timeout is dead

    engine = create_engine(url, **kwargs)

    if url.startswith("sqlite"):
        _tune_sqlite(engine)
    return engine


def _tune_sqlite(engine: Engine) -> None:
    """Pragmas that make SQLite behave like a database rather than a file.

    ``WAL`` is the one that matters: without it a writer blocks every reader,
    and the audit table makes the service write on *every* request. ``busy_timeout``
    converts "database is locked" from an exception into a wait, which is the
    right trade for a write that takes microseconds.
    """

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection, _record):  # type: ignore[no-untyped-def]
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
        finally:
            cursor.close()


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """One transaction, committed on success and rolled back on any exception.

    The service uses this everywhere. Getting the boundary wrong is the easiest
    way to end up with a grant that exists and no audit row explaining it, which
    is precisely the state an audit trail must never be in.
    """
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
