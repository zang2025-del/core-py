"""Who is calling, and which workspaces they may name.

Two questions, and they are deliberately separate:

**Authentication** -- is this caller who it says it is? A bearer token, matched
against a SHA-256 digest stored in ``clients``. Never against the token itself:
a database is backed up, replicated and restored into staging, and a table of
live credentials turns every one of those into a leak.

**Authorisation** -- may this caller name that workspace? The roots it may name
are rows in ``client_roots``. Without this half, a caller can send any
``project_root`` it likes, and the service's headline property -- grants are
isolated per project -- becomes true only of the paths an honest client chooses
to use.

Collapsing the two is the classic mistake and it runs both ways: treating a
valid token as permission to name any workspace, or refusing a caller that
merely named a root it was never hosted on. So a token that authenticates and a
root that is not on its list produce two different answers, ``401`` and ``403``,
because to the person debugging them they are two different problems.

**Why there is no credential cache.** ``storage/cache.py`` caches grant sets and
bounds the resulting multi-process staleness with a TTL. The same trick here
would be worse, not equal: caching a revoked token for fifteen seconds means a
credential that has been turned off still opens the door for fifteen seconds,
and the thing being cached is not a decision's *input* but its *precondition*.
The lookup is one indexed row on a request that already does several, so it is
paid rather than cached, and the reason is written down here so that a later
optimisation has to argue with it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from fastapi import Request
from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings
from ..services.errors import AuthenticationRequired, RootNotAllowed
from ..storage.database import session_scope
from ..storage.keys import is_within, normalise_root
from ..storage.repositories import ClientRepository

BEARER_PREFIX = "bearer "


def token_digest(token: str) -> str:
    """SHA-256 hex digest of a bearer token.

    A plain digest rather than a password hash (bcrypt, argon2), and the
    difference is not laziness. Those functions are deliberately slow to make
    guessing a low-entropy *human-chosen* secret expensive. A bearer token here
    is generated at 256 bits and never typed by a person, so there is no
    dictionary to search and the only thing a slow hash would buy is latency on
    every authenticated request.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller and the workspaces it may name.

    ``unrestricted`` exists for exactly one configuration: a deployment with
    ``auth_required=False``. It is a field rather than a missing object so that
    "nobody is identified" is a value the code can be written against and
    counted, instead of an ``None`` that every call site has to remember to
    handle.
    """

    name: str
    roots: tuple[str, ...] = ()
    unrestricted: bool = False

    @classmethod
    def anonymous(cls) -> Principal:
        """The caller when authentication is switched off.

        Named rather than left blank: ``decisions.actor`` will read
        ``anonymous``, and an audit row that says who acted is worth more than
        one that says nobody did.
        """
        return cls(name="anonymous", unrestricted=True)

    def may_name(self, root: str) -> bool:
        return self.unrestricted or any(is_within(root, prefix) for prefix in self.roots)

    def authorise_root(self, project_root: str) -> str:
        """The resolved root, or ``RootNotAllowed``.

        Returns the **resolved** value and callers must use the return value,
        never the argument. Authorising one string and then operating on a
        different one is how a check becomes decorative: resolve, check, and
        hand forward the thing that was checked -- in that order.
        """
        resolved = normalise_root(project_root)
        if not self.may_name(resolved):
            raise RootNotAllowed(
                f"client {self.name!r} may not name this workspace",
                details={"project_root": resolved},
            )
        return resolved


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if header is None:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != BEARER_PREFIX.strip() or not value.strip():
        return None
    return value.strip()


def require_principal(request: Request) -> Principal:
    """FastAPI dependency: identify the caller or refuse the request.

    Health and readiness are excluded at the router, not by a branch here --
    a probe cannot present a credential, and a liveness check that fails when
    the database is unreachable would restart a process that is fine.
    """
    container = request.app.state.container
    settings: Settings = container.settings
    if not settings.auth_required:
        return Principal.anonymous()

    token = _bearer_token(request)
    if token is None:
        raise AuthenticationRequired("a bearer token is required")

    # A short transaction of its own, opened after the token is parsed: an
    # unauthenticated request never reaches the database at all.
    with session_scope(container.session_factory) as session:
        client = ClientRepository(session).find_active_by_token_hash(token_digest(token))
        if client is None:
            # One message for "no such token" and "revoked token". The caller
            # cannot act differently on the two, and telling them apart hands an
            # attacker a way to check whether a guessed token ever existed.
            raise AuthenticationRequired("the bearer token is not recognised")
        return Principal(name=client.name, roots=ClientRepository(session).roots_for(client.id))


def bootstrap_client(
    session_factory: sessionmaker[Session],
    *,
    name: str,
    token: str,
    roots: tuple[str, ...],
) -> bool:
    """Create or refresh a client from configuration. True if it was created.

    This is the way into a fresh deployment, which otherwise has a chicken-and-
    egg problem: every endpoint needs a credential and the only way to make one
    is an endpoint. It is deliberately the *only* self-service path, it comes
    from the environment rather than from a request, and re-running it is how a
    mistakenly revoked bootstrap client is brought back.
    """
    with session_scope(session_factory) as session:
        _, created = ClientRepository(session).upsert(
            name=name, token_hash=token_digest(token), roots=list(roots)
        )
        return created


def configure_clients(session_factory: sessionmaker[Session], settings: Settings) -> None:
    """Apply bootstrap settings, then refuse to serve without credentials.

    **Fail closed, at startup.** The alternative -- coming up with identity
    switched on but no client able to authenticate -- is a service that accepts
    every request until somebody notices, and noticing is not a control. A
    process that cannot be reached is a deploy that fails loudly; a process that
    answers everyone is a deploy that fails silently, which is the worse of the
    two and the one this project keeps arguing against.
    """
    if settings.auth_bootstrap_token:
        bootstrap_client(
            session_factory,
            name="bootstrap",
            token=settings.auth_bootstrap_token,
            roots=tuple(settings.auth_bootstrap_roots),
        )

    if not settings.auth_required:
        return

    with session_scope(session_factory) as session:
        active = ClientRepository(session).count_active()
    if active == 0:
        raise RuntimeError(
            "authentication is required but no client exists, so no request could "
            "ever succeed. Create one with --bootstrap-token, or set "
            "PERMGATE_AUTH_REQUIRED=false to run without authentication."
        )
