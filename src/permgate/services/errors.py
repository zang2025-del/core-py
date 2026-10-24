"""Service-layer errors.

They live here rather than in ``api/`` so the service layer can be used without
FastAPI, and they carry enough structure that the API layer maps them to status
codes mechanically instead of by pattern-matching on message text.
"""

from __future__ import annotations

from typing import ClassVar


class ServiceError(Exception):
    """Base class. ``status_code`` is the HTTP status the API should use."""

    status_code = 500
    code = "internal_error"
    #: Extra response headers this failure owes the client. On the base class
    #: rather than special-cased in the handler, so the next error that needs
    #: one does not have to be taught to the API layer. A class variable, not
    #: per-instance state: a failure is a value, not an object with mutation.
    headers: ClassVar[dict[str, str] | None] = None

    def __init__(self, message: str, *, details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ProjectNotFound(ServiceError):
    status_code = 404
    code = "project_not_found"


class DecisionNotFound(ServiceError):
    status_code = 404
    code = "decision_not_found"


class AlreadyAnswered(ServiceError):
    """The prompt was already answered. A replay must not rewrite history."""

    status_code = 409
    code = "already_answered"


class UnknownTool(ServiceError):
    status_code = 422
    code = "unknown_tool"


class ModeNotAllowed(ServiceError):
    """The request asked for a run mode this deployment does not serve.

    Raised at the edge rather than deep in the engine so that a bypass request
    is refused before anything is loaded, decided or written.
    """

    status_code = 403
    code = "mode_not_allowed"


class InvalidAnswer(ServiceError):
    status_code = 422
    code = "invalid_answer"


class AuthenticationRequired(ServiceError):
    """No usable credential: the caller is not identified.

    401, and the API layer attaches ``WWW-Authenticate: Bearer``. "Was one sent
    at all" is safe to distinguish -- the caller already knows that -- but a
    token that was rejected is never narrowed further than "not recognised", so
    the response cannot be used to search the token space.
    """

    status_code = 401
    code = "authentication_required"
    headers: ClassVar[dict[str, str] | None] = {"WWW-Authenticate": "Bearer"}


class RootNotAllowed(ServiceError):
    """The caller is identified, but may not name that workspace.

    403 rather than 404: the client is who it says it is, and answering "no such
    workspace" would turn an authorisation decision into a guessing game. The
    resolved root is echoed in ``details`` because a 403 here is usually a
    misconfigured allowlist, and a debugging aid that omits the value that was
    actually checked sends people back to the logs.
    """

    status_code = 403
    code = "root_not_allowed"
