"""Service-layer errors.

They live here rather than in ``api/`` so the service layer can be used without
FastAPI, and they carry enough structure that the API layer maps them to status
codes mechanically instead of by pattern-matching on message text.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Base class. ``status_code`` is the HTTP status the API should use."""

    status_code = 500
    code = "internal_error"

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
