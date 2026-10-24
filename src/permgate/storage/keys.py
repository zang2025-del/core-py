"""Project identity: which workspace a request belongs to.

The gateway has to answer "which project is this?" before it can answer
anything else, because grants are scoped to one. The rule is carried over
unchanged from the reference implementation, and it earns its keep twice:

1. **Walk up to the nearest project root**, rather than using the working
   directory. A run in ``proj/src/`` shares the grant made in ``proj/`` instead
   of minting a separate store for every directory the user happens to ``cd``
   into.
2. **Key on a digest of the resolved root**, so two projects that merely share a
   directory name (``~/work/api`` and ``~/scratch/api``) never collide. The
   readable slug is kept alongside because a store directory full of hex is a
   store directory nobody can audit by looking at it.

Sharing a grant across projects is the failure this prevents: approving ``bash``
in a scratch repository used to approve it in every repository on the machine.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path, PurePosixPath

#: Markers that identify a project root.
PROJECT_MARKERS: tuple[str, ...] = (
    ".git",
    "pyproject.toml",
    "package.json",
    "go.mod",
    "Cargo.toml",
)

_UNSAFE_IN_SLUG = re.compile(r"[^A-Za-z0-9._-]+")

DIGEST_LENGTH = 12
"""12 hex characters = 48 bits. Short enough to read in a filename, long enough
that a collision between two projects on one machine is not a thing that
happens. The full digest is not needed because the key only has to separate
sibling directories, not resist an adversary -- the root path is not secret."""


def normalise_root(path: str | Path) -> str:
    """Canonical form of a project root.

    Resolved, so ``proj`` and ``./proj/`` and ``proj/../proj`` are one project;
    forward slashes throughout, so a root recorded on Windows and the same root
    recorded from WSL do not become two.
    """
    return Path(path).expanduser().resolve().as_posix()


def find_project_root(start: str | Path) -> str:
    """Nearest ancestor of ``start`` (inclusive) that looks like a project root.

    Falls back to ``start`` itself when nothing matches, so a directory that is
    not inside any project still gets a stable identity of its own rather than
    an error.
    """
    current = Path(start).expanduser().resolve()
    for candidate in (current, *current.parents):
        if any((candidate / marker).exists() for marker in PROJECT_MARKERS):
            return candidate.as_posix()
    return current.as_posix()


def project_key(root: str | Path) -> str:
    """Filename-safe, collision-resistant key for a project root."""
    normalised = normalise_root(root)
    digest = hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:DIGEST_LENGTH]
    name = Path(normalised).name
    slug = _UNSAFE_IN_SLUG.sub("-", name).strip("-") or "project"
    return f"{slug}-{digest}"


def _same_component(left: str, right: str) -> bool:
    """Compare one path component, on the platform's own terms.

    ``os.path.normcase`` lower-cases on Windows and does nothing on POSIX, which
    is exactly right: ``C:/Users/me`` and ``c:/users/me`` are one directory on
    Windows and two on Linux. Comparing raw strings would let a Windows client
    through or lock it out depending on which case it happened to type. Applied
    per component because ``normcase`` also rewrites separators, and the
    splitting has already happened by the time it is called.
    """
    return os.path.normcase(left) == os.path.normcase(right)


def is_within(root: str | Path, prefix: str | Path) -> bool:
    """True if ``root`` is ``prefix`` or lives underneath it.

    **Component-wise, not a string prefix**, and that distinction is the whole
    reason this function exists. ``"/srv/app-2".startswith("/srv/app")`` is true,
    so a string comparison would let a caller allowed to name ``/srv/app`` --
    say, a contractor scoped to one repository -- name the directory next door
    and inherit whatever standing authority is there. Path containment is a
    question about directory components, so it is answered by comparing
    components.

    It lives here, beside :func:`normalise_root`, rather than in the API layer
    that first needed it: ``services/`` uses the same rule to decide which
    audit rows a caller may read, and a second copy of "is this the same
    workspace?" is exactly the kind of thing that drifts.
    """
    root_parts = PurePosixPath(normalise_root(root)).parts
    prefix_parts = PurePosixPath(normalise_root(prefix)).parts
    if len(root_parts) < len(prefix_parts):
        return False
    # The length check above makes the slice exactly as long as ``prefix_parts``;
    # ``strict=True`` asserts that instead of assuming it, so a future edit that
    # drops the check fails here rather than silently comparing fewer components.
    return all(
        _same_component(a, b)
        for a, b in zip(root_parts[: len(prefix_parts)], prefix_parts, strict=True)
    )
