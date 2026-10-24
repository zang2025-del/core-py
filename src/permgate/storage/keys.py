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
import re
from pathlib import Path

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
