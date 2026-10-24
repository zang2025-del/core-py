"""Bash-specific risk classification and command scoping.

Two things live here, and they answer different questions:

``classify_bash_command``
    *Can we vouch for this command?* Returns ``None`` when yes, or a
    human-readable reason when no. A reason is **not an accusation** -- it is
    the honest statement that we cannot vouch for it, which is exactly when a
    person should be the one to decide.

``command_scope``
    *What command family does this belong to?* Returns the pattern a **narrow**
    grant would name: ``git clean -fd``, ``git push --force``, ``git push``.

The second is what makes an unattended run configurable at all. A pipeline needs
``pip install -r requirements.txt`` to work with nobody watching and does not
need ``terraform destroy`` to, and while a grant could only name a *tool* there
was no way to say so.

Pure module: no IO, no config, no logging.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .lexer import split_commands, split_words
from .rules import (
    BOUNDED_MUTATORS,
    DANGEROUS_PATTERNS,
    GIT_LISTING_VERBS,
    GIT_MUTATING_FLAGS,
    GIT_VALUE_FLAGS,
    NEVER_SAFE,
    REDIRECTION_OK,
    REGENERABLE,
    SAFE_GIT_VERBS,
    SAFE_PROGRAMS,
    SAFE_PY_MODULES,
    SENSITIVE_EXEMPT,
    SENSITIVE_PATH,
    SHELL_EXPANSION,
    TEMP_ROOTS,
    WINDOWS_ABSOLUTE,
)

# --------------------------------------------------------------------------
# Layer 2: the blocklist
# --------------------------------------------------------------------------


def check_dangerous(command: str) -> str | None:
    """Return a reason if the command matches the blocklist, else ``None``."""
    for pattern, reason in DANGEROUS_PATTERNS:
        if pattern.search(command):
            return reason
    return None


def execution_block(command: str) -> str | None:
    """The last-resort stop, applied where the command actually runs.

    Two conditions, both required: the command is **not** one the allowlist can
    vouch for, **and** the pattern list recognizes it as unrecoverable. The
    first condition is what keeps this from being a false-positive machine --
    ``rm -rf ./build`` is vouched for, so it runs, even though the pattern list
    would have flagged it.

    Everything the allowlist merely *declines to vouch for* -- ``pip install``,
    ``docker ps``, ``git commit`` -- is deliberately not blocked here. Those go
    to the user through the consent layer, and a user who says yes should get
    the command they asked for. A hard stop that overrides an explicit yes is
    the silent-veto behaviour this project set out to remove.
    """
    if classify_bash_command(command) is None:
        return None
    return check_dangerous(command)


# --------------------------------------------------------------------------
# Layer 1: the allowlist
# --------------------------------------------------------------------------


def _in_temp_root(posix_path: str) -> bool:
    """True if the path is strictly *inside* a temp directory, not the directory.

    ``rm -rf /tmp/scratch`` is bounded. ``rm -rf /tmp`` is not -- the directory
    itself is not scratch space.
    """
    return any(posix_path.startswith(root) and len(posix_path) > len(root) for root in TEMP_ROOTS)


def _is_regenerable(target: str) -> bool:
    """True if the target looks like build output rather than source."""
    name = target.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return name in REGENERABLE or name.endswith(".egg-info")


def _is_recursive(rest: list[str]) -> bool:
    """True if the flags ask for a recursive delete."""
    for word in rest:
        if word == "--recursive":
            return True
        if word.startswith("-") and not word.startswith("--") and ("r" in word or "R" in word):
            return True
    return False


def _bounded_mutation_risk(program: str, rest: list[str]) -> str | None:
    """``None`` if every path this call touches stays inside the project."""
    targets = [word for word in rest if not word.startswith("-")]
    if not targets:
        return f"`{program}` with no path argument"

    recursive = _is_recursive(rest)
    for target in targets:
        if SHELL_EXPANSION.search(target):
            return f"`{program}` target expands at runtime ({target})"

        posix = target.replace("\\", "/")
        # ``..`` is checked before the temp allowance, so ``/tmp/../etc`` cannot
        # climb out through a door that was opened for ``/tmp/scratch``.
        if ".." in posix.split("/"):
            return f"`{program}` reaches outside the project ({target})"
        if _in_temp_root(posix):
            continue
        if target.startswith(("/", "~", "\\")) or WINDOWS_ABSOLUTE.match(target):
            return f"`{program}` reaches outside the project ({target})"

        # A recursive delete is only routine when the target is build output.
        # ``chmod`` is exempt: it changes permissions, it does not destroy data.
        if recursive and program in ("rm", "rmdir") and not _is_regenerable(target):
            return f"`{program} -r {target}` may not be regenerable"
    return None


def _git_verb_index(rest: list[str]) -> int:
    """Index of the git subcommand in ``rest``, or -1. Skips global flags."""
    i = 0
    while i < len(rest):
        word = rest[i]
        if word in GIT_VALUE_FLAGS:
            i += 2
            continue
        if word.startswith("-"):
            i += 1
            continue
        return i
    return -1


def _git_listing_risk(verb: str, tail: list[str]) -> str | None:
    """``None`` if a listing verb is being used to list, else why it is not.

    ``git branch`` and ``git branch -D main`` share a verb and nothing else.
    What separates them is whether the call names a ref or passes a flag that
    changes one, so that is what this looks for.
    """
    # ``-l`` is ``--list`` for ``git tag`` and ``git config``, but
    # ``--create-reflog`` for ``git branch``, and creating a reflog writes. The
    # long form is unambiguous everywhere; the short form only means "list" for
    # two verbs.
    lists = "--list" in tail or (verb in ("tag", "config") and "-l" in tail)

    for word in tail:
        if word in GIT_MUTATING_FLAGS or (word == "-l" and not lists):
            return f"`git {verb} {word}` writes"

    if lists:
        return None

    named = [word for word in tail if not word.startswith("-")]
    if not named:
        return None  # flag-only: `git branch -a`, `git remote -v`
    if verb == "config":
        # one positional is a lookup (`git config user.email`), two is a write
        return "`git config <key> <value>` writes config" if len(named) > 1 else None
    return f"`git {verb} {named[0]}` is not read-only"


def _segment_risk(segment: str) -> str | None:
    """``None`` if this one command is recognized safe, else why it is not."""
    if ">" in REDIRECTION_OK.sub("", segment):
        return "output redirection writes a file"

    hit = SENSITIVE_PATH.search(segment)
    if hit and not SENSITIVE_EXEMPT.search(segment):
        shown = hit.group(0).strip("/\\~")
        return f"touches a credential-shaped path ({shown})"

    words = split_words(segment)

    # Skip leading ``FOO=bar`` assignments: they set the environment for
    # whatever runs next, they are not the program.
    i = 0
    while i < len(words) and "=" in words[i] and not words[i].startswith("-"):
        i += 1
    if i >= len(words):
        return None  # assignments only, nothing runs

    program = words[i].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    rest = words[i + 1 :]

    if program in BOUNDED_MUTATORS:
        return _bounded_mutation_risk(program, rest)
    if program in NEVER_SAFE:
        return f"`{program}` is never auto-approved"
    if program not in SAFE_PROGRAMS:
        return f"`{program}` is not on the known-safe list"

    if program == "git":
        index = _git_verb_index(rest)
        if index < 0:
            return "bare `git` with no subcommand"
        verb = rest[index]
        if verb not in SAFE_GIT_VERBS:
            return f"`git {verb}` is not a read-only git command"
        if verb in GIT_LISTING_VERBS:
            return _git_listing_risk(verb, rest[index + 1 :])

    if program == "find" and any(flag in ("-delete", "-exec", "-execdir", "-ok") for flag in rest):
        return "`find` with -delete/-exec modifies the filesystem"

    if program in ("python", "python3"):
        if "-c" in rest:
            return "`python -c` runs arbitrary inline code"
        if "-m" in rest:
            index = rest.index("-m") + 1
            module = rest[index] if index < len(rest) else ""
            if module.split(".")[0] not in SAFE_PY_MODULES:
                return f"`python -m {module or '?'}` is not a known-safe module"

    return None


def classify_bash_command(command: str) -> str | None:
    """``None`` if every command on the line is recognized safe, else the reason.

    The allowlist has the final say on "safe", because it is the only one of the
    two layers that reads the *arguments*: ``rm -rf ./build`` and ``rm -rf /``
    are the same string as far as the blocklist regex is concerned, and it
    rejects both. Letting the regex preempt would mean the allowlist never gets
    to make the distinction it exists to make.

    Once a command is *not* vouched for, the blocklist's wording wins when it
    has one -- "recursive delete on home/root" tells the user more than
    "``rm`` reaches outside the project".
    """
    if not command.strip():
        return None  # nothing runs, so there is nothing to ask about

    reason = None
    for segment in split_commands(command):
        reason = _segment_risk(segment)
        if reason:
            break

    if reason is None:
        return None
    return check_dangerous(command) or reason


def risk_reason(tool: str, arguments: Mapping[str, Any]) -> str | None:
    """Consent-layer risk signal for one tool call.

    ``None`` when the call is either not a bash call or is vouched for.
    """
    if tool != "bash":
        return None
    return classify_bash_command(arguments.get("command") or "")


# --------------------------------------------------------------------------
# Command scoping
# --------------------------------------------------------------------------


def command_scope(tool: str, arguments: Mapping[str, Any]) -> str | None:
    """The command pattern a grant can be narrowed to, or ``None``.

    The pattern is **the program, the verb it runs, and the flags it passes**;
    positional arguments are what vary between two runs of the same intent.
    That is the coarsest shape that still separates the cases that matter::

        git clean -fd          ->  git clean -fd
        git push --force ...   ->  git push --force
        git push origin main   ->  git push

    A program on its own is too coarse to be the unit of approval: granting
    ``git`` hands over the force-push along with the cleanup, and the two share
    nothing but a name. Measured, that costs exactly one dangerous command --
    ``git push --force`` slips in behind a ``git`` grant.

    A chain (``a && b``) is several patterns at once and so has none to name:
    ``None``, and the call falls back to the tool-level rules.
    """
    if tool != "bash":
        return None

    segments = split_commands(arguments.get("command") or "")
    if len(segments) != 1:
        return None

    words = split_words(segments[0])
    i = 0
    while i < len(words) and "=" in words[i] and not words[i].startswith("-"):
        i += 1  # skip leading `FOO=bar` assignments
    if i >= len(words):
        return None

    program = words[i].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if not program:
        return None

    parts = [program]
    flags: list[str] = []
    for word in words[i + 1 :]:
        if word.startswith("-"):
            flags.append(word)
        elif len(parts) == 1:
            parts.append(word)  # the verb, once
    parts.extend(sorted(set(flags)))
    return " ".join(parts)
