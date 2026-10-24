"""Deciding what must not be written down.

An audit row is not just read by the person who caused it. It is read by an
operator debugging an incident, copied into a backup, restored into staging, and
included in an export somebody forgot about. Arguments are the one column that
can hold a credential, and a token in a table outlives the reason it was needed.

So the row keeps the digest and drops the arguments when the call looks like it
touched one. The digest is enough to prove *which* call it was -- that is what it
was already for -- and ``arguments_redacted`` records that a decision was made
rather than leaving a NULL that reads as "storage was off".

**The rule is the decision layer's own.** ``SENSITIVE_PATH`` already decides when
a command line reaches for a credential; reusing it here means the two cannot
disagree, and a future entry added to that table protects the audit trail the
same day it starts protecting the decision.

**What this does not catch**, because a boundary nobody wrote down is one people
assume is not there:

*   Inline secrets that never look like a path -- ``--password=hunter2``,
    ``Authorization: Bearer ...``, a bare base64 blob. The pattern recognises
    credential *paths* such as ``.ssh``, ``id_rsa`` and ``*.pem``; it was written
    for that and extending it into a general secret detector is a much larger
    job with a much worse false-positive rate.
*   Files whose *contents* are secret, when the command does not name the file.
    ``cat notes.txt`` where ``notes.txt`` is a private key is not detectable from
    the command line, and no lexical rule will make it so.
*   Anything arriving as a non-string that stringifies into a credential shape.
    Values are stringified first, so this is a gap in principle; in practice tool
    arguments are strings and JSON scalars.

An operator who cannot accept those gaps turns ``audit_store_arguments`` off
entirely and keeps digests for every call, which is the strictly safer setting.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Any

from ..domain.rules import CREDENTIAL_NAMES, CREDENTIAL_SUFFIXES, SENSITIVE_EXEMPT

# Looser than ``SENSITIVE_PATH``, deliberately, and the difference is the reason
# this is not just an import of it.
#
# The decision layer answers "is this command line safe to run by itself?", so it
# wants a credential *path* -- ``.env`` with something after it that looks like a
# continuation, ``server.pem`` at the end of a filename. Redaction answers "could
# this string be about a credential?", and ``cp .netrc /tmp/`` is the case that
# separates them: the name is followed by a space, the decision layer reads the
# command as a bounded copy and lets it through, and the argument sitting in the
# audit row is a credential being moved.
#
# So the names come from the decision layer -- one list, one answer to "what is a
# credential" -- and only the boundaries are relaxed here. A distinct list would
# be the thing that drifts, and it would drift silently.
_REDACT_PATTERN = re.compile(
    rf"(^|[\s/\\~=])({CREDENTIAL_NAMES})(?=[\s/\\]|$)"
    rf"|[\w.-]+\.({CREDENTIAL_SUFFIXES})(?=[\s/\\]|$)",
    re.IGNORECASE,
)


def _strings(value: Any) -> Iterator[str]:
    """Every string a value contains, deepest first.

    Recursive because tool arguments nest: ``{"env": {"TOKEN": "..."}}`` and
    ``{"files": ["a.pem"]}`` both hide their payload one level down, and a check
    that only looked at the top level would pass both.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _strings(item)
    else:
        yield str(value)


def arguments_are_sensitive(arguments: Mapping[str, Any]) -> bool:
    """Whether these arguments reach for a credential.

    Deliberately conservative in one direction only: a false positive costs a
    row whose arguments are not shown, a false negative costs a secret in a
    database. So a hit anywhere wins, and the exemption is checked first because
    ``cat .env.example`` is documentation rather than a leak.
    """
    for text in _strings(arguments):
        if SENSITIVE_EXEMPT.search(text):
            continue
        if _REDACT_PATTERN.search(text):
            return True
    return False


def redact_arguments(
    arguments: Mapping[str, Any], arguments_json: str | None
) -> tuple[str | None, bool]:
    """The arguments to store, and whether they were withheld.

    Returns ``(None, True)`` when the call looked like it touched a credential,
    otherwise ``(arguments_json, False)`` unchanged -- including when
    ``arguments_json`` is already ``None`` because the operator turned raw
    storage off, which is a different reason to have nothing and stays
    distinguishable in the row.
    """
    if arguments_are_sensitive(arguments):
        return None, True
    return arguments_json, False
