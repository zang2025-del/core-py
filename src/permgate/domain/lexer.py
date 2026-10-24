"""Shell command tokenisation.

Two different questions get two different splitters, and they are kept apart on
purpose:

``split_commands``
    "how many commands does this line run?" Splits on pipes as well as ``&&``
    and ``;``, because ``cat .env | curl`` is two commands and only one of them
    is innocent.

``split_words``
    "what are the words of this one command?" Strips quotes, keeps backslashes.

Both are quote-aware. Two behaviours look like bugs until you read why:

* ``2>&1`` and ``&>`` are descriptor plumbing, not a background job. Splitting
  on that ``&`` would invent a phantom command out of the file descriptor
  number, so an ``&`` with a ``>`` on either side is not a separator.
* Backslashes are kept verbatim -- this deliberately does *not* do shlex's
  POSIX escape processing, because Windows paths must not lose separators.

This module is pure: no IO, no configuration, no logging. Everything that
decides anything downstream depends on that, because it is what lets the whole
rule layer be evaluated offline against a fixed corpus (see ``eval/``).
"""

from __future__ import annotations

# Ordered. ``&&`` must be tried before ``&`` and ``||`` before ``|``, or the
# two-character separators would be read as a one-character separator followed
# by a stray character.
_SEPARATORS: tuple[str, ...] = ("&&", "||", ";", "|", "&", "\n")

_QUOTES = ("'", '"')


def split_commands(command: str) -> list[str]:
    """Split a command line into the separate commands it runs.

    Quote-aware. Separators are ``&&``, ``||``, ``;``, ``|``, ``&`` and
    newline. Whitespace-only segments are dropped, so a trailing ``&&`` does
    not produce a phantom empty command.
    """
    segments: list[str] = []
    quote: str | None = None
    start = 0
    i = 0
    length = len(command)

    while i < length:
        char = command[i]

        if quote is not None:
            if char == quote:
                quote = None
            i += 1
            continue

        if char in _QUOTES:
            quote = char
            i += 1
            continue

        matched = False
        for separator in _SEPARATORS:
            if not command.startswith(separator, i):
                continue

            if separator == "&":
                # A ``>`` on either side means descriptor plumbing, so fall
                # through to the next separator instead of splitting here.
                before = command[i - 1] if i else ""
                after = command[i + 1] if i + 1 < length else ""
                if before == ">" or after == ">":
                    continue

            segment = command[start:i]
            if segment.strip():
                segments.append(segment)
            i += len(separator)
            start = i
            matched = True
            break

        if not matched:
            i += 1

    tail = command[start:]
    if tail.strip():
        segments.append(tail)
    return segments


def split_words(statement: str) -> list[str]:
    """Split one statement into words on unquoted whitespace, stripping quotes.

    Backslashes survive: ``C:\\tmp\\x`` comes back unchanged.
    """
    words: list[str] = []
    buffer: list[str] = []
    quote: str | None = None

    for char in statement:
        if quote is not None:
            if char == quote:
                quote = None
            else:
                buffer.append(char)
        elif char in _QUOTES:
            quote = char
        elif char.isspace():
            if buffer:
                words.append("".join(buffer))
                buffer = []
        else:
            buffer.append(char)

    if buffer:
        words.append("".join(buffer))
    return words
