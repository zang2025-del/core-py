"""The port matches the reference implementation, verdict for verdict.

``permgate.domain.bash_policy`` is a port of a Python classifier that had four
rounds of measured hardening behind it. Rewriting it is only safe if something
checks the rewrite against the original, and that check has to keep working
after the original is no longer on the machine.

So the reference verdicts were frozen once into ``tests/fixtures/conformance.tsv``
(see ``tools/generate_conformance_fixture.py``) and are replayed here on every
run. 119 commands x four outputs -- blocklist reason, allowlist reason,
execution-gate reason, command scope -- all compared for exact equality,
including the *absence* of a match.

This is the test that turns "I ported it" into "I ported it and can prove it".
It is also the tripwire for rule changes: when a change to ``rules.py`` moves a
verdict, this fails and names the command, so the change becomes a decision
instead of a silent drift.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from permgate.domain import bash_policy

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "conformance.tsv"


def _unescape(cell: str) -> str | None:
    """Inverse of the generator's ``_cell``. Empty means ``None``."""
    if cell == "":
        return None
    out: list[str] = []
    i = 0
    while i < len(cell):
        if cell[i] == "\\" and i + 1 < len(cell):
            nxt = cell[i + 1]
            out.append({"\\": "\\", "t": "\t", "n": "\n"}.get(nxt, nxt))
            i += 2
        else:
            out.append(cell[i])
            i += 1
    return "".join(out)


def _load() -> list[tuple[str, str | None, str | None, str | None, str | None]]:
    rows = []
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        command, blocklist, allowlist, hard_block, scope = line.split("\t")
        rows.append(
            (
                _unescape(command) or "",
                _unescape(blocklist),
                _unescape(allowlist),
                _unescape(hard_block),
                _unescape(scope),
            )
        )
    return rows


CASES = _load()
IDS = [f"{index:03d}:{row[0][:48]!r}" for index, row in enumerate(CASES)]


def test_fixture_is_not_empty() -> None:
    """A conformance suite that silently loads zero rows would pass forever."""
    assert len(CASES) >= 100, f"fixture looks truncated: {len(CASES)} rows"


@pytest.mark.parametrize(
    ("command", "blocklist", "allowlist", "hard_block", "scope"), CASES, ids=IDS
)
def test_blocklist_matches_reference(
    command: str,
    blocklist: str | None,
    allowlist: str | None,
    hard_block: str | None,
    scope: str | None,
) -> None:
    assert bash_policy.check_dangerous(command) == blocklist


@pytest.mark.parametrize(
    ("command", "blocklist", "allowlist", "hard_block", "scope"), CASES, ids=IDS
)
def test_allowlist_matches_reference(
    command: str,
    blocklist: str | None,
    allowlist: str | None,
    hard_block: str | None,
    scope: str | None,
) -> None:
    assert bash_policy.classify_bash_command(command) == allowlist


@pytest.mark.parametrize(
    ("command", "blocklist", "allowlist", "hard_block", "scope"), CASES, ids=IDS
)
def test_execution_gate_matches_reference(
    command: str,
    blocklist: str | None,
    allowlist: str | None,
    hard_block: str | None,
    scope: str | None,
) -> None:
    assert bash_policy.execution_block(command) == hard_block


@pytest.mark.parametrize(
    ("command", "blocklist", "allowlist", "hard_block", "scope"), CASES, ids=IDS
)
def test_scope_matches_reference(
    command: str,
    blocklist: str | None,
    allowlist: str | None,
    hard_block: str | None,
    scope: str | None,
) -> None:
    assert bash_policy.command_scope("bash", {"command": command}) == scope
