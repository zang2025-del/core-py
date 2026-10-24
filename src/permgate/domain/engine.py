"""The decision engine: pure policy evaluation.

``decide()`` is a function of its arguments and nothing else. It does not read
the database, the clock, the environment or a log. Everything it needs arrives
in the call, and everything it concludes leaves in the return value.

That is the single most consequential design choice in this service, and it is
worth naming the three things it buys:

1. **The rule layer can be evaluated offline.** ``eval/`` runs the whole
   classifier against a fixed corpus of 49 labelled commands and 11 real
   incidents with no server, no database and no network. Those measurements are
   what the security claims in ``docs/`` rest on, and they would not be
   reproducible if a decision needed a live grant store.
2. **The rule layer can be unit-tested exhaustively.** ~200 tests cover the
   ordering below, and they are fast enough to run on every save.
3. **The expensive part is obvious.** Because ``decide`` is pure, the only
   reason it can ever be slow is that its *inputs* were expensive to assemble.
   That places the whole performance budget on the grant lookup, which is
   exactly where the cache lives.

The ordering is the security model, so it is stated once, here, and the tests
pin each step:

    1. BYPASS short-circuits everything. It is the --dangerously-skip-permissions
       path and nothing else may select it.
    2. Read-only tools never reach a human. Asking about `read_file` trains
       people to approve without reading.
    3. A **scoped** grant covers the family it names, flagged calls included.
    4. A pre-approved scope (the CI list) does the same for unattended runs.
    5. A **tool-level** grant covers unflagged calls only.
    6. With nobody to ask, an unanswered ASK becomes a DENY.

Steps 3 and 5 are the asymmetry the whole project turns on: **a grant's
strength is set against its breadth.** The tool-level grant is broad, so it
stays weak and a flagged call still reaches the user. The scoped grant is
narrow, so it covers the family it names, flagged calls included. A weak narrow
grant would be useless -- the calls people want to stop being asked about are
exactly the flagged ones -- and a strong broad grant is the exposure this
project set out to remove.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .decision import Decision, Rule, RunMode, Verdict
from .policies import DEFAULT_REGISTRY, PolicyRegistry, ToolPolicy
from .rules import READ_ONLY_TOOLS


@dataclass(frozen=True, slots=True)
class Grant:
    """A standing pre-approval.

    Two shapes, and the difference is the point:

    ``Grant("bash")``
        Tool-level. Broad, therefore weak: it covers unflagged bash calls and
        nothing else.

    ``Grant("bash", "git push")``
        Scoped. Narrow, therefore strong: it covers every ``git push``,
        including ones the classifier flagged.
    """

    tool: str
    scope: str | None = None

    @property
    def key(self) -> str:
        """The string this grant is stored under."""
        return self.tool if self.scope is None else f"{self.tool}:{self.scope}"

    @property
    def is_scoped(self) -> bool:
        return self.scope is not None

    @classmethod
    def from_key(cls, key: str) -> Grant:
        """Parse a stored key back into a grant.

        Only the first colon splits, so a scope that itself contains one
        survives the round trip.
        """
        tool, separator, scope = key.partition(":")
        return cls(tool=tool, scope=scope if separator else None)


@dataclass(frozen=True, slots=True)
class GrantSet:
    """The standing grants in force for one request. Immutable by design."""

    keys: frozenset[str] = field(default_factory=frozenset)

    def __contains__(self, key: object) -> bool:
        return key in self.keys

    def covers_tool(self, tool: str) -> bool:
        return tool in self.keys

    def covers_scope(self, tool: str, scope: str | None) -> bool:
        return scope is not None and Grant(tool, scope).key in self.keys

    def __len__(self) -> int:
        return len(self.keys)

    @classmethod
    def of(cls, grants: list[Grant]) -> GrantSet:
        return cls(frozenset(grant.key for grant in grants))


@dataclass(frozen=True, slots=True)
class PolicyProfile:
    """Operational settings: how much of a human is available, and what they
    pre-authorised before the run started."""

    mode: RunMode = RunMode.INTERACTIVE
    preapproved_scopes: frozenset[str] = field(default_factory=frozenset)


# The refusal texts travel back to the model as ordinary tool results, so they
# are written for the model to act on, not for a log file. Each one says what
# happened and what to do instead.
_DENIED_FLAGGED = (
    "Permission denied: {tool} was flagged as risky ({reason}), and this session is "
    "non-interactive so nobody can approve it. Tell the user the exact command so "
    "they can judge it themselves."
)
_DENIED_MUTATES = (
    "Permission denied: {tool} mutates state and this session is non-interactive, so "
    "nobody can approve it. Rerun with --yes, or tell the user the exact step so "
    "they can run it themselves."
)


def decide(
    *,
    tool: str,
    arguments: Mapping[str, Any],
    grants: GrantSet = GrantSet(),
    profile: PolicyProfile = PolicyProfile(),
    registry: PolicyRegistry = DEFAULT_REGISTRY,
) -> Decision:
    """Evaluate one tool call. Pure: same inputs, same verdict, always.

    ``registry`` selects which **frozen configuration** answers for this tool.
    Production passes the default; ``eval/`` passes one of the historical
    registries so that "before" and "after" are the same function of different
    data rather than two different code paths.
    """
    mode = profile.mode

    if mode is RunMode.BYPASS:
        return Decision(verdict=Verdict.ALLOW, rule=Rule.BYPASS)

    if tool in READ_ONLY_TOOLS:
        return Decision(verdict=Verdict.ALLOW, rule=Rule.READ_ONLY)

    policy: ToolPolicy = registry.for_tool(tool)
    risk = policy.risk(tool, arguments)
    scope = policy.scope(tool, arguments)

    # A narrow grant covers the family it names, flagged calls included. The
    # user picked that scope deliberately, and the flagged calls are the ones
    # they were trying to stop being asked about.
    if grants.covers_scope(tool, scope):
        return Decision(verdict=Verdict.ALLOW, rule=Rule.SCOPED_GRANT, scope=scope)

    # The same shape, but authorised ahead of the run rather than interactively.
    if mode is RunMode.UNATTENDED and scope is not None and scope in profile.preapproved_scopes:
        return Decision(verdict=Verdict.ALLOW, rule=Rule.PREAPPROVED_SCOPE, scope=scope)

    # A broad grant stays weak: it never covers a flagged call.
    if risk is None and grants.covers_tool(tool):
        return Decision(verdict=Verdict.ALLOW, rule=Rule.TOOL_GRANT, scope=scope)

    # Routine calls pass in an unattended run, which is what `--yes` now means:
    # pre-approve everything that would not be flagged, and still stop at a
    # destructive command instead of sailing past it.
    if risk is None and mode is RunMode.UNATTENDED:
        return Decision(verdict=Verdict.ALLOW, rule=Rule.ROUTINE, scope=scope)

    if mode in (RunMode.HEADLESS, RunMode.UNATTENDED):
        # There is nobody to ask, and an ASK that can never be answered is a
        # hang. Refuse, and say why, so the model can route around it.
        if risk is not None:
            return Decision(
                verdict=Verdict.DENY,
                rule=Rule.NO_APPROVER_FLAGGED,
                reason=_DENIED_FLAGGED.format(tool=tool, reason=risk),
                scope=scope,
            )
        return Decision(
            verdict=Verdict.DENY,
            rule=Rule.NO_APPROVER,
            reason=_DENIED_MUTATES.format(tool=tool),
            scope=scope,
        )

    return Decision(
        verdict=Verdict.ASK,
        rule=Rule.RISK_FLAGGED if risk is not None else Rule.UNRECOGNISED,
        reason=risk,
        scope=scope,
    )


def execution_gate(
    tool: str,
    arguments: Mapping[str, Any],
    registry: PolicyRegistry = DEFAULT_REGISTRY,
) -> str | None:
    """The hard stop applied where the command actually runs.

    Separate from :func:`decide` because it answers a different question. The
    engine decides *who gets to say yes*; this decides whether the answer even
    matters. It is the only check that survives BYPASS, and it fires only for
    commands the allowlist declined to vouch for *and* the blocklist recognizes
    as unrecoverable.

    The gate belongs to the policy rather than to a module-level function
    because its *strength* is part of the configuration: the legacy gate is the
    raw blocklist, and the current one is the two-condition check. Swapping the
    policy has to swap both, or a historical replay would run the new gate
    against the old rules -- measuring the change instead of the baseline.
    """
    return registry.for_tool(tool).gate(tool, arguments)


def grant_for_answer(answer: str, decision: Decision, tool: str) -> Grant | None:
    """Which grant, if any, a human's answer records.

    ``answer`` is one of ``once`` / ``always`` / ``scoped`` / ``deny``.

    The business rule enforced here is the one that took the longest to get
    right in the reference implementation: **answering "always" on a flagged
    call records nothing.** Agreeing to one destructive command says nothing
    about the next one, so the only answer that covers a flagged call is the
    narrow one that names the command family. This function is the single place
    that rule lives, and ``tests/unit/test_engine.py`` pins it.
    """
    if answer == "always":
        # Only ever covers unflagged calls -- see the module docstring, step 5.
        # The check reads the decision's rule rather than re-deriving the risk,
        # because "was this flagged" is already recorded there and a second
        # derivation is a second thing that can disagree with the first.
        if decision.rule is Rule.RISK_FLAGGED:
            return None
        return Grant(tool=tool)
    if answer == "scoped":
        if decision.scope is None:
            # No single family to name (a chain, or a non-bash tool), so there
            # is nothing narrower than the tool to grant. Fall back to the weak
            # grant rather than silently widening it.
            return Grant(tool=tool)
        return Grant(tool=tool, scope=decision.scope)
    return None
