"""What a decision is, and what the caller is allowed to do with it.

The service answers one question -- "may this tool call proceed?" -- and the
answer has to carry enough for three different audiences:

* the **agent**, which needs to route around a refusal (``reason``);
* the **human**, who is shown a prompt and needs to know what they are
  approving (``reason``, ``scope``);
* the **operator**, who has to explain months later why a call was allowed
  (``rule``, and the audit row it lands in).

That third audience is why every decision names the rule that produced it.
"policy said allow" is not an audit trail; "scoped grant ``bash:git push``,
recorded 2026-09-14, allowed it" is.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """The three outcomes a caller has to handle."""

    ALLOW = "allow"
    """Run it. Nothing else to do."""

    ASK = "ask"
    """Stop and get a human. The caller is responsible for collecting the
    answer and, if the human grants one, calling the grant API."""

    DENY = "deny"
    """Refuse. The reason travels back to the model as an ordinary tool result
    so the loop survives and the model can route around it."""


class RunMode(str, Enum):
    """How much of a human is available, and how much they pre-authorised.

    These are not variations on a theme -- each one is a distinct operational
    setting with a distinct failure mode, and the whole point of the mode enum
    is to make the setting explicit at every call site instead of implicit in a
    pile of booleans.
    """

    INTERACTIVE = "interactive"
    """A person is at the keyboard. Anything unflagged that is not covered by a
    standing grant becomes an ASK."""

    UNATTENDED = "unattended"
    """``--yes``: nobody is watching, so routine (unflagged) calls go through
    and flagged calls stop. This is *not* "allow everything" -- a pre-approval
    that swallows a destructive command is the exposure this project exists to
    remove."""

    HEADLESS = "headless"
    """No approver at all and no blanket pre-approval: anything that would have
    been an ASK becomes a DENY, because an ASK nobody can answer is a hang."""

    BYPASS = "bypass"
    """``--dangerously-skip-permissions``. Skips consent *and* the risk signal.
    Nothing else in the system should select this, and the API refuses to
    serve it unless the deployment explicitly enables it."""


class Rule(str, Enum):
    """Which rule produced the verdict.

    Kept as an enum rather than a free string so the metric labels cannot drift
    into a long tail of near-duplicates -- a label set that grows without bound
    is how a metrics backend falls over.
    """

    READ_ONLY = "read_only"
    BYPASS = "bypass"
    SCOPED_GRANT = "scoped_grant"
    PREAPPROVED_SCOPE = "preapproved_scope"
    TOOL_GRANT = "tool_grant"
    ROUTINE = "routine"
    RISK_FLAGGED = "risk_flagged"
    UNRECOGNISED = "unrecognised"
    NO_APPROVER = "no_approver"
    NO_APPROVER_FLAGGED = "no_approver_flagged"


@dataclass(frozen=True, slots=True)
class Decision:
    """One verdict, with everything the three audiences above need."""

    verdict: Verdict
    rule: Rule
    reason: str | None = None
    """Human-readable, and shown verbatim in the agent's tool result. None when
    there is nothing to explain."""

    scope: str | None = None
    """The command family this call belongs to, when it has exactly one. This
    is what a *narrow* grant would name, so the caller needs it in order to
    offer "always allow this pattern" as a choice."""

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "rule": self.rule.value,
            "reason": self.reason,
            "scope": self.scope,
        }
