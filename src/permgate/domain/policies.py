"""Tool policies: which signal a tool contributes, and which historical
configuration is in force.

The reference implementation injected three callbacks (``risk``, ``scope``,
and an ``ask``) into the consent layer. That worked for one process with one
configuration, but it makes the *history* unreachable: the only behaviour
available is the newest one, so the claim "this change moved the exposure from 8
to 0" can never be re-measured, only remembered.

A policy object fixes that. Each named policy is a **frozen configuration**, and
``eval/`` runs the same corpus through all of them, which is what makes the
numbers in ``docs/permission-model.md`` reproducible rather than asserted.

The three that matter:

``LegacyPolicy``
    Before any change. The consent layer knows the tool's name and nothing else,
    and the execution layer falls back on the raw blocklist. This is the
    baseline every later number is measured against.

``BlocklistPolicy``
    Round one. The blocklist's verdict now reaches the consent layer, so silent
    blocks become visible questions. The *signal source* is unchanged, which is
    why this round did not move the exposure at all -- the negative result the
    project reports about itself.

``AllowlistPolicy``
    Round three, and the current default. The question flips from "does this
    look dangerous" to "can we vouch for this", and the execution gate becomes
    the two-condition check instead of the raw blocklist.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from . import bash_policy


@runtime_checkable
class ToolPolicy(Protocol):
    """What one tool contributes to a decision.

    All three methods are pure and take the tool name even though an
    implementation usually only answers for one, because the registry dispatches
    by name and a policy that wants to answer for several should be able to.
    """

    def risk(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        """A reason this call looks destructive, or ``None``.

        ``None`` is not a clean bill of health -- it means the policy has no
        objection it can articulate, which for an unrecognised command is
        exactly the point.
        """
        ...

    def scope(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        """The command family this call belongs to, or ``None`` when it has no
        single one (a chain, or a tool with no finer granularity than itself).
        """
        ...

    def gate(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        """The execution-layer hard stop, or ``None``. This is the only check
        that survives a bypass, so its strength matters more than its breadth.
        """
        ...


class LegacyPolicy:
    """Configuration in force before any of the four rounds.

    Two failures, and they compound. The consent layer cannot see what the
    command is, so a whole-tool grant covers every future call; and the
    execution layer's only defence is a regex list that misses 32% of the
    dangerous corpus.
    """

    name = "legacy"

    def risk(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        return None  # the consent layer was never told

    def scope(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        return None  # so there was nothing finer than the tool to grant

    def gate(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        if tool != "bash":
            return None
        return bash_policy.check_dangerous(arguments.get("command") or "")


class BlocklistPolicy:
    """Round one: the blocklist's verdict reaches the consent layer.

    A flagged call can no longer be auto-approved by an earlier grant, so
    silently-blocked commands become visible questions. The signal is the same
    68%-recall regex, so the exposure is untouched -- which is the whole finding.
    """

    name = "blocklist"

    def risk(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        if tool != "bash":
            return None
        return bash_policy.check_dangerous(arguments.get("command") or "")

    def scope(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        return None

    def gate(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        if tool != "bash":
            return None
        return bash_policy.check_dangerous(arguments.get("command") or "")


class AllowlistPolicy:
    """Rounds three and four, and the current default.

    The question flips from "does this look dangerous" to "can we vouch for
    this". Recall goes to 100%, the false-positive rate goes to zero, and the
    cost is that every legitimate-but-unrecognised command now reaches a human.
    """

    name = "allowlist"

    def risk(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        return bash_policy.risk_reason(tool, arguments)

    def scope(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        return bash_policy.command_scope(tool, arguments)

    def gate(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        if tool != "bash":
            return None
        return bash_policy.execution_block(arguments.get("command") or "")


class NullPolicy:
    """A tool with no signal of its own.

    Reaching for this for ``bash`` would silently disable the whole model, so
    the registry is built explicitly rather than by default-construction.
    """

    name = "null"

    def risk(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        return None

    def scope(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        return None

    def gate(self, tool: str, arguments: Mapping[str, Any]) -> str | None:
        return None


class PolicyRegistry:
    """Resolves a tool name to the policy that speaks for it.

    Adding a tool is a registration, not an edit to the engine -- which is the
    difference between a rule layer that grows and one that accretes.
    """

    def __init__(
        self, default: ToolPolicy, by_tool: Mapping[str, ToolPolicy] | None = None
    ) -> None:
        self._default = default
        self._by_tool = dict(by_tool or {})

    def for_tool(self, tool: str) -> ToolPolicy:
        return self._by_tool.get(tool, self._default)

    def with_tool(self, tool: str, policy: ToolPolicy) -> PolicyRegistry:
        """A copy with one more registration. Registries are not mutated in
        place, so a request cannot observe another request's edit."""
        merged = dict(self._by_tool)
        merged[tool] = policy
        return PolicyRegistry(self._default, merged)

    @property
    def tools(self) -> frozenset[str]:
        return frozenset(self._by_tool)


#: The production registry. Only bash has a signal today; every other mutating
#: tool is handled by the engine's tool-level rules, which is honest -- the
#: service does not pretend to understand tools it has no rules for.
DEFAULT_REGISTRY = PolicyRegistry(default=NullPolicy(), by_tool={"bash": AllowlistPolicy()})

#: The three frozen configurations the evaluation harness replays.
HISTORY: dict[str, tuple[PolicyRegistry, str]] = {
    "legacy": (
        PolicyRegistry(default=NullPolicy(), by_tool={"bash": LegacyPolicy()}),
        LegacyPolicy.name,
    ),
    "blocklist": (
        PolicyRegistry(default=NullPolicy(), by_tool={"bash": BlocklistPolicy()}),
        BlocklistPolicy.name,
    ),
    "allowlist": (DEFAULT_REGISTRY, AllowlistPolicy.name),
}
