"""Offline evaluation harness: replay the corpus through the decision engine.

No server, no database, no network. That is possible because
``permgate.domain.engine.decide`` is pure -- everything a decision needs arrives
in the call -- and it is the reason the security claims in ``docs/`` are
reproducible instead of remembered.

Three client behaviours are simulated, because the consent layer's behaviour
only makes sense against a model of the person answering it:

``cautious``
    Answers every prompt with "once" and never grants anything standing.

``trusting``
    Answers every prompt with "always". This is the behaviour the prompt itself
    offers as an option, and the natural response to being asked repeatedly.
    It is the behaviour the whole exposure measurement is about.

``ci``
    Nobody is watching. Scopes on the pre-approved list are granted in advance;
    everything else is refused.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum

from permgate.domain.decision import Decision, RunMode, Verdict
from permgate.domain.engine import PolicyProfile, decide, execution_gate, grant_for_answer
from permgate.domain.policies import PolicyRegistry

from .corpus import BENIGN_COMMANDS, DANGEROUS_COMMANDS


class Outcome(str, Enum):
    """Where a command ended up. These four buckets are the whole measurement."""

    PROMPTED = "prompted"
    """A human was asked. The command runs if they say yes."""

    SILENT_BLOCK = "silent_block"
    """Nobody was asked and a mechanism stopped it anyway. The user's mental
    model of what the agent does is now wrong -- which is its own hazard, and
    the reason round one counted as a win even though the exposure did not move.
    """

    SILENT_EXEC = "silent_exec"
    """Nobody was asked, nothing stopped it, it ran. **This is the main metric**:
    the risk a user carries without knowing."""

    DENIED = "denied"
    """The policy refused. In an unattended run this is the substitute for a
    prompt."""


Answerer = Callable[[str, Decision], str]
"""``(command, decision) -> "once" | "always" | "scoped" | "deny"``"""


def cautious(_command: str, _decision: Decision) -> str:
    return "once"


def trusting(_command: str, _decision: Decision) -> str:
    return "always"


def ci(preapproved: frozenset[str]) -> Answerer:
    def answerer(_command: str, decision: Decision) -> str:
        return "scoped" if decision.scope in preapproved else "deny"

    return answerer


@dataclass(frozen=True)
class RunResult:
    """One configuration's outcome over the whole corpus."""

    label: str
    by_label: Mapping[str, Mapping[Outcome, tuple[str, ...]]]
    prompts: int

    def bucket(self, corpus_label: str, outcome: Outcome) -> tuple[str, ...]:
        return self.by_label[corpus_label][outcome]

    @property
    def exposure(self) -> int:
        """Dangerous commands that ran with nobody asked and nothing stopping
        them. The number this whole project exists to move."""
        return len(self.bucket("dangerous", Outcome.SILENT_EXEC))

    @property
    def silent_blocks(self) -> int:
        return sum(
            len(self.bucket(label, Outcome.SILENT_BLOCK)) for label in ("benign", "dangerous")
        )

    @property
    def benign_silent_exec(self) -> int:
        return len(self.bucket("benign", Outcome.SILENT_EXEC))


def run_chain(
    *,
    label: str,
    registry: PolicyRegistry,
    answerer: Answerer,
    mode: RunMode = RunMode.INTERACTIVE,
    preapproved_scopes: frozenset[str] = frozenset(),
    commands: Mapping[str, Iterable[str]] | None = None,
) -> RunResult:
    """Replay every command once, in order, sharing one grant set.

    Sharing the grant set across the whole run is not a shortcut -- it is the
    thing being measured. A single session accumulates grants, and the exposure
    is what that accumulation lets through by the end.
    """
    corpus = commands or {"benign": BENIGN_COMMANDS, "dangerous": DANGEROUS_COMMANDS}
    profile = PolicyProfile(mode=mode, preapproved_scopes=preapproved_scopes)

    granted: set[str] = set()
    prompts = 0
    by_label: dict[str, dict[Outcome, tuple[str, ...]]] = {}

    for corpus_label, items in corpus.items():
        buckets: dict[Outcome, list[str]] = {outcome: [] for outcome in Outcome}
        for command in items:
            arguments = {"command": command}
            decision = decide(
                tool="bash",
                arguments=arguments,
                grants=_grant_set(granted),
                profile=profile,
                registry=registry,
            )

            if decision.verdict is Verdict.DENY:
                buckets[Outcome.DENIED].append(command)
                continue

            if decision.verdict is Verdict.ASK:
                prompts += 1
                answer = answerer(command, decision)
                grant = grant_for_answer(answer, decision, "bash")
                if grant is not None:
                    granted.add(grant.key)
                if answer == "deny":
                    buckets[Outcome.DENIED].append(command)
                else:
                    buckets[Outcome.PROMPTED].append(command)
                continue

            # Allowed. The execution gate is the last thing between the command
            # and the shell, and it is the only check a bypass does not skip.
            if execution_gate("bash", arguments, registry) is not None:
                buckets[Outcome.SILENT_BLOCK].append(command)
            else:
                buckets[Outcome.SILENT_EXEC].append(command)

        by_label[corpus_label] = {outcome: tuple(v) for outcome, v in buckets.items()}

    return RunResult(label=label, by_label=by_label, prompts=prompts)


def _grant_set(keys: set[str]):
    from permgate.domain.engine import GrantSet

    return GrantSet(frozenset(keys))


def run_unattended(
    *,
    label: str,
    registry: PolicyRegistry,
    mode: RunMode,
    preapproved_scopes: frozenset[str],
) -> RunResult:
    """A run with nobody at the keyboard: no prompts, only allow / deny."""
    answerer = ci(preapproved_scopes) if preapproved_scopes else (lambda _c, _d: "deny")
    return run_chain(
        label=label,
        registry=registry,
        answerer=answerer,
        mode=mode,
        preapproved_scopes=preapproved_scopes,
    )
