"""The decision engine's ordering, one test per branch.

The ordering *is* the security model, so each step gets its own test rather than
being covered incidentally by a larger scenario. A test that exercises four
rules at once tells you the combination is wrong, not which rule broke.
"""

from __future__ import annotations

import pytest

from permgate.domain.decision import Rule, RunMode, Verdict
from permgate.domain.engine import (
    Grant,
    GrantSet,
    PolicyProfile,
    decide,
    execution_gate,
    grant_for_answer,
)

# A command the allowlist vouches for, and one it does not. Named once so a
# change to the rule tables shows up as a failing test here rather than as a
# silently different scenario.
VOUCHED = "ls -la"
FLAGGED = "kubectl delete namespace production"
BARE_GRANT = GrantSet.of([Grant("bash")])
SCOPED_GRANT = GrantSet.of([Grant("bash", "kubectl delete")])


class TestReadOnly:
    def test_read_only_tools_never_reach_a_human(self):
        for tool in ("read_file", "glob", "grep", "todo_write"):
            result = decide(tool=tool, arguments={"file_path": "x"})
            assert result.verdict is Verdict.ALLOW
            assert result.rule is Rule.READ_ONLY

    def test_read_only_is_checked_before_the_risk_signal(self):
        # A read-only tool carrying something that looks dangerous is still
        # read-only: the risk signal is about what a command *does*, and this
        # one does not run anything.
        result = decide(tool="read_file", arguments={"file_path": "/etc/shadow"})
        assert result.rule is Rule.READ_ONLY


class TestBypass:
    def test_bypass_allows_everything(self):
        result = decide(
            tool="bash",
            arguments={"command": FLAGGED},
            profile=PolicyProfile(mode=RunMode.BYPASS),
        )
        assert result.verdict is Verdict.ALLOW
        assert result.rule is Rule.BYPASS

    def test_bypass_short_circuits_even_a_scoped_grant_lookup(self):
        # Bypass is checked first, so the grant set is never consulted. That is
        # what makes it a bypass rather than a very permissive grant.
        result = decide(
            tool="bash",
            arguments={"command": FLAGGED},
            grants=GrantSet(),
            profile=PolicyProfile(mode=RunMode.BYPASS),
        )
        assert result.rule is Rule.BYPASS


class TestGrantAsymmetry:
    """The rule the whole project turns on: strength is set against breadth."""

    def test_a_tool_grant_covers_unflagged_calls(self):
        result = decide(tool="bash", arguments={"command": VOUCHED}, grants=BARE_GRANT)
        assert result.verdict is Verdict.ALLOW
        assert result.rule is Rule.TOOL_GRANT

    def test_a_tool_grant_does_not_cover_a_flagged_call(self):
        result = decide(tool="bash", arguments={"command": FLAGGED}, grants=BARE_GRANT)
        assert result.verdict is Verdict.ASK
        assert result.rule is Rule.RISK_FLAGGED

    def test_a_scoped_grant_does_cover_a_flagged_call(self):
        result = decide(tool="bash", arguments={"command": FLAGGED}, grants=SCOPED_GRANT)
        assert result.verdict is Verdict.ALLOW
        assert result.rule is Rule.SCOPED_GRANT
        assert result.scope == "kubectl delete"

    def test_a_scoped_grant_does_not_leak_to_a_sibling_family(self):
        # `bash:git push` must not authorise `git push --force`. Same program,
        # different flags, different intent -- and this is the exact pair that
        # made a program-level grant insufficient.
        grants = GrantSet.of([Grant("bash", "git push")])
        result = decide(
            tool="bash", arguments={"command": "git push --force origin main"}, grants=grants
        )
        assert result.verdict is Verdict.ASK


class TestAnswers:
    def test_always_on_a_flagged_call_records_nothing(self):
        decision = decide(tool="bash", arguments={"command": FLAGGED})
        assert decision.rule is Rule.RISK_FLAGGED
        assert grant_for_answer("always", decision, "bash") is None

    def test_always_on_an_unflagged_call_records_a_tool_grant(self):
        decision = decide(tool="bash", arguments={"command": VOUCHED})
        grant = grant_for_answer("always", decision, "bash")
        assert grant is not None
        assert grant.key == "bash"
        assert not grant.is_scoped

    def test_scoped_records_the_narrow_grant(self):
        decision = decide(tool="bash", arguments={"command": FLAGGED})
        grant = grant_for_answer("scoped", decision, "bash")
        assert grant is not None
        assert grant.key == "bash:kubectl delete"
        assert grant.is_scoped

    def test_scoped_with_no_scope_falls_back_to_the_weak_grant(self):
        # A chain (`a && b`) has no single family to name. Recording a tool-level
        # grant is the conservative choice: it is weaker than what was asked
        # for, never stronger.
        decision = decide(tool="bash", arguments={"command": "ls && pwd"})
        assert decision.scope is None
        grant = grant_for_answer("scoped", decision, "bash")
        assert grant is not None and not grant.is_scoped

    @pytest.mark.parametrize("answer", ["once", "deny"])
    def test_once_and_deny_record_nothing(self, answer: str):
        decision = decide(tool="bash", arguments={"command": VOUCHED})
        assert grant_for_answer(answer, decision, "bash") is None


class TestUnattended:
    def test_routine_calls_pass_without_a_human(self):
        result = decide(
            tool="bash",
            arguments={"command": VOUCHED},
            profile=PolicyProfile(mode=RunMode.UNATTENDED),
        )
        assert result.verdict is Verdict.ALLOW
        assert result.rule is Rule.ROUTINE

    def test_a_flagged_call_is_denied_rather_than_asked(self):
        result = decide(
            tool="bash",
            arguments={"command": FLAGGED},
            profile=PolicyProfile(mode=RunMode.UNATTENDED),
        )
        assert result.verdict is Verdict.DENY
        assert result.rule is Rule.NO_APPROVER_FLAGGED
        assert result.reason is not None and "kubectl" in result.reason

    def test_a_preapproved_scope_is_the_only_way_through(self):
        result = decide(
            tool="bash",
            arguments={"command": FLAGGED},
            profile=PolicyProfile(
                mode=RunMode.UNATTENDED, preapproved_scopes=frozenset({"kubectl delete"})
            ),
        )
        assert result.verdict is Verdict.ALLOW
        assert result.rule is Rule.PREAPPROVED_SCOPE

    def test_a_preapproval_does_not_leak_across_families(self):
        result = decide(
            tool="bash",
            arguments={"command": "terraform destroy -auto-approve"},
            profile=PolicyProfile(
                mode=RunMode.UNATTENDED, preapproved_scopes=frozenset({"kubectl delete"})
            ),
        )
        assert result.verdict is Verdict.DENY


class TestHeadless:
    def test_no_approver_turns_an_ask_into_a_deny(self):
        result = decide(
            tool="bash",
            arguments={"command": VOUCHED},
            profile=PolicyProfile(mode=RunMode.HEADLESS),
        )
        # Nothing to flag, but also nobody to say yes -- and an ASK nobody can
        # answer is a hang, which is worse than a refusal.
        assert result.verdict is Verdict.DENY
        assert result.rule is Rule.NO_APPROVER

    def test_headless_explains_itself_differently_when_flagged(self):
        flagged = decide(
            tool="bash",
            arguments={"command": FLAGGED},
            profile=PolicyProfile(mode=RunMode.HEADLESS),
        )
        assert flagged.rule is Rule.NO_APPROVER_FLAGGED
        assert flagged.reason is not None and "risky" in flagged.reason


class TestExecutionGate:
    def test_the_gate_only_fires_for_unvouched_commands(self):
        # The two-condition rule: the allowlist must decline to vouch AND the
        # blocklist must recognize it. `rm -rf ./build` is vouched for, so it
        # runs even though the blocklist regex matches it.
        assert execution_gate("bash", {"command": "rm -rf ./build"}) is None

    def test_the_gate_fires_for_the_unrecoverable(self):
        assert execution_gate("bash", {"command": "mkfs.ext4 /dev/sda1"}) is not None

    def test_the_gate_ignores_non_bash_tools(self):
        assert execution_gate("write_file", {"file_path": "x", "content": "y"}) is None


class TestGrantKeys:
    def test_round_trip_tool_level(self):
        assert Grant.from_key("bash") == Grant("bash")

    def test_round_trip_scoped(self):
        assert Grant.from_key("bash:git push") == Grant("bash", "git push")

    def test_only_the_first_colon_splits(self):
        # A scope containing a colon must survive; `bash:a:b` is tool `bash`
        # with scope `a:b`, not tool `bash` with scope `a`.
        grant = Grant.from_key("bash:a:b")
        assert grant.tool == "bash"
        assert grant.scope == "a:b"
